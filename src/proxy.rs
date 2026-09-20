//! The application behind the SMTP server: collect, ask the API, relay.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tracing::{debug, info, warn};

use crate::api::{
    ApiClient, CheckRequest, CheckResponse, Recipient, RequestHeader, ResponseHeader,
};
use crate::ratelimit::RateLimiter;
use crate::relay::{
    Envelope, RelayConfig, RelayError, UpstreamCaps, UpstreamSession, UpstreamVerdict,
    assert_relayable, probe,
};
use crate::server::{BodySink, Handler, HandlerFactory, Rejection};
use crate::smtp::params::Param;

pub struct ProxyConfig {
    pub api: ApiClient,
    pub relay: RelayConfig,
    /// Messages a single authenticated username may start per minute.
    /// 0 means unlimited.
    pub messages_per_minute: u32,
}

#[derive(Clone)]
pub struct ProxyFactory {
    config: Arc<ProxyConfig>,
    upstream_dsn: Arc<AtomicBool>,
    /// False until the first answer is in, which is the Perl's "undefined
    /// until asked" state. Kept apart from `upstream_dsn` so that the first
    /// answer is logged even when it is the same as the initial `false`.
    upstream_dsn_known: Arc<AtomicBool>,
    /// The upstream's stated SIZE limit, or 0 for "none stated". Zero is
    /// safe as the sentinel because RFC 1870's `SIZE 0` already means "no
    /// fixed maximum", so a real limit is never zero.
    upstream_size: Arc<AtomicUsize>,
    /// Shared by every connection, because the limit is per username and a
    /// username may arrive on any number of them.
    limiter: Arc<RateLimiter>,
}

impl ProxyFactory {
    pub fn new(config: ProxyConfig) -> Self {
        let limiter = Arc::new(RateLimiter::new(config.messages_per_minute));
        Self {
            config: Arc::new(config),
            upstream_dsn: Arc::new(AtomicBool::new(false)),
            upstream_dsn_known: Arc::new(AtomicBool::new(false)),
            upstream_size: Arc::new(AtomicUsize::new(0)),
            limiter,
        }
    }

    /// Spec 9.3: forgets the buckets of usernames not seen for `idle`,
    /// called from a timer so that a busy relay's map does not grow with
    /// every username that ever connected.
    pub fn prune_rate_limits(&self, idle: std::time::Duration) {
        self.limiter.prune(idle);
    }

    /// How many rate-limit buckets are held. A bucket is keyed on the
    /// username claimed at AUTH, so this is the count of distinct unverified
    /// identities the process is currently remembering.
    pub fn rate_limit_buckets(&self) -> usize {
        self.limiter.bucket_count()
    }

    pub fn upstream_dsn(&self) -> Arc<AtomicBool> {
        self.upstream_dsn.clone()
    }

    fn upstream_name(&self) -> String {
        format!("{}:{}", self.config.relay.host, self.config.relay.port)
    }

    /// Logs only when the answer changes (spec 6).
    fn note_upstream_caps(&self, caps: UpstreamCaps) {
        let previous = self.upstream_dsn.swap(caps.dsn, Ordering::Relaxed);
        let known = self.upstream_dsn_known.swap(true, Ordering::Relaxed);
        if !known || previous != caps.dsn {
            info!(
                "{} {}; the extension will {}be offered to clients",
                self.upstream_name(),
                if caps.dsn {
                    "announces DSN"
                } else {
                    "does not announce DSN"
                },
                if caps.dsn { "" } else { "not " }
            );
        }
        let size = caps.size.unwrap_or(0);
        let previous_size = self.upstream_size.swap(size, Ordering::Relaxed);
        if !known || previous_size != size {
            match caps.size {
                Some(n) => info!(
                    "{} accepts messages up to {n} bytes; the limit will be offered to clients",
                    self.upstream_name()
                ),
                None => info!(
                    "{} states no message size limit; none will be offered to clients",
                    self.upstream_name()
                ),
            }
        }
    }

    /// The upstream's stated limit, or `None` when it stated none or has not
    /// been asked yet. Both are the same answer to a client: say nothing.
    pub fn upstream_size_limit(&self) -> Option<usize> {
        match self.upstream_size.load(Ordering::Relaxed) {
            0 => None,
            n => Some(n),
        }
    }

    /// Asked once at startup and kept current from every relay afterwards,
    /// so an upstream that gains or loses DSN is noticed without polling.
    /// Never fails: an upstream that is down at startup simply leaves DSN
    /// unannounced until the first mail is relayed.
    pub async fn probe_upstream(&self) {
        let upstream = self.upstream_name();
        debug!("Asking {upstream} which extensions it offers");
        match probe(&self.config.relay).await {
            Ok(caps) => self.note_upstream_caps(caps),
            Err(e) => warn!(
                "Could not ask {upstream} which extensions it offers ({e}); DSN will not be announced until a mail is relayed"
            ),
        }
    }
}

impl HandlerFactory for ProxyFactory {
    type Handler = ProxyHandler;

    fn create(&self, client: SocketAddr, _id: &str) -> ProxyHandler {
        ProxyHandler {
            factory: self.clone(),
            client,
            username: None,
            password: None,
            transaction: Transaction::default(),
        }
    }
}

/// Spec 5.1: everything `reset()` clears. The session-wide credentials live
/// on the handler itself, so that a RSET or a second EHLO cannot drop them.
#[derive(Default)]
struct Transaction {
    from: String,
    mail_params: Vec<Param>,
    recipients: Vec<Recipient>,
    headers: Vec<RequestHeader>,
}

pub struct ProxyHandler {
    factory: ProxyFactory,
    client: SocketAddr,
    username: Option<String>,
    password: Option<String>,
    transaction: Transaction,
}

/// Splits at a line break followed by a non-blank (folded lines stay whole),
/// then at the first colon. A line without a colon, and a line with nothing
/// at all behind the colon, is logged and dropped (spec 5.2).
///
/// **Divergence from the Perl, approved 2026-09-12.** The Perl splits on
/// `/\r\n(?=$|\S)/` and so only ever on CRLF. `HeaderCollector` accepts a bare
/// LF as a line terminator (`server::data`, as the Perl's reader does), so a
/// header block written with bare LF genuinely arrives here -- and split on
/// CRLF alone it becomes a *single* header whose value carries every
/// remaining header. API-side header policy would then be evadable by
/// sending LF instead of CRLF. Splitting on the LF of either terminator
/// closes that.
pub fn parse_headers(block: &str) -> Vec<RequestHeader> {
    let mut lines: Vec<String> = Vec::new();
    for raw in block.split_inclusive('\n') {
        // The Perl splits on `/\r\n(?=$|\S)/`, whose `\S` counts the
        // vertical tab and the form feed as continuation as well.
        let continuation = raw.starts_with([' ', '\t', '\x0b', '\x0c']);
        match lines.last_mut() {
            Some(last) if continuation => last.push_str(raw),
            _ => lines.push(raw.to_string()),
        }
    }
    let mut out = Vec::new();
    for line in lines {
        let line = line.trim_end_matches(['\r', '\n']);
        match line.split_once(':') {
            // `[^:]+` needs a name and `(.+)` needs at least one character
            // behind the colon, so `Subject:` does not parse.
            Some((name, rest)) if !name.is_empty() && !rest.is_empty() => out.push(RequestHeader {
                name: name.to_string(),
                value: perl_header_value(rest),
            }),
            _ => warn!("Could not parse header '{line}'"),
        }
    }
    out
}

/// The value half of the Perl's `/^([^:]+):\s*(.+)$/s` (`SMTPProxy.pm:96`).
/// `\s*` is greedy, so leading whitespace -- the CRLF and indent of a folded
/// line included -- is stripped. But `(.+)` needs one character, so when
/// everything behind the colon is whitespace the regex backtracks by exactly
/// one: `Subject:  ` yields a single space, not the empty string. Faithful
/// here because the header list goes to the customer's API as it is.
fn perl_header_value(rest: &str) -> String {
    let trimmed = rest.trim_start();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    rest.chars()
        .next_back()
        .map(String::from)
        .unwrap_or_default()
}

/// Spec 5.4: remove every header the API names, then append those it gave a
/// value, in API order.
///
/// **Divergence from the Perl, approved 2026-09-12.** The Perl compares names
/// exactly (`%toRemove` keyed on the raw name, `SMTPProxy.pm:248-250`), so an
/// API answering `subject` while the client sent `Subject` removes nothing
/// and the relayed message carries *both*. RFC 5322 3.6.8 makes field names
/// case-insensitive, so the comparison is too. ASCII case is the right fold:
/// a field name is printable US-ASCII by the same section.
pub fn merge_headers(existing: Vec<RequestHeader>, api: &[ResponseHeader]) -> Vec<RequestHeader> {
    let mut out: Vec<RequestHeader> = existing
        .into_iter()
        .filter(|h| !api.iter().any(|a| a.name.eq_ignore_ascii_case(&h.name)))
        .collect();
    out.extend(api.iter().filter_map(|a| {
        a.value.clone().map(|value| RequestHeader {
            name: a.name.clone(),
            value,
        })
    }));
    out
}

/// Whether a line break at `i` in `value` is a proper fold: the break itself,
/// then a space or a tab (RFC 5322 3.2.2 FWS). `\r\n` and a bare `\n` both
/// count as the break, because a client-supplied folded header reaches this
/// point with whichever of the two it arrived with (see [`parse_headers`]).
fn folds_at(value: &[u8], i: usize) -> bool {
    let after = if value[i] == b'\r' {
        if value.get(i + 1) != Some(&b'\n') {
            // A CR that is not the start of a CRLF is not a fold and not a
            // line break either; it has no business in a relayed header.
            return false;
        }
        i + 2
    } else {
        i + 1
    };
    matches!(value.get(after), Some(b' ' | b'\t'))
}

/// Refuses any header that would not survive [`header_block`] intact
/// (spec 5.4 writes `name: value` and a CRLF, with no escaping of either
/// half). A value carrying `\r\n\r\n` splits the relayed message and forges
/// a body; one carrying a single `\r\n` forges a header.
///
/// A line break inside a value is legal only as a proper fold -- a `\r\n` or
/// a bare `\n` immediately followed by a space or a tab. That precision is
/// required rather than a blanket "no CRLF": client-supplied folded headers
/// arrive here with their break intact and have to keep relaying. A *name*
/// may hold no `\r`, `\n` or `:` at all, since the colon is what separates
/// it from the value.
///
/// `Err` carries the offending header's **name only**. The value may hold
/// customer content and this string is logged.
///
/// **Divergence from the Perl, approved 2026-09-12.** The Perl interpolates
/// the value unchecked (`SMTPProxy.pm:252-253`). The envelope addresses are
/// guarded on both sides ([`crate::relay::assert_relayable`]); the headers
/// were not.
pub fn assert_header_relayable(headers: &[RequestHeader]) -> Result<(), String> {
    for h in headers {
        if h.name.contains(['\r', '\n', ':']) {
            return Err(h.name.clone());
        }
        let value = h.value.as_bytes();
        for i in 0..value.len() {
            if (value[i] == b'\r' || value[i] == b'\n') && !folds_at(value, i) {
                return Err(h.name.clone());
            }
        }
    }
    Ok(())
}

/// Spec 5.4: `name: value` per header and then the empty line that ends the
/// block -- put into the form DATA requires, which is two jobs and not one.
///
/// **Both jobs used to belong to `normalize_and_stuff` (`relay.rs`), which
/// ran over the whole formatted message.** That function is gone with the
/// buffering, and the body no longer needs either: it arrives already
/// stuffed and already CRLF-framed by `BodyFramer` (`server::data`), and is
/// relayed verbatim (spec 5.1). The header block needs both, because it is
/// built here out of parsed content rather than passed through:
///
/// 1. [`normalize_breaks`] -- a folded value may carry a **bare LF** as its
///    break. `HeaderCollector` appends header lines verbatim, [`parse_headers`]
///    keeps whichever break arrived inside the folded value, and [`folds_at`]
///    accepts a bare `\n` before a space or tab. Written out as it stands,
///    that LF would go on the wire inside DATA, against RFC 5321 2.3.8.
/// 2. [`dot_stuff`] -- `HeaderCollector` *unstuffs* on the way in, so that
///    the API and [`parse_headers`] see content rather than wire form. A
///    client line `..X-Foo: y` is therefore held here as `.X-Foo: y`, and
///    written raw it would reach the upstream as `X-Foo: y`, a header name
///    one character shorter than the one the client sent.
///    [`assert_header_relayable`] refuses only `\r`, `\n` and `:` in a name,
///    so a leading dot gets this far.
///
/// The two passes commute -- [`dot_stuff`] keys on the LF, which both break
/// forms carry -- so the order is the reading order and nothing rests on it.
/// Headers the API supplied go through both alike: this is a wire encoding,
/// not a property of where a header came from.
pub fn header_block(headers: &[RequestHeader]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    for h in headers {
        out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    dot_stuff(&normalize_breaks(&out))
}

/// Rewrites every `\r?\n` to `\r\n` (RFC 5321 2.3.8: inside DATA a line ends
/// with CRLF and with nothing else).
///
/// A lone CR is left alone, exactly as the Perl's `s/\015?\012/\015\012/`
/// left it: it is not a line ending, and turning it into one would split a
/// header. [`assert_header_relayable`] refuses one in a value anyway, so the
/// case is unreachable from here -- the rule is stated because the function
/// has to have one, not because a header can carry it.
fn normalize_breaks(block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(block.len() + 8);
    let mut i = 0;
    while i < block.len() {
        match block[i] {
            b'\n' => {
                out.extend_from_slice(b"\r\n");
                i += 1;
            }
            b'\r' if block.get(i + 1) == Some(&b'\n') => {
                out.extend_from_slice(b"\r\n");
                i += 2;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Doubles a `.` that begins a line (RFC 5321 4.5.2).
///
/// A line begins at offset 0 and after every LF, which is what SMTP frames
/// on. Run after [`normalize_breaks`], so every LF here is the second byte of
/// a CRLF and a lone CR begins no line.
fn dot_stuff(block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(block.len() + 8);
    let mut at_line_start = true;
    for &b in block {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    out
}

/// A failure on the way to the upstream, in the proxy's own voice. The codes
/// are [`RelayError::client_code`]'s, unchanged: the upstream's own code
/// where it gave one, `451` where it never answered at all, `550` for our own
/// refusal of a malformed address.
fn relay_error_to_rejection(e: RelayError) -> Rejection {
    Rejection {
        code: e.client_code(),
        text: e.to_string(),
    }
}

/// The one text for "the proxy could not establish that this message is
/// allowed", shared by both refusals below so that the reply code is the
/// only thing telling them apart. Splitting the wording would let a client
/// distinguish them by text and stop reading the code, which is the part
/// that decides whether the mail is retried.
const AUTH_SERVICE_FAILED: &str = "authentication service failed";

/// Permanent: the message itself is unacceptable and resending it unchanged
/// cannot help. Only for a fault in the data at hand -- anything the client
/// could get past by coming back later belongs in
/// [`auth_service_unavailable`], because a `5xx` there destroys mail that
/// was never wrong.
fn auth_service_failed() -> Rejection {
    Rejection {
        code: 550,
        text: AUTH_SERVICE_FAILED.into(),
    }
}

/// Transient: the proxy, not the message, is why there is no verdict, so the
/// client is asked to come back. `451` is RFC 5321's "local error in
/// processing" and matches what
/// [`crate::relay::RelayError::client_code`] already answers when the other
/// side is unreachable. Returning a `5xx` here would discard mail for an
/// outage of ours.
fn auth_service_unavailable() -> Rejection {
    Rejection {
        code: 451,
        text: AUTH_SERVICE_FAILED.into(),
    }
}

impl ProxyHandler {
    fn check_request(&self) -> CheckRequest {
        let t = &self.transaction;
        CheckRequest {
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            from: t.from.clone(),
            to: t.recipients.iter().map(|r| r.address.clone()).collect(),
            headers: t.headers.clone(),
            mail_parameters: t.mail_params.clone(),
            rcpt_parameters: t.recipients.clone(),
        }
    }
}

/// The open upstream transaction, waiting for body. Everything the proxy had
/// an opinion about was settled in [`ProxyHandler::open_body`]; from here on
/// the only voice is the upstream's, which is why the errors are
/// [`UpstreamVerdict`] and not [`Rejection`].
pub struct ProxySink {
    upstream: UpstreamSession,
    client: SocketAddr,
    /// Kept for the two debug dumps on the relay error path, which is the
    /// only place either is read.
    request: CheckRequest,
    outcome: CheckResponse,
}

/// The three lines `relay_message` used to log on a refusal: the operator's
/// sentence naming the failure, and the two debug dumps that say what was in
/// the message that failed.
///
/// Both roads out of the body go through here -- a refusal the upstream
/// speaks mid-body and one it speaks at the terminator -- so an operator
/// grepping `Mail refused by relay server` sees every refused message,
/// whichever stage it died at. `stage` is the SMTP command the failure is
/// reported against: `DATA` while the body is still arriving, `DATA_END` at
/// the terminator.
///
/// A free function taking the three fields rather than a method on
/// [`ProxySink`], because `UpstreamSession::finish` consumes the session out
/// of the sink and the report still has to be written from what is left.
fn report_refusal(
    client: SocketAddr,
    request: &CheckRequest,
    outcome: &CheckResponse,
    verdict: &UpstreamVerdict,
    stage: &'static str,
) {
    // Named for the log only. `into_relay_error` is what turns a lost
    // connection into a sentence an operator can read; the verdict itself
    // goes to the client untouched.
    let reported = verdict.clone().into_relay_error(stage);
    info!("Mail refused by relay server ({reported}) for {client}");
    debug!("Mail {}", request.redacted_json());
    // The Perl dumps the API result next to the mail: it is what says whether
    // the refused message carried injected headers or a substituted sender.
    // JSON like the line above it, because README promises that every debug
    // dump on this branch is JSON.
    debug!("ApiResult {}", outcome.json());
}

impl BodySink for ProxySink {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), UpstreamVerdict> {
        // Straight out, exactly as the client wrote it. The client's own dot
        // stuffing is the wire encoding the upstream wants, so nothing here
        // touches it (spec 5.1).
        let result = self.upstream.write(chunk).await;
        if let Err(verdict) = &result {
            // A refusal here never reaches `finish`: `read_message` hands the
            // verdict straight to `mirror`, whose only output is a `debug!`.
            // So this is the one place the operator's three lines can come
            // from for the mid-body road -- the newest failure mode on this
            // branch, and the one an operator is least likely to know about.
            report_refusal(self.client, &self.request, &self.outcome, verdict, "DATA");
        }
        result
    }

    async fn finish(self) -> Result<String, UpstreamVerdict> {
        // Taken apart first: `UpstreamSession::finish` consumes the session,
        // and the refusal report below reads the three fields beside it.
        let Self {
            upstream,
            client,
            request,
            outcome,
        } = self;
        match upstream.finish().await {
            Ok(message) => {
                debug!("Upstream server says: {message}");
                match &outcome.auth_id {
                    Some(id) => {
                        info!("Relayed mail successfully for {client} using token {id}")
                    }
                    None => info!("Relayed mail successfully for {client} using no token"),
                }
                Ok(message)
            }
            Err(verdict) => {
                report_refusal(client, &request, &outcome, &verdict, "DATA_END");
                Err(verdict)
            }
        }
    }
}

impl Handler for ProxyHandler {
    type Sink = ProxySink;

    /// Spec 2: the credentials are accepted without being checked. They are
    /// forwarded to the API with the message, and a bad password surfaces
    /// there as `550 <reason>` after DATA, exactly as in the Perl.
    async fn auth(&mut self, _authzid: &str, authcid: &str, password: &str) -> Result<(), String> {
        self.username = Some(authcid.to_string());
        self.password = Some(password.to_string());
        Ok(())
    }

    async fn mail(&mut self, from: &str, params: &[Param]) -> Result<(), Rejection> {
        // Spec 9.3: at MAIL, so a client over its limit is turned away
        // before it spends a transaction, and before the API is called. The
        // username is the one claimed at AUTH, which nothing has verified
        // yet -- the limit bounds API calls per claimed identity.
        let username = self.username.clone().unwrap_or_default();
        if !self.factory.limiter.allow(&username) {
            info!(
                "Message rate limit reached for user {username} from {}",
                self.client
            );
            return Err(Rejection::rate_limited());
        }
        // The session has already reset, but a handler that only clears its
        // transaction when someone else remembers to ask is a trap.
        self.reset();
        self.transaction.from = from.to_string();
        self.transaction.mail_params = params.to_vec();
        Ok(())
    }

    async fn rcpt(&mut self, to: &str, params: &[Param]) -> Result<(), Rejection> {
        self.transaction.recipients.push(Recipient {
            address: to.to_string(),
            parameters: params.to_vec(),
        });
        Ok(())
    }

    /// Every decision the proxy makes on its own, in one place: ask the API,
    /// merge the headers it returns, check them, and settle the envelope.
    /// What comes back is a sink with no opinions left.
    async fn open_body(&mut self, headers: String) -> Result<ProxySink, Rejection> {
        self.transaction.headers = parse_headers(&headers);
        debug!("Making call to auth/headers API");
        let request = self.check_request();
        // The verdict is needed before MAIL FROM, which the API may rewrite,
        // and before the headers go out -- both ahead of the body. So the
        // connect is the only thing that can overlap the call, and it does.
        let (verdict, upstream) = tokio::join!(
            self.factory.config.api.check(&request),
            UpstreamSession::connect(&self.factory.config.relay),
        );
        let outcome = match verdict {
            Ok(outcome) => outcome,
            Err(e) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                // Transient because the fault is ours: the sender did nothing
                // to earn a permanent refusal, and an outage we come back from
                // makes the retry succeed.
                return Err(auth_service_unavailable());
            }
        };
        if !outcome.allow {
            let reason = outcome.reason.clone().unwrap_or_default();
            info!("Mail rejected by API ({reason}) for {}", self.client);
            debug!("INPUT {}", request.redacted_json());
            // `upstream` is dropped here, unused. A refused message costs the
            // upstream one opened connection and nothing else.
            //
            // A policy refusal is permanent: the API looked at this message
            // and said no. Unlike the relay paths, there is nothing here for
            // the client to retry.
            return Err(Rejection {
                code: 550,
                text: reason,
            });
        }
        // Cloned rather than taken: the debug dump on the relay error path
        // has to show the headers the API was asked about.
        let merged = merge_headers(self.transaction.headers.clone(), &outcome.headers);
        // On the merged list, so that a break the API introduced and a break
        // the client sent are both caught, and caught before the connection
        // is used for anything. `escape_debug` because the name is the one
        // thing that might itself carry the break being complained about.
        if let Err(which) = assert_header_relayable(&merged) {
            warn!(
                "Refusing to relay header '{}' for {}: unfolded line break",
                which.escape_debug(),
                self.client
            );
            return Err(auth_service_failed());
        }
        // Spec 5.5: the API may replace the envelope sender.
        let from = outcome
            .from
            .clone()
            // The Perl is `$apiResult->{from} || $mail{from}`, and an empty
            // string is false there, so it keeps the client's sender rather
            // than relaying the null return path and sending the bounces
            // somewhere else.
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| self.transaction.from.clone());
        // Every road out of the relay logs what `relay_message` used to log:
        // the operator's one line naming the failure, and the two debug dumps
        // that say what was in the message that failed. Once the body has
        // started there are two such roads, not one, and they end in
        // different places: a refusal at the terminator lands in
        // `ProxySink::finish`, one spoken mid-body lands in
        // `ProxySink::write` and never reaches `finish` at all. Both call
        // the free `report_refusal`, which is the same three lines -- free
        // rather than a method because `UpstreamSession::finish` consumes
        // the session out of the sink.
        let refuse = |e: RelayError| {
            info!("Mail refused by relay server ({e}) for {}", self.client);
            debug!("Mail {}", request.redacted_json());
            debug!("ApiResult {}", outcome.json());
            relay_error_to_rejection(e)
        };
        // Both checks before a single command goes out, exactly where
        // `relay` used to run them: an address the API substituted must not
        // be able to inject a further command into an authenticated upstream
        // session.
        assert_relayable(&from).map_err(&refuse)?;
        for r in &self.transaction.recipients {
            assert_relayable(&r.address).map_err(&refuse)?;
        }
        debug!("Relaying Mail to upstream SMTP Server");
        let mut upstream = upstream.map_err(&refuse)?;
        self.factory.note_upstream_caps(upstream.caps());
        upstream
            .open_transaction(Envelope {
                from: &from,
                mail_params: &self.transaction.mail_params,
                recipients: &self.transaction.recipients,
            })
            .await
            .map_err(&refuse)?;
        upstream
            .write(&header_block(&merged))
            .await
            .map_err(|v| refuse(v.into_relay_error("DATA")))?;
        Ok(ProxySink {
            upstream,
            client: self.client,
            request,
            outcome,
        })
    }

    fn reset(&mut self) {
        self.transaction = Transaction::default();
    }

    fn dsn_available(&self) -> bool {
        self.factory.upstream_dsn.load(Ordering::Relaxed)
    }

    fn size_limit(&self) -> Option<usize> {
        self.factory.upstream_size_limit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: &str, v: &str) -> RequestHeader {
        RequestHeader {
            name: n.into(),
            value: v.into(),
        }
    }

    fn rh(n: &str, v: Option<&str>) -> ResponseHeader {
        ResponseHeader {
            name: n.into(),
            value: v.map(String::from),
        }
    }

    #[test]
    fn headers_split_at_unfolded_crlf() {
        let block = "From: a@b.com\r\nSubject: long\r\n  folded line\r\nTo:x@y.com\r\nBroken header line\r\n";
        let parsed = parse_headers(block);
        assert_eq!(
            parsed,
            vec![
                h("From", "a@b.com"),
                h("Subject", "long\r\n  folded line"),
                h("To", "x@y.com")
            ]
        );
    }

    /// M2. The Perl's `(.+)` needs a character behind the colon, so a
    /// header with nothing there is dropped -- from the API request and
    /// from the relayed message alike. One with only whitespace behind the
    /// colon keeps exactly one of those characters.
    #[test]
    fn a_header_with_nothing_behind_the_colon_is_dropped() {
        let parsed = parse_headers(
            "Subject:\r\nX-Empty:\r\nX-Space: \r\nX-Spaces:   \r\nX-Tab:\t\r\nTo: x@y.com\r\n",
        );
        assert_eq!(
            parsed,
            vec![
                h("X-Space", " "),
                h("X-Spaces", " "),
                h("X-Tab", "\t"),
                h("To", "x@y.com"),
            ]
        );
    }

    /// M7. The Perl's `\S` lookahead treats the vertical tab and the form
    /// feed as continuation, not as the start of a new header.
    #[test]
    fn vertical_tab_and_form_feed_continue_a_header() {
        let parsed = parse_headers("Subject: a\r\n\x0bb\r\n\x0cc\r\nTo: x@y.com\r\n");
        assert_eq!(
            parsed,
            vec![h("Subject", "a\r\n\x0bb\r\n\x0cc"), h("To", "x@y.com")]
        );
    }

    #[test]
    fn merge_removes_named_then_appends_defined() {
        let existing = vec![h("To", "old"), h("Subject", "s"), h("X-Remove", "1")];
        let api = vec![
            ResponseHeader {
                name: "To".into(),
                value: Some("new".into()),
            },
            ResponseHeader {
                name: "X-Remove".into(),
                value: None,
            },
            ResponseHeader {
                name: "Sender".into(),
                value: Some("bar@blah.com".into()),
            },
        ];
        assert_eq!(
            merge_headers(existing, &api),
            vec![
                h("Subject", "s"),
                h("To", "new"),
                h("Sender", "bar@blah.com")
            ]
        );
    }

    /// Item 2. RFC 5322 3.6.8: field names are case-insensitive, so an API
    /// that answers `subject` replaces the client's `Subject` instead of
    /// leaving the message with both.
    #[test]
    fn api_header_replaces_client_header_regardless_of_case() {
        let existing = vec![h("Subject", "client"), h("To", "x@y.com")];
        let api = vec![rh("subject", Some("api"))];
        let merged = merge_headers(existing, &api);
        assert_eq!(merged, vec![h("To", "x@y.com"), h("subject", "api")]);
    }

    /// The removal half of the same rule: a `None` value still removes, and
    /// now removes whatever the client's casing was.
    #[test]
    fn a_null_api_value_removes_the_client_header_regardless_of_case() {
        let existing = vec![h("X-Remove", "1"), h("To", "x@y.com")];
        let api = vec![rh("x-REMOVE", None)];
        assert_eq!(merge_headers(existing, &api), vec![h("To", "x@y.com")]);
    }

    /// Item 3. `HeaderCollector` accepts a bare LF, so this block genuinely
    /// arrives. Split on CRLF alone it would be one header named `From`
    /// whose value carried `Subject` and `To` -- and the API would never see
    /// them to have an opinion about them.
    #[test]
    fn bare_lf_header_block_splits_into_headers() {
        let parsed = parse_headers("From: a@b.com\nSubject: hi\nTo: x@y.com\n");
        assert_eq!(
            parsed,
            vec![h("From", "a@b.com"), h("Subject", "hi"), h("To", "x@y.com")]
        );
    }

    #[test]
    fn bare_lf_folding_still_folds() {
        let parsed = parse_headers("Subject: long\n  folded\nTo: x@y.com\n");
        assert_eq!(
            parsed,
            vec![h("Subject", "long\n  folded"), h("To", "x@y.com")]
        );
    }

    #[test]
    fn mixed_crlf_and_lf_block_splits_on_both() {
        let parsed = parse_headers("A: 1\r\nB: 2\nC: 3\r\n");
        assert_eq!(parsed, vec![h("A", "1"), h("B", "2"), h("C", "3")]);
    }

    /// Item 5. A fold is a line break followed by a space or a tab, and a
    /// client-supplied folded header arrives here with its break intact, so
    /// refusing every CRLF would refuse legitimate mail.
    #[test]
    fn a_folded_value_is_still_relayable() {
        assert!(assert_header_relayable(&[h("Subject", "long\r\n  folded")]).is_ok());
        assert!(assert_header_relayable(&[h("Subject", "long\n\tfolded")]).is_ok());
        assert!(assert_header_relayable(&[h("Subject", "plain")]).is_ok());
    }

    #[test]
    fn an_unfolded_break_in_a_value_is_refused() {
        assert!(assert_header_relayable(&[h("X", "a\r\n\r\nforged body")]).is_err());
        assert!(assert_header_relayable(&[h("X", "a\r\nInjected: yes")]).is_err());
        assert!(assert_header_relayable(&[h("X", "a\nInjected: yes")]).is_err());
        assert!(assert_header_relayable(&[h("X", "trailing\r\n")]).is_err());
        // A CR that is not the start of a CRLF is not a fold either.
        assert!(assert_header_relayable(&[h("X", "a\r b")]).is_err());
    }

    #[test]
    fn a_break_or_colon_in_a_name_is_refused() {
        assert!(assert_header_relayable(&[h("X\r\nY", "v")]).is_err());
        assert!(assert_header_relayable(&[h("X: Y", "v")]).is_err());
        assert!(assert_header_relayable(&[h("X\nY", "v")]).is_err());
    }

    /// The error names the offending header and nothing else: the value may
    /// hold customer content and the name is what gets logged.
    #[test]
    fn the_refusal_names_the_header_and_not_its_value() {
        let e = assert_header_relayable(&[h("Good", "ok"), h("X-Bad", "a\r\nb")]).unwrap_err();
        assert_eq!(e, "X-Bad");
    }

    #[test]
    fn header_block_layout() {
        let block = header_block(&[h("A", "1"), h("B", "2")]);
        assert_eq!(block, b"A: 1\r\nB: 2\r\n\r\n");
    }

    /// The header block goes out inside DATA, so a name that begins with a
    /// dot has to be stuffed or the upstream reads one character fewer than
    /// the client sent. `HeaderCollector` took the client's own stuffing off
    /// on the way in (`server::data`), which is how a name can begin with a
    /// dot at all.
    #[test]
    fn a_header_beginning_with_a_dot_is_stuffed() {
        assert_eq!(
            header_block(&[h(".X-Foo", "y")]),
            b"...X-Foo: y\r\n\r\n".strip_prefix(b".").unwrap()
        );
        // Not at a line start, so untouched.
        assert_eq!(header_block(&[h("X", ".v")]), b"X: .v\r\n\r\n");
    }

    /// A folded value's continuation begins with a space or a tab, so the
    /// dot that follows it is not at a line start. The break itself may be a
    /// bare LF (see `parse_headers`), and a dot behind *that* is -- which is
    /// why `dot_stuff` runs on the normalised block and keys on the LF.
    #[test]
    fn stuffing_follows_the_line_starts_a_fold_makes() {
        assert_eq!(
            header_block(&[h("Subject", "a\r\n .b")]),
            b"Subject: a\r\n .b\r\n\r\n"
        );
        assert_eq!(dot_stuff(b"a\r\n.b\r\n"), b"a\r\n..b\r\n");
        assert_eq!(dot_stuff(b".a\r\n"), b"..a\r\n");
        assert_eq!(dot_stuff(b""), b"");
        // A lone CR ends no line, so it starts none either.
        assert_eq!(dot_stuff(b"a\r.b"), b"a\r.b");
    }

    /// Ruling 35. A folded value keeps whichever break arrived
    /// (`parse_headers`), and `folds_at` accepts a bare LF before a space or
    /// a tab -- so a bare LF genuinely reaches `header_block`. Inside DATA a
    /// line ends with CRLF and nothing else (RFC 5321 2.3.8). This was the
    /// other half of what `normalize_and_stuff` did for the whole message.
    #[test]
    fn a_bare_lf_fold_is_normalised_on_the_way_out() {
        assert_eq!(
            header_block(&[h("Subject", "a\n b")]),
            b"Subject: a\r\n b\r\n\r\n"
        );
        assert_eq!(
            header_block(&[h("Subject", "a\n\tb"), h("To", "x@y.com")]),
            b"Subject: a\r\n\tb\r\nTo: x@y.com\r\n\r\n"
        );
        assert_eq!(normalize_breaks(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
        assert_eq!(normalize_breaks(b""), b"");
        // A lone CR is not a line ending and is not made into one.
        assert_eq!(normalize_breaks(b"a\rb"), b"a\rb");
        assert_eq!(normalize_breaks(b"a\r\r\n"), b"a\r\r\n");
    }
}
