//! The application behind the SMTP server: collect, ask the API, relay.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tracing::{debug, info, warn};

use crate::api::{
    ApiClient, CheckRequest, CheckResponse, Recipient, RequestHeader, ResponseHeader,
};
use crate::ratelimit::RateLimiter;
use crate::relay::{Envelope, RelayConfig, UpstreamCaps, UpstreamVerdict, probe, relay};
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

/// Refuses any header that would not survive `format_message` intact
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

/// Spec 5.4: `name: value` per header, an empty line, then the body as it
/// was received. Every header has passed [`assert_header_relayable`] by the
/// time it gets here.
pub fn format_message(headers: &[RequestHeader], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 256);
    for h in headers {
        out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Undoes the client's dot stuffing on a body that arrived verbatim.
///
/// **Task 9 removes this, together with the second stuffing it undoes.**
/// `BodyFramer` passes body lines through exactly as the client wrote them
/// (`server::data`, spec 5.1), stuffing dot included, while the write path
/// still stuffs the whole message a second time (`relay.rs`, `fn
/// normalize_and_stuff`). Without this a client's `..foo` would leave the
/// proxy as `...foo`.
///
/// A line begins at offset 0 or after a CRLF, which is exactly where
/// `normalize_and_stuff` puts a dot back. The framer has already normalised
/// every line ending to CRLF, so a bare CR is data here and begins no line.
/// The body holds no terminator -- `BodyFramer::push` reports that without
/// appending it -- so nothing here can be turned into one.
fn unstuff_body(body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len());
    let mut at_line_start = true;
    for &b in body {
        if at_line_start && b == b'.' {
            at_line_start = false;
            continue;
        }
        out.push(b);
        at_line_start = out.ends_with(b"\r\n");
    }
    out
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

/// An owned mirror of [`Envelope`]. The sink outlives the transaction whose
/// fields that type borrows, so it cannot hold the references.
struct OwnedEnvelope {
    from: String,
    mail_params: Vec<Param>,
    recipients: Vec<Recipient>,
}

/// Buffers, for now, and relays on `finish`. Task 9 replaces the innards
/// with a live upstream session; the interface above it does not change.
pub struct ProxySink {
    factory: ProxyFactory,
    client: SocketAddr,
    envelope: OwnedEnvelope,
    /// Merged and checked in `open_body`, because both are the proxy's own
    /// decisions and `Rejection` is the only voice it has left once the sink
    /// exists.
    headers: Vec<RequestHeader>,
    /// Kept for the two debug dumps on the relay error path, which is the
    /// only place either is read.
    request: CheckRequest,
    outcome: CheckResponse,
    message: Vec<u8>,
}

impl BodySink for ProxySink {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), UpstreamVerdict> {
        self.message.extend_from_slice(chunk);
        Ok(())
    }

    async fn finish(self) -> Result<String, UpstreamVerdict> {
        debug!("Relaying Mail to upstream SMTP Server");
        let message = format_message(&self.headers, &unstuff_body(&self.message));
        let envelope = Envelope {
            from: &self.envelope.from,
            mail_params: &self.envelope.mail_params,
            recipients: &self.envelope.recipients,
        };
        match relay(&self.factory.config.relay, envelope, &message).await {
            Ok(relayed) => {
                self.factory.note_upstream_caps(relayed.caps);
                debug!("Upstream server says: {}", relayed.message);
                match &self.outcome.auth_id {
                    Some(id) => info!(
                        "Relayed mail successfully for {} using token {id}",
                        self.client
                    ),
                    None => info!(
                        "Relayed mail successfully for {} using no token",
                        self.client
                    ),
                }
                Ok(relayed.message)
            }
            Err(e) => {
                info!("Mail refused by relay server ({e}) for {}", self.client);
                debug!("Mail {}", self.request.redacted_json());
                // The Perl dumps the API result next to the mail: it is what
                // says whether the refused message carried injected headers
                // or a substituted sender.
                // JSON like the line above it, because README promises that
                // every debug dump on this branch is JSON.
                debug!("ApiResult {}", self.outcome.json());
                // Spec 6, and the ruling of 2026-09-13: the upstream's own
                // code, not a blanket 550. See `RelayError::client_code`.
                // `relay` never leaves the client without an answer, so
                // `Dropped` -- the verdict with nothing to say -- cannot
                // arise until task 9 drives the upstream from here.
                Err(UpstreamVerdict::Replied {
                    code: e.client_code(),
                    text: e.to_string(),
                })
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
        let outcome = match self.factory.config.api.check(&request).await {
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
        // costs anything. `escape_debug` because the name is the one thing
        // that might itself carry the break being complained about.
        if let Err(which) = assert_header_relayable(&merged) {
            warn!(
                "Refusing to relay header '{}' for {}: unfolded line break",
                which.escape_debug(),
                self.client
            );
            return Err(auth_service_failed());
        }
        // Spec 5.5: the API may replace the envelope sender. `relay` runs the
        // printable-ASCII check on it before it writes any command.
        let from = outcome
            .from
            .clone()
            // The Perl is `$apiResult->{from} || $mail{from}`, and an empty
            // string is false there, so it keeps the client's sender rather
            // than relaying the null return path and sending the bounces
            // somewhere else.
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| self.transaction.from.clone());
        Ok(ProxySink {
            factory: self.factory.clone(),
            client: self.client,
            envelope: OwnedEnvelope {
                from,
                mail_params: self.transaction.mail_params.clone(),
                recipients: self.transaction.recipients.clone(),
            },
            headers: merged,
            request,
            outcome,
            message: Vec::new(),
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

    /// The invariant that makes this task's seam safe. `BodyFramer` hands
    /// the sink the client's own bytes; `unstuff_body` takes one dot off
    /// each stuffed line and `normalize_and_stuff` puts it back, so the far
    /// end sees exactly what the client wrote. Make `unstuff_body` the
    /// identity and every stuffed case below gains a dot.
    #[test]
    fn unstuffing_is_undone_exactly_by_the_stuffing_the_write_path_adds() {
        for body in [
            &b""[..],
            b"plain\r\n",
            b"..\r\n",
            b"..foo\r\n",
            b"....bar\r\n",
            b"a\r\n..b\r\nc\r\n",
            b"..a\r\n\r\n..b\r\n",
            // A bare CR is body data, not a line ending, so the dot after it
            // is not on a line start and neither side touches it.
            b"mid\rcr\r\n",
        ] {
            assert_eq!(
                crate::relay::normalize_and_stuff(&unstuff_body(body)),
                body,
                "round trip changed {:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// The halves of that round trip, named, so a failure says which one
    /// moved.
    #[test]
    fn unstuffing_takes_one_dot_off_a_line_start_and_no_other() {
        assert_eq!(
            unstuff_body(b"..foo\r\n"),
            b"..foo\r\n".strip_prefix(b".").unwrap()
        );
        assert_eq!(unstuff_body(b"..\r\n"), b".\r\n");
        assert_eq!(unstuff_body(b"a..b\r\n"), b"a..b\r\n");
        assert_eq!(unstuff_body(b"a\r\n..b\r\n"), b"a\r\n.b\r\n");
    }

    #[test]
    fn message_layout() {
        let msg = format_message(&[h("A", "1"), h("B", "2")], b"body\r\n");
        assert_eq!(msg, b"A: 1\r\nB: 2\r\n\r\nbody\r\n");
    }
}
