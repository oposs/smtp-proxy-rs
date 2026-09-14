//! The application behind the SMTP server: collect, ask the API, relay.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::task::JoinHandle;
use tracing::{Instrument, debug, info, warn};

use crate::api::{
    ApiClient, ApiError, CheckRequest, CheckResponse, Recipient, RequestHeader, ResponseHeader,
};
use crate::ratelimit::RateLimiter;
use crate::relay::{Envelope, RelayConfig, probe, relay};
use crate::server::{Handler, HandlerFactory, Rejection};
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
    fn note_upstream_dsn(&self, supported: bool) {
        let previous = self.upstream_dsn.swap(supported, Ordering::Relaxed);
        let known = self.upstream_dsn_known.swap(true, Ordering::Relaxed);
        if !known || previous != supported {
            info!(
                "{} {}; the extension will {}be offered to clients",
                self.upstream_name(),
                if supported {
                    "announces DSN"
                } else {
                    "does not announce DSN"
                },
                if supported { "" } else { "not " }
            );
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
            Ok(dsn) => self.note_upstream_dsn(dsn),
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
    /// The API call, started as soon as the headers are in and awaited when
    /// the body is complete, so it overlaps the body transfer (spec 2).
    api_call: Option<JoinHandle<Result<CheckResponse, ApiError>>>,
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
/// `/\r\n(?=$|\S)/` and so only ever on CRLF. `DataReader` accepts a bare LF
/// as a line terminator (`server::data`, as the Perl's reader does), so a
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

    async fn relay_message(
        &mut self,
        outcome: CheckResponse,
        body: Vec<u8>,
    ) -> Result<String, Rejection> {
        debug!("Relaying Mail to upstream SMTP Server");
        // Cloned rather than taken: the debug dump on the error path below
        // has to show the headers the API was asked about.
        let headers = merge_headers(self.transaction.headers.clone(), &outcome.headers);
        // On the merged list, so that a break the API introduced and a break
        // the client sent are both caught, and caught before the connection
        // costs anything. `escape_debug` because the name is the one thing
        // that might itself carry the break being complained about.
        if let Err(which) = assert_header_relayable(&headers) {
            warn!(
                "Refusing to relay header '{}' for {}: unfolded line break",
                which.escape_debug(),
                self.client
            );
            return Err(auth_service_failed());
        }
        let message = format_message(&headers, &body);
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
        let envelope = Envelope {
            from: &from,
            mail_params: &self.transaction.mail_params,
            recipients: &self.transaction.recipients,
        };
        match relay(&self.factory.config.relay, envelope, &message).await {
            Ok(relayed) => {
                self.factory.note_upstream_dsn(relayed.upstream_dsn);
                debug!("Upstream server says: {}", relayed.message);
                match &outcome.auth_id {
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
                debug!("Mail {}", self.check_request().redacted_json());
                // The Perl dumps the API result next to the mail: it is what
                // says whether the refused message carried injected headers
                // or a substituted sender.
                // JSON like the line above it, because README promises that
                // every debug dump on this branch is JSON.
                debug!("ApiResult {}", outcome.json());
                // Spec 6, and the ruling of 2026-09-13: the upstream's own
                // code, not a blanket 550. See `RelayError::client_code`.
                Err(Rejection {
                    code: e.client_code(),
                    text: e.to_string(),
                })
            }
        }
    }
}

impl Handler for ProxyHandler {
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

    /// The headers are in; the body is still arriving. The API call starts
    /// here and is awaited in `message`.
    async fn headers(&mut self, headers: String) -> Result<(), String> {
        self.transaction.headers = parse_headers(&headers);
        debug!("Making call to auth/headers API");
        let api = self.factory.config.api.clone();
        let request = self.check_request();
        // `tokio::spawn` starts a task with no span of its own, so without
        // this the spec 5.3 redacted-request dump that `ApiClient::check`
        // writes on a failure would come out with no `[cid]` bracket at all
        // (spec 8.1) -- on the one line an operator reads to find out why a
        // customer's mail was refused.
        self.transaction.api_call = Some(tokio::spawn(
            async move { api.check(&request).await }.in_current_span(),
        ));
        Ok(())
    }

    async fn message(&mut self, body: Vec<u8>) -> Result<String, Rejection> {
        // Unreachable from the session, which always delivers the headers
        // before the body: a missing call means a bug, not a bad client, and
        // silently relaying an unchecked mail would be the worse answer.
        // Transient because the fault is ours: the sender did nothing to
        // earn a permanent refusal, and a bug we later fix or restart out of
        // makes the retry succeed.
        let Some(call) = self.transaction.api_call.take() else {
            warn!("No API call was started for {}", self.client);
            return Err(auth_service_unavailable());
        };
        let outcome = match call.await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                return Err(auth_service_unavailable());
            }
            Err(e) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                return Err(auth_service_unavailable());
            }
        };
        if !outcome.allow {
            let reason = outcome.reason.clone().unwrap_or_default();
            info!("Mail rejected by API ({reason}) for {}", self.client);
            debug!("INPUT {}", self.check_request().redacted_json());
            // A policy refusal is permanent: the API looked at this message
            // and said no. Unlike the relay paths below, there is nothing
            // here for the client to retry.
            return Err(Rejection {
                code: 550,
                text: reason,
            });
        }
        self.relay_message(outcome, body).await
    }

    fn reset(&mut self) {
        // An API call whose transaction is gone has nobody left to answer.
        if let Some(call) = self.transaction.api_call.take() {
            call.abort();
        }
        self.transaction = Transaction::default();
    }

    fn dsn_available(&self) -> bool {
        self.factory.upstream_dsn.load(Ordering::Relaxed)
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

    /// Item 3. `DataReader` accepts a bare LF, so this block genuinely
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
    fn message_layout() {
        let msg = format_message(&[h("A", "1"), h("B", "2")], b"body\r\n");
        assert_eq!(msg, b"A: 1\r\nB: 2\r\n\r\nbody\r\n");
    }
}
