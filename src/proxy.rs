//! The application behind the SMTP server: collect, ask the API, relay.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::api::{
    ApiClient, ApiError, CheckRequest, CheckResponse, Recipient, RequestHeader, ResponseHeader,
};
use crate::relay::{Envelope, RelayConfig, probe, relay};
use crate::server::{Handler, HandlerFactory};
use crate::smtp::params::Param;

pub struct ProxyConfig {
    pub api: ApiClient,
    pub relay: RelayConfig,
}

#[derive(Clone)]
pub struct ProxyFactory {
    config: Arc<ProxyConfig>,
    upstream_dsn: Arc<AtomicBool>,
    /// False until the first answer is in, which is the Perl's "undefined
    /// until asked" state. Kept apart from `upstream_dsn` so that the first
    /// answer is logged even when it is the same as the initial `false`.
    upstream_dsn_known: Arc<AtomicBool>,
}

impl ProxyFactory {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config: Arc::new(config),
            upstream_dsn: Arc::new(AtomicBool::new(false)),
            upstream_dsn_known: Arc::new(AtomicBool::new(false)),
        }
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

/// Splits at CRLF followed by a non-blank (folded lines stay whole), then at
/// the first colon. A line without a colon is logged and dropped (spec 5.2).
pub fn parse_headers(block: &str) -> Vec<RequestHeader> {
    let mut lines: Vec<String> = Vec::new();
    for raw in block.split_inclusive("\r\n") {
        let continuation = raw.starts_with([' ', '\t']);
        match lines.last_mut() {
            Some(last) if continuation => last.push_str(raw),
            _ => lines.push(raw.to_string()),
        }
    }
    let mut out = Vec::new();
    for line in lines {
        let line = line.trim_end_matches("\r\n");
        match line.split_once(':') {
            Some((name, value)) if !name.is_empty() => out.push(RequestHeader {
                name: name.to_string(),
                value: value.trim_start().to_string(),
            }),
            _ => warn!("Could not parse header '{line}'"),
        }
    }
    out
}

/// Spec 5.4: remove every header the API names, then append those it gave a
/// value, in API order. Names are compared exactly, as in the Perl.
pub fn merge_headers(existing: Vec<RequestHeader>, api: &[ResponseHeader]) -> Vec<RequestHeader> {
    let mut out: Vec<RequestHeader> = existing
        .into_iter()
        .filter(|h| !api.iter().any(|a| a.name == h.name))
        .collect();
    out.extend(api.iter().filter_map(|a| {
        a.value.clone().map(|value| RequestHeader {
            name: a.name.clone(),
            value,
        })
    }));
    out
}

/// Spec 5.4: `name: value` per header, an empty line, then the body as it
/// was received.
pub fn format_message(headers: &[RequestHeader], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 256);
    for h in headers {
        out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
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
    ) -> Result<String, String> {
        debug!("Relaying Mail to upstream SMTP Server");
        // Cloned rather than taken: the debug dump on the error path below
        // has to show the headers the API was asked about.
        let headers = merge_headers(self.transaction.headers.clone(), &outcome.headers);
        let message = format_message(&headers, &body);
        // Spec 5.5: the API may replace the envelope sender. `relay` runs the
        // printable-ASCII check on it before it writes any command.
        let from = outcome
            .from
            .clone()
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
                Err(e.to_string())
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

    async fn mail(&mut self, from: &str, params: &[Param]) -> Result<(), String> {
        // The session has already reset, but a handler that only clears its
        // transaction when someone else remembers to ask is a trap.
        self.reset();
        self.transaction.from = from.to_string();
        self.transaction.mail_params = params.to_vec();
        Ok(())
    }

    async fn rcpt(&mut self, to: &str, params: &[Param]) -> Result<(), String> {
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
        self.transaction.api_call = Some(tokio::spawn(async move { api.check(&request).await }));
        Ok(())
    }

    async fn message(&mut self, body: Vec<u8>) -> Result<String, String> {
        // Unreachable from the session, which always delivers the headers
        // before the body: a missing call means a bug, not a bad client, and
        // silently relaying an unchecked mail would be the worse answer.
        let Some(call) = self.transaction.api_call.take() else {
            warn!("No API call was started for {}", self.client);
            return Err("authentication service failed".into());
        };
        let outcome = match call.await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                return Err("authentication service failed".into());
            }
            Err(e) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                return Err("authentication service failed".into());
            }
        };
        if !outcome.allow {
            let reason = outcome.reason.clone().unwrap_or_default();
            info!("Mail rejected by API ({reason}) for {}", self.client);
            debug!("INPUT {}", self.check_request().redacted_json());
            return Err(reason);
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

    #[test]
    fn message_layout() {
        let msg = format_message(&[h("A", "1"), h("B", "2")], b"body\r\n");
        assert_eq!(msg, b"A: 1\r\nB: 2\r\n\r\nbody\r\n");
    }
}
