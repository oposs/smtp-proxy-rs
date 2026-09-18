//! The SMTP server side.
pub mod auth;
pub mod data;
pub mod listener;
pub mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::relay::UpstreamVerdict;
use crate::smtp::params::Param;

/// The shutdown side of the server (spec 9.1). `token` is cancelled once a
/// signal arrives: the accept loops stop and every session that is waiting
/// for its next command answers `421` and closes. `tracker` holds one entry
/// per live session, and nothing else, so `connections` is a truthful count
/// and waiting on it waits for the messages that are already in flight --
/// and only for those.
#[derive(Clone, Default)]
pub struct Drain {
    pub token: CancellationToken,
    pub tracker: TaskTracker,
}

impl Drain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sessions still running.
    pub fn connections(&self) -> usize {
        self.tracker.len()
    }

    /// Waits until every session has ended. `None` waits for as long as
    /// they take, which is what `--drain_timeout 0` means: zero is "no
    /// limit" here as it is for every other limit. Returns `false` when the
    /// timeout expired with sessions still running, so that the caller can
    /// say so before it exits anyway.
    ///
    /// Nothing is aborted on expiry. `JoinHandle::abort` only schedules
    /// cancellation, so it could not shorten the wait it would be used for;
    /// the process exiting is what ends those sessions.
    pub async fn wait_drained(&self, timeout: Option<Duration>) -> bool {
        match timeout {
            Some(limit) => tokio::time::timeout(limit, self.tracker.wait())
                .await
                .is_ok(),
            None => {
                self.tracker.wait().await;
                true
            }
        }
    }
}

/// A handler's refusal, carrying the reply the client is to be sent. The
/// handler picks the code, so a refusal that is not the session's own
/// default -- a rate limit, say -- keeps its own meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub code: u16,
    pub text: String,
}

impl Rejection {
    /// The Perl's MAIL refusal (`Connection.pm:576`).
    pub fn mail(why: impl Into<String>) -> Self {
        Self {
            code: 553,
            text: format!("Requested action not taken: {}", why.into()),
        }
    }

    /// The Perl's RCPT refusal (`Connection.pm:598`).
    pub fn rcpt(why: impl Into<String>) -> Self {
        Self {
            code: 550,
            text: format!("Will not send mail to this user: {}", why.into()),
        }
    }

    /// Spec 9.3. Temporary on purpose: the client is asked to come back,
    /// not told the mail is unacceptable.
    pub fn rate_limited() -> Self {
        Self {
            code: 450,
            text: "4.7.1 Rate limit exceeded, try again later".into(),
        }
    }
}

/// Consumes one message body. Obtained from [`Handler::open_body`] and owned
/// for exactly the body's lifetime.
///
/// Dropping it without `finish` **aborts** the message: the upstream
/// connection closes with no terminator sent, so nothing is delivered. That
/// is the whole abort path -- there is no other.
pub trait BodySink: Send {
    fn write(&mut self, chunk: &[u8]) -> impl Future<Output = Result<(), UpstreamVerdict>> + Send;
    fn finish(self) -> impl Future<Output = Result<String, UpstreamVerdict>> + Send;
}

/// The application side of a connection. One instance per connection.
pub trait Handler: Send + 'static {
    type Sink: BodySink;

    fn auth(
        &mut self,
        authzid: &str,
        authcid: &str,
        password: &str,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn mail(
        &mut self,
        from: &str,
        params: &[Param],
    ) -> impl Future<Output = Result<(), Rejection>> + Send;
    fn rcpt(
        &mut self,
        to: &str,
        params: &[Param],
    ) -> impl Future<Output = Result<(), Rejection>> + Send;
    /// The header block is complete and the body is about to arrive. This is
    /// where every decision the proxy makes on its own is made: the policy
    /// verdict, the header merge, the upstream connection and the envelope.
    ///
    /// Once this returns a sink, the proxy has no opinions left -- from then
    /// on it only relays what the upstream says. That is why the two error
    /// types differ: `Rejection` is the proxy's own voice, `UpstreamVerdict`
    /// is the upstream's.
    fn open_body(
        &mut self,
        headers: String,
    ) -> impl Future<Output = Result<Self::Sink, Rejection>> + Send;
    /// RSET, or EHLO/HELO while a transaction is running.
    fn reset(&mut self);
    fn dsn_available(&self) -> bool;
    /// The largest message to announce in EHLO, or `None` to announce no
    /// SIZE line at all. The proxy has no limit of its own; this is the
    /// upstream's, relayed.
    fn size_limit(&self) -> Option<usize>;
}

pub trait HandlerFactory: Clone + Send + Sync + 'static {
    type Handler: Handler;
    fn create(&self, client: SocketAddr, connection_id: &str) -> Self::Handler;
}

pub struct ServerConfig {
    pub service_name: String,
    pub require_starttls: bool,
    pub require_auth: bool,
    /// None means STARTTLS is not offered (tests only; production always has it).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub max_header_size: usize,
    pub smtplog: Option<Arc<crate::smtplog::SmtpLog>>,
    /// Inactivity timeout on the client connection. The Perl arms this only
    /// after STARTTLS (600 s) and leaves the pre-TLS phase untimed; here it
    /// covers the whole session, because before TLS a silent client would
    /// otherwise hold a `max_connections` slot for ever. See the divergence
    /// note on `session::Session::next_line`.
    pub idle_timeout: std::time::Duration,
    /// The shorter deadline that governs the wait for the client's *first*
    /// command, before `idle_timeout` takes over for the rest of the
    /// session. `--greeting_timeout`, default 30 s. It exists because a
    /// connection that has sent nothing at all is the cheap way to hold a
    /// `max_connections` slot, and nothing legitimate is silent there: a
    /// real client sends EHLO as soon as it has read the 220.
    pub greeting_timeout: std::time::Duration,
    /// Total concurrent connections across all listeners. 0 means unlimited.
    pub max_connections: usize,
    /// Concurrent connections from a single client IP. 0 means unlimited.
    pub max_connections_per_ip: usize,
    /// RCPT entries accepted in one transaction. 0 means unlimited.
    pub max_recipients: usize,
    /// None means this server never drains: the accept loops run until the
    /// future is dropped and sessions are never asked to close (tests that
    /// do not exercise shutdown; production always has one).
    pub drain: Option<Drain>,
}

impl ServerConfig {
    /// Builds a rustls server configuration from a PEM certificate chain and
    /// a PEM private key.
    pub fn load_tls(
        cert: &std::path::Path,
        key: &std::path::Path,
    ) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_file_iter(cert)
                .map_err(|e| anyhow::anyhow!("cannot read certificate {}: {e}", cert.display()))?
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("bad certificate in {}: {e}", cert.display()))?;
        let private_key = rustls_pki_types::PrivateKeyDer::from_pem_file(key)
            .map_err(|e| anyhow::anyhow!("cannot read key {}: {e}", key.display()))?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;
        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Notify;

    /// A drain whose tracker holds one session that is parked until the
    /// test releases it. Parked, not slow: the delays below therefore only
    /// bound how long the test takes, never what it observes -- a wait on
    /// a tracker that can never empty cannot succeed on a fast host and
    /// fail on a loaded one.
    fn parked() -> (Drain, Arc<Notify>) {
        let drain = Drain::new();
        let gate = Arc::new(Notify::new());
        let held = gate.clone();
        drain.tracker.spawn(async move { held.notified().await });
        drain.tracker.close();
        (drain, gate)
    }

    #[tokio::test]
    async fn wait_drained_returns_true_once_the_sessions_end() {
        let (drain, gate) = parked();
        assert_eq!(drain.connections(), 1);
        gate.notify_one();
        assert!(drain.wait_drained(Some(Duration::from_secs(30))).await);
        assert_eq!(drain.connections(), 0);
    }

    #[tokio::test]
    async fn wait_drained_gives_up_at_the_timeout() {
        let (drain, _gate) = parked();
        assert!(!drain.wait_drained(Some(Duration::from_millis(50))).await);
        // Still there: the timeout reports, it does not abort.
        assert_eq!(drain.connections(), 1);
    }

    /// `--drain_timeout 0` means no limit, not "do not wait": the wait
    /// outlives any deadline the caller could name, and ends only when the
    /// last session does.
    #[tokio::test]
    async fn a_timeout_of_none_waits_indefinitely() {
        let (drain, gate) = parked();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), drain.wait_drained(None))
                .await
                .is_err()
        );
        gate.notify_one();
        assert!(drain.wait_drained(None).await);
    }
}
