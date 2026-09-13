//! The SMTP server side.
pub mod auth;
pub mod data;
pub mod listener;
pub mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::smtp::params::Param;

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

/// The application side of a connection. One instance per connection.
pub trait Handler: Send + 'static {
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
    /// Header block complete; body still arriving.
    fn headers(&mut self, headers: String) -> impl Future<Output = Result<(), String>> + Send;
    /// Terminator arrived. Ok: text for `250 OK: <text>`. Err: text for `550 <text>`.
    fn message(&mut self, body: Vec<u8>) -> impl Future<Output = Result<String, String>> + Send;
    /// RSET, or EHLO/HELO while a transaction is running.
    fn reset(&mut self);
    fn dsn_available(&self) -> bool;
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
    pub max_message_size: usize,
    pub smtplog: Option<Arc<crate::smtplog::SmtpLog>>,
    /// Inactivity timeout once TLS is up. Perl: 600 s.
    pub tls_idle_timeout: std::time::Duration,
    /// Total concurrent connections across all listeners. 0 means unlimited.
    pub max_connections: usize,
    /// Concurrent connections from a single client IP. 0 means unlimited.
    pub max_connections_per_ip: usize,
    /// RCPT entries accepted in one transaction. 0 means unlimited.
    pub max_recipients: usize,
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
