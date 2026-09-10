//! One client connection, driven as sequential async code: read a command,
//! handle it completely, reply, repeat. Pipelined commands are therefore
//! answered in order, and the reply to DATA is on the wire before the next
//! command is read, so a late relay result cannot land in a later
//! transaction.
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::server::auth::{PASSWORD_CHALLENGE, USERNAME_CHALLENGE, decode_login, decode_plain};
use crate::server::data::{DataEvent, DataReader};
use crate::server::{Handler, ServerConfig};
use crate::smtp::command::{Command, CommandError, parse_command, take_line};
use crate::smtp::dsn::{DsnCommand, validate_dsn};
use crate::smtp::reply::Reply;

type Stream = Pin<Box<dyn AsyncReadWrite>>;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}

/// Spec 4.1. The order matters: `state >= WantMail` is what "a transaction
/// may be running, and the session is past authentication" means, so the
/// derived `Ord` carries part of the protocol.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
// The shared `Want` prefix is the spec's own naming (4.1) and the Perl's
// (WANT_GREETING and friends); dropping it would break that correspondence.
#[allow(clippy::enum_variant_names)]
enum State {
    WantGreeting,
    WantStartTls,
    WantAuth,
    WantMail,
    WantRcpt,
    WantData,
}

/// Why the loop ended. Only for logging.
enum End {
    Quit,
    Eof,
    Io(std::io::Error),
    Timeout,
    TlsFailed,
}

enum Flow {
    Continue,
    Quit,
    TlsFailed,
}

struct Session<H> {
    stream: Stream,
    buf: Vec<u8>,
    state: State,
    tls_active: bool,
    client: SocketAddr,
    id: String,
    config: Arc<ServerConfig>,
    handler: H,
}

pub async fn run<H: Handler>(
    stream: TcpStream,
    client: SocketAddr,
    id: String,
    config: Arc<ServerConfig>,
    handler: H,
) {
    let mut s = Session {
        stream: Box::pin(stream),
        buf: Vec::new(),
        state: State::WantGreeting,
        tls_active: false,
        client,
        id,
        config,
        handler,
    };
    match s.serve().await {
        End::Quit | End::Eof | End::TlsFailed => {}
        End::Timeout => tracing::error!("Timeout on stream for {}", s.client),
        End::Io(e) => tracing::error!("Error on stream for {}: {e}", s.client),
    }
}

impl<H: Handler> Session<H> {
    async fn serve(&mut self) -> End {
        let greeting = Reply::new(
            220,
            format!("{} SMTP service ready", self.config.service_name),
        );
        if let Err(e) = self.send(greeting).await {
            return End::Io(e);
        }
        loop {
            let line = match self.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => return End::Eof,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return End::Timeout,
                Err(e) => return End::Io(e),
            };
            let text = String::from_utf8_lossy(&line)
                .trim_end_matches(['\r', '\n'])
                .to_string();
            if let Some(log) = &self.config.smtplog {
                log.received(&self.id, &text);
            }
            let command = match parse_command(&line) {
                Ok(c) => c,
                Err(CommandError { code, text }) => {
                    if let Err(e) = self.send(Reply::new(code, text)).await {
                        return End::Io(e);
                    }
                    continue;
                }
            };
            match self.dispatch(command).await {
                Ok(Flow::Continue) => {}
                Ok(Flow::Quit) => return End::Quit,
                Ok(Flow::TlsFailed) => return End::TlsFailed,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return End::Timeout,
                Err(e) => return End::Io(e),
            }
        }
    }

    /// One line including its terminator; None at EOF. After TLS, an idle
    /// connection times out; before TLS it does not, as in the Perl.
    async fn next_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(line) = take_line(&mut self.buf) {
                return Ok(Some(line));
            }
            let mut chunk = [0u8; 8192];
            let n = if self.tls_active {
                match tokio::time::timeout(
                    self.config.tls_idle_timeout,
                    self.stream.read(&mut chunk),
                )
                .await
                {
                    Ok(r) => r?,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "inactivity timeout",
                        ));
                    }
                }
            } else {
                self.stream.read(&mut chunk).await?
            };
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn send(&mut self, reply: Reply) -> std::io::Result<()> {
        let wire = reply.wire();
        if let Some(log) = &self.config.smtplog {
            log.sent(&self.id, &wire);
        }
        self.stream.write_all(wire.as_bytes()).await?;
        self.stream.flush().await
    }

    fn start_transaction(&mut self) {
        self.handler.reset();
    }

    async fn dispatch(&mut self, command: Command) -> std::io::Result<Flow> {
        match command {
            Command::Quit => {
                debug!("Processing QUIT for {}", self.client);
                self.send(Reply::new(
                    221,
                    format!("{} closing transmission channel", self.config.service_name),
                ))
                .await?;
                let _ = self.stream.shutdown().await;
                Ok(Flow::Quit)
            }
            Command::Noop => {
                debug!("Processing NOOP for {}", self.client);
                self.send(Reply::new(250, "OK")).await?;
                Ok(Flow::Continue)
            }
            Command::Vrfy { .. } => {
                debug!("Processing VRFY for {}", self.client);
                self.send(Reply::new(553, "Unimplemented")).await?;
                Ok(Flow::Continue)
            }
            Command::Ehlo { .. } | Command::Helo { .. } => {
                debug!("Processing {} for {}", command.verb(), self.client);
                self.greeting(matches!(command, Command::Ehlo { .. }))
                    .await?;
                Ok(Flow::Continue)
            }
            Command::Rset => {
                debug!("Processing RSET for {}", self.client);
                self.start_transaction();
                if self.state > State::WantMail {
                    self.state = State::WantMail;
                }
                self.send(Reply::new(250, "OK")).await?;
                Ok(Flow::Continue)
            }
            other => match self.state {
                State::WantGreeting => self.bad_sequence().await,
                State::WantStartTls => self.want_starttls(other).await,
                State::WantAuth => self.want_auth(other).await,
                State::WantMail => self.want_mail(other).await,
                State::WantRcpt => self.want_rcpt(other).await,
                State::WantData => self.want_data(other).await,
            },
        }
    }

    async fn bad_sequence(&mut self) -> std::io::Result<Flow> {
        self.send(Reply::new(503, "Bad sequence of commands"))
            .await?;
        Ok(Flow::Continue)
    }

    /// RFC 5321 4.1.4: a greeting at any point resets the transaction like
    /// RSET, but never the session: authentication survives. Being at or
    /// past WantMail is what "authenticated, or authentication is not
    /// required" means, so no separate flag is kept.
    async fn greeting(&mut self, ehlo: bool) -> std::io::Result<()> {
        let svc = &self.config.service_name;
        let first = if self.tls_active {
            format!("{svc} offers another warm hug of welcome")
        } else {
            format!("{svc} offers a warm hug of welcome")
        };
        let mut lines = vec![first];
        if ehlo {
            let tls_offered = self.config.tls.is_some();
            if !self.tls_active && tls_offered {
                lines.push("STARTTLS".into());
            }
            if self.tls_active || !self.config.require_starttls {
                lines.push("AUTH PLAIN LOGIN".into());
            }
            if self.handler.dsn_available() {
                lines.push("DSN".into());
            }
        }
        if self.state >= State::WantMail {
            self.start_transaction();
        }
        self.state = if self.state >= State::WantMail {
            State::WantMail
        } else if self.state >= State::WantAuth || self.tls_active {
            State::WantAuth
        } else {
            State::WantStartTls
        };
        self.send(Reply::multi(250, lines)).await
    }

    async fn want_starttls(&mut self, command: Command) -> std::io::Result<Flow> {
        match command {
            Command::StartTls if self.config.tls.is_some() => {
                self.send(Reply::new(220, "Go ahead")).await?;
                // CVE-2011-0411: whatever else is in the buffer arrived in the
                // clear, and must not be run as though sent inside TLS.
                if !self.buf.is_empty() {
                    info!(
                        "Discarding {} byte(s) received before STARTTLS from {}",
                        self.buf.len(),
                        self.client
                    );
                    self.buf.clear();
                }
                debug!("Starting TLS upgrade for {}", self.client);
                let acceptor = TlsAcceptor::from(self.config.tls.clone().expect("checked above"));
                let plain = std::mem::replace(&mut self.stream, Box::pin(tokio::io::empty()));
                match acceptor.accept(plain).await {
                    Ok(tls) => {
                        debug!("Successful TLS upgrade for {}", self.client);
                        self.stream = Box::pin(tls);
                        self.tls_active = true;
                        self.state = State::WantAuth;
                        Ok(Flow::Continue)
                    }
                    Err(e) => {
                        info!("Failed TLS upgrade for {}: {e}", self.client);
                        Ok(Flow::TlsFailed)
                    }
                }
            }
            _ if self.config.require_starttls => {
                self.send(Reply::new(530, "Must issue a STARTTLS command first"))
                    .await?;
                Ok(Flow::Continue)
            }
            other => {
                self.state = State::WantAuth;
                self.want_auth(other).await
            }
        }
    }

    async fn want_auth(&mut self, command: Command) -> std::io::Result<Flow> {
        match command {
            Command::Auth { mechanism, initial } => match mechanism.as_str() {
                "PLAIN" => {
                    debug!("Processing AUTH PLAIN for {}", self.client);
                    let token = match initial {
                        Some(t) => t,
                        None => {
                            self.send(Reply::new(334, "")).await?;
                            match self.auth_continuation().await? {
                                Some(t) => t,
                                None => return Ok(Flow::Continue),
                            }
                        }
                    };
                    let creds = decode_plain(&token);
                    self.finish_auth(creds).await
                }
                "LOGIN" => {
                    debug!("Processing AUTH LOGIN for {}", self.client);
                    self.send(Reply::new(334, USERNAME_CHALLENGE)).await?;
                    let Some(user) = self.auth_continuation().await? else {
                        return Ok(Flow::Continue);
                    };
                    self.send(Reply::new(334, PASSWORD_CHALLENGE)).await?;
                    let Some(pass) = self.auth_continuation().await? else {
                        return Ok(Flow::Continue);
                    };
                    debug!("Received AUTH LOGIN password for {}", self.client);
                    let creds = decode_login(&user, &pass);
                    self.finish_auth(creds).await
                }
                other => {
                    debug!("Unsupported AUTH mechanism {other} used by {}", self.client);
                    self.send(Reply::new(504, "Authentication mechanism not supported"))
                        .await?;
                    Ok(Flow::Continue)
                }
            },
            _ if self.config.require_auth => {
                debug!("Authentication required sent to {}", self.client);
                self.send(Reply::new(530, "Authentication required"))
                    .await?;
                Ok(Flow::Continue)
            }
            other => {
                self.state = State::WantMail;
                self.want_mail(other).await
            }
        }
    }

    /// One SASL continuation line. None means a 500 was already sent.
    /// Spec 4.5: a continuation line that carries a line break before its
    /// end is answered `500 confused authentication response`. An empty line
    /// is the degenerate case of that, and an embedded CR or LF the general
    /// one; neither can be a base64 token.
    async fn auth_continuation(&mut self) -> std::io::Result<Option<String>> {
        let Some(line) = self.next_line().await? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in AUTH",
            ));
        };
        let raw = String::from_utf8_lossy(&line).into_owned();
        let text = raw
            .strip_suffix("\r\n")
            .or_else(|| raw.strip_suffix('\n'))
            .unwrap_or(&raw)
            .to_string();
        if let Some(log) = &self.config.smtplog {
            log.received_auth_secret(&self.id, &text);
        }
        if text.is_empty() || text.contains(['\r', '\n']) {
            self.send(Reply::new(500, "confused authentication response"))
                .await?;
            return Ok(None);
        }
        Ok(Some(text))
    }

    async fn finish_auth(
        &mut self,
        creds: Option<crate::server::auth::Credentials>,
    ) -> std::io::Result<Flow> {
        let ok = match creds {
            Some(c) => self
                .handler
                .auth(&c.authzid, &c.authcid, &c.password)
                .await
                .is_ok(),
            None => false,
        };
        if ok {
            self.send(Reply::new(235, "Authentication successful"))
                .await?;
            debug!("Successfully authenticated {}", self.client);
            self.state = State::WantMail;
        } else {
            self.send(Reply::new(535, "Authentication credentials invalid"))
                .await?;
            debug!("Authentication failed for {}", self.client);
        }
        Ok(Flow::Continue)
    }

    async fn want_mail(&mut self, command: Command) -> std::io::Result<Flow> {
        let Command::Mail { from, params } = command else {
            return self.bad_sequence().await;
        };
        if let Err(text) = validate_dsn(&params, DsnCommand::Mail) {
            debug!("Rejected MAIL parameters from {}: {text}", self.client);
            self.send(Reply::new(501, text)).await?;
            return Ok(Flow::Continue);
        }
        self.start_transaction();
        match self.handler.mail(&from, &params).await {
            Ok(()) => {
                self.send(Reply::new(250, "OK")).await?;
                debug!("Accepted MAIL command from {}", self.client);
                self.state = State::WantRcpt;
            }
            Err(e) => {
                self.send(Reply::new(553, format!("Requested action not taken: {e}")))
                    .await?;
                debug!("MAIL command rejected for {}", self.client);
            }
        }
        Ok(Flow::Continue)
    }

    async fn want_rcpt(&mut self, command: Command) -> std::io::Result<Flow> {
        let Command::Rcpt { to, params } = command else {
            return self.bad_sequence().await;
        };
        if let Err(text) = validate_dsn(&params, DsnCommand::Rcpt) {
            debug!("Rejected RCPT parameters from {}: {text}", self.client);
            self.send(Reply::new(501, text)).await?;
            return Ok(Flow::Continue);
        }
        match self.handler.rcpt(&to, &params).await {
            Ok(()) => {
                self.send(Reply::new(250, "OK")).await?;
                debug!("Accepted RCPT command from {}", self.client);
                self.state = State::WantData;
            }
            Err(e) => {
                self.send(Reply::new(
                    550,
                    format!("Will not send mail to this user: {e}"),
                ))
                .await?;
                debug!("RCPT command rejected for {}", self.client);
            }
        }
        Ok(Flow::Continue)
    }

    async fn want_data(&mut self, command: Command) -> std::io::Result<Flow> {
        match command {
            Command::Rcpt { .. } => self.want_rcpt(command).await,
            Command::Data => self.read_message().await,
            _ => self.bad_sequence().await,
        }
    }

    async fn read_message(&mut self) -> std::io::Result<Flow> {
        self.send(Reply::new(354, "End data with <CR><LF>.<CR><LF>"))
            .await?;
        let mut reader = DataReader::new(self.config.max_message_size);
        let mut headers_error: Option<String> = None;
        let mut logged_mb = 0usize;
        let mut received = 0usize;
        let outcome: Result<String, (u16, String)> = loop {
            let Some(line) = self.next_line().await? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in DATA",
                ));
            };
            received += line.len();
            if received / 1_000_000 > logged_mb {
                logged_mb = received / 1_000_000;
                debug!("received {logged_mb} MB data");
            }
            match reader.push_line(&line) {
                None => {}
                Some(DataEvent::HeadersComplete(h)) => {
                    debug!("Header received. Resolving Header Promise");
                    if let Err(e) = self.handler.headers(h).await {
                        headers_error = Some(e);
                    }
                }
                Some(DataEvent::TooLarge) => {
                    break Err((
                        552,
                        format!(
                            "Message exceeds maximum size of {} bytes",
                            self.config.max_message_size
                        ),
                    ));
                }
                Some(DataEvent::MessageComplete(body)) => {
                    if let Some(h) = reader.take_pending_headers() {
                        debug!(
                            "Header received (empty Body). Resolving Header Promise and Empty Body Promise."
                        );
                        if let Err(e) = self.handler.headers(h).await {
                            headers_error = Some(e);
                        }
                    } else {
                        debug!(
                            "Body received {} Bytes. Resolving Body Promise.",
                            body.len()
                        );
                    }
                    if let Some(e) = headers_error.take() {
                        break Err((550, e));
                    }
                    break self.handler.message(body).await.map_err(|t| (550, t));
                }
            }
        };
        self.state = State::WantMail;
        match outcome {
            Ok(message) => {
                debug!("Accepted DATA for {} {message}", self.client);
                if let Err(e) = self.send(Reply::new(250, format!("OK: {message}"))).await {
                    info!(
                        "Client {} left before the message could be accepted: {message}",
                        self.client
                    );
                    return Err(e);
                }
            }
            Err((code, text)) => {
                debug!("DATA rejected for {} {text}", self.client);
                if code == 552 {
                    self.start_transaction();
                }
                if let Err(e) = self.send(Reply::new(code, text.clone())).await {
                    info!(
                        "Client {} left before the rejection could be sent: {text}",
                        self.client
                    );
                    return Err(e);
                }
            }
        }
        Ok(Flow::Continue)
    }
}
