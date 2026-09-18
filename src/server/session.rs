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

use crate::relay::UpstreamVerdict;
use crate::server::auth::{PASSWORD_CHALLENGE, USERNAME_CHALLENGE, decode_login, decode_plain};
use crate::server::data::{
    BodyFramer, BodyPiece, HeaderCollector, HeaderEvent, WRITE_CHUNK, is_terminator,
};
use crate::server::{BodySink, Handler, Rejection, ServerConfig};
use crate::smtp::command::{Command, CommandError, parse_command, take_line};
use crate::smtp::dsn::{DsnCommand, validate_dsn};
use crate::smtp::reply::Reply;

type Stream = Pin<Box<dyn AsyncReadWrite>>;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}

/// How many bytes of an unterminated command line the reader will hold
/// before it gives up on ever finding the end of it. RFC 5321 4.5.3.1.4
/// caps a command line at 512 octets, so this is generous; its job is only
/// to keep a client that never sends a newline from filling memory.
const MAX_COMMAND_BUFFER: usize = 64 * 1024;

/// Bytes of headroom the header collector keeps on top of what the header
/// cap still allows, so that a half-read terminator is never mistaken for an
/// over-cap line. The terminator and the blank line that ends the header
/// block are both free of charge, and the longest either can be while still
/// incomplete is `.\r`.
const TERMINATOR_SLACK: usize = 2;

/// What one read attempt produced.
enum Line {
    Got(Vec<u8>),
    /// The client closed its side.
    Eof,
    /// The budget ran out before a newline arrived. Nothing is consumed;
    /// the caller decides what to do with what is buffered.
    TooLong,
}

/// The Perl's cumulative `received <n> MB data` debug line
/// (`Connection.pm`, `sub _dataLine`): one line per megabyte of DATA, header
/// bytes and discarded bytes alike. It survives the split of DATA into a
/// header phase, a body phase and a drain, which is the only reason it is a
/// type rather than two locals.
///
/// Bytes of a line that outgrew the read budget are not counted, as they
/// were not before: only complete lines reach [`ReceiptLog::note`].
#[derive(Default)]
struct ReceiptLog {
    received: usize,
    logged_mb: usize,
}

impl ReceiptLog {
    fn note(&mut self, bytes: usize) {
        self.received += bytes;
        if self.received / 1_000_000 > self.logged_mb {
            self.logged_mb = self.received / 1_000_000;
            debug!("received {} MB data", self.logged_mb);
        }
    }
}

/// A client that simply went away. Routine, so it is logged once at info and
/// never as an error: only a genuinely unexpected I/O failure is an error.
fn is_hangup(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{
        BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected, UnexpectedEof,
    };
    matches!(
        e.kind(),
        UnexpectedEof | BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected
    )
}

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
    /// Ended deliberately, with the reason already logged.
    Closed,
    /// A drain began while this session was between commands (spec 9.1).
    Drained,
}

enum Flow {
    Continue,
    Quit,
    TlsFailed,
    /// Stop serving this connection; the reason has already been logged.
    Close,
}

/// What one SASL continuation line produced.
enum AuthLine {
    Token(String),
    /// A `500 confused authentication response` went out; the session lives on.
    Confused,
    /// The connection is finished and the reason is already logged.
    Closed,
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
    /// Set the moment the first complete command line is taken, which is
    /// what hands the session from `greeting_timeout` to `idle_timeout`. It
    /// never goes back to false, so the short deadline does not re-arm --
    /// the EHLO a client sends again after STARTTLS is not a first command.
    first_command_seen: bool,
    /// RCPT entries accepted in the running transaction, for
    /// `max_recipients`. Repeats count, as the spec says (9.3).
    recipients: usize,
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
        first_command_seen: false,
        recipients: 0,
    };
    match s.serve().await {
        End::Quit | End::Eof | End::TlsFailed | End::Closed | End::Drained => {}
        End::Timeout => tracing::error!("Timeout on stream for {}", s.client),
        End::Io(e) if is_hangup(&e) => info!("Client {} hung up: {e}", s.client),
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
            let line = match self.next_command_line().await {
                Ok(Some(Line::Got(line))) => {
                    // From here on the ordinary inactivity timeout governs.
                    self.first_command_seen = true;
                    line
                }
                Ok(Some(Line::Eof)) => return End::Eof,
                Ok(Some(Line::TooLong)) => {
                    self.refuse_long_line().await;
                    return End::Closed;
                }
                Ok(None) => return self.drained().await,
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
                Ok(Flow::Close) => return End::Closed,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return End::Timeout,
                Err(e) => return End::Io(e),
            }
        }
    }

    /// The next command, unless a drain begins first: `Ok(None)` says the
    /// drain won and the session is to close with a 421.
    ///
    /// Only this wait is cancellable. `read_message` -- the handler call it
    /// makes included -- reads on, so a message that is already on its way
    /// is received and answered in full, and the drain takes effect at the
    /// following command instead (spec 9.1).
    async fn next_command_line(&mut self) -> std::io::Result<Option<Line>> {
        let Some(drain) = self.config.drain.clone() else {
            return self.next_line(MAX_COMMAND_BUFFER).await.map(Some);
        };
        tokio::select! {
            // `biased`: on an already-cancelled token the first arm is
            // ready, so a session that has just finished a message drains
            // even when the client's next command is sitting in the buffer.
            biased;
            _ = drain.token.cancelled() => Ok(None),
            line = self.next_line(MAX_COMMAND_BUFFER) => line.map(Some),
        }
    }

    /// Spec 9.1: this session was between commands when the drain began,
    /// so there is nothing to finish -- say why and close.
    async fn drained(&mut self) -> End {
        debug!("Draining connection from {}", self.client);
        let _ = self
            .send(Reply::new(
                421,
                format!(
                    "{} Service not available, closing transmission channel",
                    self.config.service_name
                ),
            ))
            .await;
        let _ = self.stream.shutdown().await;
        End::Drained
    }

    /// One line including its terminator. An idle connection times out, in
    /// every phase of the session.
    ///
    /// Deliberate divergence from the Perl, which arms its inactivity timer
    /// only after STARTTLS (`SMTPProxy.pm` passes `timeout => 0` to the
    /// stream at accept; `SMTPServer/Connection.pm` sets
    /// `$self->stream->timeout(600)` on the upgraded stream). Measured against
    /// the running Perl: a client that connects and then stays silent is still
    /// connected after 90 s, with no close and no `Timeout on stream` log line.
    ///
    /// The Perl could afford that because a stalled connection cost it only
    /// a file descriptor. Here it costs a slot in `max_connections` /
    /// `max_connections_per_ip` (spec 9.2), taken at accept
    /// (`listener.rs`, `limits.try_acquire(client.ip())`) and released only
    /// when the session future is dropped. An untimed read before TLS
    /// therefore means an unauthenticated client can hold every slot for ever
    /// by sending nothing at all, which turns the new connection limit into
    /// the lockout mechanism.
    ///
    /// The wait for the client's *first* command has a shorter deadline of
    /// its own, `--greeting_timeout` (30 s), because `idle_timeout` alone
    /// only makes the lockout self-healing rather than impossible: 1000 slots
    /// over 600 s is one new connection every twelve seconds from each of
    /// twenty addresses, which costs an attacker nothing. User ruling
    /// 2026-09-14. It is a deliberate narrowing of RFC 5321 4.5.3.2, which
    /// asks for five minutes per command, and it is defensible only because
    /// it applies to a connection that has sent *nothing at all*: a real
    /// client sends EHLO as soon as it has read the 220. Once one complete
    /// command line has arrived the RFC's own budget applies for the rest of
    /// the session, STARTTLS and the EHLO after it included.
    ///
    /// `max_incomplete` bounds the bytes held while no newline has arrived.
    /// Without it a client that sends bytes and never a newline grows the
    /// buffer without limit: `HeaderCollector` cannot help, because `push_line`
    /// only ever sees lines that are already complete.
    async fn next_line(&mut self, max_incomplete: usize) -> std::io::Result<Line> {
        // A half-written first command does not buy the longer budget: the
        // flag is set by `serve` when a *complete* line has been taken, so a
        // client that dribbles "EHL" and stops is still on the greeting
        // deadline.
        let deadline = if self.first_command_seen {
            self.config.idle_timeout
        } else {
            self.config.greeting_timeout
        };
        loop {
            if let Some(line) = take_line(&mut self.buf) {
                return Ok(Line::Got(line));
            }
            if self.buf.len() > max_incomplete {
                return Ok(Line::TooLong);
            }
            let mut chunk = [0u8; 8192];
            let n = match tokio::time::timeout(deadline, self.stream.read(&mut chunk)).await {
                Ok(r) => r?,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "inactivity timeout",
                    ));
                }
            };
            if n == 0 {
                return Ok(Line::Eof);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// A command line with no end in sight: say so once and close, because
    /// there is no way to resynchronise on a command boundary that the
    /// client never sends.
    async fn refuse_long_line(&mut self) {
        info!("Line too long from {}", self.client);
        let _ = self.send(Reply::new(500, "Line too long")).await;
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
        self.recipients = 0;
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
            if let Some(n) = self.handler.size_limit() {
                lines.push(format!("SIZE {n}"));
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
                                AuthLine::Token(t) => t,
                                AuthLine::Confused => return Ok(Flow::Continue),
                                AuthLine::Closed => return Ok(Flow::Close),
                            }
                        }
                    };
                    let creds = decode_plain(&token);
                    self.finish_auth(creds).await
                }
                "LOGIN" => {
                    debug!("Processing AUTH LOGIN for {}", self.client);
                    self.send(Reply::new(334, USERNAME_CHALLENGE)).await?;
                    let user = match self.auth_continuation().await? {
                        AuthLine::Token(t) => t,
                        AuthLine::Confused => return Ok(Flow::Continue),
                        AuthLine::Closed => return Ok(Flow::Close),
                    };
                    self.send(Reply::new(334, PASSWORD_CHALLENGE)).await?;
                    let pass = match self.auth_continuation().await? {
                        AuthLine::Token(t) => t,
                        AuthLine::Confused => return Ok(Flow::Continue),
                        AuthLine::Closed => return Ok(Flow::Close),
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

    /// One SASL continuation line.
    /// Spec 4.5: a continuation line that carries a line break before its
    /// end is answered `500 confused authentication response`. An empty line
    /// is the degenerate case of that, and an embedded CR or LF the general
    /// one; neither can be a base64 token.
    async fn auth_continuation(&mut self) -> std::io::Result<AuthLine> {
        let line = match self.next_line(MAX_COMMAND_BUFFER).await? {
            Line::Got(line) => line,
            Line::Eof => {
                info!("Client {} hung up during authentication", self.client);
                return Ok(AuthLine::Closed);
            }
            Line::TooLong => {
                self.refuse_long_line().await;
                return Ok(AuthLine::Closed);
            }
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
            return Ok(AuthLine::Confused);
        }
        Ok(AuthLine::Token(text))
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
            Err(rejection) => {
                self.send(Reply::new(rejection.code, rejection.text))
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
        // Spec 9.3: the handler never hears about the recipient that would
        // exceed the cap, and the transaction keeps the ones it has -- the
        // client may still send the message to those.
        if self.config.max_recipients > 0 && self.recipients >= self.config.max_recipients {
            debug!(
                "Recipient limit of {} reached for {}",
                self.config.max_recipients, self.client
            );
            self.send(Reply::new(452, "4.5.3 Too many recipients"))
                .await?;
            return Ok(Flow::Continue);
        }
        match self.handler.rcpt(&to, &params).await {
            Ok(()) => {
                self.recipients += 1;
                self.send(Reply::new(250, "OK")).await?;
                debug!("Accepted RCPT command from {}", self.client);
                self.state = State::WantData;
            }
            Err(rejection) => {
                self.send(Reply::new(rejection.code, rejection.text))
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

    /// DATA, from the `354` to the reply that ends it.
    ///
    /// Three phases, in order: collect the header block, hand it to the
    /// handler in exchange for a body sink, then pump body lines into that
    /// sink until the terminator. Each phase has exactly one way out that is
    /// not the next phase -- the client leaving, or a refusal -- and every
    /// refusal is spoken at the terminator, never where it was decided, so
    /// that the rest of the message is drained as a message instead of being
    /// read as commands (spec 6).
    async fn read_message(&mut self) -> std::io::Result<Flow> {
        self.send(Reply::new(354, "End data with <CR><LF>.<CR><LF>"))
            .await?;
        let mut log = ReceiptLog::default();
        let mut collector = HeaderCollector::new(self.config.max_header_size);
        // `true` while a body is still to come. The terminator can arrive
        // inside the header block, and then there is nothing left to pump and
        // nothing left to drain.
        let (headers, body_follows) = loop {
            // An incomplete header line counts against the cap like any other
            // bytes. The collector never runs out of capacity here -- the two
            // events that would empty it leave this loop -- so the fallback
            // bound is a plain safety net and not a path.
            //
            // TERMINATOR_SLACK covers the two lines that cost nothing: the
            // terminator and the blank line that ends the headers. A header
            // block that fills the cap exactly leaves no capacity, and the
            // ".\r\n" or "\r\n" that follows can still be split across reads.
            // Held half-read it is at most ".\r", two bytes, so without the
            // slack it would look like an over-cap line, the message would be
            // discarded, and the rest of the terminator would be eaten as a
            // discarded tail -- leaving the session waiting for a terminator
            // that had already arrived. Two bytes cannot hide a real header
            // line: any header line costs at least its own terminator.
            let budget = collector
                .remaining_capacity()
                .map_or(MAX_COMMAND_BUFFER, |left| left + TERMINATOR_SLACK);
            let line = match self.next_line(budget).await? {
                Line::Got(line) => line,
                Line::Eof => {
                    info!("Client {} hung up during DATA", self.client);
                    return Ok(Flow::Close);
                }
                // The budget here is what the cap still allows, so a line with
                // no end in sight has crossed it. What is buffered goes, and
                // the drain starts mid-line: the rest of this line is still to
                // come, and a tail that happened to be `.` must not be read as
                // the terminator.
                Line::TooLong => {
                    debug!(
                        "Header block from {} crossed the size cap inside an unterminated line",
                        self.client
                    );
                    // Both buffers go now rather than at the end of the
                    // message: the drain below can run for as long as the
                    // client keeps writing, and nothing will ever read either
                    // of them again.
                    self.buf.clear();
                    collector.mark_too_large();
                    return self.refuse_large_headers(false, &mut log).await;
                }
            };
            log.note(line.len());
            match collector.push_line(&line) {
                None => {}
                Some(HeaderEvent::Complete(h)) => {
                    debug!("Header received. Resolving Header Promise");
                    break (h, true);
                }
                Some(HeaderEvent::Terminator) => {
                    // The terminator before any blank line: the message is a
                    // header block and nothing else. `take_pending` is `Some`
                    // without fail here -- the two states that empty it, the
                    // block delivered and the cap crossed, both leave this
                    // loop -- and an empty block is the honest reading if it
                    // ever were not.
                    debug!(
                        "Header received (empty Body). Resolving Header Promise and Empty Body Promise."
                    );
                    break (collector.take_pending().unwrap_or_default(), false);
                }
                Some(HeaderEvent::TooLarge) => {
                    return self.refuse_large_headers(true, &mut log).await;
                }
            }
        };
        let mut sink = match self.handler.open_body(headers).await {
            Ok(sink) => sink,
            Err(Rejection { code, text }) => {
                // The handler has refused in its own voice, and the client is
                // still writing. Read the rest of the message away, then
                // answer where every other DATA answer is given.
                if body_follows
                    && matches!(
                        self.discard_to_terminator(true, &mut log).await?,
                        Flow::Close
                    )
                {
                    return Ok(Flow::Close);
                }
                self.state = State::WantMail;
                return self.refuse_data(code, text).await;
            }
        };
        if !body_follows {
            return self.conclude(sink.finish().await).await;
        }
        let mut framer = BodyFramer::new();
        // What the Perl's `Body received` counts: the body as the *message*
        // holds it, which is the bytes the client sent with the stuffing dots
        // taken back off (`Connection.pm`, `$line =~ s/^\.//` before
        // `$handled .= $line`). Counted here, against what arrived, rather
        // than against what goes upstream: the wire form keeps its stuffing
        // and would count a dot the message does not have.
        let mut body_bytes = 0usize;
        // Mirrors the framer's own view of where a line begins, as of the
        // piece just pushed. The framer keeps it privately for the
        // terminator; the session needs it for two things the framer cannot
        // answer for: a drain that starts mid-line, and whether a leading dot
        // is stuffing or content. The body starts at a line start.
        let mut at_line_start = true;
        loop {
            // The state the bytes about to be read begin in, before the arms
            // below move it on.
            let begins_line = at_line_start;
            // What these bytes add to the message: their own length, less
            // the stuffing dot if they begin a line with one. Set by every
            // arm that reads bytes; the one that does not returns.
            let arrived;
            let piece = match self.next_line(WRITE_CHUNK).await? {
                Line::Got(line) => {
                    log.note(line.len());
                    at_line_start = true;
                    arrived = line.len() - usize::from(begins_line && line.starts_with(b"."));
                    framer.push(&line)
                }
                // No newline within a chunk's worth of bytes. There is no
                // body cap to refuse it against, so it goes out as it is and
                // the framer stays mid-line -- which is what stops `self.buf`
                // growing with a body that has no line breaks at all.
                //
                // The slice is never empty, so `push_partial` needs no guard
                // for one: `next_line` reports `TooLong` only once the buffer
                // is already longer than the budget it was given.
                Line::TooLong => {
                    let partial = std::mem::take(&mut self.buf);
                    at_line_start = false;
                    arrived = partial.len() - usize::from(begins_line && partial.starts_with(b"."));
                    framer.push_partial(&partial)
                }
                Line::Eof => {
                    info!("Client {} hung up during DATA", self.client);
                    // `sink` is dropped here: the upstream connection closes
                    // with no terminator, so nothing is delivered.
                    return Ok(Flow::Close);
                }
            };
            // The terminator is not part of the message, so the line that
            // carries it adds nothing. Decided from the framer's answer
            // rather than re-tested here, so the two cannot disagree.
            if !matches!(piece, BodyPiece::Terminator) {
                body_bytes += arrived;
            }
            match piece {
                // Staged, and not yet a write's worth. Read on.
                BodyPiece::Pending => {}
                BodyPiece::Chunk(chunk) => {
                    if let Err(verdict) = sink.write(&chunk).await {
                        return self.mirror(verdict, at_line_start, &mut log).await;
                    }
                }
                BodyPiece::Terminator => break,
            }
        }
        // What is staged below a chunk is still body. Without this every
        // message shorter than `WRITE_CHUNK` would be delivered empty.
        let rest = framer.flush();
        if !rest.is_empty()
            && let Err(verdict) = sink.write(&rest).await
        {
            // No drain: the terminator has already been read, so what would
            // be drained is the *next* client's commands.
            return self.conclude(Err(verdict)).await;
        }
        debug!("Body received {body_bytes} Bytes. Resolving Body Promise.");
        self.conclude(sink.finish().await).await
    }

    /// Spec 6: the `552` is spoken at the terminator, never when the cap is
    /// crossed, so that the rest of the message is drained as a message
    /// instead of being read as commands.
    ///
    /// `at_line_start` says whether the bytes still to come begin a line; see
    /// [`Session::discard_to_terminator`].
    async fn refuse_large_headers(
        &mut self,
        at_line_start: bool,
        log: &mut ReceiptLog,
    ) -> std::io::Result<Flow> {
        if matches!(
            self.discard_to_terminator(at_line_start, log).await?,
            Flow::Close
        ) {
            return Ok(Flow::Close);
        }
        self.state = State::WantMail;
        // Our own cap discarded the message, so there is a half-read
        // transaction here to clear. An upstream that answers `552` is a
        // different thing entirely and leaves none.
        self.start_transaction();
        self.refuse_data(
            552,
            format!(
                "Header block exceeds maximum size of {} bytes",
                self.config.max_header_size
            ),
        )
        .await
    }

    /// Reads the rest of the message and throws it away, up to and including
    /// the terminator. The one alternative -- answering where the refusal was
    /// decided and going back to reading commands -- would parse the body as
    /// commands.
    ///
    /// `at_line_start` is false when the tail of a line that was already taken
    /// is still to come. That tail ends a line without beginning one, so it
    /// must not be read as a line of its own: a tail that happened to be `.`
    /// would end DATA early and leave the rest of the body to be parsed as
    /// commands.
    ///
    /// The terminator is tested here rather than asked of the collector on
    /// purpose: a `HeaderCollector` that is discarding answers `TooLarge` to
    /// every line, the terminator included.
    async fn discard_to_terminator(
        &mut self,
        mut at_line_start: bool,
        log: &mut ReceiptLog,
    ) -> std::io::Result<Flow> {
        loop {
            match self.next_line(MAX_COMMAND_BUFFER).await? {
                Line::Got(line) => {
                    log.note(line.len());
                    if at_line_start && is_terminator(&line) {
                        return Ok(Flow::Continue);
                    }
                    at_line_start = true;
                }
                Line::TooLong => {
                    self.buf.clear();
                    at_line_start = false;
                }
                Line::Eof => {
                    info!("Client {} hung up during DATA", self.client);
                    return Ok(Flow::Close);
                }
            }
        }
    }

    /// The proxy is a mirror during DATA: whatever the upstream did to us,
    /// we do to the client. A client is not insulated from what it would
    /// have met talking to the upstream directly.
    ///
    /// This is the mid-body form, for a verdict that arrived while the client
    /// was still writing. [`Session::conclude`] is the same rule once the
    /// terminator is in.
    async fn mirror(
        &mut self,
        verdict: UpstreamVerdict,
        at_line_start: bool,
        log: &mut ReceiptLog,
    ) -> std::io::Result<Flow> {
        match verdict {
            // A verdict with nothing to say closes the client wherever it
            // arrives, and there is nothing to drain for: the client is told
            // by the close itself.
            UpstreamVerdict::Dropped => self.conclude(Err(UpstreamVerdict::Dropped)).await,
            UpstreamVerdict::Replied { code, text } => {
                self.state = State::WantMail;
                // Sent now, mid-DATA, exactly as the upstream sent it to us.
                // What follows is body the client is still writing, and a
                // server that has already answered reads it only to resync.
                if matches!(self.refuse_data(code, text).await?, Flow::Close) {
                    return Ok(Flow::Close);
                }
                let flow = self.discard_to_terminator(at_line_start, log).await?;
                self.start_transaction();
                Ok(flow)
            }
        }
    }

    /// The upstream's last word on a message whose terminator is already
    /// read. [`Session::mirror`] without the drain, because there is nothing
    /// left of the message to drain.
    async fn conclude(
        &mut self,
        outcome: Result<String, UpstreamVerdict>,
    ) -> std::io::Result<Flow> {
        self.state = State::WantMail;
        match outcome {
            Ok(message) => {
                debug!("Accepted DATA for {} {message}", self.client);
                if let Err(e) = self.send(Reply::new(250, format!("OK: {message}"))).await {
                    if !is_hangup(&e) {
                        return Err(e);
                    }
                    // Spec 4.7: the reply is dropped and logged at info, as
                    // the Perl does. A client that hung up is not an error.
                    info!(
                        "Client {} left before the message could be accepted: {message}",
                        self.client
                    );
                    return Ok(Flow::Close);
                }
                Ok(Flow::Continue)
            }
            Err(UpstreamVerdict::Replied { code, text }) => self.refuse_data(code, text).await,
            Err(UpstreamVerdict::Dropped) => {
                info!(
                    "Upstream closed during DATA for {}; closing the client too",
                    self.client
                );
                Ok(Flow::Close)
            }
        }
    }

    /// The reply that refuses a message, with spec 4.7's allowance for a
    /// client that has already gone: the reply is dropped and logged at info,
    /// never reported as an error.
    async fn refuse_data(&mut self, code: u16, text: String) -> std::io::Result<Flow> {
        debug!("DATA rejected for {} {text}", self.client);
        if let Err(e) = self.send(Reply::new(code, text.clone())).await {
            if !is_hangup(&e) {
                return Err(e);
            }
            info!(
                "Client {} left before the rejection could be sent: {text}",
                self.client
            );
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }
}
