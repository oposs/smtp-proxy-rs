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
use crate::server::{Handler, Rejection, ServerConfig};
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

/// Bytes of headroom the DATA reader keeps on top of what the size cap still
/// allows, so that a half-read terminator is never mistaken for an over-cap
/// line. The terminator and the blank line that ends the header block are
/// both free of charge, and the longest either can be while still incomplete
/// is `.\r`.
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
    /// buffer without limit: `DataReader` cannot help, because `push_line`
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

    async fn read_message(&mut self) -> std::io::Result<Flow> {
        self.send(Reply::new(354, "End data with <CR><LF>.<CR><LF>"))
            .await?;
        let mut reader = DataReader::new(self.config.max_message_size);
        let mut headers_error: Option<String> = None;
        let mut logged_mb = 0usize;
        let mut received = 0usize;
        // Set when *our own* size cap discarded the message. An upstream may
        // now answer 552 as well (a handler rejection carries the upstream's
        // own code), and that is a different thing entirely: it leaves no
        // half-read transaction behind here.
        let mut too_large = false;
        // Set when an unterminated line was thrown away mid-flight: the rest
        // of that line is still to come, and must not be read as a line of
        // its own -- a tail that happened to be `.` would end DATA early and
        // leave the remaining body to be parsed as commands.
        let mut discarding_line_tail = false;
        let outcome: Result<String, Rejection> = loop {
            // An incomplete line counts against the cap like any other bytes.
            // Once the reader is already discarding, the cap has nothing left
            // to say and a plain byte bound keeps the drain bounded.
            //
            // TERMINATOR_SLACK covers the two lines that cost nothing: the
            // terminator and the blank line that ends the headers. A message
            // that fills the cap exactly leaves no capacity, and the ".\r\n"
            // or "\r\n" that follows can still be split across reads. Held
            // half-read it is at most ".\r", two bytes, so without the slack
            // it would look like an over-cap line, the message would be
            // discarded, and the rest of the terminator would be eaten as a
            // discarded tail -- leaving the session waiting for a terminator
            // that had already arrived. Two bytes cannot hide a real line:
            // any body line costs at least its own terminator.
            let budget = reader
                .remaining_capacity()
                .map_or(MAX_COMMAND_BUFFER, |left| left + TERMINATOR_SLACK);
            let line = match self.next_line(budget).await? {
                Line::Got(line) => line,
                Line::Eof => {
                    info!("Client {} hung up during DATA", self.client);
                    return Ok(Flow::Close);
                }
                Line::TooLong => {
                    debug!(
                        "Message from {} crossed the size cap inside an unterminated line",
                        self.client
                    );
                    reader.mark_too_large();
                    self.buf.clear();
                    discarding_line_tail = true;
                    continue;
                }
            };
            if discarding_line_tail {
                discarding_line_tail = false;
                continue;
            }
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
                    too_large = true;
                    break Err(Rejection {
                        code: 552,
                        text: format!(
                            "Message exceeds maximum size of {} bytes",
                            self.config.max_message_size
                        ),
                    });
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
                        break Err(Rejection { code: 550, text: e });
                    }
                    break self.handler.message(body).await;
                }
            }
        };
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
            }
            Err(Rejection { code, text }) => {
                debug!("DATA rejected for {} {text}", self.client);
                if too_large {
                    self.start_transaction();
                }
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
            }
        }
        Ok(Flow::Continue)
    }
}
