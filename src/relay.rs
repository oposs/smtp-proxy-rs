//! A minimal SMTP client for the upstream: one session per message.
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    Chain, ReadHalf, WriteHalf,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::api::Recipient;
use crate::server::data::WRITE_CHUNK;
use crate::smtp::dsn::{is_mail_dsn_keyword, is_rcpt_dsn_keyword};
use crate::smtp::extensions::{Extensions, parse_extensions};
use crate::smtp::params::Param;

/// Any transport a session can run over. The upstream connection changes
/// type in the middle of a session (STARTTLS), so it is held as a trait
/// object rather than as a type parameter.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// How much TLS the outbound leg asks for (spec 6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum UpstreamTlsMode {
    /// Plain SMTP, STARTTLS never sent.
    Off,
    /// STARTTLS when the upstream announces it, plain when it does not.
    #[default]
    Opportunistic,
    /// STARTTLS always; an upstream that does not announce it is an error.
    Required,
    /// TLS from the first byte, before the greeting (submissions, port 465).
    Implicit,
}

#[derive(Clone, Debug)]
pub struct UpstreamTls {
    pub mode: UpstreamTlsMode,
    /// None only for mode Off.
    pub client_config: Option<Arc<rustls::ClientConfig>>,
}

/// Accepts any server certificate. Only reachable through
/// `--upstream_tls_insecure` and through the tests' own client.
#[derive(Debug)]
pub struct NoVerify(pub Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl UpstreamTls {
    pub fn off() -> Self {
        Self {
            mode: UpstreamTlsMode::Off,
            client_config: None,
        }
    }

    /// System roots plus `extra_ca` (PEM bundle). `insecure` disables
    /// verification.
    pub fn build(
        mode: UpstreamTlsMode,
        extra_ca: Option<&Path>,
        insecure: bool,
    ) -> anyhow::Result<Self> {
        if mode == UpstreamTlsMode::Off {
            return Ok(Self::off());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?;
        let config = if insecure {
            warn!("--upstream_tls_insecure is set; the upstream certificate is not verified");
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
            if let Some(path) = extra_ca {
                use rustls_pki_types::pem::PemObject;
                for cert in rustls_pki_types::CertificateDer::pem_file_iter(path)
                    .map_err(|e| anyhow::anyhow!("cannot read CA file {}: {e}", path.display()))?
                {
                    roots.add(cert.map_err(|e| {
                        anyhow::anyhow!("bad certificate in {}: {e}", path.display())
                    })?)?;
                }
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        Ok(Self {
            mode,
            client_config: Some(Arc::new(config)),
        })
    }
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub host: String,
    pub port: u16,
    /// Perl: 60 s inactivity.
    pub timeout: Duration,
    pub tls: UpstreamTls,
    /// Name the upstream certificate has to be valid for. `None` means
    /// `host`, which is what a plain deployment wants. It is separate from
    /// `host` because the address one connects to and the name one validates
    /// are not always the same string: an upstream reached by IP address, or
    /// through a local forwarder, still presents the certificate of the mail
    /// service it is.
    pub tls_server_name: Option<String>,
}

impl RelayConfig {
    fn server_name(&self) -> &str {
        self.tls_server_name.as_deref().unwrap_or(&self.host)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The upstream answered outside the expected class. The string is the
    /// reply text without its code, which is what the client gets in its 550.
    #[error("{text}")]
    Rejected { code: u16, text: String },
    #[error(
        "Refusing to relay the address '{0}': it contains characters that cannot appear in an SMTP command line"
    )]
    Address(String),
    #[error("timeout talking to the upstream")]
    Timeout,
    #[error("TLS to the upstream failed: {0}")]
    Tls(String),
    #[error("upstream does not offer STARTTLS")]
    NoStartTls,
}

impl RelayError {
    /// The reply code the client is given for this failure.
    ///
    /// `Rejected` passes the upstream's own code through verbatim. There is
    /// no case where we know better than the upstream what its own rejection
    /// meant, and overwriting a `451` with a `550` -- which is what the Perl
    /// does unconditionally (`Connection.pm:682`) -- produces a reply that
    /// contradicts itself: `550 4.3.2 Service not available`, a permanent
    /// code wrapping a transient enhanced status. A client reading the one
    /// deletes the mail the other asked it to queue.
    ///
    /// `Io`, `Timeout`, `Tls` and `NoStartTls` carry no upstream code at all,
    /// because the upstream never answered. [`UpstreamSession::connect`]
    /// opens a fresh connection per message, so an upstream restarted between
    /// two messages lands in this group: nothing about the message was wrong,
    /// so `451` and the client comes back.
    ///
    /// `Address` stays `550`. That is *our* refusal of a malformed address,
    /// it is permanent, and it is not the upstream's opinion at all.
    ///
    /// # Invariant
    ///
    /// **Everything this returns has to be a code the client can actually be
    /// sent.** A reply code outside `200..=599` cannot go on the wire at all
    /// -- it aborts the session and answers the client nothing, which is
    /// worse than any wrong-but-sendable code. `Rejected` is the one place an
    /// outside-supplied code enters that path: it is three digits an upstream
    /// chose, `000` to `999`, and this function is the only thing standing
    /// between those and the client. So the range test below is load-bearing,
    /// not cosmetic: widening it past `599`, or dropping it and returning
    /// `*code`, hands a broken or hostile upstream a way to kill sessions.
    /// The edges are tested, and so is the property itself.
    pub fn client_code(&self) -> u16 {
        match self {
            // An upstream that answered outside the expected class with a
            // 2xx or a 3xx did not reject anything -- it broke the protocol,
            // and relaying its code would answer the client `250` for a
            // message that was never accepted. Verbatim pass-through is for
            // codes that are actually a refusal.
            RelayError::Rejected { code, .. } if (400..600).contains(code) => *code,
            RelayError::Address(_) => 550,
            RelayError::Rejected { .. }
            | RelayError::Io(_)
            | RelayError::Timeout
            | RelayError::Tls(_)
            | RelayError::NoStartTls => 451,
        }
    }
}

/// The most bytes one reply line may hold, its terminator included. RFC 5321
/// 4.5.3.1.5 caps a reply line at 512 octets, so this is generous; its job is
/// only to keep a hostile or broken upstream from feeding an endless line
/// into memory. The Perl bounds neither this nor [`MAX_REPLY_TOTAL`].
pub const MAX_REPLY_LINE: usize = 4096;

/// The most bytes a whole multi-line reply may hold. Without it an upstream
/// that answers `220-x` for ever is exactly as unbounded as one that never
/// sends a newline at all.
pub const MAX_REPLY_TOTAL: usize = 65536;

pub struct Envelope<'a> {
    pub from: &'a str,
    pub mail_params: &'a [Param],
    pub recipients: &'a [Recipient],
}

/// What the upstream announced at EHLO, as far as this proxy cares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpstreamCaps {
    pub dsn: bool,
    /// The largest message the upstream states it will take. `None` means
    /// it stated none -- see `Extensions::size`.
    pub size: Option<usize>,
    /// Whether the upstream announced the `SIZE` keyword at all, regardless
    /// of what limit (if any) it stated.
    ///
    /// Not the same question as `size.is_some()`: `Extensions::size` folds
    /// RFC 1870's `SIZE 0` ("no fixed maximum") and an unparseable value
    /// into `None`, so an upstream that announced `SIZE 0` has `size: None`
    /// but `size_announced: true`. Sending a client's `SIZE=` parameter
    /// risks a `555` only when the keyword was never offered, so that is
    /// the question this field answers.
    pub size_announced: bool,
}

impl UpstreamCaps {
    fn of(extensions: &Extensions) -> Self {
        Self {
            dsn: extensions.contains("DSN"),
            size: extensions.size(),
            size_announced: extensions.contains("SIZE"),
        }
    }
}

/// RFC 5321 4.1.2 builds a path out of printable ASCII; the angle brackets
/// are excluded because this code supplies them. A CR or LF in an address
/// the API substituted would be a further command injected into an
/// authenticated upstream session.
pub fn assert_relayable(address: &str) -> Result<(), RelayError> {
    let ok = address
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && b != b'<' && b != b'>');
    if ok {
        Ok(())
    } else {
        Err(RelayError::Address(address.to_string()))
    }
}

/// RFC 3461 5.2.2: a relay whose next hop does not support DSN must issue
/// the notification itself. We cannot, so the parameters are dropped with
/// a warning rather than risking the delivery.
pub fn dsn_suffix(params: &[Param], keep: fn(&str) -> bool, upstream_dsn: bool) -> String {
    let wanted: Vec<&Param> = params.iter().filter(|p| keep(&p.keyword)).collect();
    if wanted.is_empty() {
        return String::new();
    }
    if !upstream_dsn {
        let names: Vec<String> = wanted
            .iter()
            .map(|p| p.keyword.to_ascii_uppercase())
            .collect();
        warn!(
            "Upstream does not announce DSN; dropping {}",
            names.join(", ")
        );
        return String::new();
    }
    wanted
        .iter()
        .map(|p| match &p.value {
            Some(v) => format!(" {}={v}", p.keyword),
            None => format!(" {}", p.keyword),
        })
        .collect()
}

/// The client's own `SIZE=` on MAIL FROM, passed through so the upstream can
/// refuse an oversized message before a single body byte is transferred.
///
/// Guarded on the announcement for the same reason `dsn_suffix` is: an
/// upstream that never offered SIZE answers `555` to the parameter, turning
/// a deliverable message into a rejected one.
pub fn size_suffix(params: &[Param], upstream_announces_size: bool) -> String {
    let Some(size) = params
        .iter()
        .find(|p| p.keyword.eq_ignore_ascii_case("SIZE"))
        .and_then(|p| p.value.as_deref())
    else {
        return String::new();
    };
    if !upstream_announces_size {
        warn!("Upstream does not announce SIZE; dropping SIZE={size}");
        return String::new();
    }
    format!(" SIZE={size}")
}

/// The name in every EHLO and HELO this proxy sends upstream.
///
/// `Mojo::SMTP::Client` has `has hello => 'localhost.localdomain'`
/// (`Client.pm:54`) and only ever supplies that default (`Client.pm:134`);
/// neither `_relayMail` nor `probeUpstream` passes a `hello` of its own, so
/// every greeting the Perl proxy ever sent carried this name. Sending the
/// machine's hostname instead would be refused by any upstream that
/// allow-lists the greeting name -- and in the `FROM scratch` image that
/// hostname is whatever the container runtime invented.
const HELLO: &str = "localhost.localdomain";

/// The transport is a trait object for two reasons. STARTTLS replaces it in
/// the middle of a session, and the timing tests drive a whole relay session
/// through `tokio::io::duplex`, where the number of bytes that fit in flight
/// is one the test chose rather than one the host's TCP buffers decided.
/// `server::session` carries the same seam for the client side.
///
/// This is the connection *before* a transaction: the greeting, EHLO with its
/// HELO fallback, the STARTTLS upgrade, and the QUIT a probe ends on. It is
/// deliberately *not* split, because the upgrade replaces the stream wholesale
/// (`mem::replace` then `into_inner`) and a `split` cannot be undone without
/// both halves back in hand. Reads and writes strictly alternate at this
/// stage, so buffering the read side only and writing through costs nothing.
///
/// Once the handshake is done, [`UpstreamSession::from_handshake`] takes the
/// stream apart and everything after that runs on the split form.
struct Upstream {
    stream: BufReader<Box<dyn Io>>,
    timeout: Duration,
}

/// The read half of a driven session, with whatever the handshake's
/// `BufReader` had already pulled off the socket put back in front of it.
type SessionReader = BufReader<Chain<Cursor<Vec<u8>>, ReadHalf<Box<dyn Io>>>>;

/// A connection past its handshake, driven one step at a time by the caller:
/// MAIL/RCPT/DATA, then the body in as many pieces as it likes, then the
/// terminator and the upstream's verdict.
///
/// Unlike `Upstream` the stream is split in two, so that a blocked body
/// write and a read of the upstream's reply can be awaited *at the same time*
/// -- an upstream that refuses a message mid-transfer stops draining the
/// write, and noticing that means watching both halves at once. Splitting is
/// only safe once the STARTTLS upgrade is behind us.
pub struct UpstreamSession {
    reader: SessionReader,
    writer: WriteHalf<Box<dyn Io>>,
    timeout: Duration,
    caps: UpstreamCaps,
    /// The last byte handed to [`UpstreamSession::write`], so that `finish`
    /// knows whether the body already ends in a newline. `transact` used to
    /// see the whole payload at once and could just look at it.
    last_written: Option<u8>,
}

/// What the upstream did, when it did something other than accept.
///
/// During DATA the proxy mirrors the upstream, so this is the whole
/// vocabulary a caller needs: either the upstream said something, which is
/// relayed verbatim, or the connection died, which has nothing to relay. An
/// upstream that has merely gone quiet joins the second group once the
/// inactivity timer fires -- mirroring "hangs forever" would leak a
/// connection per hung upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamVerdict {
    Dropped,
    Replied { code: u16, text: String },
}

impl UpstreamVerdict {
    /// What the upstream said, in a form the client can actually be told.
    ///
    /// During DATA this verdict is mirrored straight at the client
    /// (`server::session`, `fn mirror` and `fn conclude`), and
    /// [`crate::smtp::reply::Reply::wire`] **panics** on a code outside
    /// `200..=599` -- the session task would die and the client would be
    /// answered nothing at all. A reply code is three digits an upstream
    /// chose, `000` to `999`, so this constructor is the only thing between
    /// those digits and that panic. **Every `Replied` built from an upstream
    /// reply has to come through here.**
    ///
    /// The bound is `400..600` rather than the wider sendable range for the
    /// reason [`RelayError::client_code`] gives, and to the same `451`: a 2xx
    /// or 3xx mid-DATA is not a refusal at all, and relaying it would answer
    /// the client `250` for a message nobody accepted. The upstream's text is
    /// kept either way -- it is the only account of what happened.
    fn replied(code: u16, text: String) -> Self {
        UpstreamVerdict::Replied {
            code: if (400..600).contains(&code) {
                code
            } else {
                451
            },
            text,
        }
    }

    /// `command` is the step that was in flight, and it is the caller's to
    /// name: the body and the terminator are two different failures to an
    /// operator reading a log, and only the caller knows which one it drove.
    ///
    /// It reaches a log on the `Dropped` road alone. A `Replied` upstream
    /// becomes `Rejected`, whose whole rendering is the upstream's own reply
    /// text -- that is the Perl's `Mail refused by relay server ($error)`
    /// line, and `$error` there stringifies to the text and nothing else.
    /// So there is no slot to put the step in without diverging, and
    /// `Rejected` deliberately does not carry one.
    pub fn into_relay_error(self, command: &'static str) -> RelayError {
        match self {
            // Deliberately vague about *how* the upstream was lost, because
            // `Dropped` is reached by more than one road and naming only one
            // of them would be a false log line. A connection that really
            // closed, one that went silent until the inactivity timer fired,
            // and one that answered something unparseable or endless all
            // arrive here, and this is the line an operator reads to decide
            // whether to suspect the network or the peer.
            UpstreamVerdict::Dropped => RelayError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!(
                    "lost the upstream during {command}: it stopped reading, closed the connection, or answered unintelligibly"
                ),
            )),
            UpstreamVerdict::Replied { code, text } => RelayError::Rejected { code, text },
        }
    }
}

struct UpstreamReply {
    code: u16,
    /// Text of every line, without the codes, joined with "\n".
    text: String,
    /// Every line as it arrived, codes and terminators included, which is
    /// what `parse_extensions` needs to see.
    raw: String,
}

/// Reads one reply, however many lines it spans, under the inactivity
/// timeout and under both byte caps.
///
/// Free rather than a method because both session forms need it and their
/// readers are different types: `BufReader<Box<dyn Io>>` before the split,
/// [`SessionReader`] after it.
async fn read_reply<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
) -> Result<UpstreamReply, RelayError> {
    let mut raw = String::new();
    let mut texts = Vec::new();
    loop {
        let mut line = String::new();
        // `take` borrows the reader, so the budget is re-applied per line
        // rather than one `Take` being held across the loop -- which is
        // also what makes it a per-line cap and not a per-reply one.
        let n = tokio::time::timeout(
            timeout,
            (&mut *reader)
                .take(MAX_REPLY_LINE as u64)
                .read_line(&mut line),
        )
        .await
        .map_err(|_| RelayError::Timeout)??;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "upstream closed the connection",
            )
            .into());
        }
        // A line that spent its whole budget without reaching a newline
        // has no end in sight. One that stopped short of the budget
        // ended at EOF instead, and is parsed as it always was.
        if !line.ends_with('\n') && line.len() >= MAX_REPLY_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("upstream reply line exceeds {MAX_REPLY_LINE} bytes"),
            )
            .into());
        }
        raw.push_str(&line);
        if raw.len() > MAX_REPLY_TOTAL {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("upstream reply exceeds {MAX_REPLY_TOTAL} bytes"),
            )
            .into());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let b = trimmed.as_bytes();
        if b.len() < 3 || !b[..3].iter().all(u8::is_ascii_digit) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unparseable upstream reply: {trimmed}"),
            )
            .into());
        }
        let code: u16 = trimmed[..3].parse().unwrap();
        texts.push(trimmed.get(4..).unwrap_or("").to_string());
        if b.len() == 3 || b[3] == b' ' {
            return Ok(UpstreamReply {
                code,
                text: texts.join("\n"),
                raw,
            });
        }
    }
}

/// Hands everything written so far to the transport, under the
/// inactivity timeout like every other step.
///
/// Not a formality on a TLS connection. `tokio_rustls`' `poll_write`
/// takes the plaintext into rustls' send buffer and then pushes as much
/// ciphertext at the socket as the socket will take; when the socket
/// blocks it still reports the plaintext as written
/// (`common/mod.rs:296-306`). So `write_all` can return `Ok` with the
/// tail of the message still sitting in rustls. Nothing on the read path
/// pushes it out -- `poll_fill_buf` only ever calls `read_io` -- so
/// without this flush a large message to a slow upstream would end with
/// the relay waiting for a `250` for bytes the upstream has not been
/// sent, until the inactivity timer turned a deliverable message into a
/// `550`. `server::session` flushes the client-facing leg for the same
/// reason.
async fn flush<W: AsyncWrite + Unpin>(writer: &mut W, timeout: Duration) -> Result<(), RelayError> {
    tokio::time::timeout(timeout, writer.flush())
        .await
        .map_err(|_| RelayError::Timeout)??;
    Ok(())
}

/// Writes a payload, restarting the inactivity timer for every chunk.
/// See [`WRITE_CHUNK`].
///
/// Every chunk is flushed before the next one is written, rather than
/// once at the end. On a TLS connection the leftovers of each chunk
/// would otherwise pile up in rustls' send buffer, which has no bound:
/// at the 1 GiB message cap a slow upstream could leave most of the
/// message in memory and then have to drain it all inside the single
/// timer of one final flush. Per chunk, what is in flight stays one
/// chunk and each flush gets its own timer, which is the inactivity
/// semantics [`WRITE_CHUNK`] describes.
async fn write_chunks<W: AsyncWrite + Unpin>(
    writer: &mut W,
    timeout: Duration,
    payload: &[u8],
) -> Result<(), RelayError> {
    for chunk in payload.chunks(WRITE_CHUNK) {
        tokio::time::timeout(timeout, writer.write_all(chunk))
            .await
            .map_err(|_| RelayError::Timeout)??;
        flush(writer, timeout).await?;
    }
    Ok(())
}

/// Writes one command line and pushes it out. A command is always shorter
/// than [`WRITE_CHUNK`], so this is a single timed write and its flush.
async fn send_command<W: AsyncWrite + Unpin>(
    writer: &mut W,
    timeout: Duration,
    line: &str,
) -> Result<(), RelayError> {
    debug!("upstream <- {line}");
    write_chunks(writer, timeout, format!("{line}\r\n").as_bytes()).await
}

/// Logs a reply and requires it to be in the class the command expected.
fn require_class(reply: UpstreamReply, expect_class: u16) -> Result<UpstreamReply, RelayError> {
    debug!(
        "upstream -> {} {}",
        reply.code,
        reply.text.replace('\n', " / ")
    );
    if reply.code / 100 != expect_class {
        return Err(RelayError::Rejected {
            code: reply.code,
            text: reply.text,
        });
    }
    Ok(reply)
}

impl Upstream {
    fn new(stream: Box<dyn Io>, timeout: Duration) -> Self {
        Self {
            stream: BufReader::new(stream),
            timeout,
        }
    }

    /// Writes a command and requires a reply in the given class.
    ///
    /// A method rather than a free function because `self.stream` is both the
    /// reader and the writer here: the two borrows have to be sequential, and
    /// inside a method they are.
    async fn command(
        &mut self,
        line: String,
        expect_class: u16,
    ) -> Result<UpstreamReply, RelayError> {
        send_command(&mut self.stream, self.timeout, &line).await?;
        let reply = read_reply(&mut self.stream, self.timeout).await?;
        require_class(reply, expect_class)
    }

    /// Greeting and EHLO (HELO fallback on 5xx), then STARTTLS if the mode
    /// asks for it. Returns the extension set -- the one from the EHLO
    /// inside TLS when the session was upgraded, because that is the only
    /// one that counts: an upstream may announce DSN, SIZE or AUTH only to
    /// a client that has authenticated the channel (RFC 3207 4.2 requires
    /// the client to discard what it learned before the handshake).
    async fn open(
        &mut self,
        tls: &UpstreamTls,
        server_name: &str,
    ) -> Result<Extensions, RelayError> {
        let greeting = read_reply(&mut self.stream, self.timeout).await?;
        if greeting.code / 100 != 2 {
            return Err(RelayError::Rejected {
                code: greeting.code,
                text: greeting.text,
            });
        }
        let mut extensions = match self.command(format!("EHLO {HELLO}"), 2).await {
            Ok(reply) => parse_extensions(&reply.raw),
            Err(RelayError::Rejected { code, .. }) if code / 100 == 5 => {
                self.command(format!("HELO {HELLO}"), 2).await?;
                Extensions::default()
            }
            Err(e) => return Err(e),
        };
        let want_tls = match tls.mode {
            // Implicit has handshaken before the greeting; Off never does.
            UpstreamTlsMode::Off | UpstreamTlsMode::Implicit => false,
            UpstreamTlsMode::Opportunistic => extensions.contains("STARTTLS"),
            UpstreamTlsMode::Required => {
                if !extensions.contains("STARTTLS") {
                    return Err(RelayError::NoStartTls);
                }
                true
            }
        };
        if want_tls {
            self.command("STARTTLS".into(), 2).await?;
            self.upgrade(tls, server_name).await?;
            extensions = parse_extensions(&self.command(format!("EHLO {HELLO}"), 2).await?.raw);
        }
        Ok(extensions)
    }

    /// The TLS handshake of STARTTLS, on a connection that has just been
    /// answered 220.
    async fn upgrade(&mut self, tls: &UpstreamTls, server_name: &str) -> Result<(), RelayError> {
        // Anything already buffered arrived before the handshake and would
        // be read as if it had come from inside it (RFC 3207 4.2). Dropping
        // it silently is how a plaintext injection survives an upgrade, so
        // the session ends instead.
        if !self.stream.buffer().is_empty() {
            return Err(RelayError::Tls(
                "the upstream sent data after its reply to STARTTLS".into(),
            ));
        }
        let placeholder: Box<dyn Io> = Box::new(tokio::io::empty());
        let plain = std::mem::replace(&mut self.stream, BufReader::new(placeholder)).into_inner();
        self.stream = BufReader::new(handshake(plain, tls, server_name, self.timeout).await?);
        Ok(())
    }

    async fn quit(&mut self) {
        let _ = self.command("QUIT".into(), 2).await;
    }
}

/// The rustls client handshake, under the inactivity timeout like every
/// other step of the session.
async fn handshake(
    stream: Box<dyn Io>,
    tls: &UpstreamTls,
    server_name: &str,
    timeout: Duration,
) -> Result<Box<dyn Io>, RelayError> {
    let client_config = tls
        .client_config
        .clone()
        .ok_or_else(|| RelayError::Tls("no TLS client configuration".into()))?;
    // `ServerName` takes an IP address as readily as a DNS name, so an
    // upstream given as `--tohost 10.0.0.5` is validated against the IP
    // addresses in the certificate rather than refused here.
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| RelayError::Tls(format!("invalid server name '{server_name}': {e}")))?;
    let stream = tokio::time::timeout(
        timeout,
        TlsConnector::from(client_config).connect(name, stream),
    )
    .await
    .map_err(|_| RelayError::Timeout)?
    .map_err(|e| RelayError::Tls(e.to_string()))?;
    Ok(Box::new(stream))
}

/// The TCP connection, with the implicit-TLS handshake already done when the
/// mode asks for it.
///
/// Named `dial` rather than `connect` so that a reader of
/// [`UpstreamSession::connect`] cannot mistake the call inside it for a
/// recursive `Self::connect`.
async fn dial(config: &RelayConfig) -> Result<Box<dyn Io>, RelayError> {
    let tcp = tokio::time::timeout(
        config.timeout,
        TcpStream::connect((config.host.as_str(), config.port)),
    )
    .await
    .map_err(|_| RelayError::Timeout)??;
    if config.tls.mode == UpstreamTlsMode::Implicit {
        handshake(
            Box::new(tcp),
            &config.tls,
            config.server_name(),
            config.timeout,
        )
        .await
    } else {
        Ok(Box::new(tcp))
    }
}

/// Everything before a transaction: the connection, the greeting and EHLO.
/// The one place all four entry points get an opened upstream from.
async fn greet(
    stream: Box<dyn Io>,
    timeout: Duration,
    tls: &UpstreamTls,
    server_name: &str,
) -> Result<(Upstream, UpstreamCaps), RelayError> {
    let mut up = Upstream::new(stream, timeout);
    let extensions = up.open(tls, server_name).await?;
    Ok((up, UpstreamCaps::of(&extensions)))
}

impl UpstreamSession {
    /// TCP (plus implicit TLS), then the greeting and EHLO -- everything
    /// before a transaction. [`caps`](Self::caps) is answerable from here on.
    pub async fn connect(config: &RelayConfig) -> Result<Self, RelayError> {
        let (up, caps) = greet(
            dial(config).await?,
            config.timeout,
            &config.tls,
            config.server_name(),
        )
        .await?;
        Ok(Self::from_handshake(up, caps))
    }

    /// [`connect`](Self::connect) over a stream the caller supplies, without
    /// TLS. See [`Io`].
    pub async fn over<S: Io + 'static>(stream: S, timeout: Duration) -> Result<Self, RelayError> {
        let (up, caps) = greet(Box::new(stream), timeout, &UpstreamTls::off(), "").await?;
        Ok(Self::from_handshake(up, caps))
    }

    /// Splits a handshaken [`Upstream`] into the two halves a driven session
    /// needs.
    ///
    /// Whatever the handshake's `BufReader` had already pulled off the socket
    /// is carried over in front of the read half. `into_inner` would otherwise
    /// drop those bytes silently and the protocol would desynchronise. They
    /// are ordinary pipelined data at this point, not the plaintext-injection
    /// hazard `upgrade` refuses at STARTTLS: the channel there is about to
    /// change, and here it is not.
    fn from_handshake(up: Upstream, caps: UpstreamCaps) -> Self {
        let timeout = up.timeout;
        let leftover = up.stream.buffer().to_vec();
        let (read_half, write_half) = tokio::io::split(up.stream.into_inner());
        Self {
            reader: BufReader::new(Cursor::new(leftover).chain(read_half)),
            writer: write_half,
            timeout,
            caps,
            last_written: None,
        }
    }

    /// What the upstream announced at the EHLO that counts.
    pub fn caps(&self) -> UpstreamCaps {
        self.caps
    }

    /// Writes a command and requires a reply in the given class. A method for
    /// symmetry with [`Upstream::command`], though here the two halves are
    /// separate fields.
    async fn command(
        &mut self,
        line: String,
        expect_class: u16,
    ) -> Result<UpstreamReply, RelayError> {
        send_command(&mut self.writer, self.timeout, &line).await?;
        let reply = read_reply(&mut self.reader, self.timeout).await?;
        require_class(reply, expect_class)
    }

    /// MAIL, every RCPT, then DATA. Returns once the upstream has answered
    /// `354` and the body may be written.
    pub async fn open_transaction(&mut self, envelope: Envelope<'_>) -> Result<(), RelayError> {
        let mail = format!(
            "MAIL FROM:<{}>{}{}",
            envelope.from,
            dsn_suffix(envelope.mail_params, is_mail_dsn_keyword, self.caps.dsn),
            size_suffix(envelope.mail_params, self.caps.size_announced),
        );
        self.command(mail, 2).await?;
        for r in envelope.recipients {
            let rcpt = format!(
                "RCPT TO:<{}>{}",
                r.address,
                dsn_suffix(&r.parameters, is_rcpt_dsn_keyword, self.caps.dsn)
            );
            self.command(rcpt, 2).await?;
        }
        self.command("DATA".into(), 3).await?;
        Ok(())
    }

    /// One piece of the body, already normalised and dot-stuffed by the
    /// caller. An empty piece writes nothing and leaves the record of the
    /// last byte alone, so that `write(b"")` cannot make `finish` believe the
    /// body ended in a newline it never saw.
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), UpstreamVerdict> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.last_written = chunk.last().copied();
        // Hoisted above the two field borrows below, so that the `async` block
        // in the `select!` does not have to capture `self` as well.
        let timeout = self.timeout;
        for piece in chunk.chunks(WRITE_CHUNK) {
            // An upstream may refuse mid-transfer, and one that refuses
            // usually stops reading. Writing blind would then fill the send
            // buffer and time out, reporting our own impatience instead of
            // its answer -- so both halves are awaited together and whichever
            // happens first wins. This is the whole reason the session holds
            // the stream split in two (`relay.rs`, `struct UpstreamSession`).
            //
            // What is raced is `fill_buf`, not `read_reply`. `read_reply`
            // accumulates a reply line by line and is not cancel safe, so
            // losing the race would lose a partial line. `fill_buf` is cancel
            // safe and consumes nothing: it fills the `BufReader`'s own buffer
            // and hands back a slice, and dropping it leaves those bytes right
            // where they are. So the `read_reply` below runs to completion,
            // uncancelled, with its per-line timers intact -- which is also
            // why a single `read_reply` future is not held across the loop
            // instead: its timer would then span the whole body transfer and
            // fire on a healthy but slow upstream.
            //
            // The write and its flush are raced *together*, as one step. On a
            // TLS connection the write is not where the transfer blocks at
            // all: `poll_write` reports the plaintext written as soon as it is
            // in rustls' send buffer, however little ciphertext the socket
            // took (see [`flush`]). Leaving the flush outside the race would
            // leave every TLS upstream exactly as blind as watching neither
            // half. The flush is per chunk and carries its own timer for the
            // reasons [`write_chunks`] gives; this loop is that loop with the
            // reader raced against it.
            let reader = &mut self.reader;
            let writer = &mut self.writer;
            let early = tokio::select! {
                pushed = async {
                    tokio::time::timeout(timeout, writer.write_all(piece))
                        .await
                        .map_err(|_| RelayError::Timeout)??;
                    flush(&mut *writer, timeout).await
                } => match pushed {
                    Err(_) => return Err(UpstreamVerdict::Dropped),
                    Ok(()) => false,
                },
                // The borrow of `reader` ends here: what leaves this branch is
                // a bool, never the slice `fill_buf` returned.
                ready = reader.fill_buf() => match ready {
                    Err(_) => return Err(UpstreamVerdict::Dropped),
                    // `Ok(&[])` is end of file, which `read_reply` turns into
                    // the same `Dropped` an error would.
                    Ok(_) => true,
                },
            };
            if early {
                return Err(match read_reply(&mut self.reader, timeout).await {
                    Ok(r) => UpstreamVerdict::replied(r.code, r.text),
                    Err(_) => UpstreamVerdict::Dropped,
                });
            }
        }
        Ok(())
    }

    /// The terminator, the upstream's verdict on the message, then QUIT.
    pub async fn finish(mut self) -> Result<String, UpstreamVerdict> {
        // RFC 5321 4.1.1.4: the terminator is a line of its own, so a body
        // that did not end in CRLF gets one first. `transact` used to make
        // this decision against the whole payload, which it still had in
        // hand; a driven session only remembers the last byte it wrote.
        // The test is on the LF alone because that is what SMTP frames on:
        // a body whose last byte is an LF has ended its line, whatever came
        // before it. The proxy's own framer (`server::data`, `struct
        // BodyFramer`) emits no bare LF at all, so there the two questions
        // are the same one.
        let tail: &[u8] = if self.last_written == Some(b'\n') {
            b".\r\n"
        } else {
            b"\r\n.\r\n"
        };
        if write_chunks(&mut self.writer, self.timeout, tail)
            .await
            .is_err()
        {
            return Err(UpstreamVerdict::Dropped);
        }
        let accepted = match read_reply(&mut self.reader, self.timeout).await {
            Ok(reply) => reply,
            Err(_) => return Err(UpstreamVerdict::Dropped),
        };
        if accepted.code / 100 != 2 {
            return Err(UpstreamVerdict::replied(accepted.code, accepted.text));
        }
        self.quit().await;
        Ok(accepted.text)
    }

    async fn quit(&mut self) {
        let _ = self.command("QUIT".into(), 2).await;
    }
}

/// EHLO + QUIT. Returns what the upstream announces.
///
/// Stays on the unsplit `Upstream`: a probe never writes a body, so it has
/// no use for the two halves a [`UpstreamSession`] hands out.
pub async fn probe(config: &RelayConfig) -> Result<UpstreamCaps, RelayError> {
    let (mut up, caps) = greet(
        dial(config).await?,
        config.timeout,
        &config.tls,
        config.server_name(),
    )
    .await?;
    up.quit().await;
    Ok(caps)
}

/// [`probe`] over a stream the caller supplies, without TLS. See
/// [`Io`].
pub async fn probe_over<S: Io + 'static>(
    stream: S,
    timeout: Duration,
) -> Result<UpstreamCaps, RelayError> {
    let (mut up, caps) = greet(Box::new(stream), timeout, &UpstreamTls::off(), "").await?;
    up.quit().await;
    Ok(caps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(k: &str, v: Option<&str>) -> Param {
        Param {
            keyword: k.into(),
            value: v.map(String::from),
        }
    }

    #[test]
    fn relayable_addresses() {
        assert!(assert_relayable("").is_ok());
        assert!(assert_relayable("a@b.com").is_ok());
        assert!(assert_relayable("a b@c.com").is_err());
        assert!(assert_relayable("a@b.com>").is_err());
        assert!(assert_relayable("a\r\nb").is_err());
        assert!(assert_relayable("caf\u{e9}@b.com").is_err());
    }

    #[test]
    fn suffix_keeps_only_dsn_keywords_and_only_with_dsn() {
        let params = [
            p("RET", Some("HDRS")),
            p("SIZE", Some("1")),
            p("envid", Some("Q")),
            p("NOTIFY", None),
        ];
        assert_eq!(
            dsn_suffix(&params, is_mail_dsn_keyword, true),
            " RET=HDRS envid=Q"
        );
        assert_eq!(dsn_suffix(&params, is_rcpt_dsn_keyword, true), " NOTIFY");
        assert_eq!(dsn_suffix(&params, is_mail_dsn_keyword, false), "");
    }

    #[test]
    fn size_suffix_forwards_the_clients_size_when_the_upstream_announces_size() {
        let params = [p("SIZE", Some("4096"))];
        assert_eq!(size_suffix(&params, true), " SIZE=4096");
    }

    #[test]
    fn size_suffix_drops_the_clients_size_when_the_upstream_is_silent() {
        let params = [p("SIZE", Some("4096"))];
        assert_eq!(size_suffix(&params, false), "");
    }

    /// RFC 1870's `SIZE 0` means "no fixed maximum", which `Extensions::size`
    /// deliberately folds into `None` alongside "SIZE absent" -- but the
    /// keyword was still announced, so forwarding a client's `SIZE=` is
    /// still safe (an upstream that never offered SIZE at all is the one
    /// that would answer 555). `UpstreamCaps::size_announced` is the field
    /// that keeps this case apart from an upstream that said nothing.
    #[test]
    fn size_suffix_is_forwarded_when_the_upstream_states_size_zero() {
        let extensions = parse_extensions("250-localhost\r\n250 SIZE 0\r\n");
        let caps = UpstreamCaps::of(&extensions);
        assert_eq!(caps.size, None);
        let params = [p("SIZE", Some("4096"))];
        assert_eq!(size_suffix(&params, caps.size_announced), " SIZE=4096");
    }

    #[test]
    fn size_suffix_ignores_a_bare_size_keyword_with_no_value() {
        let params = [p("SIZE", None)];
        assert_eq!(size_suffix(&params, true), "");
    }

    /// The value is forwarded as-is rather than parsed: the upstream is the
    /// one that will validate it, and a proxy that silently reinterprets or
    /// drops a malformed parameter risks masking what the client actually
    /// sent.
    #[test]
    fn size_suffix_forwards_a_non_numeric_value_verbatim() {
        let params = [p("SIZE", Some("abc"))];
        assert_eq!(size_suffix(&params, true), " SIZE=abc");
    }

    /// A client sending the same MAIL FROM parameter twice is malformed.
    /// `size_suffix` takes the first occurrence, unlike `dsn_suffix` (which
    /// forwards every matching parameter it finds) -- SIZE takes one value,
    /// not a list, so there is no second slot to put a duplicate in.
    #[test]
    fn size_suffix_uses_the_first_of_a_duplicated_size_parameter() {
        let params = [p("SIZE", Some("1")), p("SIZE", Some("2"))];
        assert_eq!(size_suffix(&params, true), " SIZE=1");
    }

    fn rejected(code: u16) -> RelayError {
        RelayError::Rejected {
            code,
            text: "text".into(),
        }
    }

    /// The upstream's code reaches the client as it was sent, not reduced to
    /// its class: a `452` stays a `452` and a `552` stays a `552`.
    #[test]
    fn a_rejection_keeps_the_upstream_code() {
        assert_eq!(rejected(451).client_code(), 451);
        assert_eq!(rejected(452).client_code(), 452);
        assert_eq!(rejected(550).client_code(), 550);
        assert_eq!(rejected(552).client_code(), 552);
    }

    /// Nothing the upstream said, so nothing to relay: the client is asked
    /// to come back rather than told the message was unacceptable. Our own
    /// address refusal is the exception -- it is permanent and it is ours.
    #[test]
    fn a_failure_without_an_upstream_code_is_transient() {
        let io = RelayError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(io.client_code(), 451);
        assert_eq!(RelayError::Timeout.client_code(), 451);
        assert_eq!(RelayError::Tls("bad".into()).client_code(), 451);
        assert_eq!(RelayError::NoStartTls.client_code(), 451);
        assert_eq!(RelayError::Address("a b".into()).client_code(), 550);
    }

    /// An upstream that answers a `250` where a `354` was required has not
    /// refused the message, it has broken the protocol. Relaying that code
    /// would tell the client the mail was accepted.
    #[test]
    fn a_reply_outside_the_rejection_range_does_not_become_the_clients_code() {
        assert_eq!(rejected(250).client_code(), 451);
        assert_eq!(rejected(354).client_code(), 451);
    }

    /// The exact edges of the pass-through range, because it is the only
    /// thing keeping an unsendable code away from the client. An off-by-one
    /// on either boundary is invisible in every other test here.
    #[test]
    fn the_pass_through_range_holds_at_its_edges() {
        assert_eq!(rejected(399).client_code(), 451);
        assert_eq!(rejected(400).client_code(), 400);
        assert_eq!(rejected(599).client_code(), 599);
        assert_eq!(rejected(600).client_code(), 451);
    }

    /// The invariant itself, asserted across the module boundary rather than
    /// only described in both: whatever three digits an upstream answers, the
    /// code handed to the client is one `smtp::reply` can put on the wire.
    /// Anything else panics the session task instead of replying.
    #[test]
    fn every_client_code_is_sendable() {
        for upstream in [0, 1, 199, 200, 250, 354, 399, 400, 451, 550, 599, 600, 999] {
            let code = rejected(upstream).client_code();
            assert!(
                crate::smtp::reply::format_reply(code, &["text"]).is_ok(),
                "an upstream {upstream} produced {code}, which cannot be sent"
            );
        }
    }
}
