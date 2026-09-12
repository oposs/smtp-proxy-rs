//! A minimal SMTP client for the upstream: one session per message.
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::api::Recipient;
use crate::smtp::dsn::{is_mail_dsn_keyword, is_rcpt_dsn_keyword};
use crate::smtp::extensions::parse_extensions;
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
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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
    Rejected {
        command: &'static str,
        code: u16,
        text: String,
    },
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

pub struct Envelope<'a> {
    pub from: &'a str,
    pub mail_params: &'a [Param],
    pub recipients: &'a [Recipient],
}

/// Outcome of a relayed message.
#[derive(Clone, Debug)]
pub struct Relayed {
    /// Text of the 250 reply to the final dot (the upstream queue id). A
    /// multi-line reply arrives here with its lines joined by `\n`;
    /// `smtp::reply::sanitize` folds those away before a client sees it.
    pub message: String,
    pub upstream_dsn: bool,
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

/// Rewrites every `\r?\n` to `\r\n` and doubles a dot that follows one
/// (RFC 5321 4.5.2), in a single pass. This is the Perl's
///
/// ```text
/// s/\015?\012(\.?)/\015\012$1$1/g
/// ```
///
/// (`Mojo/SMTP/Client.pm:517`) written out. The order matters: the Perl
/// decides the terminator from the *normalised* payload (`_has_nl`,
/// `Client.pm:594`), so a body that ends in a bare `\n` already ends in CRLF
/// by the time that decision is made and gains no extra blank line.
///
/// A dot at offset 0 is stuffed here where the Perl's non-coderef branch
/// leaves it alone. The two cannot differ in this proxy -- the payload
/// always begins with a header name or with the header/body blank line --
/// and RFC 5321 4.5.2 asks for the stuffing, so it stays.
pub fn normalize_and_stuff(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
    if message.first() == Some(&b'.') {
        out.push(b'.');
    }
    let mut i = 0;
    while i < message.len() {
        let eol = match message[i] {
            b'\n' => Some(1),
            b'\r' if message.get(i + 1) == Some(&b'\n') => Some(2),
            _ => None,
        };
        match eol {
            Some(len) => {
                out.extend_from_slice(b"\r\n");
                i += len;
                if message.get(i) == Some(&b'.') {
                    out.extend_from_slice(b"..");
                    i += 1;
                }
            }
            None => {
                out.push(message[i]);
                i += 1;
            }
        }
    }
    out
}

/// The message body is written in pieces of this size, each under its own
/// timer. Spec 6 gives the relay an *inactivity* timeout, so what has to
/// hold is "some progress within the timeout", not "the whole body within
/// the timeout": a single deadline over the payload would abort a healthy
/// but merely slow upstream, and at the default 1 GiB message cap it would
/// demand a sustained 17 MB/s. At 64 KiB a chunk the 60 s default asks the
/// upstream for about 1 KB/s, which no working relay fails.
const WRITE_CHUNK: usize = 64 * 1024;

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
/// Reads and writes are strictly alternating here, so the stream is buffered
/// on the read side only and written through -- and that is what makes the
/// STARTTLS upgrade possible at all, since a `split` cannot be undone
/// without both halves back in hand.
struct Upstream {
    stream: BufReader<Box<dyn Io>>,
    timeout: Duration,
}

struct UpstreamReply {
    code: u16,
    /// Text of every line, without the codes, joined with "\n".
    text: String,
    /// Every line as it arrived, codes and terminators included, which is
    /// what `parse_extensions` needs to see.
    raw: String,
}

impl Upstream {
    fn new(stream: Box<dyn Io>, timeout: Duration) -> Self {
        Self {
            stream: BufReader::new(stream),
            timeout,
        }
    }

    async fn read_reply(&mut self) -> Result<UpstreamReply, RelayError> {
        let mut raw = String::new();
        let mut texts = Vec::new();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(self.timeout, self.stream.read_line(&mut line))
                .await
                .map_err(|_| RelayError::Timeout)??;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "upstream closed the connection",
                )
                .into());
            }
            raw.push_str(&line);
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

    /// Writes a command and requires a reply in the given class.
    async fn command(
        &mut self,
        name: &'static str,
        line: String,
        expect_class: u16,
    ) -> Result<UpstreamReply, RelayError> {
        debug!("upstream <- {line}");
        tokio::time::timeout(
            self.timeout,
            self.stream.write_all(format!("{line}\r\n").as_bytes()),
        )
        .await
        .map_err(|_| RelayError::Timeout)??;
        self.flush().await?;
        let reply = self.read_reply().await?;
        debug!(
            "upstream -> {} {}",
            reply.code,
            reply.text.replace('\n', " / ")
        );
        if reply.code / 100 != expect_class {
            return Err(RelayError::Rejected {
                command: name,
                code: reply.code,
                text: reply.text,
            });
        }
        Ok(reply)
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
    ) -> Result<HashSet<String>, RelayError> {
        let greeting = self.read_reply().await?;
        if greeting.code / 100 != 2 {
            return Err(RelayError::Rejected {
                command: "CONNECT",
                code: greeting.code,
                text: greeting.text,
            });
        }
        let mut extensions = match self.command("EHLO", format!("EHLO {HELLO}"), 2).await {
            Ok(reply) => parse_extensions(&reply.raw),
            Err(RelayError::Rejected { code, .. }) if code / 100 == 5 => {
                self.command("HELO", format!("HELO {HELLO}"), 2).await?;
                HashSet::new()
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
            self.command("STARTTLS", "STARTTLS".into(), 2).await?;
            self.upgrade(tls, server_name).await?;
            extensions =
                parse_extensions(&self.command("EHLO", format!("EHLO {HELLO}"), 2).await?.raw);
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
    async fn flush(&mut self) -> Result<(), RelayError> {
        tokio::time::timeout(self.timeout, self.stream.flush())
            .await
            .map_err(|_| RelayError::Timeout)??;
        Ok(())
    }

    /// Writes the message body, restarting the inactivity timer for every
    /// chunk. See [`WRITE_CHUNK`].
    ///
    /// Every chunk is flushed before the next one is written, rather than
    /// once at the end. On a TLS connection the leftovers of each chunk
    /// would otherwise pile up in rustls' send buffer, which has no bound:
    /// at the 1 GiB message cap a slow upstream could leave most of the
    /// message in memory and then have to drain it all inside the single
    /// timer of one final flush. Per chunk, what is in flight stays one
    /// chunk and each flush gets its own timer, which is the inactivity
    /// semantics [`WRITE_CHUNK`] describes.
    async fn write_body(&mut self, payload: &[u8]) -> Result<(), RelayError> {
        for chunk in payload.chunks(WRITE_CHUNK) {
            tokio::time::timeout(self.timeout, self.stream.write_all(chunk))
                .await
                .map_err(|_| RelayError::Timeout)??;
            self.flush().await?;
        }
        Ok(())
    }

    async fn quit(&mut self) {
        let _ = self.command("QUIT", "QUIT".into(), 2).await;
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
async fn connect(config: &RelayConfig) -> Result<Box<dyn Io>, RelayError> {
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

/// EHLO + QUIT. Returns whether the upstream announces DSN.
pub async fn probe(config: &RelayConfig) -> Result<bool, RelayError> {
    let mut up = Upstream::new(connect(config).await?, config.timeout);
    let extensions = up.open(&config.tls, config.server_name()).await?;
    up.quit().await;
    Ok(extensions.contains("DSN"))
}

/// [`probe`] over a stream the caller supplies, without TLS. See
/// [`Upstream`].
pub async fn probe_over<S: Io + 'static>(stream: S, timeout: Duration) -> Result<bool, RelayError> {
    let mut up = Upstream::new(Box::new(stream), timeout);
    let extensions = up.open(&UpstreamTls::off(), "").await?;
    up.quit().await;
    Ok(extensions.contains("DSN"))
}

/// A whole session: EHLO, MAIL, RCPT.., DATA, message, QUIT.
pub async fn relay(
    config: &RelayConfig,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    // Before the connection, so that an address the API substituted cannot
    // even cost a TCP handshake.
    assert_relayable(envelope.from)?;
    for r in envelope.recipients {
        assert_relayable(&r.address)?;
    }
    let mut up = Upstream::new(connect(config).await?, config.timeout);
    let extensions = up.open(&config.tls, config.server_name()).await?;
    transact(up, extensions, envelope, message).await
}

/// [`relay`] over a stream the caller supplies, without TLS. See
/// [`Upstream`].
pub async fn relay_over<S: Io + 'static>(
    stream: S,
    timeout: Duration,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    assert_relayable(envelope.from)?;
    for r in envelope.recipients {
        assert_relayable(&r.address)?;
    }
    let mut up = Upstream::new(Box::new(stream), timeout);
    let extensions = up.open(&UpstreamTls::off(), "").await?;
    transact(up, extensions, envelope, message).await
}

/// Everything after the greeting: MAIL, RCPT.., DATA, message, QUIT.
async fn transact(
    mut up: Upstream,
    extensions: HashSet<String>,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    let upstream_dsn = extensions.contains("DSN");
    let mail = format!(
        "MAIL FROM:<{}>{}",
        envelope.from,
        dsn_suffix(envelope.mail_params, is_mail_dsn_keyword, upstream_dsn)
    );
    up.command("MAIL", mail, 2).await?;
    for r in envelope.recipients {
        let rcpt = format!(
            "RCPT TO:<{}>{}",
            r.address,
            dsn_suffix(&r.parameters, is_rcpt_dsn_keyword, upstream_dsn)
        );
        up.command("RCPT", rcpt, 2).await?;
    }
    up.command("DATA", "DATA".into(), 3).await?;
    let mut payload = normalize_and_stuff(message);
    if !payload.ends_with(b"\r\n") {
        payload.extend_from_slice(b"\r\n");
    }
    payload.extend_from_slice(b".\r\n");
    up.write_body(&payload).await?;
    let accepted = up.read_reply().await?;
    if accepted.code / 100 != 2 {
        return Err(RelayError::Rejected {
            command: "DATA_END",
            code: accepted.code,
            text: accepted.text,
        });
    }
    up.quit().await;
    Ok(Relayed {
        message: accepted.text,
        upstream_dsn,
    })
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
    fn dot_stuffing_on_the_way_out() {
        assert_eq!(
            normalize_and_stuff(b"a\r\n.\r\n..x\r\n"),
            b"a\r\n..\r\n...x\r\n"
        );
        assert_eq!(normalize_and_stuff(b".start"), b"..start");
        assert_eq!(normalize_and_stuff(b"no dots\r\n"), b"no dots\r\n");
    }

    /// The Perl's one regex does both jobs, so a bare LF never reaches the
    /// upstream and a dot behind one is stuffed just the same.
    #[test]
    fn bare_lf_is_normalised_on_the_way_out() {
        assert_eq!(normalize_and_stuff(b"a\nb\n"), b"a\r\nb\r\n");
        assert_eq!(normalize_and_stuff(b"a\n.b\n"), b"a\r\n..b\r\n");
        assert_eq!(normalize_and_stuff(b"a\r\nb\n.\r\n"), b"a\r\nb\r\n..\r\n");
        // A lone CR is not a line ending: `\015?\012` needs the LF.
        assert_eq!(normalize_and_stuff(b"a\rb"), b"a\rb");
        assert_eq!(normalize_and_stuff(b"a\r\r\n"), b"a\r\r\n");
        assert_eq!(normalize_and_stuff(b""), b"");
    }
}
