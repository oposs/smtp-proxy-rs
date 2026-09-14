//! A line-level SMTP client for the tests, ported from `RawSMTPClient.pm`.
//! It speaks the wire protocol by hand so that a test can pipeline, send a
//! malformed line, or hang up in the middle of a message.
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The transport seam and the permissive verifier both live in the relay,
/// which needs them for the upstream leg; the tests use the very same ones
/// rather than a second copy that could drift.
pub use smtp_proxy::relay::{Io, NoVerify};

pub struct RawClient {
    stream: Box<dyn Io>,
    buf: Vec<u8>,
}

impl RawClient {
    /// Connects and returns the client together with the 220 greeting.
    pub async fn connect(addr: SocketAddr) -> (Self, String) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut c = Self {
            stream: Box::new(stream),
            buf: Vec::new(),
        };
        let greeting = c.read_reply().await;
        (c, greeting)
    }

    pub async fn command(&mut self, line: &str) -> String {
        self.write_raw(&format!("{line}\r\n")).await;
        self.read_reply().await
    }

    pub async fn write_raw(&mut self, data: &str) {
        self.stream.write_all(data.as_bytes()).await.unwrap();
    }

    /// Reads until a line whose code is followed by a space. Panics after 30 s.
    pub async fn read_reply(&mut self) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if let Some(end) = complete_reply_len(&self.buf) {
                    return String::from_utf8(self.buf.drain(..end).collect()).unwrap();
                }
                let mut chunk = [0u8; 4096];
                let n = self.stream.read(&mut chunk).await.unwrap();
                assert!(
                    n > 0,
                    "connection closed before a reply arrived; buffer: {:?}",
                    String::from_utf8_lossy(&self.buf)
                );
                self.buf.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .expect("timed out waiting for a reply")
    }

    /// Returns true if the server closed the connection without sending more.
    /// Strict on purpose: a server that leaks stray bytes before closing
    /// must fail this check, so the QUIT-close and line-too-long-close
    /// callers keep their original guarantee.
    pub async fn expect_close(&mut self) -> bool {
        let mut chunk = [0u8; 64];
        matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.stream.read(&mut chunk)
            )
            .await,
            Ok(Ok(0))
        )
    }

    /// Like `expect_close`, but for the one case where trailing bytes are
    /// legitimate: after a failed TLS handshake, tokio-rustls 0.26.5 does a
    /// "last-gasp write" that flushes a fatal alert before the handshake
    /// error reaches the caller, so the next read yields alert bytes, not
    /// an immediate EOF. This drains whatever arrives (discarding it) until
    /// EOF, a reset, or the timeout. It is deliberately not used for a
    /// clean-close case: it cannot distinguish a legitimate TLS alert from
    /// any other stray byte the server might leak, so it must not replace
    /// the strict `expect_close` there.
    pub async fn expect_close_after_failed_handshake(&mut self) -> bool {
        let mut chunk = [0u8; 4096];
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match self.stream.read(&mut chunk).await {
                    Ok(0) => return true,
                    Ok(_) => continue,
                    Err(_) => return true,
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    pub async fn auth_plain(&mut self, username: &str, password: &str) -> String {
        use base64::Engine;
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{password}"));
        self.command(&format!("AUTH PLAIN {token}")).await
    }

    /// Sends STARTTLS, expects 220, upgrades.
    pub async fn starttls(&mut self) {
        let reply = self.command("STARTTLS").await;
        assert!(reply.starts_with("220"), "{reply}");
        self.upgrade().await;
    }

    /// The TLS half of STARTTLS on its own, for tests that send the command
    /// by hand (pipelining a command behind it, for instance).
    pub async fn upgrade(&mut self) {
        self.upgrade_with_versions(rustls::DEFAULT_VERSIONS).await;
    }

    /// Like `upgrade`, but restricted to TLS 1.2, to prove the server's
    /// floor protocol version still handshakes (spec 11.2).
    pub async fn upgrade_tls12(&mut self) {
        self.upgrade_with_versions(&[&rustls::version::TLS12]).await;
    }

    async fn upgrade_with_versions(
        &mut self,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let plain = std::mem::replace(&mut self.stream, Box::new(tokio::io::empty()));
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = connector.connect(name, plain).await.unwrap();
        self.stream = Box::new(tls);
        self.buf.clear();
    }

    /// Full session setup for proxy tests: EHLO, STARTTLS, EHLO, AUTH PLAIN.
    pub async fn login(&mut self, username: &str, password: &str) {
        assert!(
            self.command("EHLO client.example.com")
                .await
                .starts_with("250")
        );
        self.starttls().await;
        assert!(
            self.command("EHLO client.example.com")
                .await
                .starts_with("250")
        );
        let r = self.auth_plain(username, password).await;
        assert!(r.starts_with("235"), "{r}");
    }
}

fn complete_reply_len(buf: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let nl = buf[pos..].iter().position(|b| *b == b'\n')? + pos + 1;
        let line = &buf[pos..nl];
        if line.len() >= 4 && line[..3].iter().all(u8::is_ascii_digit) && line[3] == b' ' {
            return Some(nl);
        }
        pos = nl;
    }
}
