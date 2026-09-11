//! A minimal SMTP client for the upstream: one session per message.
use std::collections::HashSet;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, warn};

use crate::api::Recipient;
use crate::smtp::dsn::{is_mail_dsn_keyword, is_rcpt_dsn_keyword};
use crate::smtp::extensions::parse_extensions;
use crate::smtp::params::Param;

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub host: String,
    pub port: u16,
    /// Perl: 60 s inactivity.
    pub timeout: Duration,
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
}

pub struct Envelope<'a> {
    pub from: &'a str,
    pub mail_params: &'a [Param],
    pub recipients: &'a [Recipient],
}

/// Outcome of a relayed message.
#[derive(Clone, Debug)]
pub struct Relayed {
    /// Text of the 250 reply to the final dot (the upstream queue id).
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

/// Doubles a leading dot on every line (RFC 5321 4.5.2).
pub fn dot_stuff(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
    let mut at_line_start = true;
    for &b in message {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
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

struct Upstream {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
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
    async fn connect(config: &RelayConfig) -> Result<Self, RelayError> {
        let stream = tokio::time::timeout(
            config.timeout,
            TcpStream::connect((config.host.as_str(), config.port)),
        )
        .await
        .map_err(|_| RelayError::Timeout)??;
        let (r, w) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(r),
            writer: w,
            timeout: config.timeout,
        })
    }

    async fn read_reply(&mut self) -> Result<UpstreamReply, RelayError> {
        let mut raw = String::new();
        let mut texts = Vec::new();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(self.timeout, self.reader.read_line(&mut line))
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
            self.writer.write_all(format!("{line}\r\n").as_bytes()),
        )
        .await
        .map_err(|_| RelayError::Timeout)??;
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

    /// Greeting and EHLO (HELO fallback on 5xx). Returns the extension set.
    async fn open(&mut self) -> Result<HashSet<String>, RelayError> {
        let greeting = self.read_reply().await?;
        if greeting.code / 100 != 2 {
            return Err(RelayError::Rejected {
                command: "CONNECT",
                code: greeting.code,
                text: greeting.text,
            });
        }
        let host = local_hostname();
        match self.command("EHLO", format!("EHLO {host}"), 2).await {
            Ok(reply) => Ok(parse_extensions(&reply.raw)),
            Err(RelayError::Rejected { code, .. }) if code / 100 == 5 => {
                self.command("HELO", format!("HELO {host}"), 2).await?;
                Ok(HashSet::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Writes the message body, restarting the inactivity timer for every
    /// chunk. See [`WRITE_CHUNK`].
    async fn write_body(&mut self, payload: &[u8]) -> Result<(), RelayError> {
        for chunk in payload.chunks(WRITE_CHUNK) {
            tokio::time::timeout(self.timeout, self.writer.write_all(chunk))
                .await
                .map_err(|_| RelayError::Timeout)??;
        }
        Ok(())
    }

    async fn quit(&mut self) {
        let _ = self.command("QUIT", "QUIT".into(), 2).await;
    }
}

fn local_hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".into())
}

/// EHLO + QUIT. Returns whether the upstream announces DSN.
pub async fn probe(config: &RelayConfig) -> Result<bool, RelayError> {
    let mut up = Upstream::connect(config).await?;
    let extensions = up.open().await?;
    up.quit().await;
    Ok(extensions.contains("DSN"))
}

/// A whole session: EHLO, MAIL, RCPT.., DATA, message, QUIT.
pub async fn relay(
    config: &RelayConfig,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    assert_relayable(envelope.from)?;
    for r in envelope.recipients {
        assert_relayable(&r.address)?;
    }
    let mut up = Upstream::connect(config).await?;
    let extensions = up.open().await?;
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
    let mut payload = dot_stuff(message);
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
        assert_eq!(dot_stuff(b"a\r\n.\r\n..x\r\n"), b"a\r\n..\r\n...x\r\n");
        assert_eq!(dot_stuff(b".start"), b"..start");
        assert_eq!(dot_stuff(b"no dots\r\n"), b"no dots\r\n");
    }
}
