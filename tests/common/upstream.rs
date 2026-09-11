//! A recording SMTP server to relay against, ported from the Perl
//! `RecordingSMTPServer.pm`.
//!
//! Recording is **per connection**, and the two command accessors span
//! deliberately different scopes:
//!
//! - [`RecordingUpstream::commands`] returns the transcript of the *latest*
//!   connection only, so index assertions such as `commands()[1]` stay
//!   stable no matter how many messages were relayed before.
//! - [`RecordingUpstream::commands_matching`] flattens *every* connection
//!   since the last [`RecordingUpstream::clear`], so a test that relays two
//!   messages over two connections sees both.
//!
//! A test that asserts a count therefore has to say which one it means: two
//! probes leave `commands_matching("QUIT").len() == 2` but `commands()`
//! holding a single QUIT.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct RecordingUpstream {
    /// Where a TCP client reaches this upstream. `127.0.0.1:0` for an
    /// [`RecordingUpstream::in_memory`] one, which has no listener at all.
    pub addr: SocketAddr,
    inner: Arc<Mutex<Inner>>,
}

/// One transcript per connection. Each is handed to its connection task as
/// its own handle, so `clear()` can drop the list without disturbing a
/// session that is still running.
type Transcript = Arc<Mutex<Vec<String>>>;

struct Inner {
    extensions: Vec<String>,
    connections: Vec<Transcript>,
    /// Exactly the bytes the relay wrote between `354` and the terminating
    /// dot, dot-stuffing and line endings included. Recorded verbatim: a
    /// fake that re-normalises what it stores cannot see a relay that fails
    /// to normalise what it sends.
    messages: Vec<Vec<u8>>,
    /// Reply to EHLO with this 5xx text instead of the extension list, so
    /// the HELO fallback can be reached.
    reject_ehlo: Option<String>,
    /// Reply to MAIL FROM with this 5xx text instead of 250.
    reject_mail: Option<String>,
    /// Reply to the final dot with this text after `250 `.
    accept_text: String,
    /// Stop reading for this long right after `354`, before taking a single
    /// byte of the body: an upstream that has gone away mid-transfer.
    data_stall: Option<Duration>,
    /// While reading the body, pause for `pause` after every `bytes`
    /// consumed, at most `times` times: an upstream that accepts the body
    /// slowly but steadily. Once the socket buffers fill, the relay's writes
    /// block until the next drain, which is what makes the difference
    /// between an inactivity timer and a whole-payload deadline observable.
    ///
    /// `times` is what keeps such a test honest. When the relay's last write
    /// returns, megabytes are still sitting unread in the socket buffers,
    /// and the relay is by then waiting for the `250` under a *single*
    /// timer. Pacing that tail would put a run of pauses inside that one
    /// wait and time it out for a reason the test does not mean to
    /// exercise. So a test paces an early prefix of the body only, and picks
    /// a body several times bigger than the buffers can hold, which puts
    /// every pause safely inside the transfer.
    data_pace: Option<(usize, Duration, usize)>,
}

impl Inner {
    fn new(extensions: &[&str]) -> Self {
        Self {
            extensions: extensions.iter().map(|s| s.to_string()).collect(),
            connections: Vec::new(),
            messages: Vec::new(),
            reject_ehlo: None,
            reject_mail: None,
            accept_text: "OK message accepted".into(),
            data_stall: None,
            data_pace: None,
        }
    }
}

impl RecordingUpstream {
    pub async fn start(extensions: &[&str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let inner = Arc::new(Mutex::new(Inner::new(extensions)));
        let state = inner.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_one(stream, state.clone()));
            }
        });
        Self { addr, inner }
    }

    /// An upstream with no listener, reached only through
    /// [`RecordingUpstream::connect_duplex`].
    pub fn in_memory(extensions: &[&str]) -> Self {
        Self {
            addr: "127.0.0.1:0".parse().unwrap(),
            inner: Arc::new(Mutex::new(Inner::new(extensions))),
        }
    }

    /// A connection carried by `tokio::io::duplex` rather than by TCP: at
    /// most `capacity` bytes sit in flight before a write blocks, which is
    /// what makes a write-side timing test deterministic. The kernel's
    /// socket buffers are tuned per host and can swallow tens of megabytes,
    /// so a TCP-backed timing test is at their mercy.
    pub fn connect_duplex(&self, capacity: usize) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(capacity);
        tokio::spawn(serve_one(server, self.inner.clone()));
        client
    }

    /// The transcript of the latest connection only.
    pub fn commands(&self) -> Vec<String> {
        match self.inner.lock().unwrap().connections.last() {
            Some(transcript) => transcript.lock().unwrap().clone(),
            None => Vec::new(),
        }
    }

    /// Every command starting with `prefix`, across all connections since
    /// the last `clear()`.
    pub fn commands_matching(&self, prefix: &str) -> Vec<String> {
        let connections = self.inner.lock().unwrap().connections.clone();
        connections
            .iter()
            .flat_map(|transcript| transcript.lock().unwrap().clone())
            .filter(|c| c.starts_with(prefix))
            .collect()
    }

    /// Every message as text. Lossy, so an assertion about the exact bytes
    /// of a line ending belongs on [`RecordingUpstream::raw_messages`].
    pub fn messages(&self) -> Vec<String> {
        self.raw_messages()
            .iter()
            .map(|m| String::from_utf8_lossy(m).into_owned())
            .collect()
    }

    /// Every message exactly as it came off the wire.
    pub fn raw_messages(&self) -> Vec<Vec<u8>> {
        self.inner.lock().unwrap().messages.clone()
    }

    pub fn set_extensions(&self, extensions: &[&str]) {
        self.inner.lock().unwrap().extensions = extensions.iter().map(|s| s.to_string()).collect();
    }

    pub fn reject_ehlo(&self, text: Option<&str>) {
        self.inner.lock().unwrap().reject_ehlo = text.map(String::from);
    }

    pub fn reject_mail(&self, text: Option<&str>) {
        self.inner.lock().unwrap().reject_mail = text.map(String::from);
    }

    pub fn accept_text(&self, text: &str) {
        self.inner.lock().unwrap().accept_text = text.into();
    }

    /// Read nothing at all for `pause` after answering `354`.
    pub fn stall_data(&self, pause: Duration) {
        self.inner.lock().unwrap().data_stall = Some(pause);
    }

    /// Consume the body in steps of `bytes`, pausing for `pause` between
    /// them, for the first `times` steps only. See `Inner::data_pace` for
    /// why the pacing has to stop before the body does.
    pub fn pace_data(&self, bytes: usize, pause: Duration, times: usize) {
        self.inner.lock().unwrap().data_pace = Some((bytes, pause, times));
    }

    /// Drops every recorded connection and message. The startup probe's own
    /// EHLO and QUIT would otherwise shift every later command index.
    pub fn clear(&self) {
        let mut i = self.inner.lock().unwrap();
        i.connections.clear();
        i.messages.clear();
    }
}

/// Generic over the transport so the same recording server can be reached
/// over TCP or over a `tokio::io::duplex` pair.
async fn serve_one<S: AsyncRead + AsyncWrite + Send + 'static>(
    stream: S,
    state: Arc<Mutex<Inner>>,
) {
    let transcript: Transcript = Arc::new(Mutex::new(Vec::new()));
    state.lock().unwrap().connections.push(transcript.clone());
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    if w.write_all(b"220 recording.upstream ESMTP ready\r\n")
        .await
        .is_err()
    {
        return;
    }
    let mut in_data = false;
    let mut message: Vec<u8> = Vec::new();
    let mut since_pause = 0usize;
    let mut pauses_done = 0usize;
    let mut stall_after_reply: Option<Duration> = None;
    loop {
        // `read_until` rather than `lines()`: the body has to be recorded
        // byte for byte, terminators included.
        let mut raw: Vec<u8> = Vec::new();
        match reader.read_until(b'\n', &mut raw).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if in_data {
            // CRLF only. A fake that ended on `.\n` as well would accept a
            // relay that had stopped normalising its line endings, which is
            // the very defect this byte-exact recording exists to catch.
            if raw == b".\r\n" {
                in_data = false;
                since_pause = 0;
                pauses_done = 0;
                let text = {
                    let mut s = state.lock().unwrap();
                    s.messages.push(std::mem::take(&mut message));
                    s.accept_text.clone()
                };
                if w.write_all(format!("250 {text}\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
            } else {
                since_pause += raw.len();
                message.extend_from_slice(&raw);
                let pace = state.lock().unwrap().data_pace;
                if let Some((bytes, pause, times)) = pace
                    && pauses_done < times
                    && since_pause >= bytes
                {
                    since_pause = 0;
                    pauses_done += 1;
                    tokio::time::sleep(pause).await;
                }
            }
            continue;
        }
        let line = String::from_utf8_lossy(&raw)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        transcript.lock().unwrap().push(line.clone());
        let upper = line.to_ascii_uppercase();
        let reply = if upper.starts_with("EHLO") {
            let (rejection, ext) = {
                let s = state.lock().unwrap();
                (s.reject_ehlo.clone(), s.extensions.clone())
            };
            if let Some(text) = rejection {
                format!("500 {text}\r\n")
            } else {
                let mut r = String::from("250-recording.upstream\r\n");
                for (i, e) in ext.iter().enumerate() {
                    let sep = if i + 1 == ext.len() { ' ' } else { '-' };
                    r.push_str(&format!("250{sep}{e}\r\n"));
                }
                if ext.is_empty() {
                    r.push_str("250 HELP\r\n");
                }
                r
            }
        } else if upper.starts_with("MAIL") {
            let rejection = state.lock().unwrap().reject_mail.clone();
            match rejection {
                Some(text) => format!("553 {text}\r\n"),
                None => "250 OK\r\n".into(),
            }
        } else if upper.starts_with("HELO")
            || upper.starts_with("RCPT")
            || upper.starts_with("RSET")
            || upper.starts_with("NOOP")
        {
            "250 OK\r\n".into()
        } else if upper.starts_with("DATA") {
            in_data = true;
            stall_after_reply = state.lock().unwrap().data_stall;
            "354 Go ahead\r\n".into()
        } else if upper.starts_with("QUIT") {
            let _ = w.write_all(b"221 Bye\r\n").await;
            return;
        } else {
            "502 Command not implemented\r\n".into()
        };
        if w.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
        if let Some(pause) = stall_after_reply.take() {
            tokio::time::sleep(pause).await;
        }
    }
}
