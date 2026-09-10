# Hardening Implementation Plan (part 2 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add upstream TLS, connection and rate limits, graceful drain, Debian and release packaging, and the Perl conformance gate on top of the core proxy from part 1.

**Architecture:** Each feature is a small addition behind the existing seams: `RelayConfig` grows a TLS mode; the listener gains a semaphore and a per-IP map; the proxy handler gains a token bucket keyed by username; the session gains a recipient counter and a cancellation point between commands; `main` gains a drain sequence.

**Tech Stack:** as part 1, plus tokio-util 0.7 (`CancellationToken`, `TaskTracker`), rustls-native-certs 0.8, rcgen 0.14 (tests), cargo-deb.

**Spec:** `docs/superpowers/specs/2026-09-10-rust-rewrite-design.md`, sections 6.1, 7 (new flags), 9.1 to 9.3, 10, 11.3. Part 1 is `2026-09-10-core-proxy.md`; every task here assumes part 1 is complete and green.

## Global Constraints

Same as part 1: verbatim reply texts, 4 jobs max, `timeout: 600000` on cargo commands, memory cap on unbounded-input tests, English identifiers, commit per task with the `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` trailer, clippy and fmt clean.

New reply texts (verbatim): `421 smtp-proxy Service not available, closing transmission channel`, `421 smtp-proxy Too many connections, try again later`, `450 4.7.1 Rate limit exceeded, try again later`, `452 4.5.3 Too many recipients`.

New flags and defaults: `--upstream_tls` (opportunistic), `--upstream_tls_ca`, `--upstream_tls_insecure`, `--max_connections` (1000), `--max_connections_per_ip` (50), `--max_messages_per_minute` (60), `--max_recipients` (1000), `--drain_timeout` (30). Zero means unlimited for every limit.

---

### Task 16: Upstream TLS (spec 6.1)

**Files:**
- Modify: `src/relay.rs`, `src/config.rs`, `src/main.rs`, `tests/common/upstream.rs`, `tests/relay.rs`, `Cargo.toml`

**Interfaces:**
- Produces in `relay.rs`:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum UpstreamTlsMode { Off, Opportunistic, Required, Implicit }

#[derive(Clone)]
pub struct UpstreamTls {
    pub mode: UpstreamTlsMode,
    /// None only for mode Off.
    pub client_config: Option<Arc<rustls::ClientConfig>>,
}

impl UpstreamTls {
    pub fn off() -> Self;
    /// System roots plus `extra_ca` (PEM bundle). `insecure` disables verification.
    pub fn build(mode: UpstreamTlsMode, extra_ca: Option<&Path>, insecure: bool) -> anyhow::Result<Self>;
}

pub struct RelayConfig {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub tls: UpstreamTls,        // new
}
```

  `RelayError` gains `#[error("TLS to the upstream failed: {0}")] Tls(String)` and `#[error("upstream does not offer STARTTLS")] NoStartTls`.

- [ ] **Step 1: TLS-capable recording upstream**

Extend `tests/common/upstream.rs`: `RecordingUpstream::start_tls(extensions: &[&str], implicit: bool) -> Self` using the test certificate (`common::test_tls()`); `serve_one` becomes generic over the stream via `Box<dyn Io>` (the same `Io` trait as in `raw_client.rs`). When `starttls` is enabled the EHLO reply includes `STARTTLS` before the other extensions, and a `STARTTLS` command answers `220 Go ahead`, then accepts with `tokio_rustls::TlsAcceptor`, then continues the loop on the TLS stream. Record `"STARTTLS"` in `commands` like any other command. Also record whether TLS was up when each command arrived: `pub tls_commands: Vec<String>` holds the commands received inside TLS.

- [ ] **Step 2: Tests** (append to `tests/relay.rs`)

```rust
fn tls_config(up: &RecordingUpstream, mode: UpstreamTlsMode, insecure: bool) -> RelayConfig {
    let ca = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs/server.crt");
    RelayConfig {
        host: "localhost".into(),   // the test certificate's CN
        port: up.addr.port(),
        timeout: std::time::Duration::from_secs(5),
        tls: UpstreamTls::build(mode, if insecure { None } else { Some(&ca) }, insecure).unwrap(),
    }
}

#[tokio::test]
async fn opportunistic_uses_starttls_when_offered() {
    let up = RecordingUpstream::start_tls(&["DSN"], false).await;
    let recipients = vec![Recipient { address: "x@baz.com".into(), parameters: vec![] }];
    let env = Envelope { from: "a@b.com", mail_params: &[], recipients: &recipients };
    relay(&tls_config(&up, UpstreamTlsMode::Opportunistic, false), env, b"x\r\n").await.unwrap();
    let cmds = up.commands();
    assert!(cmds[0].starts_with("EHLO"));
    assert_eq!(cmds[1], "STARTTLS");
    assert!(cmds[2].starts_with("EHLO"));
    assert!(up.tls_commands().iter().any(|c| c.starts_with("MAIL")));
}

#[tokio::test]
async fn opportunistic_stays_plain_without_starttls_but_required_fails() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let recipients = vec![Recipient { address: "x@baz.com".into(), parameters: vec![] }];
    let env = Envelope { from: "a@b.com", mail_params: &[], recipients: &recipients };
    relay(&tls_config(&up, UpstreamTlsMode::Opportunistic, false), env, b"x\r\n").await.unwrap();
    assert!(!up.commands().contains(&"STARTTLS".to_string()));
    let env = Envelope { from: "a@b.com", mail_params: &[], recipients: &recipients };
    assert!(matches!(relay(&tls_config(&up, UpstreamTlsMode::Required, false), env, b"x\r\n").await, Err(RelayError::NoStartTls)));
}

#[tokio::test]
async fn certificate_failure_does_not_fall_back_to_plain() {
    let up = RecordingUpstream::start_tls(&["DSN"], false).await;
    let recipients = vec![Recipient { address: "x@baz.com".into(), parameters: vec![] }];
    let env = Envelope { from: "a@b.com", mail_params: &[], recipients: &recipients };
    // No extra CA: the self-signed test certificate is not trusted.
    let mut cfg = tls_config(&up, UpstreamTlsMode::Opportunistic, false);
    cfg.tls = UpstreamTls::build(UpstreamTlsMode::Opportunistic, None, false).unwrap();
    assert!(matches!(relay(&cfg, env, b"x\r\n").await, Err(RelayError::Tls(_))));
    assert!(!up.commands().iter().any(|c| c.starts_with("MAIL")));
    // Insecure mode accepts it.
    let env = Envelope { from: "a@b.com", mail_params: &[], recipients: &recipients };
    relay(&tls_config(&up, UpstreamTlsMode::Opportunistic, true), env, b"x\r\n").await.unwrap();
}

#[tokio::test]
async fn implicit_tls_and_dsn_from_the_tls_ehlo() {
    let up = RecordingUpstream::start_tls(&["DSN"], true).await;
    assert!(probe(&tls_config(&up, UpstreamTlsMode::Implicit, false)).await.unwrap());
    // An upstream that only announces DSN inside TLS.
    let up = RecordingUpstream::start_tls(&[], false).await;
    up.set_tls_extensions(&["DSN"]);
    assert!(probe(&tls_config(&up, UpstreamTlsMode::Opportunistic, false)).await.unwrap());
}
```

`set_tls_extensions` sets the extension list announced by the EHLO inside TLS (default: the same as outside). Update every existing `RelayConfig { .. }` literal in the tests to add `tls: UpstreamTls::off()`.

- [ ] **Step 3: Implement**

In `relay.rs`, `Upstream` holds `stream: Pin<Box<dyn AsyncReadWrite>>` split into a `BufReader` on read and write halves via `tokio::io::split`. Add:

```rust
impl UpstreamTls {
    pub fn off() -> Self {
        Self { mode: UpstreamTlsMode::Off, client_config: None }
    }

    pub fn build(mode: UpstreamTlsMode, extra_ca: Option<&Path>, insecure: bool) -> anyhow::Result<Self> {
        if mode == UpstreamTlsMode::Off {
            return Ok(Self::off());
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
        let config = if insecure {
            tracing::warn!("--upstream_tls_insecure is set; the upstream certificate is not verified");
            builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
            if let Some(path) = extra_ca {
                use rustls_pki_types::pem::PemObject;
                for cert in rustls_pki_types::CertificateDer::pem_file_iter(path)? {
                    roots.add(cert?)?;
                }
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        Ok(Self { mode, client_config: Some(Arc::new(config)) })
    }
}
```

`NoVerify` is the same verifier as in the test client; move it into `relay.rs` as `pub struct NoVerify(pub Arc<rustls::crypto::CryptoProvider>)` and have the test client use it.

In `Upstream::open`, after the first EHLO:

```rust
let want_tls = match config.tls.mode {
    UpstreamTlsMode::Off | UpstreamTlsMode::Implicit => false,
    UpstreamTlsMode::Opportunistic => extensions.contains("STARTTLS"),
    UpstreamTlsMode::Required => {
        if !extensions.contains("STARTTLS") { return Err(RelayError::NoStartTls); }
        true
    }
};
if want_tls {
    self.command("STARTTLS", "STARTTLS".into(), 2).await?;
    self.upgrade(config).await?;           // rustls client handshake; Err -> RelayError::Tls
    extensions = parse_extensions(&self.command("EHLO", format!("EHLO {host}"), 2).await?.raw);
}
```

For `Implicit`, `Upstream::connect` performs the handshake right after the TCP connect, before reading the greeting. The server name for the handshake is `config.host` parsed as `ServerName::try_from`, so an IP address works too.

In `config.rs`, add the three flags to `Cli` and `Config` (`upstream_tls: UpstreamTlsMode` default `opportunistic`, `upstream_tls_ca: Option<PathBuf>`, `upstream_tls_insecure: bool`). In `main.rs`, build `UpstreamTls::build(..)` into `RelayConfig`.

Add `rustls-native-certs = "0.8"` to `Cargo.toml`.

- [ ] **Step 4: Run, commit**

Run: `cargo test` (whole suite). Expected green.

```bash
git add -A && git commit -m "TLS to the upstream: off, opportunistic, required, implicit"
```

---

### Task 17: Connection limits (spec 9.2)

**Files:**
- Modify: `src/server/mod.rs` (`ServerConfig` gains `max_connections: usize`, `max_connections_per_ip: usize`), `src/server/listener.rs`, `src/config.rs`, `src/main.rs`
- Create: `tests/limits.rs`

**Interfaces:**
- Produces in `listener.rs`: `pub struct ConnectionLimits { total: Option<Arc<tokio::sync::Semaphore>>, per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>, per_ip_max: usize }` with `fn try_acquire(&self, ip: IpAddr) -> Result<ConnectionPermit, &'static str>` where the `&'static str` is `"total"` or `"per-ip"` and `ConnectionPermit` releases both counters on drop.

- [ ] **Step 1: Tests**

```rust
mod common;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};

#[tokio::test]
async fn total_connection_limit() {
    let mut config = server_config(false, false);
    config.max_connections = 2;
    let addr = start_server(config, ScriptedFactory::default()).await;
    let (_c1, g1) = RawClient::connect(addr).await;
    let (_c2, g2) = RawClient::connect(addr).await;
    assert!(g1.starts_with("220") && g2.starts_with("220"));
    let (mut c3, g3) = RawClient::connect(addr).await;
    assert_eq!(g3, "421 test.service.name Too many connections, try again later\r\n");
    assert!(c3.expect_close().await);
    drop(_c1);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let (_c4, g4) = RawClient::connect(addr).await;
    assert!(g4.starts_with("220"));
}

#[tokio::test]
async fn per_ip_connection_limit() {
    let mut config = server_config(false, false);
    config.max_connections_per_ip = 1;
    let addr = start_server(config, ScriptedFactory::default()).await;
    let (_c1, g1) = RawClient::connect(addr).await;
    assert!(g1.starts_with("220"));
    let (_c2, g2) = RawClient::connect(addr).await;
    assert!(g2.starts_with("421"));
}

#[tokio::test]
async fn zero_means_unlimited() {
    let mut config = server_config(false, false);
    config.max_connections = 0;
    config.max_connections_per_ip = 0;
    let addr = start_server(config, ScriptedFactory::default()).await;
    let mut clients = Vec::new();
    for _ in 0..20 {
        let (c, g) = RawClient::connect(addr).await;
        assert!(g.starts_with("220"));
        clients.push(c);
    }
}
```

Update `common::server_config` to set `max_connections: 0, max_connections_per_ip: 0` (tests default to unlimited) and later `max_recipients: 0`, `drain: None`.

- [ ] **Step 2: Implement**

In `listener::serve`, before spawning the session:

```rust
let permit = match limits.try_acquire(client.ip()) {
    Ok(p) => p,
    Err(which) => {
        info!("Connection limit reached ({which}) for {client}");
        let reply = Reply::new(421, format!("{} Too many connections, try again later", config.service_name)).wire();
        tokio::spawn(async move {
            let mut stream = stream;
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        continue;
    }
};
```

and move `permit` into the session task so it drops when the session ends. `ConnectionLimits` is built once from `config` at the top of `serve`. The semaphore uses `try_acquire_owned` on an `Arc<Semaphore>`; the per-IP map increments under a `std::sync::Mutex` and the permit's `Drop` decrements and removes the entry at zero.

Add the two flags to `config.rs` (defaults 1000 and 50) and pass them in `main.rs`.

- [ ] **Step 3: Run, commit**

```bash
cargo test && git add -A && git commit -m "Total and per-IP connection limits"
```

---

### Task 18: Message rate and recipient limits (spec 9.3)

**Files:**
- Modify: `src/server/mod.rs` (`Handler::mail` and `Handler::rcpt` return `Result<(), Rejection>`; `ServerConfig` gains `max_recipients: usize`), `src/server/session.rs`, `src/proxy.rs`, `src/config.rs`, `src/main.rs`, `tests/common/fake_handler.rs`, `tests/limits.rs`
- Create: `src/ratelimit.rs`

**Interfaces:**
- Produces in `server/mod.rs`:

```rust
/// A handler's refusal of MAIL or RCPT, with the reply to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection { pub code: u16, pub text: String }

impl Rejection {
    /// The Perl texts: 553 "Requested action not taken: <why>" for MAIL,
    /// 550 "Will not send mail to this user: <why>" for RCPT.
    pub fn mail(why: impl Into<String>) -> Self;
    pub fn rcpt(why: impl Into<String>) -> Self;
    pub fn rate_limited() -> Self;     // 450 4.7.1 Rate limit exceeded, try again later
}
```

- Produces in `ratelimit.rs`:

```rust
/// Token buckets keyed by string, capacity and refill of `per_minute` per minute.
pub struct RateLimiter { .. }
impl RateLimiter {
    pub fn new(per_minute: u32) -> Self;           // 0 = unlimited
    pub fn allow(&self, key: &str) -> bool;         // takes one token if available
    pub fn allow_at(&self, key: &str, now: std::time::Instant) -> bool;  // for tests
    /// Drops entries idle for longer than `idle`.
    pub fn prune(&self, idle: std::time::Duration);
}
```

  Internally `Mutex<HashMap<String, Bucket { tokens: f64, last: Instant }>>`. `allow_at` refills `tokens += elapsed_minutes * per_minute`, caps at `per_minute`, then takes one if `tokens >= 1`. `main.rs` spawns a task that calls `prune(10 min)` every minute.

- [ ] **Step 1: Unit tests for the limiter** (in `src/ratelimit.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn bucket_empties_and_refills() {
        let l = RateLimiter::new(2);
        let t0 = Instant::now();
        assert!(l.allow_at("u", t0));
        assert!(l.allow_at("u", t0));
        assert!(!l.allow_at("u", t0));
        assert!(l.allow_at("other", t0));
        assert!(l.allow_at("u", t0 + Duration::from_secs(30)));   // half a minute refills one
        assert!(!l.allow_at("u", t0 + Duration::from_secs(30)));
    }

    #[test]
    fn zero_is_unlimited_and_prune_forgets_idle_keys() {
        let l = RateLimiter::new(0);
        for _ in 0..1000 { assert!(l.allow("u")); }
        let l = RateLimiter::new(1);
        assert!(l.allow("u"));
        l.prune(Duration::ZERO);
        assert!(l.allow("u"));   // forgotten, so a fresh bucket
    }
}
```

- [ ] **Step 2: Integration tests** (append to `tests/limits.rs`)

```rust
#[tokio::test]
async fn recipient_limit_answers_452_and_keeps_the_transaction() {
    let mut config = server_config(false, false);
    config.max_recipients = 2;
    let factory = ScriptedFactory::default();
    let addr = start_server(config, factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<1@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<2@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<3@b.com>").await, "452 4.5.3 Too many recipients\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("S: x\r\n\r\n.\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
    assert_eq!(factory.recorded().rcpt.len(), 2);
}

#[tokio::test]
async fn message_rate_limit_per_username() {
    // Through the real proxy handler, which owns the limiter.
    let api = common::fake_api::FakeApi::start().await;
    let upstream = common::upstream::RecordingUpstream::start(&["DSN"]).await;
    let mut proxy_config = smtp_proxy::proxy::ProxyConfig {
        api: smtp_proxy::api::ApiClient::new(api.url.clone()).unwrap(),
        relay: smtp_proxy::relay::RelayConfig { host: "127.0.0.1".into(), port: upstream.addr.port(), timeout: std::time::Duration::from_secs(5), tls: smtp_proxy::relay::UpstreamTls::off() },
        messages_per_minute: 2,
    };
    let factory = smtp_proxy::proxy::ProxyFactory::new(proxy_config);
    let addr = start_server(server_config(true, true), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    c.login("alice", "pw").await;
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "450 4.7.1 Rate limit exceeded, try again later\r\n");
    // Another user is not affected.
    let (mut c2, _) = RawClient::connect(addr).await;
    c2.login("bob", "pw").await;
    assert_eq!(c2.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
}
```

Remove the `mut` from `proxy_config` if clippy objects. `ProxyConfig` gains `messages_per_minute: u32`; update the `rig()` in `tests/proxy_end_to_end.rs` to set it to 0.

- [ ] **Step 3: Implement**

- `session.rs`: `want_mail` / `want_rcpt` reply `Reply::new(rej.code, rej.text)` on `Err(rej)`. In `want_rcpt`, before calling the handler: `if self.config.max_recipients > 0 && self.recipients >= self.config.max_recipients { send 452 4.5.3 Too many recipients; return Ok(Flow::Continue) }`.
- `proxy.rs`: `ProxyFactory` holds `limiter: Arc<RateLimiter>` built from `config.messages_per_minute`; `ProxyHandler::mail` checks `self.factory.limiter.allow(username)` first and returns `Err(Rejection::rate_limited())` with `info!("Message rate limit reached for user {username} from {client}")`. Expose `pub fn prune_rate_limits(&self)` for the timer in `main.rs`.
- `fake_handler.rs`: `mail_error` / `rcpt_error` become `Option<Rejection>`; the existing tests use `Rejection::mail("no")` and `Rejection::rcpt("bad user")`.
- `config.rs`: `--max_messages_per_minute` (60), `--max_recipients` (1000).

- [ ] **Step 4: Run, commit**

```bash
cargo test && git add -A && git commit -m "Per-username message rate limit and recipient limit"
```

---

### Task 19: Graceful drain (spec 9.1)

**Files:**
- Modify: `src/server/mod.rs` (`ServerConfig` gains `drain: Option<Drain>`), `src/server/listener.rs`, `src/server/session.rs`, `src/main.rs`, `src/config.rs`, `Cargo.toml` (add `tokio-util = { version = "0.7", features = ["rt"] }`)
- Create: `tests/drain.rs`

**Interfaces:**
- Produces in `server/mod.rs`:

```rust
#[derive(Clone)]
pub struct Drain {
    pub token: tokio_util::sync::CancellationToken,
    pub tracker: tokio_util::task::TaskTracker,
}
impl Drain { pub fn new() -> Self; pub fn connections(&self) -> usize; }
```

- `listener::serve` returns when `drain.token` is cancelled (the accept loops `select!` on it) and spawns sessions via `drain.tracker.spawn(..)` when a `Drain` is configured.
- `session.rs`: `next_line` selects on `token.cancelled()` while waiting for a command between transactions (states up to `WantRcpt`/`WantData` before DATA has been issued); on cancellation it sends `421 <svc> Service not available, closing transmission channel` and ends with a new `End::Drained`. Inside `read_message` and while awaiting the handler, the token is not consulted, so an in-flight message completes.
- `main.rs`: on signal, `drain.token.cancel()`, log info `Shutting down; draining <n> connection(s)`, then `tokio::time::timeout(drain_timeout, drain.tracker.wait())`; on timeout log warn `Drain timeout; closing <n> connection(s)` and exit anyway. A second signal during the drain exits immediately.

- [ ] **Step 1: Tests**

```rust
mod common;

use std::time::Duration;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};
use smtp_proxy::server::Drain;

#[tokio::test]
async fn idle_sessions_get_421_and_in_flight_messages_finish() {
    let drain = Drain::new();
    let mut config = server_config(false, false);
    config.drain = Some(drain.clone());
    let factory = ScriptedFactory::default();
    factory.set(|s| s.message_delay = Duration::from_millis(500));
    let addr = start_server(config, factory.clone()).await;

    let (mut idle, _) = RawClient::connect(addr).await;
    assert!(idle.command("EHLO x").await.starts_with("250"));

    let (mut busy, _) = RawClient::connect(addr).await;
    assert!(busy.command("EHLO x").await.starts_with("250"));
    assert_eq!(busy.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(busy.command("RCPT TO:<x@y.com>").await, "250 OK\r\n");
    assert!(busy.command("DATA").await.starts_with("354"));
    busy.write_raw("S: x\r\n\r\n.\r\n").await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    drain.token.cancel();

    assert_eq!(idle.read_reply().await, "421 test.service.name Service not available, closing transmission channel\r\n");
    assert!(idle.expect_close().await);
    assert_eq!(busy.read_reply().await, "250 OK: queued\r\n");
    assert_eq!(busy.read_reply().await, "421 test.service.name Service not available, closing transmission channel\r\n");
    assert!(busy.expect_close().await);

    // New connections are refused once the listener is gone.
    tokio::time::timeout(Duration::from_secs(2), drain.tracker.wait()).await.expect("tracker drained");
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}
```

`start_server` must call `drain.tracker.close()` after spawning `serve` when a drain is configured, so `wait()` can complete; put that in `listener::serve` itself right after the accept loops are spawned.

- [ ] **Step 2: Implement**

In `session.rs`:

```rust
async fn next_command_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
    let Some(drain) = self.config.drain.clone() else { return self.next_line().await };
    if drain.token.is_cancelled() {
        return Ok(None);
    }
    tokio::select! {
        biased;
        _ = drain.token.cancelled() => Ok(None),
        line = self.next_line() => line,
    }
}
```

In `serve()`, use `next_command_line` for commands and, when it returns `Ok(None)` while the token is cancelled, send the 421 and return `End::Drained`. After `read_message` completes, check the token again before reading the next command, which is what produces the 421 after the 250 for the busy client.

In `listener.rs`, the accept loop becomes:

```rust
loop {
    let accepted = tokio::select! {
        biased;
        _ = cancelled(&drain) => break,
        r = listener.accept() => r,
    };
    ...
}
```

with `async fn cancelled(drain: &Option<Drain>) { match drain { Some(d) => d.token.cancelled().await, None => std::future::pending().await } }`. Sessions are spawned with `drain.tracker.spawn(..)` when present, `tokio::spawn` otherwise. After spawning the accept loops: `if let Some(d) = &drain { d.tracker.close(); }`.

In `main.rs`:

```rust
let drain = Drain::new();
// ... ServerConfig { drain: Some(drain.clone()), .. }
let serve = tokio::spawn(listener::serve(listeners, server_config, factory));
shutdown_signal().await;
let n = drain.connections();
tracing::info!("Shutting down; draining {n} connection(s)");
drain.token.cancel();
let _ = serve.await;
tokio::select! {
    _ = drain.tracker.wait() => {}
    _ = tokio::time::sleep(Duration::from_secs(config.drain_timeout)) => {
        tracing::warn!("Drain timeout; closing {} connection(s)", drain.connections());
    }
    _ = shutdown_signal() => {}
}
```

`Drain::connections()` is `self.tracker.len()`. Add `--drain_timeout` (30) to `config.rs`.

- [ ] **Step 3: Run, commit**

```bash
cargo test && git add -A && git commit -m "Graceful drain on SIGTERM and SIGINT"
```

---

### Task 20: Debian package, static release binary, Makefile (spec 10)

**Files:**
- Create: `packaging/smtp-proxy.service`, `packaging/smtp-proxy.default`, `Makefile`, `.github/workflows/release.yml` (or `.gitlab-ci.yml` if the project stays on GitLab: check `git remote -v` in `../smtp-proxy` and mirror it)
- Modify: `Cargo.toml` (`[package.metadata.deb]`), `README.md`, `Dockerfile` (if the `ring` switch was needed)

- [ ] **Step 1: systemd unit and defaults**

`packaging/smtp-proxy.service`:
```ini
[Unit]
Description=SMTP authentication and header injection proxy
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=-/etc/default/smtp-proxy
ExecStart=/usr/bin/smtp-proxy $SMTP_PROXY_OPTS
Restart=on-failure
KillSignal=SIGTERM
TimeoutStopSec=45
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/smtp-proxy

[Install]
WantedBy=multi-user.target
```

`packaging/smtp-proxy.default`:
```
# Flags for smtp-proxy; see `smtp-proxy --help`.
SMTP_PROXY_OPTS="--listen=0.0.0.0:587 --tohost=mail.example.com --toport=25 --tls_cert=/etc/smtp-proxy/server.crt --tls_key=/etc/smtp-proxy/server.key --api=https://auth.example.com/check --user=smtp-proxy --loglevel=info"
```

`Cargo.toml`:
```toml
[package.metadata.deb]
maintainer = "Tobias Oetiker <tobi@oetiker.ch>"
depends = "$auto"
section = "mail"
assets = [
    ["target/release/smtp-proxy", "usr/bin/", "755"],
    ["packaging/smtp-proxy.default", "etc/default/smtp-proxy", "644"],
    ["README.md", "usr/share/doc/smtp-proxy/", "644"],
]
conf-files = ["/etc/default/smtp-proxy"]
systemd-units = { unit-name = "smtp-proxy", enable = false }
```

The unit file must be at `packaging/smtp-proxy.service`; set `systemd-units = { unit-name = "smtp-proxy", unit-scripts = "packaging", enable = false }`.

- [ ] **Step 2: Makefile**

```makefile
JOBS ?= 4
.PHONY: build test lint release deb docker conformance

build:
	cargo build -j $(JOBS)

test:
	cargo test -j $(JOBS)

lint:
	cargo fmt --check && cargo clippy --all-targets -j $(JOBS) -- -D warnings

release:
	cargo build --release --locked -j $(JOBS) --target x86_64-unknown-linux-musl

deb: release
	cargo deb --no-build --target x86_64-unknown-linux-musl

docker:
	./build-docker.sh

conformance: build
	$(MAKE) -C conformance
```

`rustup target add x86_64-unknown-linux-musl` is needed once on the build host; note it in the README.

- [ ] **Step 3: Release workflow**

A tag `v*` triggers: checkout, install the musl target, `make lint test release deb`, upload `target/x86_64-unknown-linux-musl/release/smtp-proxy` and the `.deb` from `target/x86_64-unknown-linux-musl/debian/` as release assets, and build and push the Docker image tagged with the version.

- [ ] **Step 4: Verify locally, commit**

Run: `make lint test release deb` (timeout 600000). Expected: a `.deb` in `target/x86_64-unknown-linux-musl/debian/`. `dpkg-deb -c` lists the binary, unit, and default file.

```bash
git add -A && git commit -m "Debian package, systemd unit, Makefile, release workflow"
```

---

### Task 21: Perl conformance gate (spec 11.3)

**Files:**
- Create: `conformance/Makefile`, `conformance/lib/ProxyUnderTest.pm`, `conformance/lib/FakeHttpApi.pm`, `conformance/t/end-to-end.t` (adapted copy), `conformance/t/dsn.t`, `conformance/t/upstream-acceptance.t`, `conformance/t/api-from-injection.t`, `conformance/t/pipelining.t`, `conformance/t/rset-transaction.t`, `conformance/t/repeated-recipient.t`, `conformance/t/connection-lifecycle.t`, `conformance/t/starttls-failure.t`, `conformance/README.md`

**Interfaces:**
- `ProxyUnderTest->start(%opts)` spawns `target/debug/smtp-proxy` with `--listen 127.0.0.1:0`, the test cert and key from `../smtp-proxy/t/certs-and-keys`, `--tohost/--toport` pointing at the Perl test's own upstream, `--api` at the fake HTTP API, `--upstream_tls=off`, all limits at 0, `--loglevel debug --logpath <tempfile>`. It reads the `Waiting for connections on 127.0.0.1:<port>` line from stdout to learn the port and returns it. `stop` sends SIGTERM and waits.
- `FakeHttpApi` is a `Mojolicious::Lite` app on an ephemeral port with `result` and `calledWith` accessors mirroring `FakeAPI.pm`.

- [ ] **Step 1: Write the harness**

`conformance/lib/FakeHttpApi.pm`:
```perl
package FakeHttpApi;
use Mojo::Base -base, -signatures;
use Mojolicious;
use Mojo::Server::Daemon;
use Mojo::IOLoop::Server;

has result => sub { { allow => 1, headers => [] } };
has calledWith => sub { [] };
has 'url';

sub start ($self) {
    my $app = Mojolicious->new;
    $app->log->level('error');
    my $me = $self;
    $app->routes->post('/check' => sub ($c) {
        push @{$me->calledWith}, $c->req->json;
        $c->render(json => $me->result);
    });
    my $port = Mojo::IOLoop::Server->generate_port;
    $self->{daemon} = Mojo::Server::Daemon->new(app => $app, listen => ["http://127.0.0.1:$port"], silent => 1)->start;
    $self->url("http://127.0.0.1:$port/check");
    return $self;
}

sub clear ($self) { @{$self->calledWith} = () }

1;
```

`conformance/lib/ProxyUnderTest.pm`:
```perl
package ProxyUnderTest;
use Mojo::Base -base, -signatures;
use IPC::Open3;
use File::Temp qw(tempfile);
use FindBin;
use Symbol qw(gensym);

has binary => sub { "$FindBin::Bin/../../target/debug/smtp-proxy" };
has certs => sub { "$FindBin::Bin/../../../smtp-proxy/t/certs-and-keys" };
has [qw(tohost toport api port pid logpath)];

sub start ($self) {
    my (undef, $log) = tempfile(UNLINK => 1);
    $self->logpath($log);
    my @cmd = ($self->binary,
        '--listen', '127.0.0.1:0',
        '--tohost', $self->tohost, '--toport', $self->toport,
        '--tls_cert', $self->certs . '/server.crt', '--tls_key', $self->certs . '/server.key',
        '--api', $self->api, '--upstream_tls', 'off',
        '--max_connections', 0, '--max_connections_per_ip', 0,
        '--max_messages_per_minute', 0, '--max_recipients', 0,
        '--loglevel', 'debug', '--logpath', $log);
    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, @cmd) or die "cannot start @cmd: $!";
    $self->pid($pid);
    my $line = <$out>;
    $line =~ /Waiting for connections on 127\.0\.0\.1:(\d+)/ or die "unexpected startup line: $line";
    $self->port($1);
    <$out>; # "Will forward mails to ..."
    $self->{out} = $out;
    return $self;
}

sub stop ($self) {
    kill TERM => $self->pid;
    waitpid $self->pid, 0;
}

sub DESTROY ($self) { $self->stop if $self->pid }

1;
```

- [ ] **Step 2: Adapt the tests**

Copy each listed `.t` file from `../smtp-proxy/t/`. In each, replace the in-process proxy setup (`SMTPProxy->new(... api => $testApi ...)->setup`) with:

```perl
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../../smtp-proxy/t";
use lib "$FindBin::Bin/../../../smtp-proxy/lib";
use lib "$FindBin::Bin/../../../smtp-proxy/thirdparty/lib/perl5";
use FakeHttpApi;
use ProxyUnderTest;

my $testApi = FakeHttpApi->new->start;
# ... the Perl test's own upstream (SMTPProxy::SMTPServer or RecordingSMTPServer) on $TEST_TO_PORT as before ...
my $proxy = ProxyUnderTest->new(tohost => $TEST_HOST, toport => $TEST_TO_PORT, api => $testApi->url)->start;
my $TEST_PROXY_PORT = $proxy->port;
```

Keep every assertion. Tests that instantiate `SMTPProxy::SMTPServer` directly with `require_starttls => 0` (server-only tests) cannot run against the binary and are not copied; those behaviours are covered by the Rust suite. Where a test reads the proxy's log through `$TEST_LOG`, read `$proxy->logpath` instead. The service name in greetings is `smtp-proxy`, not `smtp.proxy.service`; adjust those literal assertions.

`conformance/Makefile`:
```makefile
PERL5LIB := ../../smtp-proxy/thirdparty/lib/perl5
test:
	cd .. && cargo build -j 4
	MOJO_REACTOR=Mojo::Reactor::EV LIBEV_FLAGS=4 PERL5LIB=$(PERL5LIB) prove -w -Ilib -I../../smtp-proxy/t -I../../smtp-proxy/lib t/
```

- [ ] **Step 3: Run**

Run: `make conformance` (timeout 600000).
Expected: every adapted file passes. A failure here is a behaviour difference: fix the Rust side unless the Perl test encodes a Perl-only artefact (document any such case in `conformance/README.md`).

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "Perl conformance gate running the original end-to-end tests against the binary"
```

---

## Self-review against the spec (part 2)

| Spec section | Task |
|---|---|
| 6.1 upstream TLS | 16 |
| 7 new flags | 16, 17, 18, 19 |
| 9.1 graceful drain | 19 |
| 9.2 connection limits | 17 |
| 9.3 rate limits | 18 |
| 10 deb, release, Makefile | 20 |
| 11.3 conformance gate | 21 |
| 12 known differences documented | README in Task 20 |
