# Hardening Implementation Plan (part 2 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add upstream TLS, connection and rate limits, graceful drain, Debian and release packaging, and the Perl conformance gate on top of the core proxy from part 1.

**Architecture:** Each feature is a small addition behind the existing seams: `RelayConfig` grows a TLS mode; the listener gains a semaphore and a per-IP map; the proxy handler gains a token bucket keyed by username; the session gains a recipient counter and a cancellation point between commands; `main` gains a drain sequence.

**Tech Stack:** as part 1, plus tokio-util 0.7 (`CancellationToken`, `TaskTracker`), rustls-native-certs 0.8, rcgen 0.14 (tests), cargo-deb.

**Spec:** `docs/superpowers/specs/2026-09-10-rust-rewrite-design.md`, sections 6.1, 7 (new flags), 9.1 to 9.3, 10, 11.3. Part 1 is `2026-09-10-core-proxy.md`; every task here assumes part 1 is complete and green.

## Global Constraints

Same as part 1: verbatim reply texts, 4 jobs max, `timeout: 600000` on cargo commands, memory cap on unbounded-input tests, English identifiers, commit per task with a `Co-Authored-By:` trailer naming the model that actually authored the commit, clippy and fmt clean.

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

### Task 22: Carried-over hardening from part 1 (seven items, divergence approved)

User ruling, 2026-09-12: **fix all five** carried-over items, and **divergence
from the Perl is acceptable** where a fix requires it. This overrides part 1's
"faithful to the Perl, do not fix" entry for the case-sensitive header merge,
the opaque bare-LF header block, and the missing `setgroups`.

**Files:**
- Modify: `src/relay.rs` (items 1, 6), `src/proxy.rs` (items 2, 3, 5, 6), `src/privdrop.rs` (item 4), `src/server/session.rs` and `src/server/mod.rs` (item 6), `src/server/auth.rs` (item 7), `README.md`
- Modify tests: `tests/relay.rs`, `tests/proxy_end_to_end.rs`, `tests/common/fake_handler.rs`

**Interfaces:**
- Produces in `relay.rs`: `const MAX_REPLY_LINE: usize = 4096;` and `const MAX_REPLY_TOTAL: usize = 65536;`
- Produces in `proxy.rs`: `pub fn assert_header_relayable(headers: &[RequestHeader]) -> Result<(), String>`
- Produces in `privdrop.rs`: `trait PrivOps` with `init_groups`, `set_gid`, `set_uid`, so the syscall *order* is testable without root.

---

#### Item 1 — bound the upstream reply (`src/relay.rs`, `read_reply`)

Today both dimensions are unbounded: one `read_line` can consume an endless
line, and the multi-line loop can accumulate endless lines. Cap both.

- [ ] **Step 1: Tests** (in `tests/relay.rs`, over `tokio::io::duplex` like the
      existing timing tests — never a real socket)

```rust
#[tokio::test]
async fn endless_reply_line_is_refused_not_buffered() {
    // Upstream sends "220 " then 1 MiB of 'x' with no newline.
    // Assert: the relay returns an error, and does so after reading at most
    // MAX_REPLY_LINE + a small slack, not after consuming the whole stream.
}

#[tokio::test]
async fn endless_multiline_reply_is_refused() {
    // Upstream sends "220-a\r\n" repeatedly and never a final "220 a\r\n".
    // Assert: the relay returns an error once the accumulated reply passes
    // MAX_REPLY_TOTAL.
}
```

Both tests MUST be run under a memory cap when first executed:
`systemd-run --user --scope -p MemoryMax=2G -- cargo test --test relay`.
A red version of either test that OOMs instead of failing is a broken test.

- [ ] **Step 2: Implement**

Replace the bare `self.reader.read_line(&mut line)` with a bounded read:

```rust
use tokio::io::AsyncReadExt;
let n = tokio::time::timeout(
    self.timeout,
    (&mut self.reader).take(MAX_REPLY_LINE as u64).read_line(&mut line),
).await.map_err(|_| RelayError::Timeout)??;
```

After the read, if `line` reached the cap without ending in `\n`, fail with
`std::io::ErrorKind::InvalidData` and the message
`upstream reply line exceeds 4096 bytes`. Track the accumulated `raw.len()`
across loop iterations and fail the same way with
`upstream reply exceeds 65536 bytes` once it passes `MAX_REPLY_TOTAL`.

Note: `Take` must be released between iterations (`take` consumes `&mut`), so
re-wrap per line rather than holding one `Take` across the loop.

---

#### Item 2 — case-insensitive header merge (`src/proxy.rs`, `merge_headers`)

`a.name == h.name` is case-sensitive, so an API answering `subject` while the
client sent `Subject` emits **both**. RFC 5322 says header names are
case-insensitive. **Divergence from the Perl, approved.**

- [ ] **Step 1: Test**

```rust
#[test]
fn api_header_replaces_client_header_regardless_of_case() {
    let existing = vec![h("Subject", "client"), h("To", "x@y.com")];
    let api = vec![rh("subject", Some("api"))];
    let merged = merge_headers(existing, &api);
    assert_eq!(merged, vec![h("To", "x@y.com"), h("subject", "api")]);
}
```

(`rh` builds a `ResponseHeader`; add the helper if the test module lacks it.)
Also assert that a `None` API value still *removes* the client header
case-insensitively — that path exists today and must keep working.

- [ ] **Step 2: Implement** — change the filter to
`!api.iter().any(|a| a.name.eq_ignore_ascii_case(&h.name))`. ASCII is correct:
RFC 5322 field names are printable ASCII.

---

#### Item 3 — bare-LF header blocks (`src/proxy.rs`, `parse_headers`)

`block.split_inclusive("\r\n")` only splits on CRLF, so a header block that
uses bare LF arrives as a **single opaque header** whose value carries every
remaining header. API-side header policy is therefore evadable by sending bare
LF. `DataReader` already accepts bare-LF line terminators
(`src/server/data.rs`, `bare_lf_terminators_are_accepted`), so the block
genuinely reaches here in that shape. **Divergence from the Perl, approved.**

- [ ] **Step 1: Tests**

```rust
#[test]
fn bare_lf_header_block_splits_into_headers() {
    let parsed = parse_headers("From: a@b.com\nSubject: hi\nTo: x@y.com\n");
    assert_eq!(parsed, vec![
        h("From", "a@b.com"), h("Subject", "hi"), h("To", "x@y.com"),
    ]);
}

#[test]
fn bare_lf_folding_still_folds() {
    let parsed = parse_headers("Subject: long\n  folded\nTo: x@y.com\n");
    assert_eq!(parsed, vec![h("Subject", "long\n  folded"), h("To", "x@y.com")]);
}

#[test]
fn mixed_crlf_and_lf_block_splits_on_both() {
    let parsed = parse_headers("A: 1\r\nB: 2\nC: 3\r\n");
    assert_eq!(parsed, vec![h("A", "1"), h("B", "2"), h("C", "3")]);
}
```

**Every existing `parse_headers` test must stay green unchanged** — in
particular `headers_split_at_unfolded_crlf` and
`a_header_with_nothing_behind_the_colon_is_dropped`. If one turns red, that is
a finding, not a test to edit.

- [ ] **Step 2: Implement** — split on `'\n'` inclusive instead of `"\r\n"`,
keep the same continuation test (`raw.starts_with([' ', '\t', '\x0b', '\x0c'])`),
and trim the terminator with `trim_end_matches(['\r', '\n'])` instead of
`trim_end_matches("\r\n")`. The folded value keeps its embedded line break
verbatim, exactly as it does today for CRLF, and `perl_header_value` is
unchanged.

---

#### Item 4 — `setgroups` before `setuid` (`src/privdrop.rs`)

No `setgroups`/`initgroups` call, so a proxy started as root keeps **root's
supplementary groups** after dropping to the unprivileged user. Matches the
Perl (`SMTPProxy.pm:212-217`); fix anyway. **Divergence from the Perl, approved.**

**Ruling: use `initgroups`, not `setgroups(&[])`.** `initgroups(user, gid)`
gives the target user exactly the groups they would have on login, which is
what a conventional daemon `--user` flag does. Dropping all supplementary
groups would be more restrictive but would silently break an operator who
grants cert-file read access through a group.

- [ ] **Step 1: Tests**

The success path is irreversible and cannot be exercised in-process — part 1
deliberately did not test it. So make the **order** testable instead: extract
the three syscalls behind a small trait.

```rust
pub(crate) trait PrivOps {
    fn init_groups(&self, user: &std::ffi::CStr, gid: Gid) -> nix::Result<()>;
    fn set_gid(&self, gid: Gid) -> nix::Result<()>;
    fn set_uid(&self, uid: Uid) -> nix::Result<()>;
}
```

`drop_to` resolves the user and delegates to `drop_with(ops, user, entry)`.
Tests use a recording double:

```rust
#[test]
fn privileges_drop_in_the_order_groups_gid_uid() {
    // Assert the recorded call sequence is exactly
    // ["init_groups", "set_gid", "set_uid"].
}

#[test]
fn a_failing_initgroups_aborts_before_setgid() {
    // Double fails init_groups; assert set_gid and set_uid were never called
    // and the error names the operation.
}
```

Keep `unknown_user_is_reported_by_name` exactly as it is.

- [ ] **Step 2: Implement** — `nix::unistd::initgroups(&CString::new(user)?, entry.gid)`
before `setgid`. Enable the `nix` feature the call needs if it is not already
on. Error text follows the existing style:
`Failed to initgroups for '{user}': {e}`. Update the doc comment at the top of
the file: the ordering comment must now name all three calls.

---

#### Item 5 — refuse an unfolded line break in a relayed header (`src/proxy.rs`)

`format_message` interpolates `h.value` unchecked, so a value carrying
`\r\n\r\n` splits the relayed message and forges a body. Envelope addresses are
already guarded by `assert_relayable`; header values are not. **Divergence from
the Perl, approved.**

**Ruling on the exact rule:** a line break inside a value is legal only as a
proper fold — a `\r\n` or `\n` immediately followed by a space or tab. Anything
else is refused. A *name* may contain no `\r`, `\n` or `:` at all. This precise
rule is required, not merely "reject any CRLF": client-supplied folded headers
arrive here with their embedded break intact (see Item 3) and must keep
relaying.

- [ ] **Step 1: Tests**

```rust
#[test]
fn a_folded_value_is_still_relayable() {
    assert!(assert_header_relayable(&[h("Subject", "long\r\n  folded")]).is_ok());
    assert!(assert_header_relayable(&[h("Subject", "long\n\tfolded")]).is_ok());
}

#[test]
fn an_unfolded_break_in_a_value_is_refused() {
    assert!(assert_header_relayable(&[h("X", "a\r\n\r\nforged body")]).is_err());
    assert!(assert_header_relayable(&[h("X", "a\r\nInjected: yes")]).is_err());
    assert!(assert_header_relayable(&[h("X", "a\nInjected: yes")]).is_err());
    assert!(assert_header_relayable(&[h("X", "trailing\r\n")]).is_err());
}

#[test]
fn a_break_or_colon_in_a_name_is_refused() {
    assert!(assert_header_relayable(&[h("X\r\nY", "v")]).is_err());
    assert!(assert_header_relayable(&[h("X: Y", "v")]).is_err());
}
```

Plus one end-to-end test in `tests/proxy_end_to_end.rs`: an API response whose
header value contains `\r\n\r\n` gets the mail rejected and **nothing relayed**
— assert the `RecordingUpstream` saw no message. Do not relax `RecordingUpstream`.

- [ ] **Step 2: Implement**

Call it from `relay_message`, on the **merged** list, before `format_message`:

```rust
let headers = merge_headers(self.transaction.headers.clone(), &outcome.headers);
if let Err(which) = assert_header_relayable(&headers) {
    warn!("Refusing to relay header '{which}' for {}: unfolded line break", self.client);
    return Err("authentication service failed".into());
}
```

`Err` carries the offending header **name only** — never the value, which may
hold customer content. The client therefore sees
`550 authentication service failed`, an existing verbatim reply text: **no new
reply string is introduced by this item.**

---

#### Item 6 — relay the upstream's own reply code instead of overwriting it with 550 (`src/proxy.rs`, `src/server/session.rs`)

User ruling, 2026-09-13, raised by the user against the controller's weaker
framing of the same problem. **Divergence from the Perl, approved.**

`RelayError::Rejected` carries the upstream's real code, but its `Display` is
`#[error("{text}")]` — text only — and `relay_message` returns
`Err(e.to_string())`, which `session.rs` maps unconditionally to `(550, t)`.
The `code` field is never read on that path.

The client is still connected the whole time: the proxy relays synchronously
and only answers the client once the upstream has answered it. So the upstream's
own code is in hand and there is nothing to invent.

**This currently produces a reply that contradicts itself.** `read_reply` stores
the text as everything after the code, so an upstream `451 4.3.2 Service not
available` reaches the client as:

```
550 4.3.2 Service not available
```

A permanent reply code wrapping a transient enhanced status code. A client
reading the enhanced code queues and retries; one reading the reply code deletes
the mail. That is a wire-format defect, not a trade-off. The Perl does the same
(`Connection.pm:682` is an unconditional 550), so it is not a regression.

**Ruling on the shape: pass the code through verbatim, do not normalise it to a
class.** Verbatim is simpler and says exactly what the upstream said. The
distinction matters only for codes we would otherwise have to re-map, and there
is no case where we know better than the upstream what its own rejection meant.

**Ruling on the no-answer cases.** `Io`, `Timeout`, `Tls` and `NoStartTls` carry
no upstream code — the upstream never answered. `relay()` opens a fresh
connection per message, so a mail server restarting between two messages lands
here. These become **`451`**, because nothing about the message was wrong and
the client should retry rather than discard. `RelayError::Address` stays **550**:
that is *our* refusal of a malformed address, it is permanent, and it is not the
upstream's opinion at all.

**Not in scope, do not change:** the API-rejection path (`!outcome.allow`) keeps
its 550 — a policy refusal is permanent and correct. `"authentication service
failed"` also keeps its 550 for now, even though an API outage is arguably
transient; that is a separate question and the user has not ruled on it. Record
it in the ledger, do not fix it here.

- [ ] **Step 1: Reuse Task 18's `Rejection`**

Task 18 introduces `pub struct Rejection { pub code: u16, pub text: String }` in
`server/mod.rs` for `Handler::mail` and `Handler::rcpt`. Task 22 runs after
Task 18, so reuse it rather than inventing a parallel type: change
`Handler::message` to return `Result<String, Rejection>`, and have `session.rs`
send `Reply::new(rej.code, rej.text)` instead of hard-coding 550. Update
`tests/common/fake_handler.rs` accordingly.

- [ ] **Step 2: Tests**

In `tests/proxy_end_to_end.rs` (use the existing `rig()`, which calls
`captured_log()` — the global-subscriber-behind-`OnceLock` pattern this project
needs, because `tracing` caches callsite interest process-wide):

```rust
#[tokio::test]
async fn an_upstream_4xx_reaches_the_client_as_4xx() {
    // Upstream rejects the final dot with "451 4.3.2 Service not available".
    // Assert the client sees exactly "451 4.3.2 Service not available
"
    // -- the code AND the enhanced status agree.
}

#[tokio::test]
async fn an_upstream_5xx_still_reaches_the_client_as_that_5xx() {
    // Upstream rejects with "552 5.3.4 Message too big for system".
    // Assert the client sees 552, not 550: the code is passed through
    // verbatim, not merely reduced to its class.
}

#[tokio::test]
async fn an_unreachable_upstream_is_a_451_not_a_550() {
    // No upstream listening at all (or one that closes before the greeting).
    // Assert 451, so the client queues and retries rather than discarding.
}
```

The second test is the one that discriminates verbatim pass-through from
class-normalisation. Without it, a 5xx->550 collapse would pass unnoticed.

Every existing test that asserts a 550 from a relay rejection must be re-read,
not blindly updated: if one now expects the wrong code, changing it is correct;
if one turns red for a different reason, that is a finding.

- [ ] **Step 3: Implement**

`RelayError` gains a method giving the client-facing code — `Rejected` yields its
own `code`; `Io`/`Timeout`/`Tls`/`NoStartTls` yield 451; `Address` yields 550.
`relay_message` returns `Rejection { code, text }` built from it. Keep the log
line `Mail refused by relay server ({e}) for {client}` verbatim.

---

- [ ] **Step 4: README and commit**

Add all six to the README's "Differences from the Perl version" list: items 2,
3 and 5 change observable behaviour, item 1 changes it only against a hostile
upstream, and item 4 changes the process's group set. Say for each that the
Perl does not do it and why we do.

Gates: `cargo test`, `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`, then one commit.

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
| part-1 carry-over (5 items, user ruling 2026-09-12) | 22 |
| upstream reply-code passthrough (user ruling 2026-09-13) | 22 |
| 12 known differences documented | README in Task 20 |

## Carried over from part 1 — now covered by Task 22

Raised during part 1's execution and its final whole-branch review, and ruled
into part 2 rather than fixed on that branch. Each says why it was deferred and
what it costs. Items 1, 3, 4 and 5 are security-relevant; none is a regression,
because the Perl behaves the same way in every case.

> **User ruling, 2026-09-12: fix all five, and divergence from the Perl is
> acceptable.** This section is now the rationale; **Task 22 is the work**. The
> ruling overrides part 1's "faithful to the Perl, do not fix" entry for items
> 2, 3 and 4, and settles the sole objection to item 5 (that it diverges from
> the Perl on wire output in a drop-in release).

1. **Bound the upstream `read_reply`** (`src/relay.rs`). Unbounded today, as in
   the Perl. A hostile or compromised upstream can feed an endless reply and
   exhaust memory. Tasks 16-21 do not touch it.
2. **Case-insensitive header merge** (`src/proxy.rs`). Matches the Perl; RFC 5322
   says otherwise. Both implementations emit a duplicate header when the API
   varies the casing.
3. **Bare-LF header blocks reach the API as one opaque header** (both
   implementations), so API-side header policy can be evaded by sending bare LF
   instead of CRLF. Not a regression; worth a decision.
4. **Supplementary groups survive the privilege drop** (`src/privdrop.rs`). No
   `setgroups` before `setuid`, so a proxy started as root keeps root's
   supplementary groups. Matches the Perl (`SMTPProxy.pm:212-217`), so not a
   regression, but a real privilege-retention weakness in both.
5. **An API-supplied header value containing CRLF is relayed unchecked**
   (`src/proxy.rs`, `format_message`). A value carrying `\r\n\r\n` splits the
   relayed message and forges a body. The Perl does the same
   (`SMTPProxy.pm:252-253`), the envelope addresses *are* guarded
   (`assert_relayable`), and the API is the operator's own service — so it is
   neither a regression nor a client-facing hole. A `value.contains(['\r','\n'])`
   refusal costs nothing; it was not applied in part 1 only because it would
   diverge from the Perl on wire output in a drop-in release.


#### Item 7 — bound the AUTH username at 256 bytes (`src/server/auth.rs`)

**User ruling 2026-09-13. Divergence from the Perl approved.**

> *Ruling R38, 2026-09-14.* The paragraph below describes the code **as it
> stood before this item was implemented**, and its `auth.rs` citation is
> pinned to the base commit `618f374` for that reason. At `618f374`,
> `src/server/auth.rs:23-45` is exactly `decode_plain` and `decode_login`,
> and neither had a length check. Today line 45 *is* the bound this item
> added, so re-pointing the range would make the sentence say the opposite
> of what it means. The paragraph's other two references
> (`MAX_COMMAND_BUFFER` and the `Reply::new(535, "Authentication credentials
> invalid")` call, both in `src/server/session.rs`) still hold at the current
> tree and are left alone. Per ruling R40 they are named by anchor rather
> than by line, so that a later edit above them cannot rot them again.

Nothing bounds the length of an AUTH username. `decode_plain` and
`decode_login` (`src/server/auth.rs:23-45` **at `618f374`**) turn whatever
base64 decodes into an owned `String` with no length check. The only bound on
that path is
`MAX_COMMAND_BUFFER` (`src/server/session.rs`) at 64 KiB, whose own doc
comment records that RFC 5321 4.5.3.1.4 caps a command line at 512 octets and
calls 64 KiB "generous", its stated job being only to stop a client that never
sends a newline. So a single username can be roughly 50 KiB.

Why it matters, and why here: Task 18 keys its rate limiter on the AUTH
username and retains the key for up to one prune window, so this is the one
unverified client-supplied string the process *stores*. Task 18's fix round
capped the bucket map at 10,000 entries, which bounds the entry count at every
instant but not the bytes — 10,000 x max-key is about 1 MB for ordinary
usernames and roughly 500 MB worst case. The count ceiling is the right fix in
`ratelimit.rs`; this is the matching fix in the right place. Lowering
`MAX_BUCKETS` instead was considered and rejected: it would trade away the
headroom that keeps real deployments off the ceiling in order to half-mitigate
a problem whose fix belongs in `auth.rs`.

- Bound the decoded **username** (`authcid`) at **256 bytes**. 256 is far above
  any real username and far below anything that matters for memory.
- **Reuse the existing credential-failure reply. Invent no new reply text.** An
  over-long username is treated exactly as malformed credentials already are
  (`session.rs`, `Reply::new(535, "Authentication credentials invalid")`) —
  same code, same
  text, same path. This deliberately keeps Task 21's conformance surface from
  growing: the branch already has four new reply texts with no Perl counterpart,
  and this adds a fifth divergence but no fifth text.
- The bound is on the **decoded** length in bytes, not the base64 length, and it
  applies to both `decode_plain` (SASL PLAIN) and `decode_login` (SASL LOGIN).
- **The password stays unbounded** and that is deliberate for now: it is never
  retained, so its cost is one transient allocation per connection, itself
  bounded by `--max_connections`. Do not bound it in this item. It is recorded
  as an open question for the user, not an oversight.
- Test both SASL mechanisms: a 256-byte username is accepted, a 257-byte one is
  refused with the existing 535, and the refusal leaves no bucket behind in the
  rate limiter — the last of those is the point of the item and is the assertion
  that must not be omitted.
### Known divergences for Task 21's conformance gate

These are deliberate. The gate will report them; they are not defects.

- **User ruling R39, 2026-09-14: the inactivity timeout covers the whole
  session, not only the part after STARTTLS.** The Perl arms its timer on the
  upgraded stream alone: `SMTPProxy.pm` passes `timeout => 0` to
  `SMTPServer.pm`, whose `$stream->timeout($self->timeout)` applies it to the
  stream at accept, and `SMTPServer/Connection.pm` sets
  `$self->stream->timeout(600)` only inside the successful STARTTLS upgrade. Measured against the running Perl on
  2026-09-14: a client that connects, reads the 220, and then sends nothing
  is still connected 92 s later, with no close and no `Timeout on stream`
  log line. We time the pre-TLS read too, at the same 600 s, because the
  connection limit of spec 9.2 -- which the Perl has no equivalent of --
  takes its slot at accept, so an untimed read before TLS lets an
  unauthenticated client hold every slot for ever by sending nothing at all.
  No new flag: the existing 600 s value covers both phases, and the spec
  names no separate pre-TLS one (the sentence this supersedes is `Before TLS
  there is no inactivity timeout, as in the Perl` in
  `2026-09-10-rust-rewrite-design.md`). The gate would see this only in a Perl test
  that idles a pre-STARTTLS connection past 600 s, and there is no such test.
- **User ruling, 2026-09-14: a connection that has not yet sent a command is
  dropped after 30 s (`--greeting_timeout`, a new flag with that default).**
  This sits beside R39 rather than replacing it: R39 says why the read is
  timed at all, this says why the *first* read is timed harder. R39 alone
  makes the lockout self-healing, not impossible -- 1000 slots over 600 s is
  1.67 connections per second, or one every twelve seconds from each of
  twenty addresses given the per-IP cap of 50, which costs an attacker
  nothing. The deadline applies only before the first complete command line;
  from that line onwards `idle_timeout` governs, so it does not re-arm for the
  EHLO a client sends again after STARTTLS. It is a deliberate narrowing of
  RFC 5321 4.5.3.2, which asks for five minutes per command, defensible only
  because it applies to a connection that has sent nothing at all: a real
  client sends EHLO as soon as it has read the 220. `--greeting_timeout=0`
  hands that first wait back to `idle_timeout`. The gate would see this only
  in a Perl test that connects and then stays silent for over 30 s, and there
  is no such test.
- **Task 22 item 7 (user ruling, 2026-09-13): an AUTH username longer than 256
  decoded bytes is refused.** The Perl applies no length check, so a Perl test
  that authenticates with an absurdly long username would pass there and be
  refused here. It reuses the existing `535 Authentication credentials invalid`
  rather than adding a reply text, so the gate sees a changed *outcome* for one
  input class, not a new string. No real credential reaches 256 bytes.
- **Task 22 item 6 (user ruling, 2026-09-13): the upstream's reply code is
  relayed verbatim instead of being overwritten with 550.** The Perl always
  answers 550 (`Connection.pm:682`), so the gate WILL see this wherever a Perl
  test drives an upstream rejection that is not a 550. It is also the one item
  that fixes a self-contradicting reply rather than adding a policy: today an
  upstream `451 4.3.2 ...` reaches the client as `550 4.3.2 ...`. An unreachable
  upstream becomes 451; our own malformed-address refusal stays 550.
- **Task 22's five original items (user ruling, 2026-09-12).** Three change
  observable behaviour against the Perl and the gate will see them: the header merge is
  case-insensitive, a bare-LF header block splits into individual headers
  instead of one opaque header, and a relayed header carrying an unfolded line
  break is refused with `550 authentication service failed`. Two more diverge
  without changing a conforming exchange: the upstream reply is capped at
  4096 bytes per line and 65536 total, and the privilege drop calls
  `initgroups` before `setgid`.
- **User ruling, 2026-09-14: `authentication service failed` splits into a
  transient and a permanent half.** The Perl answers `550` on all four of our
  call sites (spec 5.3, `Connection.pm`), so the gate WILL see this wherever a
  Perl test drives an API failure: the reply becomes `451 authentication
  service failed`. The *text* is unchanged, so the gate sees a changed code
  for one input class and no new string. Transient where the proxy is at
  fault -- the API call errored, its task failed to join, or no call was
  started at all (an internal invariant break, ours and not the sender's).
  Permanent, and unchanged, where the message is at fault: the unfolded
  header break of Task 22 item 5. RFC 5321 4.2.3 `451` "local error in
  processing", matching what `RelayError::client_code` already answers for an
  unreachable upstream. The API's own `allow: false` policy refusal keeps its
  `550` and is untouched.

- **Exit codes.** The Perl does missing-mandatory → 2 on stderr and `--help` → 1
  on stdout (`pod2usage()` vs `pod2usage(1)`, measured). Ours does
  missing-mandatory → 1 on stderr and `--help`/`--man`/`--version` → 0, per spec
  section 7 and because a `--help` that exits non-zero breaks scripts.
- **`MAIL FROM` fallback on `"0"`.** The Perl's `$apiResult->{from} || $mail{from}`
  is a truthiness test, so the API returning the string `"0"` also falls back to
  the client's sender. We fall back only on an empty string.
- **Pipelined AUTH continuation.** The Perl answers `500 confused authentication
  response` and leaves its data eater installed — a Perl bug. We accept the line.
  RFC 4954 forbids the pipelining, so no real client reaches this.
- **`QUIT 0`.** The Perl's `if ($arguments)` truthiness test wrongly let the
  single argument `0` through as no argument. We answer 501. Ours is correct.
- **`500 Line too long`.** A reply the Perl never sends, reachable at the 64 KiB
  command-line cap. Documented in the README's differences list.
- **Four log-wording drifts** (`src/server/session.rs`, `src/smtplog.rs`): the
  `received <N> MB data` line counts cumulative receipt where the Perl counted
  pending buffer past 1 MB; the Perl's debug line carrying the *decoded* AUTH
  LOGIN username is deliberately omitted; redaction rejoins with a single
  space where the Perl preserved the original whitespace run; and a client that
  hangs up while its mail is being relayed is logged as `Client <addr> hung up`
  (`session.rs:143`) where the Perl always logged `left before ...` — ruling
  R36, whose reasoning follows.
- **User ruling R36, 2026-09-14: a client that hangs up mid-relay is logged as
  `Client <addr> hung up` rather than `Client <addr> left before ...`.** Found
  by Task 21's gate, which drives the race the Perl's `connection-lifecycle.t`
  was written for. The Perl has one place that can notice, so it always logs
  `left before`. We have two, and TCP picks: the client closes with a FIN, so
  the write of the rejection succeeds into the socket buffer and `send` returns
  `Ok`, and only the read after it sees the EOF -- logged from
  `session.rs:143`. Measured deterministic over four runs. The consequence is
  that `session.rs:727` and `session.rs:743` are effectively unreachable for an
  ordinary FIN close; they need an RST, or a teardown hard enough to fail the
  write. Both lines are `info` and both record the same fact, so spec 4.7 is
  satisfied either way and `src/` is not to change for this. Making `left
  before` deterministic would mean polling the client socket for readability
  before every reply -- real complexity bought for a log line.
- **Task 3: `SIZE` is advertised.** The Perl announced no SIZE extension. This
  proxy relays the upstream's stated limit to the client, so a client learns
  the real limit before it sends. When the upstream states none, or has not
  been reached yet, no SIZE line is sent.
- **Task 4: a client's `SIZE=` on `MAIL FROM` is forwarded to the upstream.**
  The Perl's `_cmd_from` builds `MAIL FROM:<addr>` plus only a DSN-keyword
  suffix and drops `SIZE=` entirely. This proxy passes it on when the
  upstream announced SIZE at EHLO, so the upstream can refuse an oversized
  message before the transfer instead of after. When the upstream never
  announced SIZE, the parameter is still dropped, with a warning logged, to
  avoid a `555` on a parameter the upstream never offered.
- **Task 1: a malformed EHLO line whose keyword is preceded by extra
  whitespace (for example `250- SIZE 10240000`) is accepted.** The Perl's
  `/^\d{3}[- ](\S+)/` fails to match such a line and drops it entirely.
  Consequence: against such an upstream this proxy may learn -- and therefore
  advertise -- an extension the Perl would have ignored.
- **Task 7: `--max_message_size` is gone, replaced by `--max_header_size`
  (default 1 MiB).** The proxy stopped having an opinion about message size:
  the only stated limit is the upstream's `SIZE`, advertised to the client and
  forwarded on `MAIL FROM` (the two bullets above). The header block is the
  one thing the proxy still holds whole -- it parses it -- so it is the one
  thing still capped, and a block over the cap is refused with `552 Header
  block exceeds maximum size of <n> bytes`, spoken at the terminator so that
  the rest of the message is drained rather than read as commands. Both flags
  are this proxy's own; the Perl had neither, and no size cap of any kind, so
  the "same CLI flags as the Perl" constraint is untouched.

### Test-suite notes for Tasks 20-21 (CI)

- The part-1 timing tests in `tests/relay.rs` were made host-independent before
  part 1 closed: `Upstream` is generic over `AsyncRead + AsyncWrite` and they run
  over `tokio::io::duplex`, so their margins are arithmetic rather than a
  function of the host's TCP buffers. Keep them that way — the earlier
  socket-based versions went *vacuous* rather than flaky on a fast host, passing
  while measuring the wrong thing.
- `RecordingUpstream` ends DATA on `.\r\n` only, and records raw bytes. Both are
  deliberate: a lenient fake hid a real wire-format bug (the missing line-ending
  normalisation) for fifteen tasks. Do not relax either to make a test green.
- This host's `registries.conf` has no `unqualified-search-registries`, so
  `podman build` cannot resolve the bare name `rust:1-alpine` without a prior
  pull and local tag. The unqualified `FROM` is faithful to the Perl's own
  `FROM alpine:3.15` — the CI file may need a fully-qualified name instead.
