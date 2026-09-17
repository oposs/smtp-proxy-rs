# Streaming DATA Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stream the message body from the client straight to the upstream, so nothing larger than the header block plus one 64 KiB chunk is ever resident.

**Architecture:** `Handler`'s `headers()`/`message()` pair collapses into `open_body()` returning a `BodySink`, which owns the live upstream connection for exactly the body's lifetime. `relay()`'s monolith becomes an `UpstreamSession` that is driven step by step. During DATA the proxy mirrors the upstream: whatever the upstream does to the proxy, the proxy does to the client. The size limit stops being the proxy's opinion and becomes the upstream's, carried in both directions.

**Tech Stack:** Rust 2024, tokio, rustls (ring), thiserror, tracing. Tests: `#[tokio::test]`, plus a Perl conformance gate driven by `make conformance`.

**Spec:** `docs/superpowers/specs/2026-09-15-streaming-data-path-design.md`

## Global Constraints

- **Machine is shared.** Never more than 4 parallel jobs for builds and tests: `cargo test -j 4`. Never compile a parallelism number into the product.
- **Every cargo call takes `timeout: 600000` and is waited for in the same turn.** Never end a turn with a build in flight.
- **Memory.** All Claude sessions on this machine share one 25 GiB cgroup. Any test fed unbounded input runs under `systemd-run --user --scope -p MemoryMax=<n> -- <binary>`.
- **`CARGO_TARGET_DIR`** is per-worktree under `/scratch/oetiker/`. The inherited env points at the shared dir; do not use it.
- **Containers are podman, not docker.**
- **Cite greppable anchors, never line numbers** (ruling R40). Write ``(`session.rs`, `fn read_message`)``, not `session.rs:657`.
- **The Perl at `/home/oetiker/checkouts/smtp-proxy` is the binding authority** for wire format, reply texts, API JSON and log formats — and nothing else. Measure it; never reason about it.
- **Gates, all four, before every commit is called done:**
  - `cargo test -j 4`
  - `make conformance`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo fmt --check`
- **Commit byline:** `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- **Evidence-backed disagreement with this plan is wanted.** If a task's instruction would go red, say so and propose the fix rather than forcing it through.

---

## File Structure

| File | Responsibility after this plan |
|---|---|
| `src/smtp/extensions.rs` | Parse an EHLO reply into keywords **and their parameters**. New: `Extensions` type. |
| `src/relay.rs` | `UpstreamSession`: a driven SMTP client. New: `UpstreamCaps`, `UpstreamVerdict`. Deleted: `normalize_and_stuff`. |
| `src/server/data.rs` | Header collector (bounded) plus a body framer that retains nothing. |
| `src/server/mod.rs` | `Handler::open_body`, new `BodySink` trait, `Handler::size_limit`. |
| `src/server/session.rs` | Client state machine; `read_message` becomes a pump. |
| `src/proxy.rs` | `open_body` = the whole policy gate. New `ProxySink`. Deleted: `format_message`, `relay_message`. |
| `src/config.rs`, `src/main.rs` | `--max_message_size` → `--max_header_size`. |
| `tests/common/fake_handler.rs` | `ScriptedSink` beside `ScriptedHandler`. |
| `tests/common/upstream.rs` | Two new mid-DATA faults, plus a count-and-discard mode. |
| `tests/streaming.rs` | New. The memory invariant. |

---

### Task 1: EHLO extensions keep their parameters

`parse_extensions` throws away everything after the keyword, so `SIZE 10240000` becomes just `SIZE`. Nothing downstream can learn the number.

**Files:**
- Modify: `src/smtp/extensions.rs` (whole file)
- Modify: `src/relay.rs` (`fn open`, `fn probe`, `fn probe_over`, `fn transact` — every `extensions.contains(..)` call site)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub struct Extensions`, with `pub fn contains(&self, keyword: &str) -> bool` and `pub fn size(&self) -> Option<usize>`. `pub fn parse_extensions(ehlo_reply: &str) -> Extensions`.

- [ ] **Step 1: Write the failing tests**

Replace the `tests` module in `src/smtp/extensions.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_are_collected_and_uppercased() {
        let set = parse_extensions(
            "250-recording.upstream\r\n250-dsn\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n",
        );
        assert!(set.contains("DSN"));
        assert!(set.contains("STARTTLS"));
        assert!(!set.contains("PIPELINING"));
    }

    #[test]
    fn garbage_is_ignored() {
        assert!(!parse_extensions("garbage\r\n").contains("DSN"));
        assert!(!parse_extensions("").contains("DSN"));
    }

    #[test]
    fn size_carries_its_value() {
        let e = parse_extensions("250-SIZE 10240000\r\n250 DSN\r\n");
        assert_eq!(e.size(), Some(10_240_000));
    }

    #[test]
    fn size_absent_is_none() {
        assert_eq!(parse_extensions("250 DSN\r\n").size(), None);
    }

    /// RFC 1870: a SIZE with no number, or an unparsable one, announces the
    /// extension without stating a limit. Treated as "no limit stated",
    /// never as zero-length.
    #[test]
    fn size_without_a_usable_number_is_none() {
        assert_eq!(parse_extensions("250 SIZE\r\n").size(), None);
        assert_eq!(parse_extensions("250 SIZE lots\r\n").size(), None);
    }

    /// RFC 1870 gives 0 the meaning "no fixed maximum", so it must not reach
    /// a caller as a limit of zero bytes.
    #[test]
    fn size_zero_means_no_limit() {
        assert_eq!(parse_extensions("250 SIZE 0\r\n").size(), None);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -j 4 --lib extensions`
Expected: FAIL — `no method named 'size'`.

- [ ] **Step 3: Implement**

Replace the top of `src/smtp/extensions.rs` (everything above `#[cfg(test)]`) with:

```rust
//! The extension keywords an EHLO reply announces, with their parameters.
use std::collections::HashMap;

/// One EHLO reply's extensions: keyword (uppercased) to the rest of the
/// line, which is empty when the keyword stands alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extensions(HashMap<String, String>);

impl Extensions {
    pub fn contains(&self, keyword: &str) -> bool {
        self.0.contains_key(&keyword.to_ascii_uppercase())
    }

    /// The SIZE limit the upstream states, if it states a usable one.
    ///
    /// `None` covers three cases a caller must treat alike -- SIZE absent,
    /// SIZE with no parseable number, and RFC 1870's `SIZE 0`, which means
    /// "no fixed maximum". A limit of zero bytes is never what was meant.
    pub fn size(&self) -> Option<usize> {
        self.0
            .get("SIZE")?
            .split_ascii_whitespace()
            .next()?
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
    }
}

pub fn parse_extensions(ehlo_reply: &str) -> Extensions {
    let mut map = HashMap::new();
    for line in ehlo_reply.split(['\r', '\n']) {
        let b = line.as_bytes();
        if b.len() < 4 || !b[..3].iter().all(u8::is_ascii_digit) || !(b[3] == b'-' || b[3] == b' ')
        {
            continue;
        }
        let rest = &line[4..];
        let mut words = rest.split_ascii_whitespace();
        if let Some(word) = words.next() {
            let params = rest[word.len()..].trim_start().to_string();
            map.insert(word.to_ascii_uppercase(), params);
        }
    }
    Extensions(map)
}
```

- [ ] **Step 4: Fix the call sites in `src/relay.rs`**

`Upstream::open` returns `HashSet<String>` today. Change its return type to `Extensions`, and change `transact`'s `extensions: HashSet<String>` parameter to `extensions: Extensions`. Delete the now-unused `use std::collections::HashSet;` if nothing else needs it. The `extensions.contains("DSN")` and `.contains("STARTTLS")` calls need no change — `Extensions::contains` takes `&str` like `HashSet::contains`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -j 4`
Expected: PASS, same count as before plus 3.

- [ ] **Step 6: Gates and commit**

```bash
cargo clippy --all-targets -- -D warnings && cargo fmt --check && make conformance
git add src/smtp/extensions.rs src/relay.rs
git commit
```

Message: `Keep an EHLO extension's parameters, not just its keyword`. Explain that SIZE's number was being discarded at the parse step, so nothing downstream could learn the upstream's limit.

---

### Task 2: Carry the upstream's SIZE through probe and relay

The factory learns DSN from the startup probe and keeps it current from every relay. SIZE rides the same rails.

**Files:**
- Modify: `src/relay.rs` (`struct Relayed`, `fn probe`, `fn probe_over`, `fn transact`)
- Modify: `src/proxy.rs` (`struct ProxyFactory`, `fn note_upstream_dsn`, `fn probe_upstream`, `fn relay_message`)
- Test: `tests/relay.rs`

**Interfaces:**
- Consumes: `Extensions::size()` from Task 1.
- Produces: `pub struct UpstreamCaps { pub dsn: bool, pub size: Option<usize> }`, `Clone + Copy + Debug + PartialEq`. `probe`/`probe_over` return `Result<UpstreamCaps, RelayError>`. `Relayed { message: String, caps: UpstreamCaps }`. On the factory: `fn upstream_size_limit(&self) -> Option<usize>`.

- [ ] **Step 1: Write the failing test**

Add to `tests/relay.rs`:

```rust
#[tokio::test]
async fn probe_reports_the_upstream_size_limit() {
    let up = RecordingUpstream::start(&["DSN", "SIZE 10240000"]).await;
    let caps = probe(&config(&up)).await.unwrap();
    assert!(caps.dsn);
    assert_eq!(caps.size, Some(10_240_000));
}

#[tokio::test]
async fn probe_reports_no_limit_when_size_is_absent() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let caps = probe(&config(&up)).await.unwrap();
    assert!(caps.dsn);
    assert_eq!(caps.size, None);
}
```

Add `probe` to the `use smtp_proxy::relay::{..}` list at the top of the file.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -j 4 --test relay probe_reports`
Expected: FAIL — `probe` returns `bool`, no field `dsn`.

- [ ] **Step 3: Implement in `src/relay.rs`**

```rust
/// What the upstream announced at EHLO, as far as this proxy cares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpstreamCaps {
    pub dsn: bool,
    /// The largest message the upstream states it will take. `None` means
    /// it stated none -- see `Extensions::size`.
    pub size: Option<usize>,
}

impl UpstreamCaps {
    fn of(extensions: &Extensions) -> Self {
        Self {
            dsn: extensions.contains("DSN"),
            size: extensions.size(),
        }
    }
}
```

Change `Relayed`:

```rust
pub struct Relayed {
    pub message: String,
    pub caps: UpstreamCaps,
}
```

`probe` and `probe_over` return `Ok(UpstreamCaps::of(&extensions))` instead of `Ok(extensions.contains("DSN"))`. In `transact`, replace `let upstream_dsn = extensions.contains("DSN");` with `let caps = UpstreamCaps::of(&extensions);` and pass `caps.dsn` where `upstream_dsn` was used, returning `Relayed { message: accepted.text, caps }`.

- [ ] **Step 4: Implement in `src/proxy.rs`**

Add `use std::sync::atomic::AtomicUsize;`. In `ProxyFactory`:

```rust
    /// The upstream's stated SIZE limit, or 0 for "none stated". Zero is
    /// safe as the sentinel because RFC 1870's `SIZE 0` already means "no
    /// fixed maximum", so a real limit is never zero.
    upstream_size: Arc<AtomicUsize>,
```

Initialise to `Arc::new(AtomicUsize::new(0))`. Rename `note_upstream_dsn` to `note_upstream_caps`, keeping its existing change-only DSN logging exactly as it is, and add the size beside it:

```rust
    fn note_upstream_caps(&self, caps: UpstreamCaps) {
        let previous = self.upstream_dsn.swap(caps.dsn, Ordering::Relaxed);
        let known = self.upstream_dsn_known.swap(true, Ordering::Relaxed);
        if !known || previous != caps.dsn {
            info!(
                "{} {}; the extension will {}be offered to clients",
                self.upstream_name(),
                if caps.dsn {
                    "announces DSN"
                } else {
                    "does not announce DSN"
                },
                if caps.dsn { "" } else { "not " }
            );
        }
        let size = caps.size.unwrap_or(0);
        let previous_size = self.upstream_size.swap(size, Ordering::Relaxed);
        if !known || previous_size != size {
            match caps.size {
                Some(n) => info!(
                    "{} accepts messages up to {n} bytes; the limit will be offered to clients",
                    self.upstream_name()
                ),
                None => info!(
                    "{} states no message size limit; none will be offered to clients",
                    self.upstream_name()
                ),
            }
        }
    }

    /// The upstream's stated limit, or `None` when it stated none or has not
    /// been asked yet. Both are the same answer to a client: say nothing.
    pub fn upstream_size_limit(&self) -> Option<usize> {
        match self.upstream_size.load(Ordering::Relaxed) {
            0 => None,
            n => Some(n),
        }
    }
```

Update the two callers: `probe_upstream`'s `Ok(dsn) => self.note_upstream_dsn(dsn)` becomes `Ok(caps) => self.note_upstream_caps(caps)`, and `relay_message`'s `self.factory.note_upstream_dsn(relayed.upstream_dsn)` becomes `self.factory.note_upstream_caps(relayed.caps)`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -j 4`
Expected: PASS, +2.

- [ ] **Step 6: Gates and commit**

Message: `Learn the upstream's stated message size, beside its DSN support`.

---

### Task 3: Advertise SIZE to the client

**Files:**
- Modify: `src/server/mod.rs` (`trait Handler`)
- Modify: `src/server/session.rs` (`fn greeting`)
- Modify: `src/proxy.rs` (`impl Handler for ProxyHandler`)
- Modify: `tests/common/fake_handler.rs`
- Test: `tests/server_commands.rs`, `tests/proxy_end_to_end.rs`
- Modify: `docs/superpowers/plans/2026-09-10-hardening.md` ("Known divergences"), `README.md` (differences list)

**Interfaces:**
- Consumes: `ProxyFactory::upstream_size_limit()` from Task 2.
- Produces: `Handler::size_limit(&self) -> Option<usize>`.

- [ ] **Step 1: Write the failing tests**

In `tests/server_commands.rs`:

```rust
#[tokio::test]
async fn ehlo_announces_the_size_limit_the_handler_reports() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.size_limit = Some(10_240_000));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let reply = c.command("EHLO x").await;
    assert!(reply.contains("SIZE 10240000"), "got {reply:?}");
}

#[tokio::test]
async fn ehlo_omits_size_when_the_handler_reports_none() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.size_limit = None);
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let reply = c.command("EHLO x").await;
    assert!(!reply.contains("SIZE"), "got {reply:?}");
}

/// HELO takes no extension list at all, so the limit must not leak into it.
#[tokio::test]
async fn helo_never_announces_size() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.size_limit = Some(64));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let reply = c.command("HELO x").await;
    assert!(!reply.contains("SIZE"), "got {reply:?}");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -j 4 --test server_commands size`
Expected: FAIL — no field `size_limit` on `Script`.

- [ ] **Step 3: Implement**

In `src/server/mod.rs`, add to `trait Handler`, beside `dsn_available`:

```rust
    /// The largest message to announce in EHLO, or `None` to announce no
    /// SIZE line at all. The proxy has no limit of its own; this is the
    /// upstream's, relayed.
    fn size_limit(&self) -> Option<usize>;
```

In `src/server/session.rs`, `fn greeting`, immediately after the `DSN` push:

```rust
            if let Some(n) = self.handler.size_limit() {
                lines.push(format!("SIZE {n}"));
            }
```

In `src/proxy.rs`:

```rust
    fn size_limit(&self) -> Option<usize> {
        self.factory.upstream_size_limit()
    }
```

In `tests/common/fake_handler.rs`, add `pub size_limit: Option<usize>` to `Script` (default `None`) and:

```rust
    fn size_limit(&self) -> Option<usize> {
        self.script().size_limit
    }
```

- [ ] **Step 4: Add the end-to-end test**

In `tests/proxy_end_to_end.rs`, following the existing DSN-announcement test's shape:

```rust
/// The whole path: the upstream's own SIZE line, learned at the probe,
/// reaches the client's EHLO.
#[tokio::test]
async fn the_upstream_size_limit_reaches_the_client() {
    let up = RecordingUpstream::start(&["DSN", "SIZE 10240000"]).await;
    let (addr, factory) = start_proxy(&up).await;
    factory.probe_upstream().await;
    let (mut c, _) = RawClient::connect(addr).await;
    let reply = c.command("EHLO x").await;
    assert!(reply.contains("SIZE 10240000"), "got {reply:?}");
}
```

Use whichever proxy-start helper that file already defines; do not add a new one.

- [ ] **Step 5: Run the tests**

Run: `cargo test -j 4`
Expected: PASS, +4.

- [ ] **Step 6: Record the divergence**

Add to the "Known divergences" section of `docs/superpowers/plans/2026-09-10-hardening.md` and to the README's differences list:

> **`SIZE` is advertised.** The Perl announced no SIZE extension. This proxy relays the upstream's stated limit to the client, so a client learns the real limit before it sends. When the upstream states none, or has not been reached yet, no SIZE line is sent.

- [ ] **Step 7: Gates and commit**

Message: `Offer the client the upstream's size limit instead of hiding it`.

---

### Task 4: Forward the client's `SIZE=` upstream

Today `dsn_suffix` keeps DSN keywords only, so a client's `SIZE=` on `MAIL FROM` is dropped and the upstream cannot refuse before the transfer.

**Files:**
- Modify: `src/relay.rs` (`fn transact`, new `fn size_suffix`)
- Test: `tests/relay.rs`

**Interfaces:**
- Consumes: `UpstreamCaps` from Task 2.
- Produces: `pub fn size_suffix(params: &[Param], upstream_announces_size: bool) -> String`.

- [ ] **Step 1: Write the failing tests**

In `tests/relay.rs`:

```rust
#[tokio::test]
async fn the_clients_size_is_forwarded_when_the_upstream_announces_size() {
    let up = RecordingUpstream::start(&["SIZE 10240000"]).await;
    let params = vec![Param { keyword: "SIZE".into(), value: Some("4096".into()) }];
    let recipients = vec![Recipient { address: "a@b.com".into(), parameters: vec![] }];
    relay(
        &config(&up),
        Envelope { from: "x@y.com", mail_params: &params, recipients: &recipients },
        b"Subject: x\r\n\r\nbody\r\n",
    )
    .await
    .unwrap();
    assert_eq!(up.commands_matching("MAIL"), vec!["MAIL FROM:<x@y.com> SIZE=4096"]);
}

/// An upstream that never announced SIZE would answer 555 to the parameter.
#[tokio::test]
async fn the_clients_size_is_dropped_when_the_upstream_is_silent_about_size() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let params = vec![Param { keyword: "SIZE".into(), value: Some("4096".into()) }];
    let recipients = vec![Recipient { address: "a@b.com".into(), parameters: vec![] }];
    relay(
        &config(&up),
        Envelope { from: "x@y.com", mail_params: &params, recipients: &recipients },
        b"Subject: x\r\n\r\nbody\r\n",
    )
    .await
    .unwrap();
    assert_eq!(up.commands_matching("MAIL"), vec!["MAIL FROM:<x@y.com>"]);
}
```

Match the existing file's spelling for `Param` and `Recipient` construction; both types are already imported there.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -j 4 --test relay clients_size`
Expected: FAIL — the first asserts `MAIL FROM:<x@y.com> SIZE=4096`, gets `MAIL FROM:<x@y.com>`.

- [ ] **Step 3: Implement**

In `src/relay.rs`, beside `dsn_suffix`:

```rust
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
```

In `transact`, extend the MAIL line:

```rust
    let mail = format!(
        "MAIL FROM:<{}>{}{}",
        envelope.from,
        dsn_suffix(envelope.mail_params, is_mail_dsn_keyword, caps.dsn),
        size_suffix(envelope.mail_params, caps.size.is_some()),
    );
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -j 4`
Expected: PASS, +2.

- [ ] **Step 5: Gates and commit**

Message: `Pass the client's SIZE= on, so the upstream can refuse before the transfer`.

---

### Task 5: Make `Upstream` a driven session (pure refactor)

`relay()` does connect, EHLO, MAIL, RCPT, DATA, whole body and QUIT in one call and takes a complete `&[u8]`. Streaming cannot use it. This task splits it with **no behaviour change** — the existing suite is the gate.

**Files:**
- Modify: `src/relay.rs` (`struct Upstream`, `fn relay`, `fn relay_over`, `fn transact`)

**Interfaces:**
- Consumes: `UpstreamCaps` from Task 2.
- Produces:
  - `pub struct UpstreamSession` (was the private `Upstream`)
  - `pub async fn UpstreamSession::connect(config: &RelayConfig) -> Result<Self, RelayError>` — TCP, TLS, EHLO
  - `pub async fn UpstreamSession::over<S: Io + 'static>(stream: S, timeout: Duration) -> Result<Self, RelayError>`
  - `pub fn UpstreamSession::caps(&self) -> UpstreamCaps`
  - `pub async fn UpstreamSession::open_transaction(&mut self, envelope: Envelope<'_>) -> Result<(), RelayError>` — MAIL, RCPT.., DATA, expects 354
  - `pub async fn UpstreamSession::write(&mut self, chunk: &[u8]) -> Result<(), RelayError>`
  - `pub async fn UpstreamSession::finish(self) -> Result<String, RelayError>` — terminator, final reply, QUIT

- [ ] **Step 1: Rename and open up the type**

Rename `struct Upstream` to `pub struct UpstreamSession` throughout `src/relay.rs`. Add two fields:

```rust
pub struct UpstreamSession {
    stream: BufReader<Box<dyn Io>>,
    timeout: Duration,
    caps: UpstreamCaps,
    /// The last byte handed to `write`, so `finish` knows whether the body
    /// already ends in a newline. `transact` used to see the whole payload
    /// at once and could just look at it.
    last_written: Option<u8>,
}
```

`Upstream::new` becomes a private constructor taking `caps: UpstreamCaps` and setting `last_written: None`.

- [ ] **Step 2: Add the phase methods**

```rust
impl UpstreamSession {
    /// TCP (plus implicit TLS), then the greeting and EHLO -- everything
    /// before a transaction. `caps()` is answerable from here on.
    pub async fn connect(config: &RelayConfig) -> Result<Self, RelayError> {
        let mut up = Self::new(connect(config).await?, config.timeout, UpstreamCaps::default());
        let extensions = up.open(&config.tls, config.server_name()).await?;
        up.caps = UpstreamCaps::of(&extensions);
        Ok(up)
    }

    /// [`connect`] over a stream the caller supplies, without TLS.
    pub async fn over<S: Io + 'static>(stream: S, timeout: Duration) -> Result<Self, RelayError> {
        let mut up = Self::new(Box::new(stream), timeout, UpstreamCaps::default());
        let extensions = up.open(&UpstreamTls::off(), "").await?;
        up.caps = UpstreamCaps::of(&extensions);
        Ok(up)
    }

    pub fn caps(&self) -> UpstreamCaps {
        self.caps
    }

    /// MAIL, every RCPT, then DATA. Returns once the upstream has answered
    /// `354` and the body may be written.
    pub async fn open_transaction(&mut self, envelope: Envelope<'_>) -> Result<(), RelayError> {
        let mail = format!(
            "MAIL FROM:<{}>{}{}",
            envelope.from,
            dsn_suffix(envelope.mail_params, is_mail_dsn_keyword, self.caps.dsn),
            size_suffix(envelope.mail_params, self.caps.size.is_some()),
        );
        self.command("MAIL", mail, 2).await?;
        for r in envelope.recipients {
            let rcpt = format!(
                "RCPT TO:<{}>{}",
                r.address,
                dsn_suffix(&r.parameters, is_rcpt_dsn_keyword, self.caps.dsn)
            );
            self.command("RCPT", rcpt, 2).await?;
        }
        self.command("DATA", "DATA".into(), 3).await
    }

    /// One piece of the body, already dot-stuffed and CRLF-terminated by the
    /// caller.
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), RelayError> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.last_written = chunk.last().copied();
        self.write_body(chunk).await
    }

    /// The terminator, the upstream's verdict on the message, then QUIT.
    pub async fn finish(mut self) -> Result<String, RelayError> {
        // RFC 5321 4.1.1.4: the terminator is a line of its own, so a body
        // that did not end in CRLF gets one first. `transact` used to make
        // this decision against the whole payload.
        let tail: &[u8] = if self.last_written == Some(b'\n') {
            b".\r\n"
        } else {
            b"\r\n.\r\n"
        };
        self.write_body(tail).await?;
        let accepted = self.read_reply().await?;
        if accepted.code / 100 != 2 {
            return Err(RelayError::Rejected {
                command: "DATA_END",
                code: accepted.code,
                text: accepted.text,
            });
        }
        self.quit().await;
        Ok(accepted.text)
    }
}
```

- [ ] **Step 3: Rewrite `relay`, `relay_over`, `probe`, `probe_over` on top of it, delete `transact`**

```rust
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
    finish_relay(UpstreamSession::connect(config).await?, envelope, message).await
}

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
    finish_relay(UpstreamSession::over(stream, timeout).await?, envelope, message).await
}

async fn finish_relay(
    mut up: UpstreamSession,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    let caps = up.caps();
    up.open_transaction(envelope).await?;
    up.write(&normalize_and_stuff(message)).await?;
    let message = up.finish().await?;
    Ok(Relayed { message, caps })
}
```

`probe` and `probe_over` become `UpstreamSession::connect(config).await?` / `::over(..)`, then read `caps()`, then `quit()`. Make `quit` `pub(crate)` or add `pub async fn close(mut self)` that calls it — whichever keeps clippy quiet.

- [ ] **Step 4: Run the whole suite — this is the gate**

Run: `cargo test -j 4`
Expected: PASS, **exactly the same count as Task 4 left**. A refactor that changes a count has changed behaviour. If the count moves, stop and find out why before going on.

- [ ] **Step 5: Gates and commit**

Message: `Turn the relay monolith into an upstream session that is driven`. Say plainly that this is a behaviour-preserving refactor and that the unchanged test count is the evidence.

---

### Task 6: `UpstreamVerdict`, and noticing an early reply while writing

The hazard: if `write` only writes, an upstream `552` sits unread until `finish()`, and an upstream that rejects and stops reading fills our send buffer, so we report a *timeout* instead of what it said.

**Files:**
- Modify: `src/relay.rs` (`fn write`, `fn finish`, new `enum UpstreamVerdict`)
- Modify: `tests/common/upstream.rs`
- Test: `tests/relay.rs`

**Interfaces:**
- Consumes: `UpstreamSession` from Task 5.
- Produces:
  - `pub enum UpstreamVerdict { Dropped, Replied { code: u16, text: String } }`
  - `UpstreamSession::write` → `Result<(), UpstreamVerdict>`; `finish` → `Result<String, UpstreamVerdict>`
  - `pub fn UpstreamVerdict::into_relay_error(self) -> RelayError`
  - On the fake: `pub fn reject_during_data(&self, after_bytes: usize, reply: (u16, &str))`, `pub fn drop_during_data(&self, after_bytes: usize)`

- [ ] **Step 1: Add the two faults to the fake**

In `tests/common/upstream.rs`, add to `struct Inner`:

```rust
    /// After this many body bytes have been consumed, send this reply and
    /// stop reading entirely: an upstream that refuses mid-transfer and
    /// leaves the sender to notice. The unread bytes are what fill the
    /// relay's send buffer, so a relay that does not watch for a reply while
    /// writing blocks here until its inactivity timer fires.
    reject_during_data: Option<(usize, u16, String)>,
    /// After this many body bytes have been consumed, close the connection.
    drop_during_data: Option<usize>,
```

Both default to `None` in `Inner::new`. Add setters in the shape of the existing `reject_data_end`:

```rust
    pub fn reject_during_data(&self, after_bytes: usize, reply: (u16, &str)) {
        self.inner.lock().unwrap().reject_during_data =
            Some((after_bytes, reply.0, reply.1.to_string()));
    }

    pub fn drop_during_data(&self, after_bytes: usize) {
        self.inner.lock().unwrap().drop_during_data = Some(after_bytes);
    }
```

In the connection task's body-reading loop, alongside where `data_pace` is honoured, count consumed body bytes and: on reaching `reject_during_data`'s threshold, write `"{code} {text}\r\n"` and then return from the connection task **without reading any further** (do not close the socket — the point is that it stays open and unread); on reaching `drop_during_data`'s threshold, return immediately so the socket closes.

- [ ] **Step 2: Write the failing tests**

In `tests/relay.rs`:

```rust
/// An upstream that refuses mid-body and stops reading. The relay must
/// surface the upstream's own code, not a timeout: a body several times
/// larger than the socket buffers guarantees the writes actually block.
#[tokio::test]
async fn a_rejection_during_the_body_is_reported_as_the_upstreams_reply() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.reject_during_data(4096, (552, "5.3.4 too big"));
    let body = format!("Subject: x\r\n\r\n{}\r\n", "y".repeat(8 * 1024 * 1024));
    let err = relay(&config_with_timeout(&up, Duration::from_secs(5)), envelope(), body.as_bytes())
        .await
        .unwrap_err();
    match err {
        RelayError::Rejected { code, ref text, .. } => {
            assert_eq!(code, 552);
            assert_eq!(text, "5.3.4 too big");
        }
        other => panic!("expected the upstream's 552, got {other:?}"),
    }
}

/// The same shape, but the upstream simply goes away. That has no reply to
/// report, so it must not become a fabricated one.
#[tokio::test]
async fn a_drop_during_the_body_is_not_reported_as_a_rejection() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.drop_during_data(4096);
    let body = format!("Subject: x\r\n\r\n{}\r\n", "y".repeat(8 * 1024 * 1024));
    let err = relay(&config_with_timeout(&up, Duration::from_secs(5)), envelope(), body.as_bytes())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RelayError::Io(_)),
        "a dead connection has no verdict to report, got {err:?}"
    );
}
```

```rust
/// Spec 6.2: a hung upstream -- not dropped, not replying -- cannot be
/// mirrored, because mirroring "hangs forever" would leak a connection per
/// hung upstream. The inactivity timer turns it into `Dropped`.
#[tokio::test]
async fn an_upstream_that_hangs_during_the_body_becomes_a_drop() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.stall_data(Duration::from_secs(30));
    let body = format!("Subject: x\r\n\r\n{}\r\n", "y".repeat(8 * 1024 * 1024));
    let err = relay(&config_with_timeout(&up, Duration::from_millis(200)), envelope(), body.as_bytes())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RelayError::Io(_) | RelayError::Timeout),
        "a hung upstream has no verdict to report, got {err:?}"
    );
}
```

Add a small `fn envelope() -> Envelope<'static>` helper to the file if one is not already there, matching how the existing tests build theirs.

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -j 4 --test relay during_the_body`
Expected: the first FAILS with `RelayError::Timeout` — which is exactly the hazard. **If it passes at this point, stop: the fault is not firing, and the test is vacuous.** Check the threshold is smaller than the body and that the fake really stops reading.

- [ ] **Step 4: Implement**

In `src/relay.rs`:

```rust
/// What the upstream did, when it did something other than accept.
///
/// During DATA the proxy mirrors the upstream, so this is the whole
/// vocabulary a caller needs: either the upstream said something, which is
/// relayed verbatim, or the connection died, which has nothing to relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamVerdict {
    Dropped,
    Replied { code: u16, text: String },
}

impl UpstreamVerdict {
    pub fn into_relay_error(self) -> RelayError {
        match self {
            UpstreamVerdict::Dropped => RelayError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "upstream closed the connection during DATA",
            )),
            UpstreamVerdict::Replied { code, text } => RelayError::Rejected {
                command: "DATA",
                code,
                text,
            },
        }
    }
}
```

Rewrite `write` to watch for a reply while writing:

```rust
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), UpstreamVerdict> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.last_written = chunk.last().copied();
        for piece in chunk.chunks(WRITE_CHUNK) {
            // An upstream may refuse mid-transfer, and one that refuses
            // usually stops reading. Writing blind would then fill the send
            // buffer and time out, reporting our own impatience instead of
            // its answer -- so both are awaited together and whichever
            // happens first wins.
            tokio::select! {
                written = tokio::time::timeout(self.timeout, self.stream.get_mut().write_all(piece)) => {
                    match written {
                        Err(_) => return Err(UpstreamVerdict::Dropped),
                        Ok(Err(_)) => return Err(UpstreamVerdict::Dropped),
                        Ok(Ok(())) => {}
                    }
                }
                early = self.read_reply() => {
                    return Err(match early {
                        Ok(r) => UpstreamVerdict::Replied { code: r.code, text: r.text },
                        Err(_) => UpstreamVerdict::Dropped,
                    });
                }
            }
            if self.flush().await.is_err() {
                return Err(UpstreamVerdict::Dropped);
            }
        }
        Ok(())
    }
```

`finish` returns `Result<String, UpstreamVerdict>`: a non-2xx final reply becomes `Replied { code, text }`, and any I/O or timeout failure becomes `Dropped`. In `finish_relay`, map with `.map_err(UpstreamVerdict::into_relay_error)?` so `relay()` keeps the error shape its existing tests assert.

**The `select!` needs `read_reply` to be cancel-safe.** It is not, as written: it accumulates into a local `String`. Move that accumulator into `UpstreamSession` as a field so a cancelled read resumes where it stopped, rather than losing a partial line. If that turns out to be a larger change than it looks, say so and propose the alternative — a readable-check before each chunk write — rather than leaving a subtly lossy read in place.

- [ ] **Step 5: Run the tests**

Run: `cargo test -j 4`
Expected: PASS, +2.

- [ ] **Step 6: Prove the faults are not vacuous**

For **each** of the two new tests: invert the assertion, run it, confirm it fails, then restore it. A fault-injection test whose assertion cannot fail is worth nothing. Record both observations in the commit message.

- [ ] **Step 7: Gates and commit**

Message: `Notice an upstream that refuses mid-body, instead of timing out at it`.

---

### Task 7: Reshape `DataReader`; `--max_message_size` becomes `--max_header_size`

The body cap exists to bound memory. Once the body streams there is nothing to bound, and the header block becomes the only thing still held whole.

**Files:**
- Modify: `src/server/data.rs` (whole file)
- Modify: `src/config.rs`, `src/main.rs`, `src/server/mod.rs` (`ServerConfig`)
- Modify: `tests/cli.rs`, `tests/server_commands.rs`, `tests/common/mod.rs`
- Modify: `README.md`, `docs/superpowers/plans/2026-09-10-hardening.md`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub struct HeaderCollector`, `pub fn HeaderCollector::new(max_header_size: usize) -> Self`, `pub fn push_line(&mut self, line: &[u8]) -> Option<HeaderEvent>`, `pub fn remaining_capacity(&self) -> Option<usize>`, `pub fn mark_too_large(&mut self)`, `pub fn take_pending(&mut self) -> Option<String>`
  - `pub enum HeaderEvent { Complete(String), Terminator, TooLarge }`, `#[derive(Debug)]` -- the unit tests match on it with `{other:?}`
  - `pub struct BodyFramer`, `pub fn BodyFramer::new() -> Self`, `pub fn push(&mut self, line: &[u8]) -> BodyPiece`, `pub fn flush(&mut self) -> Vec<u8>`
  - `pub enum BodyPiece { Chunk(Vec<u8>), Terminator }`
  - CLI: `--max_header_size`, default `1 << 20`; `ServerConfig::max_header_size`

- [ ] **Step 1: Write the failing unit tests**

Replace the `tests` module in `src/server/data.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_end_at_the_blank_line() {
        let mut h = HeaderCollector::new(usize::MAX);
        assert!(h.push_line(b"A: 1\r\n").is_none());
        match h.push_line(b"\r\n") {
            Some(HeaderEvent::Complete(s)) => assert_eq!(s, "A: 1\r\n"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_terminator_before_any_blank_line_is_a_header_only_message() {
        let mut h = HeaderCollector::new(usize::MAX);
        assert!(h.push_line(b"A: 1\r\n").is_none());
        assert!(matches!(h.push_line(b".\r\n"), Some(HeaderEvent::Terminator)));
        assert_eq!(h.take_pending().unwrap(), "A: 1\r\n");
    }

    #[test]
    fn headers_over_the_cap_report_too_large() {
        let mut h = HeaderCollector::new(8);
        assert!(matches!(
            h.push_line(b"A: aaaaaaaaaaaaaaaaaaaa\r\n"),
            Some(HeaderEvent::TooLarge)
        ));
    }

    #[test]
    fn a_body_line_passes_through_unchanged() {
        let mut f = BodyFramer::new();
        match f.push(b"hello\r\n") {
            BodyPiece::Chunk(_) => {}
            BodyPiece::Terminator => panic!("not a terminator"),
        }
        assert_eq!(f.flush(), b"hello\r\n");
    }

    /// Dot stuffing is the client's and the upstream's business. Unstuffing
    /// and restuffing was the identity for correct input, and for a client
    /// that under-stuffed both paths land on the same bytes at the far end.
    #[test]
    fn a_stuffed_line_is_not_touched() {
        let mut f = BodyFramer::new();
        f.push(b"..hidden\r\n");
        assert_eq!(f.flush(), b"..hidden\r\n");
    }

    #[test]
    fn a_bare_newline_becomes_crlf() {
        let mut f = BodyFramer::new();
        f.push(b"hello\n");
        assert_eq!(f.flush(), b"hello\r\n");
    }

    #[test]
    fn the_terminator_is_recognised_in_both_spellings() {
        assert!(matches!(BodyFramer::new().push(b".\r\n"), BodyPiece::Terminator));
        assert!(matches!(BodyFramer::new().push(b".\n"), BodyPiece::Terminator));
    }

    /// A body with no line break at all must not be held: the framer emits
    /// what it has and stays mid-line, so nothing accumulates.
    #[test]
    fn a_partial_line_is_emitted_and_does_not_end_the_message() {
        let mut f = BodyFramer::new();
        assert!(matches!(f.push_partial(b"no break here"), BodyPiece::Chunk(_)));
        // Still mid-line, so a following "." is body, not a terminator.
        assert!(matches!(f.push(b".\r\n"), BodyPiece::Chunk(_)));
    }

    /// A chunk that ends on a lone CR cannot be normalised yet: the byte is
    /// held back rather than guessed at.
    #[test]
    fn a_trailing_cr_is_carried_to_the_next_piece() {
        let mut f = BodyFramer::new();
        f.push_partial(b"abc\r");
        assert_eq!(f.flush(), b"abc");
        f.push_partial(b"\ndef");
        assert_eq!(f.flush(), b"\r\ndef");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -j 4 --lib data`
Expected: FAIL — `HeaderCollector` not found.

- [ ] **Step 3: Implement `src/server/data.rs`**

Replace the whole non-test part. `HeaderCollector` is today's `DataReader` with `body`, `headers_done` and the body branch removed, and `max_size` renamed `max_header_size`. `BodyFramer` is new:

```rust
/// One piece of body, on its way to the upstream.
#[derive(Debug)]
pub enum BodyPiece {
    Chunk(Vec<u8>),
    /// The lone dot. The body is over.
    Terminator,
}

/// Frames the body after the header block. Retains nothing beyond one
/// staging buffer and, at most, a single held-back CR.
///
/// Body lines pass through **verbatim**: the proxy neither unstuffs nor
/// restuffs. Only the line ending is normalised to CRLF, which is the one
/// thing `normalize_and_stuff` did that the wire still needs.
pub struct BodyFramer {
    out: Vec<u8>,
    /// True when the next byte begins a line. The terminator is meaningful
    /// only there -- and a multi-gigabyte line is self-evidently not a
    /// three-byte terminator.
    at_line_start: bool,
    /// A CR at the end of a piece: we cannot yet tell CRLF from a bare CR,
    /// so the byte waits for the next one rather than being guessed at.
    held_cr: bool,
}

impl BodyFramer {
    pub fn new() -> Self {
        Self { out: Vec::with_capacity(WRITE_CHUNK), at_line_start: true, held_cr: false }
    }

    /// A complete line, terminator included.
    pub fn push(&mut self, line: &[u8]) -> BodyPiece {
        if self.at_line_start && (line == b".\r\n" || line == b".\n") {
            return BodyPiece::Terminator;
        }
        self.append(line);
        self.at_line_start = true;
        BodyPiece::Chunk(std::mem::take(&mut self.out))
    }

    /// Bytes with no line ending in sight. The caller has hit its buffer
    /// bound, so these go out as they are and the framer stays mid-line.
    pub fn push_partial(&mut self, bytes: &[u8]) -> BodyPiece {
        self.append(bytes);
        self.at_line_start = false;
        BodyPiece::Chunk(std::mem::take(&mut self.out))
    }

    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    fn append(&mut self, bytes: &[u8]) {
        let mut i = 0;
        if self.held_cr {
            self.held_cr = false;
            if bytes.first() == Some(&b'\n') {
                self.out.extend_from_slice(b"\r\n");
                i = 1;
            } else {
                self.out.extend_from_slice(b"\r\n");
            }
        }
        while i < bytes.len() {
            match bytes[i] {
                b'\r' if i + 1 == bytes.len() => {
                    self.held_cr = true;
                    i += 1;
                }
                b'\r' if bytes[i + 1] == b'\n' => {
                    self.out.extend_from_slice(b"\r\n");
                    i += 2;
                }
                b'\n' => {
                    self.out.extend_from_slice(b"\r\n");
                    i += 1;
                }
                b => {
                    self.out.push(b);
                    i += 1;
                }
            }
        }
    }
}

impl Default for BodyFramer {
    fn default() -> Self {
        Self::new()
    }
}
```

Define `pub const WRITE_CHUNK: usize = 64 * 1024;` here and have `relay.rs` use this one rather than keeping its own — two constants with the same job drift apart, and `MAX_REPLY_LINE` in this project already shows how that ends.

- [ ] **Step 4: Swap the flag**

In `src/config.rs`, replace the `max_message_size` argument with:

```rust
    #[arg(
        long = "max_header_size",
        default_value_t = 1 << 20,
        help = "largest header block accepted, in bytes"
    )]
    pub max_header_size: usize,
```

Rename the field in the config struct and its assignment, in `ServerConfig` (`src/server/mod.rs`), and at the `main.rs` call site. Update `tests/common/mod.rs`'s `server_config` helper.

- [ ] **Step 5: Update the cap tests**

In `tests/server_commands.rs`, the four tests setting `config.max_message_size = 64` become `config.max_header_size = 64`, and their bodies must put the oversized content **in the headers**, since the body is no longer capped. The expected reply text changes to `552 Header block exceeds maximum size of 64 bytes\r\n`. Rename each test accordingly (for example `message_over_the_cap_is_refused_with_552` → `header_block_over_the_cap_is_refused_with_552`).

In `tests/cli.rs`, rename the `--max_message_size` assertions to `--max_header_size` and change the expected default to `1048576`.

- [ ] **Step 6: Run the tests**

Run: `cargo test -j 4`
Expected: PASS. Count rises by the new `data.rs` unit tests.

- [ ] **Step 7: Record it, gates, commit**

Note in the README and the hardening plan's divergence list that `--max_message_size` is gone, replaced by `--max_header_size`, because the body is now governed by the upstream's `SIZE`. Both flags are this project's own; the Perl had neither, so the "same CLI flags as the Perl" constraint is untouched.

Message: `Bound the header block, and stop pretending to bound the body`.

---

### Task 8: `BodySink`, with behaviour preserved

> **Do not merge the branch between tasks 7 and 9.** Task 7 removed the body
> cap (`--max_message_size`), and both it and this task still hold the whole
> body in memory -- task 7 in `read_message`'s bridge, this one in a `ProxySink`
> that still buffers. A merge here would be strictly worse than `4b78405` on
> the very axis this branch exists to fix. Task 9 restores the bound.

This changes the **interface** only. `ProxySink` still buffers and still calls `relay()`, so every existing test must pass unchanged. Task 9 changes the behaviour behind it.

**Files:**
- Modify: `src/server/mod.rs` (`trait Handler`, new `trait BodySink`)
- Modify: `src/server/session.rs` (`fn read_message`)
- Modify: `src/proxy.rs` (`impl Handler`, new `ProxySink`)
- Modify: `tests/common/fake_handler.rs`

**Interfaces:**
- Consumes: `HeaderCollector`, `BodyFramer`, `BodyPiece`, `WRITE_CHUNK` from Task 7; `UpstreamVerdict` from Task 6.
- Produces:
  - `pub trait BodySink: Send` with `fn write(&mut self, chunk: &[u8]) -> impl Future<Output = Result<(), UpstreamVerdict>> + Send;` and `fn finish(self) -> impl Future<Output = Result<String, UpstreamVerdict>> + Send;`
  - `Handler` gains `type Sink: BodySink;` and `fn open_body(&mut self, headers: String) -> impl Future<Output = Result<Self::Sink, Rejection>> + Send;`
  - `Handler::headers` and `Handler::message` are removed.

- [ ] **Step 1: Write the failing test**

In `tests/server_commands.rs`:

```rust
/// The mirror rule at its cheapest: an upstream that dies mid-body takes the
/// client connection with it, with no reply invented on its behalf.
#[tokio::test]
async fn an_upstream_that_drops_mid_body_closes_the_client_connection() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.sink_verdict = Some(UpstreamVerdict::Dropped));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\nbody\r\n.\r\n").await;
    assert!(c.expect_close().await, "a dead upstream must close the client too");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -j 4 --test server_commands drops_mid_body`
Expected: FAIL — no field `sink_verdict`.

- [ ] **Step 3: Change the trait in `src/server/mod.rs`**

```rust
/// Consumes one message body. Obtained from [`Handler::open_body`] and owned
/// for exactly the body's lifetime.
///
/// Dropping it without `finish` **aborts** the message: the upstream
/// connection closes with no terminator sent, so nothing is delivered. That
/// is the whole abort path -- there is no other.
pub trait BodySink: Send {
    fn write(&mut self, chunk: &[u8])
        -> impl Future<Output = Result<(), UpstreamVerdict>> + Send;
    fn finish(self) -> impl Future<Output = Result<String, UpstreamVerdict>> + Send;
}
```

In `trait Handler`, delete `headers` and `message` and add:

```rust
    type Sink: BodySink;

    /// The header block is complete and the body is about to arrive. This is
    /// where every decision the proxy makes on its own is made: the policy
    /// verdict, the header merge, the upstream connection and the envelope.
    ///
    /// Once this returns a sink, the proxy has no opinions left -- from then
    /// on it only relays what the upstream says. That is why the two error
    /// types differ: `Rejection` is the proxy's own voice, `UpstreamVerdict`
    /// is the upstream's.
    fn open_body(&mut self, headers: String)
        -> impl Future<Output = Result<Self::Sink, Rejection>> + Send;
```

- [ ] **Step 4: Rewrite `read_message` in `src/server/session.rs`**

Header phase: `HeaderCollector` bounded by `self.config.max_header_size`, using the existing `next_line` budget and `TooLong` handling, and on `HeaderEvent::TooLarge` keeping today's discard-to-terminator, `552`, `start_transaction()` resync — with the text now `Header block exceeds maximum size of {n} bytes`.

On `HeaderEvent::Complete(h)` (or `Terminator` with `take_pending`), call `self.handler.open_body(h).await`. An `Err(rejection)` discards to the terminator and replies with it, as the header-cap path does.

Body phase, with a sink in hand:

```rust
        let mut framer = BodyFramer::new();
        loop {
            let piece = match self.next_line(WRITE_CHUNK).await? {
                Line::Got(line) => framer.push(&line),
                // No newline within a chunk's worth of bytes. There is no
                // body cap to refuse it against, so it goes out as it is and
                // the framer stays mid-line -- which is what stops `self.buf`
                // growing with a body that has no line breaks at all.
                Line::TooLong => {
                    let partial = std::mem::take(&mut self.buf);
                    framer.push_partial(&partial)
                }
                Line::Eof => {
                    info!("Client {} hung up during DATA", self.client);
                    // `sink` is dropped here: the upstream connection closes
                    // with no terminator, so nothing is delivered.
                    return Ok(Flow::Close);
                }
            };
            match piece {
                BodyPiece::Chunk(chunk) => {
                    if let Err(verdict) = sink.write(&chunk).await {
                        return self.mirror(verdict).await;
                    }
                }
                BodyPiece::Terminator => break,
            }
        }
        let outcome = sink.finish().await;
```

and the mirror itself:

```rust
    /// The proxy is a mirror during DATA: whatever the upstream did to us,
    /// we do to the client. A client is not insulated from what it would
    /// have met talking to the upstream directly.
    async fn mirror(&mut self, verdict: UpstreamVerdict) -> std::io::Result<Flow> {
        self.state = State::WantMail;
        match verdict {
            UpstreamVerdict::Dropped => {
                info!("Upstream closed during DATA for {}; closing the client too", self.client);
                Ok(Flow::Close)
            }
            UpstreamVerdict::Replied { code, text } => {
                // Sent now, mid-DATA, exactly as the upstream sent it to us.
                // What follows is body the client is still writing, and a
                // server that has already answered reads it only to resync.
                self.send(Reply::new(code, text)).await?;
                self.discard_to_terminator().await?;
                self.start_transaction();
                Ok(Flow::Continue)
            }
        }
    }
```

Factor the existing discard-until-terminator logic — including the `discarding_line_tail` handling that stops a tail beginning with `.` from ending DATA early — into `async fn discard_to_terminator(&mut self)`, and use it from all three places that need it.

- [ ] **Step 5: `ProxySink` in `src/proxy.rs`, still buffering**

`open_body` becomes today's `headers()` and `message()` run back to back: spawn nothing, await the API inline, and on `allow` return a sink. The sink holds the merged headers and a `Vec<u8>`:

```rust
/// Buffers, for now, and relays on `finish`. Task 9 replaces the innards
/// with a live upstream session; the interface above it does not change.
pub struct ProxySink {
    factory: ProxyFactory,
    client: SocketAddr,
    envelope: OwnedEnvelope,
    message: Vec<u8>,
}

impl BodySink for ProxySink {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), UpstreamVerdict> {
        self.message.extend_from_slice(chunk);
        Ok(())
    }

    async fn finish(self) -> Result<String, UpstreamVerdict> {
        // Moved here unchanged from `relay_message`, in its existing order:
        // the `relay(&config.relay, envelope, &message)` call; on Ok, the
        // `note_upstream_caps(relayed.caps)` refresh and the two `info!`
        // arms that name the auth token or say there was none; on Err, the
        // existing `RelayError`-to-reply mapping with its codes untouched.
        // Its `Rejection` becomes `UpstreamVerdict::Replied { code, text }`.
    }
}
```

`OwnedEnvelope` is a small owned mirror of `Envelope<'a>` (`from: String`, `mail_params: Vec<Param>`, `recipients: Vec<Recipient>`), because the sink outlives the borrow. Keep `format_message` and `normalize_and_stuff` for this task only.

- [ ] **Step 6: `ScriptedSink` in `tests/common/fake_handler.rs`**

Add to `Script`: `pub sink_verdict: Option<UpstreamVerdict>` (default `None`), keeping `message_result`, `message_delay` and `message_hold` with their current meanings, now honoured in `finish`. Rename `Recorded::headers` usage to be filled by `open_body`. Then:

```rust
pub struct ScriptedSink {
    script: Arc<Mutex<Script>>,
    recorded: Arc<Mutex<Recorded>>,
    body: Vec<u8>,
}

impl BodySink for ScriptedSink {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), UpstreamVerdict> {
        if let Some(v) = self.script.lock().unwrap().sink_verdict.clone() {
            return Err(v);
        }
        self.body.extend_from_slice(chunk);
        Ok(())
    }

    async fn finish(self) -> Result<String, UpstreamVerdict> {
        let script = self.script.lock().unwrap().clone();
        if let Some(hold) = &script.message_hold {
            hold.notified().await;
        }
        tokio::time::sleep(script.message_delay).await;
        self.recorded.lock().unwrap().bodies.push(self.body);
        script.message_result.map_err(|r| UpstreamVerdict::Replied { code: r.code, text: r.text })
    }
}
```

`ScriptedHandler::open_body` records the headers, bumps `message_started`, and returns a `ScriptedSink`.

- [ ] **Step 7: Run the whole suite — this is the gate**

Run: `cargo test -j 4` then `make conformance`
Expected: PASS. **The conformance gate must stay at 9 files, 95 tests.** This task changed an interface, not a behaviour; a conformance failure here means a behaviour moved and must be found before Task 9 builds on it.

- [ ] **Step 8: Gates and commit**

Message: `Hand the session a body sink instead of a finished message`. State that behaviour is unchanged and that the unchanged conformance result is the evidence.

---

### Task 9: Stream for real

> **This is the task that restores the bound on message size.** From task 7
> until this one lands the body is uncapped *and* held whole, so the branch is
> not mergeable in part -- see the note on task 8.

**Files:**
- Modify: `src/proxy.rs` (`ProxySink`, `fn open_body`; delete `format_message`)
- Modify: `src/relay.rs` (delete `normalize_and_stuff`)
- Test: `tests/proxy_end_to_end.rs`
- Modify: `README.md`, `docs/superpowers/plans/2026-09-10-hardening.md`

**Interfaces:**
- Consumes: everything from Tasks 5, 6, 8.
- Produces: no new public API. `ProxySink` now holds an `UpstreamSession`.

- [ ] **Step 1: Write the failing tests**

In `tests/proxy_end_to_end.rs`:

```rust
/// The upstream must see the envelope before the client has finished
/// sending. Under the old design MAIL FROM could not appear until the
/// terminator had arrived.
#[tokio::test]
async fn the_envelope_reaches_the_upstream_before_the_body_ends() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let (addr, _factory) = start_proxy(&up).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\npartial body, no terminator yet\r\n").await;
    // No terminator has been sent, so under a buffering proxy the upstream
    // would still be untouched.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while up.commands_matching("MAIL").is_empty() {
        assert!(std::time::Instant::now() < deadline, "upstream never saw MAIL FROM");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
}

/// An upstream that refuses mid-body: its own code and text reach the
/// client, and the session stays usable afterwards.
#[tokio::test]
async fn an_upstream_rejection_mid_body_reaches_the_client_verbatim() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.reject_during_data(4096, (552, "5.3.4 too big"));
    let (addr, _factory) = start_proxy(&up).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(&format!("Subject: x\r\n\r\n{}\r\n.\r\n", "y".repeat(8 * 1024 * 1024)))
        .await;
    assert_eq!(c.read_reply().await, "552 5.3.4 too big\r\n");
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

/// A client that abandons the message mid-body must not deliver it.
#[tokio::test]
async fn a_client_that_hangs_up_mid_body_delivers_nothing() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let (addr, _factory) = start_proxy(&up).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\nhalf a body\r\n").await;
    drop(c);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(up.messages().is_empty(), "an abandoned message must not be delivered");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -j 4 --test proxy_end_to_end before_the_body_ends`
Expected: FAIL — the upstream sees no `MAIL` until the terminator.

- [ ] **Step 3: Implement `open_body`**

```rust
    async fn open_body(&mut self, headers: String) -> Result<Self::Sink, Rejection> {
        self.transaction.headers = parse_headers(&headers);
        debug!("Asking the API about the headers, and opening the upstream");
        // The verdict is needed before MAIL FROM, which the API may rewrite,
        // and before the headers go out -- both ahead of the body. So the
        // connect is the only thing that can overlap the call, and it does.
        let (verdict, upstream) = tokio::join!(
            self.factory.config.api.check(&self.check_request()),
            UpstreamSession::connect(&self.factory.config.relay),
        );
        let outcome = match verdict {
            Ok(o) => o,
            Err(e) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                return Err(auth_service_unavailable());
            }
        };
        if !outcome.allow {
            let reason = outcome.reason.clone().unwrap_or_default();
            info!("Mail rejected by API ({reason}) for {}", self.client);
            debug!("INPUT {}", self.check_request().redacted_json());
            // `upstream` is dropped here, unused. A refused message costs the
            // upstream one opened connection and nothing else.
            return Err(Rejection { code: 550, text: reason });
        }
        // Lifted from `relay_message`, unchanged and in its order:
        // `merge_headers(self.transaction.headers.clone(), &outcome.headers)`;
        // `assert_header_relayable(&headers)`, whose Err warns with
        // `which.escape_debug()` and returns `auth_service_failed()`; the
        // `outcome.from` / `self.transaction.from` choice with its
        // `.filter(|f| !f.is_empty())`; then `assert_relayable` on the
        // sender and on every recipient, before the connection is used.
        let mut upstream = upstream.map_err(relay_error_to_rejection)?;
        self.factory.note_upstream_caps(upstream.caps());
        upstream
            .open_transaction(envelope)
            .await
            .map_err(relay_error_to_rejection)?;
        upstream
            .write(&header_block)
            .await
            .map_err(|v| relay_error_to_rejection(v.into_relay_error()))?;
        Ok(ProxySink { /* .. */ })
    }
```

`header_block` is the merged headers formatted as `Name: value\r\n` lines followed by the blank line — `format_message`'s loop without the body. `relay_error_to_rejection` is the existing `RelayError`-to-reply mapping lifted out of `relay_message`; keep its codes exactly.

`ProxySink::write` forwards to `UpstreamSession::write`; `finish` calls `UpstreamSession::finish` and keeps the existing success logging.

- [ ] **Step 4: Delete what is now dead**

`format_message` and its test, `normalize_and_stuff` and its tests, `relay_message`, `Transaction::api_call` and its `JoinHandle` import, and the `reset()` branch that aborts the API call. Let clippy find the rest.

- [ ] **Step 5: Run everything**

Run: `cargo test -j 4` then `make conformance`
Expected: PASS, conformance still 9 files, 95 tests. Conformance is the real gate here — it is the Perl's own words on ordinary delivery.

- [ ] **Step 6: Record the divergence**

> **A dead upstream closes the client connection.** Where the Perl (and this proxy until now) answered `451`, a proxy that has already begun relaying has nothing to answer with: during DATA it mirrors the upstream, so an upstream that drops takes the client connection with it. An upstream that *replies* is still relayed verbatim, code and text.

Also add a line to `conformance/README.md`'s "what this does not measure" section: the gate cannot see mid-stream upstream death or early rejection, because the Perl buffers and its tests therefore never produce either.

- [ ] **Step 7: Gates and commit**

Message: `Stream the body to the upstream instead of collecting it first`.

---

### Task 10: The memory invariant

**Files:**
- Create: `tests/streaming.rs`
- Modify: `tests/common/upstream.rs`

**Interfaces:**
- Consumes: everything.
- Produces: `RecordingUpstream::discard_body(&self)`.

- [ ] **Step 1: Add count-and-discard to the fake**

```rust
    /// Count the body's bytes instead of storing them, for the one test that
    /// streams more than it would want to hold.
    ///
    /// **This is not a relaxation of the recording.** The strict, verbatim
    /// recording stays the default for every other test, because a fake that
    /// re-normalises what it stores cannot see a relay that fails to
    /// normalise what it sends. This mode only exists so that the memory
    /// test measures the proxy and not the fake.
    pub fn discard_body(&self) {
        self.inner.lock().unwrap().discard_body = true;
    }

    /// Bytes of body received while `discard_body` was set.
    pub fn discarded_bytes(&self) -> usize {
        self.inner.lock().unwrap().discarded_bytes
    }
```

with `discard_body: bool` and `discarded_bytes: usize` on `Inner`, honoured where the body is pushed to `messages`.

- [ ] **Step 2: Write the test**

`tests/streaming.rs`:

```rust
mod common;

use std::time::Duration;

use common::raw_client::RawClient;
use common::upstream::RecordingUpstream;

/// Peak RSS, in bytes.
fn peak_rss() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").expect("linux only");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: usize = rest
                .split_ascii_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .expect("VmHWM has a number");
            return kb * 1024;
        }
    }
    panic!("no VmHWM in /proc/self/status");
}

/// MEASURE THIS BEFORE TRUSTING IT. Run the test once, read the peak it
/// prints, and set this to a small multiple of that -- then record the
/// measured figure here so a later reader can tell drift from regression.
///
/// Measured baseline: <fill in from the first run> MiB on <date>.
const PEAK_CEILING: usize = 64 * 1024 * 1024;

const BODY: usize = 1024 * 1024 * 1024; // what --max_message_size used to allow

/// A gigabyte through a proxy that holds none of it.
///
/// The old design held the message about three times over, so this body
/// would have cost roughly 3 GiB. The assertion is the whole point of the
/// streaming rewrite, stated as a number.
#[tokio::test]
async fn a_gigabyte_body_does_not_become_a_gigabyte_of_memory() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.discard_body();
    let (addr, _factory) = common::start_proxy(&up).await;

    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n").await;

    // One reused line, so the sender allocates nothing per iteration and
    // the peak measured belongs to the proxy.
    let line = "y".repeat(1022) + "\r\n";
    let mut sent = 0usize;
    while sent < BODY {
        c.write_raw(&line).await;
        sent += line.len();
    }
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));

    assert!(up.discarded_bytes() >= BODY, "the upstream did not receive the body");

    let peak = peak_rss();
    println!("peak RSS {} MiB for a {} MiB body", peak / 1048576, BODY / 1048576);
    assert!(
        peak < PEAK_CEILING,
        "peak RSS {} MiB exceeds the {} MiB ceiling: the body is being held",
        peak / 1048576,
        PEAK_CEILING / 1048576
    );
}
```

Move `start_proxy` into `tests/common/mod.rs` if it is currently private to `proxy_end_to_end.rs`, rather than writing a second copy.

- [ ] **Step 3: Run it, and set the ceiling from what you see**

```
cargo test -j 4 --no-run --test streaming
systemd-run --user --scope -p MemoryMax=256M -- <the built test binary> a_gigabyte_body --nocapture
```

The build is **outside** the scope on purpose: cargo's own footprint would otherwise land in the ceiling and blur the measurement. Read the printed peak, set `PEAK_CEILING` to a small multiple of it, and write the measured figure and the date into the comment.

- [ ] **Step 4: Prove it can fail**

Temporarily make `ProxySink::write` accumulate into a `Vec` instead of forwarding, and run the test again. It must fail — either on the assertion or by being OOM-killed at the 256M backstop. Restore the real implementation. Record the observation in the commit message: a memory test that has never been seen to fail is a memory test that asserts nothing.

- [ ] **Step 5: Gates and commit**

Message: `Measure the memory a gigabyte of mail costs, and hold it to a number`.

---

## After the last task

Re-derive all four gates yourself on the final commit, from a clean build — do not take any earlier task's word for them:

```
cargo test -j 4
make conformance
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Check the arithmetic, not the adjective: the test count should be the 199 of the merged baseline, plus the additions each task names, minus the tests Task 7 and Task 9 delete with `format_message` and `normalize_and_stuff`. If the sum does not account for the delta, find out why before calling it green.
