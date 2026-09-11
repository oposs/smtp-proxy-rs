# Core Proxy Implementation Plan (part 1 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust binary that replaces the Perl `smtpproxy.pl` 0.8.0 with identical CLI, API JSON, SMTP wire behaviour, and log formats.

**Architecture:** One crate with a library and a thin binary. Pure protocol functions (parser, DSN validation, reply formatter) with no I/O; one tokio task per client connection written as sequential async code; a `Handler` trait separating the SMTP server from the proxy logic; our own minimal upstream SMTP client.

**Tech Stack:** Rust 1.96, edition 2024, tokio 1.53, tokio-rustls 0.26 / rustls 0.23, rustls-pki-types 1.15, reqwest 0.13, clap 4.6, serde 1, tracing 0.1, tracing-subscriber 0.3, nix 0.31, base64 0.23, jiff 0.2, rand 0.10. Test-only: axum 0.8, tempfile 3, assert_cmd 2.

**Spec:** `docs/superpowers/specs/2026-09-10-rust-rewrite-design.md`. Part 2 of the plan (`2026-09-10-hardening.md`) covers spec sections 6.1, 9.1 to 9.3, the deb/release packaging, and the Perl conformance gate.

## Global Constraints

- Every reply code and text listed in spec section 4 is verbatim. Service name is `smtp-proxy`.
- API JSON field names and order per spec 5.3: `username, password, from, to, headers, mailParameters, rcptParameters`.
- Main log line: `[YYYY-MM-DD HH:MM:SS.fffff] [pid] [level] [connection-id] message` (spec 8.1). Smtplog line: `<id> <YYYY-MM-DD HH:MM:SS> >>> line` / `<<<` (spec 8.2).
- CLI flags spelled with underscores: `--tls_cert`, `--tls_key`, `--max_message_size` (spec 7).
- Never more than 4 parallel jobs: `.cargo/config.toml` sets `jobs = 4` and `RUST_TEST_THREADS=4`. Run every cargo command with `timeout: 600000`.
- Any test feeding large or unbounded input runs under `systemd-run --user --scope -p MemoryMax=2G -- cargo test ...`.
- Comments, identifiers, and docs in English.
- Commit after every task with a `Co-Authored-By:` trailer naming the model that actually authored the commit (e.g. `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`).
- Rust 2024 edition, `cargo clippy --all-targets -- -D warnings` clean and `cargo fmt --check` clean before every commit.

---

## File structure

```
Cargo.toml
.cargo/config.toml            jobs = 4, RUST_TEST_THREADS = 4
src/lib.rs                    pub mod declarations
src/main.rs                   CLI entry
src/config.rs                 Config struct built from CLI
src/logging.rs                Mojo-compatible tracing formatter + init
src/smtplog.rs                wire log with redaction
src/privdrop.rs               setgid/setuid
src/smtp/mod.rs
src/smtp/reply.rs             format_reply, sanitize, Reply
src/smtp/params.rs            Param, parse_params
src/smtp/command.rs           take_line, Command, CommandError, parse_command
src/smtp/dsn.rs               validate_dsn
src/smtp/extensions.rs        parse_extensions
src/server/mod.rs             Handler, HandlerFactory, ServerConfig
src/server/auth.rs            Credentials, decode_plain, decode_login
src/server/data.rs            DataReader
src/server/session.rs         Session<H>
src/server/listener.rs        bind, serve
src/api.rs                    ApiClient, CheckRequest, CheckResponse
src/relay.rs                  relay, probe, Recipient
src/proxy.rs                  ProxyHandler, ProxyFactory, header helpers
tests/common/mod.rs           re-exports
tests/common/raw_client.rs    RawClient
tests/common/fake_api.rs      FakeApi
tests/common/upstream.rs      RecordingUpstream
tests/common/fake_handler.rs  ScriptedHandler for server-only tests
tests/certs/server.crt, server.key   copied from ../smtp-proxy/t/certs-and-keys
tests/server_commands.rs      spec 4.2, 4.3, 4.6 through a fake handler
tests/server_tls_auth.rs      spec 4.4, 4.5
tests/server_data.rs          spec 4.7
tests/proxy_end_to_end.rs     spec 5, 6, end-to-end scenarios
tests/cli.rs                  spec 7, 9 (binary spawned)
Dockerfile, CHANGES, README.md, LICENSE, COPYRIGHT
```

---

### Task 1: Crate scaffold

**Files:**
- Create: `Cargo.toml`, `.cargo/config.toml`, `src/lib.rs`, `src/main.rs`, `src/smtp/mod.rs`, `src/server/mod.rs`, `rustfmt.toml`
- Create: `LICENSE`, `COPYRIGHT` (copied from `../smtp-proxy`)

**Interfaces:**
- Produces: the module tree every later task fills in.

- [ ] **Step 1: Write Cargo.toml**

```toml
[package]
name = "smtp-proxy"
version = "1.0.0"
edition = "2024"
rust-version = "1.85"
description = "SMTP authentication and header injection proxy"
license = "GPL-3.0-or-later"
repository = "https://github.com/oposs/smtp-proxy-rs"

[[bin]]
name = "smtp-proxy"
path = "src/main.rs"

[dependencies]
tokio = { version = "1.53", features = ["rt-multi-thread", "net", "io-util", "macros", "sync", "time", "signal", "fs"] }
tokio-rustls = "0.26"
rustls = "0.23"
rustls-pki-types = { version = "1.15", features = ["pem", "std"] }
reqwest = { version = "0.13", default-features = false, features = ["rustls", "json", "http2", "charset"] }
clap = { version = "4.6", features = ["derive", "wrap_help"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["fmt", "std", "registry"] }
nix = { version = "0.31", features = ["user"] }
anyhow = "1"
thiserror = "2"
base64 = "0.23"
memchr = "2"
jiff = "0.2"
rand = "0.10"

[dev-dependencies]
axum = "0.8"
tempfile = "3"
assert_cmd = "2"

[profile.dev]
debug = "line-tables-only"
split-debuginfo = "unpacked"

[profile.release]
lto = "thin"
codegen-units = 1
strip = true
```

Check the license of the Perl project first: `head -5 ../smtp-proxy/LICENSE`. Use the same SPDX id in `license`.

- [ ] **Step 2: Write .cargo/config.toml and rustfmt.toml**

```toml
# .cargo/config.toml
[build]
jobs = 4

[env]
RUST_TEST_THREADS = "4"
```

```toml
# rustfmt.toml
edition = "2024"
```

- [ ] **Step 3: Write the module skeleton**

`src/lib.rs`:
```rust
//! SMTP authentication and header injection proxy.
pub mod smtp;
pub mod server;
```

`src/smtp/mod.rs` and `src/server/mod.rs`: empty for now (one comment line each, `//! Protocol pieces with no I/O.` and `//! The SMTP server side.`).

`src/main.rs`:
```rust
fn main() {
    println!("smtp-proxy {}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 4: Copy license files**

```bash
cp ../smtp-proxy/LICENSE ../smtp-proxy/COPYRIGHT .
```

- [ ] **Step 5: Build and run the empty test suite**

Run: `cargo build && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: builds, 0 tests pass, no warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Scaffold the smtp-proxy crate"
```

---

### Task 2: Reply formatter (spec 4.8)

**Files:**
- Create: `src/smtp/reply.rs`
- Modify: `src/smtp/mod.rs` (add `pub mod reply;`)

**Interfaces:**
- Produces:
  - `pub const MAX_REPLY_LINE: usize = 512;`
  - `pub fn sanitize(text: &str) -> String`
  - `pub fn format_reply(code: u16, lines: &[&str]) -> Result<String, ReplyError>`
  - `pub struct Reply { pub code: u16, pub lines: Vec<String> }` with `Reply::new(code, text)`, `Reply::multi(code, lines)`, `Reply::wire(&self) -> String` (panics on an invalid code, which is a programming error since every code is a literal in our source).
  - `#[derive(Debug, thiserror::Error)] pub enum ReplyError { #[error("Invalid response code '{0}'")] InvalidCode(u16), #[error("Must have at least one response line")] NoLines }`

- [ ] **Step 1: Write the failing tests** (port of `reply-formatter.t`)

Append to `src/smtp/reply.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn line_body(reply: &str) -> &str {
        &reply[..reply.len() - 2]
    }

    #[test]
    fn single_line() {
        assert_eq!(format_reply(250, &["OK"]).unwrap(), "250 OK\r\n");
    }

    #[test]
    fn multi_line() {
        assert_eq!(
            format_reply(250, &["greeting", "STARTTLS", "DSN"]).unwrap(),
            "250-greeting\r\n250-STARTTLS\r\n250 DSN\r\n"
        );
    }

    #[test]
    fn trailing_newline_is_removed() {
        let r = format_reply(550, &["Requested action not taken: nope\n"]).unwrap();
        assert_eq!(r, "550 Requested action not taken: nope\r\n");
        assert!(!line_body(&r).contains(['\r', '\n']));
    }

    #[test]
    fn embedded_crlf_is_folded() {
        assert_eq!(format_reply(550, &["first\r\nsecond"]).unwrap(), "550 first second\r\n");
    }

    #[test]
    fn cannot_inject_a_reply_line() {
        let r = format_reply(550, &["rejected\r\n250 OK, go ahead"]).unwrap();
        assert_eq!(r, "550 rejected 250 OK, go ahead\r\n");
        assert_eq!(r.matches("\r\n").count(), 1);
    }

    #[test]
    fn bare_cr_is_folded() {
        assert_eq!(format_reply(550, &["carriage\rreturn"]).unwrap(), "550 carriage return\r\n");
    }

    #[test]
    fn continuation_lines_are_sanitised() {
        assert_eq!(
            format_reply(250, &["one\r\ntwo", "three"]).unwrap(),
            "250-one two\r\n250 three\r\n"
        );
    }

    #[test]
    fn overlong_line_is_truncated_to_512_octets() {
        let long = format_reply(550, &["x".repeat(1000).as_str()]).unwrap();
        assert!(long.len() <= MAX_REPLY_LINE);
        assert!(long.starts_with("550 xxx"));
        assert!(long.ends_with("...\r\n"));
    }

    #[test]
    fn bad_code_is_an_error() {
        assert!(matches!(format_reply(9999, &["nope"]), Err(ReplyError::InvalidCode(9999))));
        assert!(matches!(format_reply(100, &["nope"]), Err(ReplyError::InvalidCode(100))));
        assert!(matches!(format_reply(250, &[]), Err(ReplyError::NoLines)));
    }

    #[test]
    fn control_characters_are_folded() {
        let r = format_reply(550, &["esc\x1b[31mred\x00nul\x07bell"]).unwrap();
        assert!(!line_body(&r).bytes().any(|b| b != b'\t' && !(0x20..=0x7e).contains(&b)));
        assert_eq!(r, "550 esc [31mred nul bell\r\n");
    }

    #[test]
    fn wide_characters_do_not_reach_the_wire() {
        let r = format_reply(550, &["caf\u{e9} \u{263a} smile"]).unwrap();
        assert!(r.is_ascii());
        assert!(!line_body(&r).bytes().any(|b| b != b'\t' && !(0x20..=0x7e).contains(&b)));
        let long = format_reply(550, &["\u{263a}".repeat(1000).as_str()]).unwrap();
        assert!(long.len() <= MAX_REPLY_LINE);
    }

    #[test]
    fn reply_struct_formats_the_same() {
        assert_eq!(Reply::new(250, "OK").wire(), "250 OK\r\n");
        assert_eq!(
            Reply::multi(250, vec!["a".into(), "b".into()]).wire(),
            "250-a\r\n250 b\r\n"
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib smtp::reply`
Expected: compile error, `format_reply` not found.

- [ ] **Step 3: Implement**

`src/smtp/reply.rs` above the tests:
```rust
//! Reply formatting. RFC 5321 4.5.3.1.5: a reply line is at most 512 octets
//! including the code, the separator and CRLF. Reply text is not ours (it
//! comes from the upstream and from the API), so every character outside
//! tab and printable ASCII is folded to a space: CR and LF would break the
//! framing and let text from upstream inject a forged reply line; ESC and
//! friends would be executed by the terminal of whoever tails the smtplog.

pub const MAX_REPLY_LINE: usize = 512;
const MAX_TEXT: usize = MAX_REPLY_LINE - "250 ".len() - "\r\n".len();

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplyError {
    #[error("Invalid response code '{0}'")]
    InvalidCode(u16),
    #[error("Must have at least one response line")]
    NoLines,
}

/// Folds every run of characters outside tab and printable ASCII into one
/// space, strips trailing whitespace, and truncates to fit a reply line.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_run = false;
    for c in text.chars() {
        let printable = c == '\t' || ('\u{20}'..='\u{7e}').contains(&c);
        if printable {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push(' ');
            in_run = true;
        }
    }
    let trimmed = out.trim_end();
    if trimmed.len() > MAX_TEXT {
        let mut s = trimmed[..MAX_TEXT - 3].to_string();
        s.push_str("...");
        s
    } else {
        trimmed.to_string()
    }
}

pub fn format_reply(code: u16, lines: &[&str]) -> Result<String, ReplyError> {
    if !(200..=599).contains(&code) {
        return Err(ReplyError::InvalidCode(code));
    }
    if lines.is_empty() {
        return Err(ReplyError::NoLines);
    }
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let sep = if i + 1 == lines.len() { ' ' } else { '-' };
        out.push_str(&format!("{code}{sep}{}\r\n", sanitize(line)));
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self { code, lines: vec![text.into()] }
    }

    pub fn multi(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    /// Every code in this crate is a literal, so an invalid one is a bug.
    pub fn wire(&self) -> String {
        let refs: Vec<&str> = self.lines.iter().map(String::as_str).collect();
        format_reply(self.code, &refs).expect("reply code is a literal in our source")
    }
}
```

Add `pub mod reply;` to `src/smtp/mod.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test --lib smtp::reply`
Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add src/smtp
git commit -m "Reply formatter with sanitising and the 512 octet cap"
```

---

### Task 3: ESMTP parameters and the command parser (spec 4.2, 4.5, 4.6)

**Files:**
- Create: `src/smtp/params.rs`, `src/smtp/command.rs`
- Modify: `src/smtp/mod.rs`

**Interfaces:**
- Produces in `params.rs`:
  - `#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)] pub struct Param { pub keyword: String, pub value: Option<String> }`
  - `pub fn parse_params(text: &str) -> Option<Vec<Param>>` (None when any parameter is malformed)
- Produces in `command.rs`:
  - `pub fn take_line(buf: &mut Vec<u8>) -> Option<Vec<u8>>`: removes and returns the first line including its `\n`, or None if the buffer holds no complete line.
  - `pub enum Command { Ehlo { domain: String }, Helo { domain: String }, Noop, Quit, StartTls, Data, Rset, Auth { mechanism: String, initial: Option<String> }, Mail { from: String, params: Vec<Param> }, Rcpt { to: String, params: Vec<Param> }, Vrfy { string: String } }`
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct CommandError { pub code: u16, pub text: &'static str }`
  - `pub fn parse_command(line: &[u8]) -> Result<Command, CommandError>`; `line` is one complete line including its terminator.
  - `impl Command { pub fn verb(&self) -> &'static str }` returning `"MAIL"` etc.

- [ ] **Step 1: Write the failing tests for params**

`src/smtp/params.rs` tests:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn p(k: &str, v: Option<&str>) -> Param {
        Param { keyword: k.into(), value: v.map(String::from) }
    }

    #[test]
    fn dsn_parameters_parse() {
        assert_eq!(
            parse_params("NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a@b.com"),
            Some(vec![p("NOTIFY", Some("SUCCESS,FAILURE")), p("ORCPT", Some("rfc822;a@b.com"))])
        );
    }

    #[test]
    fn valueless_parameter_has_no_value() {
        assert_eq!(parse_params("SMTPUTF8"), Some(vec![p("SMTPUTF8", None)]));
    }

    #[test]
    fn keyword_zero_is_kept() {
        assert_eq!(parse_params("0"), Some(vec![p("0", None)]));
    }

    #[test]
    fn malformed_parameters_are_rejected_as_a_whole() {
        for bad in ["NOTIFY=", "=SUCCESS", "NOTIFY=A=B", "-BAD=1", "X=caf\u{e9}", "X=del\x7f"] {
            assert_eq!(parse_params(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn printable_ascii_value_is_accepted() {
        assert!(parse_params("X=~!$%^&*()_+{}|:\"<>?").is_some());
    }

    #[test]
    fn serialises_with_null_value() {
        let json = serde_json::to_string(&p("SMTPUTF8", None)).unwrap();
        assert_eq!(json, r#"{"keyword":"SMTPUTF8","value":null}"#);
    }
}
```

- [ ] **Step 2: Implement params**

```rust
//! RFC 5321 4.1.2 esmtp-param lists.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    pub keyword: String,
    pub value: Option<String>,
}

fn is_keyword_start(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_keyword_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// esmtp-value: printable ASCII excluding "=" and space.
fn is_value_char(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && b != b'='
}

/// Returns None if any parameter is malformed. Dropping a bad one silently
/// would tell the client we honoured something we discarded.
pub fn parse_params(text: &str) -> Option<Vec<Param>> {
    let mut out = Vec::new();
    for word in text.split_ascii_whitespace() {
        let (keyword, value) = match word.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (word, None),
        };
        let kb = keyword.as_bytes();
        if kb.is_empty() || !is_keyword_start(kb[0]) || !kb.iter().all(|&b| is_keyword_char(b)) {
            return None;
        }
        if let Some(v) = value
            && (v.is_empty() || !v.bytes().all(is_value_char))
        {
            return None;
        }
        out.push(Param { keyword: keyword.to_string(), value: value.map(String::from) });
    }
    Some(out)
}
```

- [ ] **Step 3: Write the failing tests for the command parser** (port of `command-parser.t`)

`src/smtp/command.rs` tests:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::smtp::params::Param;

    fn parse(s: &str) -> Result<Command, CommandError> {
        parse_command(format!("{s}\r\n").as_bytes())
    }

    fn p(k: &str, v: Option<&str>) -> Param {
        Param { keyword: k.into(), value: v.map(String::from) }
    }

    #[test]
    fn mail_keyword_is_case_insensitive() {
        for args in ["FROM:<sender@foobar.com>", "From:<sender@foobar.com>", "From: <sender@foobar.com>", "from:<sender@foobar.com>", "FrOm:<sender@foobar.com>"] {
            assert_eq!(
                parse(&format!("MAIL {args}")),
                Ok(Command::Mail { from: "sender@foobar.com".into(), params: vec![] }),
                "{args}"
            );
        }
        assert_eq!(
            parse("MAIL From:<sender@foobar.com> SIZE=1234"),
            Ok(Command::Mail { from: "sender@foobar.com".into(), params: vec![p("SIZE", Some("1234"))] })
        );
    }

    #[test]
    fn mail_rejections() {
        for args in ["From:", "SENDER:<sender@foobar.com>", ""] {
            assert_eq!(
                parse(&format!("MAIL {args}").trim_end()),
                Err(CommandError { code: 501, text: "invalid MAIL arguments" }),
                "{args:?}"
            );
        }
        assert_eq!(
            parse("MAIL FROM:<a@b.com> NOTIFY="),
            Err(CommandError { code: 501, text: "invalid MAIL parameters" })
        );
    }

    #[test]
    fn rcpt_keyword_is_case_insensitive() {
        for args in ["TO:<rcpt@foobaz.com>", "To:<rcpt@foobaz.com>", "to:<rcpt@foobaz.com>"] {
            assert_eq!(
                parse(&format!("RCPT {args}")),
                Ok(Command::Rcpt { to: "rcpt@foobaz.com".into(), params: vec![] })
            );
        }
        assert_eq!(
            parse("RCPT tO:<rcpt@foobaz.com> NOTIFY=NEVER"),
            Ok(Command::Rcpt { to: "rcpt@foobaz.com".into(), params: vec![p("NOTIFY", Some("NEVER"))] })
        );
        assert_eq!(parse("RCPT FOR:<rcpt@foobaz.com>").unwrap_err().code, 501);
        assert_eq!(parse("RCPT").unwrap_err().code, 501);
    }

    #[test]
    fn dsn_parameters_survive() {
        assert_eq!(
            parse("RCPT TO:<a@b.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a@b.com"),
            Ok(Command::Rcpt { to: "a@b.com".into(), params: vec![p("NOTIFY", Some("SUCCESS,FAILURE")), p("ORCPT", Some("rfc822;a@b.com"))] })
        );
        assert_eq!(
            parse("MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159"),
            Ok(Command::Mail { from: "a@b.com".into(), params: vec![p("RET", Some("HDRS")), p("ENVID", Some("QQ314159"))] })
        );
    }

    #[test]
    fn null_return_path() {
        assert_eq!(parse("MAIL FROM:<>"), Ok(Command::Mail { from: String::new(), params: vec![] }));
        assert_eq!(parse("MAIL FROM:<> RET=FULL"), Ok(Command::Mail { from: String::new(), params: vec![p("RET", Some("FULL"))] }));
        assert_eq!(parse("RCPT TO:<>"), Err(CommandError { code: 501, text: "invalid RCPT arguments" }));
    }

    #[test]
    fn valueless_and_zero_parameters() {
        assert_eq!(parse("RCPT TO:<a@b.com> SMTPUTF8"), Ok(Command::Rcpt { to: "a@b.com".into(), params: vec![p("SMTPUTF8", None)] }));
        assert_eq!(parse("MAIL FROM:<a@b.com> 0"), Ok(Command::Mail { from: "a@b.com".into(), params: vec![p("0", None)] }));
        assert_eq!(parse("RCPT TO:<a@b.com> 0"), Ok(Command::Rcpt { to: "a@b.com".into(), params: vec![p("0", None)] }));
    }

    #[test]
    fn malformed_parameters_draw_501() {
        for bad in ["NOTIFY=", "=SUCCESS", "NOTIFY=A=B", "-BAD=1", "X=caf\u{e9}", "X=del\x7f", "X=\u{ff}"] {
            assert_eq!(parse(&format!("RCPT TO:<a@b.com> {bad}")).unwrap_err().code, 501, "{bad:?}");
        }
        assert!(parse("RCPT TO:<a@b.com> X=~!$%^&*()_+{}|:\"<>?").is_ok());
    }

    #[test]
    fn minimum_command_set() {
        assert_eq!(parse("HELO client.example.com"), Ok(Command::Helo { domain: "client.example.com".into() }));
        assert_eq!(parse("EHLO client.example.com"), Ok(Command::Ehlo { domain: "client.example.com".into() }));
        assert_eq!(parse("NOOP"), Ok(Command::Noop));
        assert_eq!(parse("NOOP keep alive"), Ok(Command::Noop));
        assert_eq!(parse("QUIT"), Ok(Command::Quit));
        assert_eq!(parse("RSET"), Ok(Command::Rset));
        assert_eq!(parse("DATA"), Ok(Command::Data));
        assert_eq!(parse("STARTTLS"), Ok(Command::StartTls));
        assert_eq!(parse("starttls"), Ok(Command::StartTls));
        assert_eq!(parse("VRFY someone@example.com"), Ok(Command::Vrfy { string: "someone@example.com".into() }));
    }

    #[test]
    fn no_argument_commands_reject_arguments() {
        for verb in ["QUIT", "STARTTLS", "DATA", "RSET"] {
            assert_eq!(parse(&format!("{verb} x")), Err(CommandError { code: 501, text: "no arguments allowed" }));
        }
    }

    #[test]
    fn mandatory_arguments() {
        assert_eq!(parse("EHLO"), Err(CommandError { code: 501, text: "domain required" }));
        assert_eq!(parse("HELO"), Err(CommandError { code: 501, text: "domain required" }));
        assert_eq!(parse("VRFY"), Err(CommandError { code: 501, text: "string required" }));
    }

    #[test]
    fn auth_mechanism_is_normalised() {
        for line in ["AUTH PLAIN dGVzdA==", "AUTH plain dGVzdA==", "AUTH PlAiN dGVzdA=="] {
            assert_eq!(parse(line), Ok(Command::Auth { mechanism: "PLAIN".into(), initial: Some("dGVzdA==".into()) }));
        }
        assert_eq!(parse("AUTH login"), Ok(Command::Auth { mechanism: "LOGIN".into(), initial: None }));
        assert_eq!(parse("AUTH CRAM-MD5"), Ok(Command::Auth { mechanism: "CRAM-MD5".into(), initial: None }));
        assert_eq!(parse("AUTH SCRAM-SHA-256 abcd"), Ok(Command::Auth { mechanism: "SCRAM-SHA-256".into(), initial: Some("abcd".into()) }));
        assert_eq!(parse("AUTH X_MECH"), Ok(Command::Auth { mechanism: "X_MECH".into(), initial: None }));
        assert_eq!(parse("AUTH"), Err(CommandError { code: 501, text: "invalid AUTH arguments" }));
        assert_eq!(parse(&format!("AUTH {}", "A".repeat(21))).unwrap_err().code, 501);
    }

    #[test]
    fn unknown_verbs_draw_502() {
        assert_eq!(parse("PING"), Err(CommandError { code: 502, text: "unknown command" }));
        assert_eq!(parse("PING hello").unwrap_err().code, 502);
    }

    #[test]
    fn malformed_lines_draw_500() {
        for bad in ["MAIL FROM:<a\rb>\r\n", "\r\n", "NOOP\n", " NOOP\r\n"] {
            assert_eq!(parse_command(bad.as_bytes()), Err(CommandError { code: 500, text: "malformed command" }), "{bad:?}");
        }
    }

    #[test]
    fn take_line_splits_pipelined_commands() {
        let mut buf = b"MAIL FROM:<a@b.com>\r\nRCPT TO:<c@d.com>\r\nDATA\r\n".to_vec();
        assert_eq!(take_line(&mut buf).unwrap(), b"MAIL FROM:<a@b.com>\r\n");
        assert_eq!(buf, b"RCPT TO:<c@d.com>\r\nDATA\r\n");
        assert_eq!(take_line(&mut buf).unwrap(), b"RCPT TO:<c@d.com>\r\n");
        assert_eq!(take_line(&mut buf).unwrap(), b"DATA\r\n");
        assert!(buf.is_empty());
    }

    #[test]
    fn take_line_holds_an_incomplete_line() {
        let mut buf = b"MAIL FRO".to_vec();
        assert_eq!(take_line(&mut buf), None);
        assert_eq!(buf, b"MAIL FRO");
    }

    #[test]
    fn commands_after_a_rejected_line_are_still_reached() {
        let mut buf = b"MAIL FROM:<a\rb>\r\nNOOP\r\nRSET\r\n".to_vec();
        let mut seen = Vec::new();
        while let Some(line) = take_line(&mut buf) {
            seen.push(match parse_command(&line) {
                Ok(c) => c.verb().to_string(),
                Err(e) => e.text.to_string(),
            });
        }
        assert_eq!(seen, ["malformed command", "NOOP", "RSET"]);
        assert!(buf.is_empty());
    }
}
```

- [ ] **Step 4: Implement the command parser**

```rust
//! One SMTP command line -> Command. Mirrors the Perl CommandParser: the
//! verb is letters only, the argument is separated by exactly one space,
//! and the line must end in CRLF. Anything else is a malformed command,
//! and the line is consumed so that the next one can be reached.
use crate::smtp::params::{Param, parse_params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo { domain: String },
    Helo { domain: String },
    Noop,
    Quit,
    StartTls,
    Data,
    Rset,
    Auth { mechanism: String, initial: Option<String> },
    Mail { from: String, params: Vec<Param> },
    Rcpt { to: String, params: Vec<Param> },
    Vrfy { string: String },
}

impl Command {
    pub fn verb(&self) -> &'static str {
        match self {
            Command::Ehlo { .. } => "EHLO",
            Command::Helo { .. } => "HELO",
            Command::Noop => "NOOP",
            Command::Quit => "QUIT",
            Command::StartTls => "STARTTLS",
            Command::Data => "DATA",
            Command::Rset => "RSET",
            Command::Auth { .. } => "AUTH",
            Command::Mail { .. } => "MAIL",
            Command::Rcpt { .. } => "RCPT",
            Command::Vrfy { .. } => "VRFY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub code: u16,
    pub text: &'static str,
}

const fn err(code: u16, text: &'static str) -> CommandError {
    CommandError { code, text }
}

/// Removes and returns the first line, terminator included.
pub fn take_line(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = memchr::memchr(b'\n', buf)? + 1;
    let line = buf[..end].to_vec();
    buf.drain(..end);
    Some(line)
}

pub fn parse_command(line: &[u8]) -> Result<Command, CommandError> {
    let malformed = err(500, "malformed command");
    let body = line.strip_suffix(b"\r\n").ok_or(malformed.clone())?;
    if body.contains(&b'\r') {
        return Err(malformed);
    }
    let verb_len = body.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if verb_len == 0 {
        return Err(malformed);
    }
    let verb = std::str::from_utf8(&body[..verb_len]).unwrap().to_ascii_uppercase();
    let args: Option<&str> = match &body[verb_len..] {
        [] => None,
        [b' ', rest @ ..] => Some(std::str::from_utf8(rest).map_err(|_| malformed.clone())?),
        _ => return Err(malformed),
    };

    match verb.as_str() {
        "EHLO" | "HELO" => {
            let domain = args.filter(|a| !a.is_empty()).ok_or(err(501, "domain required"))?;
            Ok(if verb == "EHLO" {
                Command::Ehlo { domain: domain.into() }
            } else {
                Command::Helo { domain: domain.into() }
            })
        }
        "NOOP" => Ok(Command::Noop),
        "QUIT" | "STARTTLS" | "DATA" | "RSET" => {
            if args.is_some_and(|a| !a.is_empty()) {
                return Err(err(501, "no arguments allowed"));
            }
            Ok(match verb.as_str() {
                "QUIT" => Command::Quit,
                "STARTTLS" => Command::StartTls,
                "DATA" => Command::Data,
                _ => Command::Rset,
            })
        }
        "AUTH" => parse_auth(args),
        "MAIL" => parse_path(args, "FROM:", true)
            .map(|(from, params)| Command::Mail { from, params })
            .map_err(|kind| match kind {
                PathError::Arguments => err(501, "invalid MAIL arguments"),
                PathError::Parameters => err(501, "invalid MAIL parameters"),
            }),
        "RCPT" => parse_path(args, "TO:", false)
            .map(|(to, params)| Command::Rcpt { to, params })
            .map_err(|kind| match kind {
                PathError::Arguments => err(501, "invalid RCPT arguments"),
                PathError::Parameters => err(501, "invalid RCPT parameters"),
            }),
        "VRFY" => {
            let string = args.filter(|a| !a.is_empty()).ok_or(err(501, "string required"))?;
            Ok(Command::Vrfy { string: string.into() })
        }
        _ => Err(err(502, "unknown command")),
    }
}

/// RFC 4954 section 4: a mechanism name is 1 to 20 characters of upper
/// alpha, digit, hyphen and underscore, matched without regard to case.
fn parse_auth(args: Option<&str>) -> Result<Command, CommandError> {
    let invalid = err(501, "invalid AUTH arguments");
    let args = args.ok_or(invalid.clone())?;
    let (mechanism, initial) = match args.split_once(' ') {
        Some((m, rest)) => (m, Some(rest)),
        None => (args, None),
    };
    let ok_len = (1..=20).contains(&mechanism.len());
    let ok_chars = mechanism.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok_len || !ok_chars {
        return Err(invalid);
    }
    Ok(Command::Auth {
        mechanism: mechanism.to_ascii_uppercase(),
        initial: initial.filter(|s| !s.is_empty()).map(String::from),
    })
}

enum PathError {
    Arguments,
    Parameters,
}

/// `FROM:<addr> [params]` / `TO:<addr> [params]`, keyword case-insensitive,
/// optional whitespace after the colon. `allow_empty` admits the null
/// return path `<>`.
fn parse_path(args: Option<&str>, keyword: &str, allow_empty: bool) -> Result<(String, Vec<Param>), PathError> {
    let args = args.ok_or(PathError::Arguments)?;
    if args.len() < keyword.len() || !args[..keyword.len()].eq_ignore_ascii_case(keyword) {
        return Err(PathError::Arguments);
    }
    let rest = args[keyword.len()..].trim_start();
    let rest = rest.strip_prefix('<').ok_or(PathError::Arguments)?;
    let close = rest.find('>').ok_or(PathError::Arguments)?;
    let address = &rest[..close];
    if address.is_empty() && !allow_empty {
        return Err(PathError::Arguments);
    }
    let tail = &rest[close + 1..];
    let params = if tail.is_empty() {
        Vec::new()
    } else if let Some(param_text) = tail.strip_prefix(' ') {
        if param_text.is_empty() {
            Vec::new()
        } else {
            parse_params(param_text).ok_or(PathError::Parameters)?
        }
    } else {
        return Err(PathError::Arguments);
    };
    Ok((address.to_string(), params))
}
```

Add `pub mod params; pub mod command;` to `src/smtp/mod.rs`.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib smtp::`
Expected: all pass (12 reply + 6 params + 16 command).

- [ ] **Step 6: Commit**

```bash
git add src/smtp
git commit -m "Command and ESMTP parameter parsers"
```

---
### Task 4: DSN parameter validation (spec 4.6, RFC 3461)

**Files:**
- Create: `src/smtp/dsn.rs`
- Modify: `src/smtp/mod.rs`

**Interfaces:**
- Produces:
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum DsnCommand { Mail, Rcpt }`
  - `pub fn validate_dsn(params: &[Param], which: DsnCommand) -> Result<(), String>`; the `Err` string is the 501 reply text.
  - `pub fn is_mail_dsn_keyword(k: &str) -> bool` (RET, ENVID, case-insensitive) and `pub fn is_rcpt_dsn_keyword(k: &str) -> bool` (NOTIFY, ORCPT), used by the relay.

- [ ] **Step 1: Write the failing tests** (the script from `dsn-validation.t`, at function level)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::smtp::params::parse_params;

    fn check(which: DsnCommand, text: &str) -> Result<(), String> {
        validate_dsn(&parse_params(text).unwrap(), which)
    }

    #[test]
    fn mail_parameters() {
        use DsnCommand::Mail;
        assert_eq!(check(Mail, "RET=PARTIAL"), Err("RET requires a value of FULL or HDRS".into()));
        assert_eq!(check(Mail, "RET"), Err("RET requires a value of FULL or HDRS".into()));
        assert_eq!(check(Mail, &format!("ENVID={}", "x".repeat(101))), Err("ENVID is limited to 100 characters".into()));
        assert_eq!(check(Mail, "ENVID=has+zz"), Err("ENVID must be xtext".into()));
        assert_eq!(check(Mail, "ENVID=one ENVID=two"), Err("ENVID given more than once".into()));
        assert_eq!(check(Mail, "RET=FULL RET=HDRS"), Err("RET given more than once".into()));
        assert_eq!(check(Mail, "RET=HDRS ENVID=QQ314159"), Ok(()));
        assert_eq!(check(Mail, "ret=hdrs"), Ok(()));
        assert_eq!(check(Mail, "SIZE=100 RET=FULL"), Ok(()));
    }

    #[test]
    fn rcpt_parameters() {
        use DsnCommand::Rcpt;
        assert_eq!(check(Rcpt, "NOTIFY=MAYBE"), Err("NOTIFY value 'MAYBE' is not recognised".into()));
        assert_eq!(check(Rcpt, "NOTIFY=NEVER,SUCCESS"), Err("NOTIFY=NEVER cannot be combined with other values".into()));
        assert_eq!(check(Rcpt, "NOTIFY=DELAY,DELAY"), Err("NOTIFY lists DELAY more than once".into()));
        assert_eq!(check(Rcpt, "NOTIFY=SUCCESS,"), Err("NOTIFY has an empty element".into()));
        assert_eq!(check(Rcpt, "ORCPT=nosemicolon"), Err("ORCPT must be an address type, a semicolon and an address".into()));
        assert_eq!(check(Rcpt, &format!("ORCPT=rfc822;{}", "x".repeat(500))), Err("ORCPT is limited to 500 characters".into()));
        assert_eq!(check(Rcpt, "NOTIFY=DELAY NOTIFY=NEVER"), Err("NOTIFY given more than once".into()));
        assert_eq!(check(Rcpt, "NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;c@d.com"), Ok(()));
        assert_eq!(check(Rcpt, "NOTIFY=NEVER"), Ok(()));
        assert_eq!(check(Rcpt, "ORCPT=rfc822;a+40b"), Ok(()));
    }

    #[test]
    fn keyword_helpers() {
        assert!(is_mail_dsn_keyword("ret") && is_mail_dsn_keyword("ENVID"));
        assert!(is_rcpt_dsn_keyword("notify") && is_rcpt_dsn_keyword("ORCPT"));
        assert!(!is_mail_dsn_keyword("NOTIFY") && !is_rcpt_dsn_keyword("SIZE"));
    }
}
```

- [ ] **Step 2: Implement**

```rust
//! RFC 3461 gives each of its four parameters a grammar and two of them a
//! length limit. A server that announces DSN MUST answer 501 to a
//! syntactically invalid one (section 5.1), at the command that carried it.
use crate::smtp::params::Param;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsnCommand {
    Mail,
    Rcpt,
}

pub fn is_mail_dsn_keyword(k: &str) -> bool {
    k.eq_ignore_ascii_case("RET") || k.eq_ignore_ascii_case("ENVID")
}

pub fn is_rcpt_dsn_keyword(k: &str) -> bool {
    k.eq_ignore_ascii_case("NOTIFY") || k.eq_ignore_ascii_case("ORCPT")
}

/// RFC 3461 section 4: xtext is printable ASCII other than '+' and '=',
/// with anything else written as '+' followed by two hex digits.
fn is_xtext(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                if i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                    return false;
                }
                i += 3;
            }
            0x21..=0x2a | 0x2c..=0x3c | 0x3e..=0x7e => i += 1,
            _ => return false,
        }
    }
    true
}

pub fn validate_dsn(params: &[Param], which: DsnCommand) -> Result<(), String> {
    let mut seen: Vec<String> = Vec::new();
    for p in params {
        let keyword = p.keyword.to_ascii_uppercase();
        let check: fn(Option<&str>) -> Result<(), String> = match (which, keyword.as_str()) {
            (DsnCommand::Mail, "RET") => check_ret,
            (DsnCommand::Mail, "ENVID") => check_envid,
            (DsnCommand::Rcpt, "NOTIFY") => check_notify,
            (DsnCommand::Rcpt, "ORCPT") => check_orcpt,
            _ => continue,
        };
        if seen.contains(&keyword) {
            return Err(format!("{keyword} given more than once"));
        }
        seen.push(keyword);
        check(p.value.as_deref())?;
    }
    Ok(())
}

fn check_ret(value: Option<&str>) -> Result<(), String> {
    match value {
        Some(v) if v.eq_ignore_ascii_case("FULL") || v.eq_ignore_ascii_case("HDRS") => Ok(()),
        _ => Err("RET requires a value of FULL or HDRS".into()),
    }
}

/// RFC 3461 4.4 caps the envelope id at 100 characters.
fn check_envid(value: Option<&str>) -> Result<(), String> {
    let v = value.filter(|v| !v.is_empty()).ok_or("ENVID requires a value")?;
    if v.len() > 100 {
        return Err("ENVID is limited to 100 characters".into());
    }
    if !is_xtext(v) {
        return Err("ENVID must be xtext".into());
    }
    Ok(())
}

/// RFC 3461 4.1: NEVER on its own, or one or more of SUCCESS, FAILURE, DELAY.
fn check_notify(value: Option<&str>) -> Result<(), String> {
    let v = value.filter(|v| !v.is_empty()).ok_or("NOTIFY requires a value")?;
    let items: Vec<&str> = v.split(',').collect();
    if items.iter().any(|i| i.is_empty()) {
        return Err("NOTIFY has an empty element".into());
    }
    let mut seen: Vec<String> = Vec::new();
    for item in &items {
        let upper = item.to_ascii_uppercase();
        if !matches!(upper.as_str(), "NEVER" | "SUCCESS" | "FAILURE" | "DELAY") {
            return Err(format!("NOTIFY value '{item}' is not recognised"));
        }
        if seen.contains(&upper) {
            return Err(format!("NOTIFY lists {upper} more than once"));
        }
        seen.push(upper);
    }
    if seen.iter().any(|s| s == "NEVER") && items.len() > 1 {
        return Err("NOTIFY=NEVER cannot be combined with other values".into());
    }
    Ok(())
}

/// RFC 3461 4.2: an address type, a semicolon and an xtext address, in at
/// most 500 characters.
fn check_orcpt(value: Option<&str>) -> Result<(), String> {
    let v = value.filter(|v| !v.is_empty()).ok_or("ORCPT requires a value")?;
    if v.len() > 500 {
        return Err("ORCPT is limited to 500 characters".into());
    }
    let bad_shape = "ORCPT must be an address type, a semicolon and an address";
    let (atype, address) = v.split_once(';').ok_or(bad_shape)?;
    let tb = atype.as_bytes();
    let type_ok = !tb.is_empty() && tb[0].is_ascii_alphanumeric() && tb.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-');
    if !type_ok || address.is_empty() {
        return Err(bad_shape.into());
    }
    if !is_xtext(address) {
        return Err("ORCPT address must be xtext".into());
    }
    Ok(())
}
```

- [ ] **Step 3: Run tests, then commit**

Run: `cargo test --lib smtp::dsn`
Expected: 3 passed.

```bash
git add src/smtp
git commit -m "RFC 3461 DSN parameter validation"
```

---

### Task 5: Extension list parser (spec 6)

**Files:**
- Create: `src/smtp/extensions.rs`
- Modify: `src/smtp/mod.rs`

**Interfaces:**
- Produces: `pub fn parse_extensions(ehlo_reply: &str) -> std::collections::HashSet<String>`; keywords uppercased, first word of every line after `NNN-` or `NNN `.

- [ ] **Step 1: Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_are_collected_and_uppercased() {
        let set = parse_extensions("250-recording.upstream\r\n250-dsn\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n");
        assert!(set.contains("DSN"));
        assert!(set.contains("SIZE"));
        assert!(set.contains("STARTTLS"));
        assert!(!set.contains("10240000"));
    }

    #[test]
    fn lines_without_a_code_are_ignored() {
        assert!(parse_extensions("garbage\r\n").is_empty());
        assert!(parse_extensions("").is_empty());
    }
}
```

- [ ] **Step 2: Implement**

```rust
//! The extension keywords an EHLO reply announces.
use std::collections::HashSet;

pub fn parse_extensions(ehlo_reply: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in ehlo_reply.split(['\r', '\n']) {
        let b = line.as_bytes();
        if b.len() < 4 || !b[..3].iter().all(u8::is_ascii_digit) || !(b[3] == b'-' || b[3] == b' ') {
            continue;
        }
        if let Some(word) = line[4..].split_ascii_whitespace().next() {
            set.insert(word.to_ascii_uppercase());
        }
    }
    set
}
```

- [ ] **Step 3: Run, commit**

Run: `cargo test --lib smtp::extensions` → 2 passed.

```bash
git add src/smtp && git commit -m "EHLO extension list parser"
```

---

### Task 6: Main log formatter and the SMTP wire log (spec 8)

**Files:**
- Create: `src/logging.rs`, `src/smtplog.rs`
- Modify: `src/lib.rs` (add `pub mod logging; pub mod smtplog;`)

**Interfaces:**
- Produces in `logging.rs`:
  - `pub fn init(path: Option<&std::path::Path>, level: &str) -> anyhow::Result<()>`; `level` is one of `trace|debug|info|warn|error|fatal`; `fatal` disables all output; `None` path means stderr. Installs the global subscriber once.
  - `pub struct MojoFormat;` implementing `tracing_subscriber::fmt::FormatEvent<S, N>`.
  - `pub fn format_timestamp(now: &jiff::Zoned) -> String` → `YYYY-MM-DD HH:MM:SS.fffff`.
  - Connection-scoped messages are emitted inside a span created with `tracing::info_span!("conn", cid = %id)`; the formatter prints `[<cid>] ` after the level for every enclosing span that has a `cid` field.
- Produces in `smtplog.rs`:
  - `pub struct SmtpLog { .. }` with `pub fn open(path: &Path, credentials: bool) -> io::Result<SmtpLog>`, `pub fn received(&self, id: &str, line: &str)`, `pub fn received_auth_secret(&self, id: &str, line: &str)`, `pub fn sent(&self, id: &str, wire: &str)`.
  - `pub fn redact_auth_line(line: &str) -> String` (pure, tested).
  - `pub fn format_entry(id: &str, timestamp: &str, sent: bool, line: &str) -> String` (pure, tested).

- [ ] **Step 1: Tests**

`src/logging.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_has_five_fractional_digits() {
        let z: jiff::Zoned = "2026-09-10T14:13:51.123456789+02:00[Europe/Zurich]".parse().unwrap();
        assert_eq!(format_timestamp(&z), "2026-09-10 14:13:51.12345");
    }

    #[test]
    fn line_layout_matches_mojo_log() {
        use tracing_subscriber::prelude::*;
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = {
            let buf = buf.clone();
            move || TestWriter(buf.clone())
        };
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer().event_format(MojoFormat).with_writer(writer),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("plain message");
            let span = tracing::info_span!("conn", cid = %"deadbeef");
            let _g = span.enter();
            tracing::warn!("scoped message");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let mut lines = out.lines();
        let first = lines.next().unwrap();
        let pid = std::process::id();
        assert!(first.starts_with('['), "{first}");
        assert!(first.ends_with(&format!("] [{pid}] [info] plain message")), "{first}");
        let second = lines.next().unwrap();
        assert!(second.ends_with(&format!("] [{pid}] [warn] [deadbeef] scoped message")), "{second}");
        // [YYYY-MM-DD HH:MM:SS.fffff]
        assert_eq!(first.find(']'), Some(27), "{first}");
    }

    struct TestWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for TestWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
```

`src/smtplog.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_arguments_are_redacted() {
        assert_eq!(redact_auth_line("AUTH PLAIN dXNlcgBwYXNz"), "AUTH PLAIN [REDACTED]");
        assert_eq!(redact_auth_line("auth plain dXNlcgBwYXNz"), "auth plain [REDACTED]");
        assert_eq!(redact_auth_line("AUTH LOGIN"), "AUTH LOGIN");
        assert_eq!(redact_auth_line("MAIL FROM:<a@b.com>"), "MAIL FROM:<a@b.com>");
    }

    #[test]
    fn entry_layout() {
        assert_eq!(
            format_entry("abc", "2026-09-10 14:13:51", false, "EHLO x"),
            "abc 2026-09-10 14:13:51 >>> EHLO x\n"
        );
        assert_eq!(
            format_entry("abc", "2026-09-10 14:13:51", true, "250 OK"),
            "abc 2026-09-10 14:13:51 <<< 250 OK\n"
        );
    }

    #[test]
    fn file_round_trip_with_and_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("smtp.log");
        let log = SmtpLog::open(&path, false).unwrap();
        log.received("id1", "AUTH PLAIN c2VjcmV0");
        log.received_auth_secret("id1", "c2VjcmV0");
        log.sent("id1", "250-a\r\n250 b\r\n");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].ends_with(">>> AUTH PLAIN [REDACTED]"));
        assert!(lines[1].ends_with(">>> [REDACTED]"));
        assert!(lines[2].ends_with("<<< 250-a"));
        assert!(lines[3].ends_with("<<< 250 b"));

        let log = SmtpLog::open(&path, true).unwrap();
        log.received("id2", "AUTH PLAIN c2VjcmV0");
        log.received_auth_secret("id2", "c2VjcmV0");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(">>> AUTH PLAIN c2VjcmV0"));
        assert!(text.contains("id2 ") && text.lines().last().unwrap().ends_with(">>> c2VjcmV0"));
    }
}
```

- [ ] **Step 2: Implement logging.rs**

```rust
//! Mojo::Log compatible output on top of tracing:
//! `[YYYY-MM-DD HH:MM:SS.fffff] [pid] [level] [cid] message`.
use std::fmt;
use std::path::Path;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

pub struct MojoFormat;

pub fn format_timestamp(now: &jiff::Zoned) -> String {
    format!(
        "{} {:02}:{:02}:{:02}.{:05}",
        now.date(),
        now.hour(),
        now.minute(),
        now.second(),
        now.subsec_nanosecond() / 10_000
    )
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
    }
}

impl<S, N> FormatEvent<S, N> for MojoFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut w: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        write!(
            w,
            "[{}] [{}] [{}] ",
            format_timestamp(&jiff::Zoned::now()),
            std::process::id(),
            level_name(event.metadata().level())
        )?;
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let ext = span.extensions();
                if let Some(fields) = ext.get::<FormattedFields<N>>() {
                    // The default field formatter renders `cid=abc`; only the id is wanted.
                    for field in fields.fields.split(' ') {
                        if let Some(id) = field.strip_prefix("cid=") {
                            write!(w, "[{id}] ")?;
                        }
                    }
                }
            }
        }
        ctx.field_format().format_fields(w.by_ref(), event)?;
        writeln!(w)
    }
}

/// Installs the global subscriber. `level` follows the Perl names; `fatal`
/// silences everything because nothing is ever logged at that level.
pub fn init(path: Option<&Path>, level: &str) -> anyhow::Result<()> {
    let filter = match level {
        "trace" => tracing::level_filters::LevelFilter::TRACE,
        "debug" => tracing::level_filters::LevelFilter::DEBUG,
        "info" => tracing::level_filters::LevelFilter::INFO,
        "warn" => tracing::level_filters::LevelFilter::WARN,
        "error" => tracing::level_filters::LevelFilter::ERROR,
        "fatal" => tracing::level_filters::LevelFilter::OFF,
        other => anyhow::bail!("unknown log level '{other}'"),
    };
    let layer = tracing_subscriber::fmt::layer().event_format(MojoFormat);
    match path {
        Some(p) if p != Path::new("/dev/stderr") => {
            let file = std::fs::OpenOptions::new().create(true).append(true).open(p)?;
            let writer = std::sync::Mutex::new(file);
            tracing_subscriber::registry().with(layer.with_writer(writer).with_filter(filter)).init();
        }
        _ => {
            tracing_subscriber::registry().with(layer.with_writer(std::io::stderr).with_filter(filter)).init();
        }
    }
    Ok(())
}
```

Note: the default `format_fields` for an event with only a message renders the message text alone, which is what the test asserts. Events must be logged as `tracing::info!("text")` or `tracing::info!("{}", value)`, never with extra key=value fields, or those would appear in the line.

- [ ] **Step 3: Implement smtplog.rs**

```rust
//! The optional wire log: one line per SMTP line sent or received.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

pub struct SmtpLog {
    file: Mutex<File>,
    credentials: bool,
}

pub fn format_entry(id: &str, timestamp: &str, sent: bool, line: &str) -> String {
    let leader = if sent { "<<<" } else { ">>>" };
    format!("{id} {timestamp} {leader} {line}\n")
}

/// `AUTH <mech> <secret>` -> `AUTH <mech> [REDACTED]`, matched on the raw
/// line because verb and mechanism are case-insensitive on the wire.
pub fn redact_auth_line(line: &str) -> String {
    let mut parts = line.splitn(3, char::is_whitespace);
    let (Some(verb), Some(mech), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return line.to_string();
    };
    if verb.eq_ignore_ascii_case("AUTH") && !mech.is_empty() && !rest.trim().is_empty() {
        let prefix_len = line.len() - rest.len();
        format!("{}[REDACTED]", &line[..prefix_len])
    } else {
        line.to_string()
    }
}

fn now() -> String {
    let z = jiff::Zoned::now();
    format!("{} {:02}:{:02}:{:02}", z.date(), z.hour(), z.minute(), z.second())
}

impl SmtpLog {
    pub fn open(path: &Path, credentials: bool) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file), credentials })
    }

    fn write(&self, id: &str, sent: bool, line: &str) {
        let entry = format_entry(id, &now(), sent, line.trim_end_matches(['\r', '\n']));
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(entry.as_bytes());
            let _ = f.flush();
        }
    }

    /// A command line from the client.
    pub fn received(&self, id: &str, line: &str) {
        let shown = if self.credentials { line.to_string() } else { redact_auth_line(line) };
        self.write(id, false, &shown);
    }

    /// An AUTH continuation line, which is entirely secret.
    pub fn received_auth_secret(&self, id: &str, line: &str) {
        let shown = if self.credentials { line } else { "[REDACTED]" };
        self.write(id, false, shown);
    }

    /// A reply as written to the wire; may hold several lines.
    pub fn sent(&self, id: &str, wire: &str) {
        for line in wire.split("\r\n").filter(|l| !l.is_empty()) {
            self.write(id, true, line);
        }
    }
}
```

- [ ] **Step 4: Run, commit**

Run: `cargo test --lib logging smtplog` → 5 passed. Also `cargo clippy --all-targets -- -D warnings`.

```bash
git add src && git commit -m "Mojo-compatible log formatter and SMTP wire log"
```

---
### Task 7: AUTH decoding (spec 4.5)

**Files:**
- Create: `src/server/auth.rs`
- Modify: `src/server/mod.rs` (add `pub mod auth;`)

**Interfaces:**
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct Credentials { pub authzid: String, pub authcid: String, pub password: String }`
  - `pub fn decode_plain(b64: &str) -> Option<Credentials>` (None on bad base64 or fewer than three NUL-separated parts)
  - `pub fn decode_login(user_b64: &str, pass_b64: &str) -> Option<Credentials>` (authzid is empty)
  - `pub fn decode_lenient(b64: &str) -> Option<Vec<u8>>` (padding optional)
  - `pub const USERNAME_CHALLENGE: &str = "VXNlcm5hbWU6"; pub const PASSWORD_CHALLENGE: &str = "UGFzc3dvcmQ6";`

- [ ] **Step 1: Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn plain_splits_on_nul() {
        let c = decode_plain(&b64(b"zid\0user\0pass")).unwrap();
        assert_eq!(c, Credentials { authzid: "zid".into(), authcid: "user".into(), password: "pass".into() });
        let c = decode_plain(&b64(b"\0user\0pass")).unwrap();
        assert_eq!(c.authzid, "");
    }

    #[test]
    fn plain_rejects_garbage() {
        assert!(decode_plain("not base64!").is_none());
        assert!(decode_plain(&b64(b"user\0pass")).is_none());
    }

    #[test]
    fn login_pairs_username_and_password() {
        let c = decode_login(&b64(b"user"), &b64(b"pass")).unwrap();
        assert_eq!(c, Credentials { authzid: String::new(), authcid: "user".into(), password: "pass".into() });
    }

    #[test]
    fn padding_is_optional() {
        assert_eq!(decode_lenient("dGVzdA").unwrap(), b"test");
        assert_eq!(decode_lenient("dGVzdA==").unwrap(), b"test");
    }

    #[test]
    fn challenges_are_the_rfc_strings() {
        assert_eq!(decode_lenient(USERNAME_CHALLENGE).unwrap(), b"Username:");
        assert_eq!(decode_lenient(PASSWORD_CHALLENGE).unwrap(), b"Password:");
    }
}
```

- [ ] **Step 2: Implement**

```rust
//! AUTH PLAIN (RFC 4616) and AUTH LOGIN decoding.
use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub authzid: String,
    pub authcid: String,
    pub password: String,
}

pub const USERNAME_CHALLENGE: &str = "VXNlcm5hbWU6";
pub const PASSWORD_CHALLENGE: &str = "UGFzc3dvcmQ6";

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub fn decode_lenient(b64: &str) -> Option<Vec<u8>> {
    LENIENT.decode(b64.trim()).ok()
}

pub fn decode_plain(b64: &str) -> Option<Credentials> {
    let raw = decode_lenient(b64)?;
    let mut parts = raw.split(|b| *b == 0);
    let authzid = String::from_utf8_lossy(parts.next()?).into_owned();
    let authcid = String::from_utf8_lossy(parts.next()?).into_owned();
    let password = String::from_utf8_lossy(parts.next()?).into_owned();
    Some(Credentials { authzid, authcid, password })
}

pub fn decode_login(user_b64: &str, pass_b64: &str) -> Option<Credentials> {
    Some(Credentials {
        authzid: String::new(),
        authcid: String::from_utf8_lossy(&decode_lenient(user_b64)?).into_owned(),
        password: String::from_utf8_lossy(&decode_lenient(pass_b64)?).into_owned(),
    })
}
```

- [ ] **Step 3: Run, commit**

Run: `cargo test --lib server::auth` → 5 passed.

```bash
git add src/server && git commit -m "AUTH PLAIN and LOGIN decoding"
```

---

### Task 8: DATA reader (spec 4.7)

**Files:**
- Create: `src/server/data.rs`
- Modify: `src/server/mod.rs`

**Interfaces:**
- Produces:
  - `pub struct DataReader { .. }` with `pub fn new(max_size: usize) -> Self`
  - `pub enum DataEvent { HeadersComplete(String), MessageComplete(Vec<u8>), TooLarge }`
  - `pub fn push_line(&mut self, line: &[u8]) -> Option<DataEvent>`; `line` is one line including its terminator (CRLF or LF). Returns `HeadersComplete` on the first empty line (or, if the dot comes first, `HeadersComplete` is returned together with the message end: see `finish`), `MessageComplete` on the lone dot, `TooLarge` on the lone dot when the size cap was exceeded.
  - `pub fn headers_done(&self) -> bool`
  - Because the dot can arrive before any empty line, `push_line` on the terminator returns `MessageComplete` and the caller must check `take_pending_headers()`: `pub fn take_pending_headers(&mut self) -> Option<String>` returns the header block if `HeadersComplete` was never emitted.

- [ ] **Step 1: Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn feed(reader: &mut DataReader, text: &str) -> Vec<DataEvent> {
        let mut events = Vec::new();
        let mut rest = text;
        while let Some(i) = rest.find('\n') {
            let (line, tail) = rest.split_at(i + 1);
            if let Some(e) = reader.push_line(line.as_bytes()) {
                events.push(e);
            }
            rest = tail;
        }
        events
    }

    #[test]
    fn headers_then_body() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(&mut r, "From: a@b.com\r\nSubject: hi\r\n\r\nline one\r\n.\r\n");
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], DataEvent::HeadersComplete(h) if h == "From: a@b.com\r\nSubject: hi\r\n"));
        assert!(matches!(&events[1], DataEvent::MessageComplete(b) if b == b"line one\r\n"));
        assert!(r.take_pending_headers().is_none());
    }

    #[test]
    fn dot_stuffing_is_undone_in_headers_and_body() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(&mut r, "..X-Odd: yes\r\n\r\n..\r\n...\r\n.\r\n");
        assert!(matches!(&events[0], DataEvent::HeadersComplete(h) if h == ".X-Odd: yes\r\n"));
        assert!(matches!(&events[1], DataEvent::MessageComplete(b) if b == b".\r\n..\r\n"));
    }

    #[test]
    fn dot_before_any_empty_line_means_headers_only() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(&mut r, "Subject: x\r\n.\r\n");
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], DataEvent::MessageComplete(b) if b.is_empty()));
        assert_eq!(r.take_pending_headers().as_deref(), Some("Subject: x\r\n"));
    }

    #[test]
    fn bare_lf_terminators_are_accepted() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(&mut r, "A: 1\n\nbody\n.\n");
        assert!(matches!(&events[0], DataEvent::HeadersComplete(h) if h == "A: 1\n"));
        assert!(matches!(&events[1], DataEvent::MessageComplete(b) if b == b"body\n"));
    }

    #[test]
    fn size_cap_discards_and_reports() {
        let mut r = DataReader::new(20);
        let events = feed(&mut r, "A: 1\r\n\r\n0123456789\r\n0123456789\r\n0123456789\r\n.\r\n");
        assert!(matches!(&events[0], DataEvent::HeadersComplete(_)));
        assert!(matches!(&events[1], DataEvent::TooLarge));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn size_cap_counts_headers_too() {
        let mut r = DataReader::new(5);
        let events = feed(&mut r, "Subject: long enough\r\n\r\n.\r\n");
        assert!(matches!(&events[0], DataEvent::HeadersComplete(_)));
        assert!(matches!(&events[1], DataEvent::TooLarge));
    }
}
```

- [ ] **Step 2: Implement**

```rust
//! Reads the lines of a DATA payload: undoes dot stuffing, splits headers
//! from body at the first empty line, ends at the lone dot, and enforces
//! the size cap without holding more than the cap in memory.

pub enum DataEvent {
    HeadersComplete(String),
    MessageComplete(Vec<u8>),
    TooLarge,
}

pub struct DataReader {
    max_size: usize,
    headers_done: bool,
    headers: Vec<u8>,
    body: Vec<u8>,
    size: usize,
    too_large: bool,
}

fn is_empty_line(line: &[u8]) -> bool {
    line == b"\r\n" || line == b"\n"
}

fn is_terminator(line: &[u8]) -> bool {
    line == b".\r\n" || line == b".\n"
}

impl DataReader {
    pub fn new(max_size: usize) -> Self {
        Self { max_size, headers_done: false, headers: Vec::new(), body: Vec::new(), size: 0, too_large: false }
    }

    pub fn headers_done(&self) -> bool {
        self.headers_done
    }

    /// `line` includes its terminator.
    pub fn push_line(&mut self, line: &[u8]) -> Option<DataEvent> {
        if is_terminator(line) {
            if self.too_large {
                return Some(DataEvent::TooLarge);
            }
            return Some(DataEvent::MessageComplete(std::mem::take(&mut self.body)));
        }
        if !self.headers_done && is_empty_line(line) {
            self.headers_done = true;
            let headers = String::from_utf8_lossy(&std::mem::take(&mut self.headers)).into_owned();
            return Some(DataEvent::HeadersComplete(headers));
        }
        let unstuffed = line.strip_prefix(b".").unwrap_or(line);
        self.size += unstuffed.len();
        if self.size > self.max_size {
            self.too_large = true;
            self.headers.clear();
            self.body.clear();
            return None;
        }
        if self.headers_done {
            self.body.extend_from_slice(unstuffed);
        } else {
            self.headers.extend_from_slice(unstuffed);
        }
        None
    }

    /// The header block, if the terminator arrived before any empty line.
    pub fn take_pending_headers(&mut self) -> Option<String> {
        if self.headers_done {
            return None;
        }
        self.headers_done = true;
        Some(String::from_utf8_lossy(&std::mem::take(&mut self.headers)).into_owned())
    }
}
```

- [ ] **Step 3: Run, commit**

Run: `cargo test --lib server::data` → 6 passed.

```bash
git add src/server && git commit -m "DATA reader with dot unstuffing and size cap"
```

---

### Task 9: Handler trait, server config, and the session state machine (spec 3.1, 3.2, 4)

This is the largest task. It ends with integration tests through a fake handler over plain TCP. TLS and AUTH over TLS are exercised in Task 10.

**Files:**
- Modify: `src/server/mod.rs`
- Create: `src/server/session.rs`, `src/server/listener.rs`
- Create: `tests/common/mod.rs`, `tests/common/raw_client.rs`, `tests/common/fake_handler.rs`, `tests/server_commands.rs`
- Copy: `../smtp-proxy/t/certs-and-keys/server.crt` and `server.key` to `tests/certs/`

**Interfaces:**
- Produces in `src/server/mod.rs`:

```rust
pub mod auth;
pub mod data;
pub mod listener;
pub mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::smtp::params::Param;

/// The application side of a connection. One instance per connection.
pub trait Handler: Send + 'static {
    fn auth(&mut self, authzid: &str, authcid: &str, password: &str) -> impl Future<Output = Result<(), String>> + Send;
    fn mail(&mut self, from: &str, params: &[Param]) -> impl Future<Output = Result<(), String>> + Send;
    fn rcpt(&mut self, to: &str, params: &[Param]) -> impl Future<Output = Result<(), String>> + Send;
    /// Header block complete; body still arriving.
    fn headers(&mut self, headers: String) -> impl Future<Output = Result<(), String>> + Send;
    /// Terminator arrived. Ok: text for `250 OK: <text>`. Err: text for `550 <text>`.
    fn message(&mut self, body: Vec<u8>) -> impl Future<Output = Result<String, String>> + Send;
    /// RSET, or EHLO/HELO while a transaction is running.
    fn reset(&mut self);
    fn dsn_available(&self) -> bool;
}

pub trait HandlerFactory: Clone + Send + Sync + 'static {
    type Handler: Handler;
    fn create(&self, client: SocketAddr, connection_id: &str) -> Self::Handler;
}

pub struct ServerConfig {
    pub service_name: String,
    pub require_starttls: bool,
    pub require_auth: bool,
    /// None means STARTTLS is not offered (tests only; production always has it).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub max_message_size: usize,
    pub smtplog: Option<Arc<crate::smtplog::SmtpLog>>,
    /// Inactivity timeout once TLS is up. Perl: 600 s.
    pub tls_idle_timeout: std::time::Duration,
}

impl ServerConfig {
    pub fn load_tls(cert: &std::path::Path, key: &std::path::Path) -> anyhow::Result<Arc<rustls::ServerConfig>>;
}
```

  `load_tls` reads PEM with `rustls_pki_types::CertificateDer::pem_file_iter` and `PrivateKeyDer::from_pem_file`, then `rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)`.

- Produces in `session.rs`: `pub async fn run<H: Handler>(stream: tokio::net::TcpStream, client: SocketAddr, id: String, config: Arc<ServerConfig>, handler: H)`. Runs to connection end. Every log line inside runs under the `conn` span with `cid = id`.
- Produces in `listener.rs`:
  - `pub async fn bind(addrs: &[SocketAddr]) -> std::io::Result<Vec<tokio::net::TcpListener>>`
  - `pub async fn serve<F: HandlerFactory>(listeners: Vec<tokio::net::TcpListener>, config: Arc<ServerConfig>, factory: F)` (never returns; part 2 adds the shutdown token)
  - `pub fn new_connection_id() -> String` (32 lowercase hex chars from `rand`)

- [ ] **Step 1: Test helpers**

`tests/common/mod.rs`:
```rust
#![allow(dead_code)]
pub mod fake_handler;
pub mod raw_client;

use std::net::SocketAddr;
use std::sync::Arc;

use smtp_proxy::server::{HandlerFactory, ServerConfig};

pub fn test_tls() -> Arc<rustls::ServerConfig> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs");
    ServerConfig::load_tls(&dir.join("server.crt"), &dir.join("server.key")).unwrap()
}

pub fn server_config(require_starttls: bool, require_auth: bool) -> ServerConfig {
    ServerConfig {
        service_name: "test.service.name".into(),
        require_starttls,
        require_auth,
        tls: Some(test_tls()),
        max_message_size: 1 << 30,
        smtplog: None,
        tls_idle_timeout: std::time::Duration::from_secs(600),
    }
}

/// Binds an ephemeral port, spawns the server, returns its address.
pub async fn start_server<F: HandlerFactory>(config: ServerConfig, factory: F) -> SocketAddr {
    let listeners = smtp_proxy::server::listener::bind(&["127.0.0.1:0".parse().unwrap()]).await.unwrap();
    let addr = listeners[0].local_addr().unwrap();
    tokio::spawn(smtp_proxy::server::listener::serve(listeners, Arc::new(config), factory));
    addr
}
```

`tests/common/raw_client.rs` (port of `RawSMTPClient.pm`):
```rust
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct RawClient {
    stream: Box<dyn Io>,
    buf: Vec<u8>,
}

/// Accepts any server certificate; the test certificate is self-signed.
#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

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
    fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl RawClient {
    /// Connects and returns the client together with the 220 greeting.
    pub async fn connect(addr: SocketAddr) -> (Self, String) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut c = Self { stream: Box::new(stream), buf: Vec::new() };
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
                    let reply = String::from_utf8(self.buf.drain(..end).collect()).unwrap();
                    return reply;
                }
                let mut chunk = [0u8; 4096];
                let n = self.stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "connection closed before a reply arrived; buffer: {:?}", String::from_utf8_lossy(&self.buf));
                self.buf.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .expect("timed out waiting for a reply")
    }

    /// Returns true if the server closed the connection without sending more.
    pub async fn expect_close(&mut self) -> bool {
        let mut chunk = [0u8; 64];
        matches!(tokio::time::timeout(std::time::Duration::from_secs(5), self.stream.read(&mut chunk)).await, Ok(Ok(0)))
    }

    pub async fn auth_plain(&mut self, username: &str, password: &str) -> String {
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{password}"));
        self.command(&format!("AUTH PLAIN {token}")).await
    }

    /// Sends STARTTLS, expects 220, upgrades.
    pub async fn starttls(&mut self) {
        let reply = self.command("STARTTLS").await;
        assert!(reply.starts_with("220"), "{reply}");
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_safe_default_protocol_versions()
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
        assert!(self.command("EHLO client.example.com").await.starts_with("250"));
        self.starttls().await;
        assert!(self.command("EHLO client.example.com").await.starts_with("250"));
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
```

`tests/common/fake_handler.rs` (the Perl tests' inline callbacks):
```rust
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use smtp_proxy::server::{Handler, HandlerFactory};
use smtp_proxy::smtp::params::Param;

#[derive(Default, Debug, Clone)]
pub struct Recorded {
    pub auth: Vec<(String, String, String)>,
    pub mail: Vec<(String, Vec<Param>)>,
    pub rcpt: Vec<(String, Vec<Param>)>,
    pub headers: Vec<String>,
    pub bodies: Vec<Vec<u8>>,
    pub resets: usize,
}

#[derive(Clone)]
pub struct Script {
    pub auth_ok: bool,
    pub mail_error: Option<String>,
    pub rcpt_error: Option<String>,
    pub message_result: Result<String, String>,
    pub dsn: bool,
    /// Delay before answering `message`, to simulate a slow relay.
    pub message_delay: std::time::Duration,
}

impl Default for Script {
    fn default() -> Self {
        Self { auth_ok: true, mail_error: None, rcpt_error: None, message_result: Ok("queued".into()), dsn: true, message_delay: std::time::Duration::ZERO }
    }
}

#[derive(Clone, Default)]
pub struct ScriptedFactory {
    pub script: Arc<Mutex<Script>>,
    pub recorded: Arc<Mutex<Recorded>>,
}

impl ScriptedFactory {
    pub fn set(&self, f: impl FnOnce(&mut Script)) {
        f(&mut self.script.lock().unwrap());
    }
    pub fn recorded(&self) -> Recorded {
        self.recorded.lock().unwrap().clone()
    }
}

pub struct ScriptedHandler {
    script: Arc<Mutex<Script>>,
    recorded: Arc<Mutex<Recorded>>,
}

impl HandlerFactory for ScriptedFactory {
    type Handler = ScriptedHandler;
    fn create(&self, _client: SocketAddr, _id: &str) -> ScriptedHandler {
        ScriptedHandler { script: self.script.clone(), recorded: self.recorded.clone() }
    }
}

impl ScriptedHandler {
    fn script(&self) -> Script {
        self.script.lock().unwrap().clone()
    }
}

impl Handler for ScriptedHandler {
    async fn auth(&mut self, authzid: &str, authcid: &str, password: &str) -> Result<(), String> {
        self.recorded.lock().unwrap().auth.push((authzid.into(), authcid.into(), password.into()));
        if self.script().auth_ok { Ok(()) } else { Err("nope".into()) }
    }
    async fn mail(&mut self, from: &str, params: &[Param]) -> Result<(), String> {
        self.recorded.lock().unwrap().mail.push((from.into(), params.to_vec()));
        self.script().mail_error.map_or(Ok(()), Err)
    }
    async fn rcpt(&mut self, to: &str, params: &[Param]) -> Result<(), String> {
        self.recorded.lock().unwrap().rcpt.push((to.into(), params.to_vec()));
        self.script().rcpt_error.map_or(Ok(()), Err)
    }
    async fn headers(&mut self, headers: String) -> Result<(), String> {
        self.recorded.lock().unwrap().headers.push(headers);
        Ok(())
    }
    async fn message(&mut self, body: Vec<u8>) -> Result<String, String> {
        let script = self.script();
        tokio::time::sleep(script.message_delay).await;
        self.recorded.lock().unwrap().bodies.push(body);
        script.message_result
    }
    fn reset(&mut self) {
        self.recorded.lock().unwrap().resets += 1;
    }
    fn dsn_available(&self) -> bool {
        self.script().dsn
    }
}
```

Add `rustls`, `tokio-rustls`, and `base64` usage in tests: they are already regular dependencies, so tests can use them. Add `futures`? Not needed.

- [ ] **Step 2: Integration tests over plain TCP** (`tests/server_commands.rs`, ports of `commands.t`, `pipelining.t`, `rset-transaction.t`, `repeated-recipient.t`, the session half of `dsn-validation.t`)

```rust
mod common;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};

async fn open_session() -> (RawClient, ScriptedFactory) {
    let factory = ScriptedFactory::default();
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, greeting) = RawClient::connect(addr).await;
    assert_eq!(greeting, "220 test.service.name SMTP service ready\r\n");
    assert!(c.command("EHLO client.example.com").await.starts_with("250"));
    (c, factory)
}

#[tokio::test]
async fn greeting_and_ehlo_reply() {
    let factory = ScriptedFactory::default();
    let addr = start_server(server_config(false, false), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let r = c.command("EHLO client.example.com").await;
    assert_eq!(r, "250-test.service.name offers a warm hug of welcome\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 DSN\r\n");
    let r = c.command("HELO client.example.com").await;
    assert_eq!(r, "250 test.service.name offers a warm hug of welcome\r\n");
}

#[tokio::test]
async fn dsn_is_announced_only_when_available() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.dsn = false);
    let addr = start_server(server_config(false, false), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let r = c.command("EHLO client.example.com").await;
    assert!(!r.contains("DSN"), "{r}");
    assert!(r.ends_with("250 AUTH PLAIN LOGIN\r\n"), "{r}");
}

#[tokio::test]
async fn commands_valid_in_any_state() {
    let (mut c, _) = open_session().await;
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
    assert_eq!(c.command("NOOP keep alive").await, "250 OK\r\n");
    assert_eq!(c.command("VRFY someone").await, "553 Unimplemented\r\n");
    assert_eq!(c.command("VRFY").await, "501 string required\r\n");
    assert_eq!(c.command("EHLO").await, "501 domain required\r\n");
    assert_eq!(c.command("PING").await, "502 unknown command\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(c.command("DATA now").await, "501 no arguments allowed\r\n");
    c.write_raw(" NOOP\r\n").await;
    assert_eq!(c.read_reply().await, "500 malformed command\r\n");
    assert_eq!(c.command("QUIT").await, "221 test.service.name closing transmission channel\r\n");
    assert!(c.expect_close().await);
}

#[tokio::test]
async fn out_of_sequence_commands_draw_503() {
    let (mut c, _) = open_session().await;
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "503 Bad sequence of commands\r\n");
    assert_eq!(c.command("DATA").await, "503 Bad sequence of commands\r\n");
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("DATA").await, "503 Bad sequence of commands\r\n");
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "503 Bad sequence of commands\r\n");
}

#[tokio::test]
async fn full_transaction_reaches_the_handler() {
    let (mut c, factory) = open_session().await;
    assert_eq!(c.command("MAIL FROM:<x@y.com> SIZE=10").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<c@d.com> NOTIFY=NEVER").await, "250 OK\r\n");
    assert_eq!(c.command("DATA").await, "354 End data with <CR><LF>.<CR><LF>\r\n");
    c.write_raw("Subject: hi\r\nTo: a@b.com\r\n\r\nbody line\r\n..dot line\r\n.\r\n").await;
    assert_eq!(c.read_reply().await, "250 OK: queued\r\n");
    let rec = factory.recorded();
    assert_eq!(rec.mail[0].0, "x@y.com");
    assert_eq!(rec.mail[0].1[0].keyword, "SIZE");
    assert_eq!(rec.rcpt.len(), 2);
    assert_eq!(rec.rcpt[1].1[0].value.as_deref(), Some("NEVER"));
    assert_eq!(rec.headers[0], "Subject: hi\r\nTo: a@b.com\r\n");
    assert_eq!(rec.bodies[0], b"body line\r\n.dot line\r\n");
    // Next transaction on the same connection.
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn handler_rejections_use_the_perl_texts() {
    let (mut c, factory) = open_session().await;
    factory.set(|s| s.mail_error = Some("no".into()));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "553 Requested action not taken: no\r\n");
    factory.set(|s| { s.mail_error = None; s.rcpt_error = Some("bad user".into()) });
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "550 Will not send mail to this user: bad user\r\n");
    factory.set(|s| { s.rcpt_error = None; s.message_result = Err("Weather too hot to email".into()) });
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n.\r\n").await;
    assert_eq!(c.read_reply().await, "550 Weather too hot to email\r\n");
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn rset_and_ehlo_reset_the_transaction_but_not_the_session() {
    let (mut c, factory) = open_session().await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "503 Bad sequence of commands\r\n");
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert!(c.command("EHLO again.example.com").await.starts_with("250"));
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "503 Bad sequence of commands\r\n");
    assert_eq!(factory.recorded().resets, 2);
    // An EHLO with no transaction running does not report a reset.
    assert!(c.command("EHLO again.example.com").await.starts_with("250"));
    assert_eq!(factory.recorded().resets, 2);
}

#[tokio::test]
async fn pipelined_commands_are_answered_in_order() {
    let (mut c, _) = open_session().await;
    c.write_raw("MAIL FROM:<x@y.com>\r\nRCPT TO:<a@b.com>\r\nRCPT TO:<c@d.com>\r\nDATA\r\n").await;
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert!(c.read_reply().await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\nbody\r\n.\r\nQUIT\r\n").await;
    assert_eq!(c.read_reply().await, "250 OK: queued\r\n");
    assert!(c.read_reply().await.starts_with("221"));
}

#[tokio::test]
async fn repeated_recipient_is_recorded_twice() {
    let (mut c, factory) = open_session().await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com> NOTIFY=SUCCESS").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com> NOTIFY=NEVER").await, "250 OK\r\n");
    let rec = factory.recorded();
    assert_eq!(rec.rcpt.len(), 2);
    assert_eq!(rec.rcpt[0].1[0].value.as_deref(), Some("SUCCESS"));
    assert_eq!(rec.rcpt[1].1[0].value.as_deref(), Some("NEVER"));
}

#[tokio::test]
async fn dsn_parameters_are_validated_at_the_command() {
    let (mut c, _) = open_session().await;
    let script: &[(&str, char)] = &[
        ("MAIL FROM:<a@b.com> RET=PARTIAL", '5'),
        ("MAIL FROM:<a@b.com> RET", '5'),
        ("MAIL FROM:<a@b.com> ENVID=has+zz", '5'),
        ("MAIL FROM:<a@b.com> ENVID=one ENVID=two", '5'),
        ("MAIL FROM:<a@b.com> RET=FULL RET=HDRS", '5'),
        ("MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159", '2'),
        ("RCPT TO:<c@d.com> NOTIFY=MAYBE", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=NEVER,SUCCESS", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=DELAY,DELAY", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=SUCCESS,", '5'),
        ("RCPT TO:<c@d.com> ORCPT=nosemicolon", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=DELAY NOTIFY=NEVER", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;c@d.com", '2'),
        ("RCPT TO:<c@d.com> NOTIFY=NEVER", '2'),
    ];
    for (line, expected) in script {
        let r = c.command(line).await;
        assert_eq!(r.chars().next().unwrap(), *expected, "{line} -> {r}");
        if *expected == '5' {
            assert!(r.starts_with("501 "), "{line} -> {r}");
        }
    }
    assert_eq!(c.command("MAIL FROM:<a@b.com> RET=PARTIAL").await, "501 RET requires a value of FULL or HDRS\r\n");
}

#[tokio::test]
async fn message_over_the_cap_is_refused_with_552() {
    let factory = ScriptedFactory::default();
    let mut config = server_config(false, false);
    config.max_message_size = 64;
    let addr = start_server(config, factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(&format!("Subject: x\r\n\r\n{}\r\n.\r\n", "y".repeat(100))).await;
    assert_eq!(c.read_reply().await, "552 Message exceeds maximum size of 64 bytes\r\n");
    assert!(factory.recorded().bodies.is_empty());
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn client_that_leaves_during_a_slow_message_is_logged_not_crashed() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.message_delay = std::time::Duration::from_millis(300));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n.\r\n").await;
    drop(c);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(factory.recorded().bodies.len(), 1);
    // Server still serves a new client.
    let (mut c2, greeting) = RawClient::connect(addr).await;
    assert!(greeting.starts_with("220"));
    assert!(c2.command("NOOP").await.starts_with("250"));
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test --test server_commands`
Expected: compile errors (no `server::listener`, no `Handler`).

- [ ] **Step 4: Implement `src/server/mod.rs`** as in the Interfaces block, plus:

```rust
impl ServerConfig {
    pub fn load_tls(cert: &std::path::Path, key: &std::path::Path) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_file_iter(cert)
                .map_err(|e| anyhow::anyhow!("cannot read certificate {}: {e}", cert.display()))?
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("bad certificate in {}: {e}", cert.display()))?;
        let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key)
            .map_err(|e| anyhow::anyhow!("cannot read key {}: {e}", key.display()))?;
        let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
        Ok(Arc::new(config))
    }
}
```

Ensure the crypto provider is installed once at startup: in `listener::bind` (and in `main`) call `let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();`.

- [ ] **Step 5: Implement `src/server/listener.rs`**

```rust
//! Accept loop: one task per client connection.
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{Instrument, debug};

use crate::server::{HandlerFactory, ServerConfig, session};

pub async fn bind(addrs: &[SocketAddr]) -> std::io::Result<Vec<TcpListener>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut listeners = Vec::with_capacity(addrs.len());
    for addr in addrs {
        listeners.push(TcpListener::bind(addr).await?);
    }
    Ok(listeners)
}

/// 32 lowercase hex characters, like Mojo::IOLoop's md5-based ids.
pub fn new_connection_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn serve<F: HandlerFactory>(listeners: Vec<TcpListener>, config: Arc<ServerConfig>, factory: F) {
    let mut tasks = tokio::task::JoinSet::new();
    for listener in listeners {
        let config = config.clone();
        let factory = factory.clone();
        tasks.spawn(async move {
            loop {
                let (stream, client) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!("accept failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let id = new_connection_id();
                let span = tracing::info_span!("conn", cid = %id);
                let handler = factory.create(client, &id);
                let config = config.clone();
                tokio::spawn(
                    async move {
                        debug!("New incoming connection from {client}");
                        session::run(stream, client, id, config, handler).await;
                        debug!("connection closed");
                    }
                    .instrument(span),
                );
            }
        });
    }
    while tasks.join_next().await.is_some() {}
}
```

Check the `rand` 0.10 API names (`rand::rng()` and `RngCore::fill_bytes`) with `cargo doc` or the docs.rs page for the exact version before relying on them; adjust if 0.10 renamed them.

- [ ] **Step 6: Implement `src/server/session.rs`**

```rust
//! One client connection, driven as sequential async code: read a command,
//! handle it completely, reply, repeat. Pipelined commands are therefore
//! answered in order, and the reply to DATA is on the wire before the next
//! command is read, so a late relay result cannot land in a later
//! transaction.
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::server::auth::{PASSWORD_CHALLENGE, USERNAME_CHALLENGE, decode_login, decode_plain};
use crate::server::data::{DataEvent, DataReader};
use crate::server::{Handler, ServerConfig};
use crate::smtp::command::{Command, CommandError, parse_command, take_line};
use crate::smtp::dsn::{DsnCommand, validate_dsn};
use crate::smtp::reply::Reply;

type Stream = Pin<Box<dyn AsyncReadWrite>>;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
}

struct Session<H> {
    stream: Stream,
    buf: Vec<u8>,
    state: State,
    tls_active: bool,
    authenticated: bool,
    recipients: usize,
    client: SocketAddr,
    id: String,
    config: Arc<ServerConfig>,
    handler: H,
}

pub async fn run<H: Handler>(stream: TcpStream, client: SocketAddr, id: String, config: Arc<ServerConfig>, handler: H) {
    let mut s = Session {
        stream: Box::pin(stream),
        buf: Vec::new(),
        state: State::WantGreeting,
        tls_active: false,
        authenticated: false,
        recipients: 0,
        client,
        id,
        config,
        handler,
    };
    let end = s.serve().await;
    match end {
        End::Quit | End::Eof | End::TlsFailed => {}
        End::Timeout => tracing::error!("Timeout on stream for {}", s.client),
        End::Io(e) => tracing::error!("Error on stream for {}: {e}", s.client),
    }
}

impl<H: Handler> Session<H> {
    async fn serve(&mut self) -> End {
        let greeting = Reply::new(220, format!("{} SMTP service ready", self.config.service_name));
        if let Err(e) = self.send(greeting).await {
            return End::Io(e);
        }
        loop {
            let line = match self.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => return End::Eof,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return End::Timeout,
                Err(e) => return End::Io(e),
            };
            let text = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string();
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
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return End::Timeout,
                Err(e) => return End::Io(e),
            }
        }
    }

    /// One line including its terminator; None at EOF. After TLS, an idle
    /// connection times out; before TLS it does not, as in the Perl.
    async fn next_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(line) = take_line(&mut self.buf) {
                return Ok(Some(line));
            }
            let mut chunk = [0u8; 8192];
            let n = if self.tls_active {
                match tokio::time::timeout(self.config.tls_idle_timeout, self.stream.read(&mut chunk)).await {
                    Ok(r) => r?,
                    Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "inactivity timeout")),
                }
            } else {
                self.stream.read(&mut chunk).await?
            };
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
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
                self.send(Reply::new(221, format!("{} closing transmission channel", self.config.service_name))).await?;
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
                self.greeting(matches!(command, Command::Ehlo { .. })).await?;
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
        self.send(Reply::new(503, "Bad sequence of commands")).await?;
        Ok(Flow::Continue)
    }

    /// RFC 5321 4.1.4: a greeting at any point resets the transaction like
    /// RSET, but never the session: authentication survives.
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
                    info!("Discarding {} byte(s) received before STARTTLS from {}", self.buf.len(), self.client);
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
                self.send(Reply::new(530, "Must issue a STARTTLS command first")).await?;
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
                                Some(t) => t,
                                None => return Ok(Flow::Continue),
                            }
                        }
                    };
                    let creds = decode_plain(&token);
                    self.finish_auth(creds).await
                }
                "LOGIN" => {
                    debug!("Processing AUTH LOGIN for {}", self.client);
                    self.send(Reply::new(334, USERNAME_CHALLENGE)).await?;
                    let Some(user) = self.auth_continuation().await? else { return Ok(Flow::Continue) };
                    self.send(Reply::new(334, PASSWORD_CHALLENGE)).await?;
                    let Some(pass) = self.auth_continuation().await? else { return Ok(Flow::Continue) };
                    debug!("Received AUTH LOGIN password for {}", self.client);
                    let creds = decode_login(&user, &pass);
                    self.finish_auth(creds).await
                }
                other => {
                    debug!("Unsupported AUTH mechanism {other} used by {}", self.client);
                    self.send(Reply::new(504, "Authentication mechanism not supported")).await?;
                    Ok(Flow::Continue)
                }
            },
            _ if self.config.require_auth => {
                debug!("Authentication required sent to {}", self.client);
                self.send(Reply::new(530, "Authentication required")).await?;
                Ok(Flow::Continue)
            }
            other => {
                self.state = State::WantMail;
                self.want_mail(other).await
            }
        }
    }

    /// One SASL continuation line. None means a 500 was already sent.
    async fn auth_continuation(&mut self) -> std::io::Result<Option<String>> {
        let Some(line) = self.next_line().await? else {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof in AUTH"));
        };
        let text = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string();
        if let Some(log) = &self.config.smtplog {
            log.received_auth_secret(&self.id, &text);
        }
        if text.is_empty() {
            self.send(Reply::new(500, "confused authentication response")).await?;
            return Ok(None);
        }
        Ok(Some(text))
    }

    async fn finish_auth(&mut self, creds: Option<crate::server::auth::Credentials>) -> std::io::Result<Flow> {
        let ok = match creds {
            Some(c) => self.handler.auth(&c.authzid, &c.authcid, &c.password).await.is_ok(),
            None => false,
        };
        if ok {
            self.send(Reply::new(235, "Authentication successful")).await?;
            debug!("Successfully authenticated {}", self.client);
            self.authenticated = true;
            self.state = State::WantMail;
        } else {
            self.send(Reply::new(535, "Authentication credentials invalid")).await?;
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
            Err(e) => {
                self.send(Reply::new(553, format!("Requested action not taken: {e}"))).await?;
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
        match self.handler.rcpt(&to, &params).await {
            Ok(()) => {
                self.send(Reply::new(250, "OK")).await?;
                debug!("Accepted RCPT command from {}", self.client);
                self.recipients += 1;
                self.state = State::WantData;
            }
            Err(e) => {
                self.send(Reply::new(550, format!("Will not send mail to this user: {e}"))).await?;
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
        self.send(Reply::new(354, "End data with <CR><LF>.<CR><LF>")).await?;
        let mut reader = DataReader::new(self.config.max_message_size);
        let mut headers_error: Option<String> = None;
        let mut logged_mb = 0usize;
        let mut received = 0usize;
        let outcome = loop {
            let Some(line) = self.next_line().await? else {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof in DATA"));
            };
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
                Some(DataEvent::TooLarge) => break Err(format!("Message exceeds maximum size of {} bytes", self.config.max_message_size)).map_err(|t| (552, t)),
                Some(DataEvent::MessageComplete(body)) => {
                    if let Some(h) = reader.take_pending_headers() {
                        debug!("Header received (empty Body). Resolving Header Promise and Empty Body Promise.");
                        if let Err(e) = self.handler.headers(h).await {
                            headers_error = Some(e);
                        }
                    } else {
                        debug!("Body received {} Bytes. Resolving Body Promise.", body.len());
                    }
                    if let Some(e) = headers_error.take() {
                        break Err((550, e));
                    }
                    break self.handler.message(body).await.map_err(|t| (550, t));
                }
            }
        };
        self.state = State::WantMail;
        match outcome {
            Ok(message) => {
                debug!("Accepted DATA for {} {message}", self.client);
                if let Err(e) = self.send(Reply::new(250, format!("OK: {message}"))).await {
                    info!("Client {} left before the message could be accepted: {message}", self.client);
                    return Err(e);
                }
            }
            Err((code, text)) => {
                debug!("DATA rejected for {} {text}", self.client);
                if code == 552 {
                    self.start_transaction();
                }
                if let Err(e) = self.send(Reply::new(code, text.clone())).await {
                    info!("Client {} left before the rejection could be sent: {text}", self.client);
                    return Err(e);
                }
            }
        }
        Ok(Flow::Continue)
    }
}

enum Flow {
    Continue,
    Quit,
    TlsFailed,
}
```

`warn` is imported for later use by part 2; remove the import if clippy flags it as unused.

- [ ] **Step 7: Copy the test certificates and run the tests**

```bash
mkdir -p tests/certs && cp ../smtp-proxy/t/certs-and-keys/server.crt ../smtp-proxy/t/certs-and-keys/server.key tests/certs/
cargo test --test server_commands
```
Expected: all 12 tests pass. Then `cargo clippy --all-targets -- -D warnings`.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "Session state machine, listener, and server integration tests"
```

---

### Task 10: STARTTLS and AUTH over TLS (spec 4.4, 4.5)

**Files:**
- Create: `tests/server_tls_auth.rs`

**Interfaces:** consumes Task 9 only. Ports `connection-lifecycle.t`, `starttls-failure.t`, `smtp-server.t`, `smtplog-redaction.t`.

- [ ] **Step 1: Tests**

```rust
mod common;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};

#[tokio::test]
async fn starttls_is_required_before_anything_else() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let r = c.command("EHLO client.example.com").await;
    assert_eq!(r, "250-test.service.name offers a warm hug of welcome\r\n250-STARTTLS\r\n250 DSN\r\n");
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "530 Must issue a STARTTLS command first\r\n");
    assert_eq!(c.command("AUTH PLAIN AAB1AHA=").await, "530 Must issue a STARTTLS command first\r\n");
    c.starttls().await;
    let r = c.command("EHLO client.example.com").await;
    assert_eq!(r, "250-test.service.name offers another warm hug of welcome\r\n250-AUTH PLAIN LOGIN\r\n250 DSN\r\n");
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "530 Authentication required\r\n");
}

#[tokio::test]
async fn auth_plain_and_login_over_tls() {
    let factory = ScriptedFactory::default();
    let addr = start_server(server_config(true, true), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    // RFC 3207 says the client SHOULD re-EHLO; some do not, and AUTH must still work.
    assert_eq!(c.auth_plain("user", "pass").await, "235 Authentication successful\r\n");
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(factory.recorded().auth[0], ("".into(), "user".into(), "pass".into()));

    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
    assert_eq!(c.command("dXNlcjI=").await, "334 UGFzc3dvcmQ6\r\n");
    assert_eq!(c.command("cGFzczI=").await, "235 Authentication successful\r\n");
    assert_eq!(factory.recorded().auth[1], ("".into(), "user2".into(), "pass2".into()));

    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(c.command("AUTH PLAIN").await, "334 \r\n");
    assert_eq!(c.command("AHVzZXIzAHBhc3Mz").await, "235 Authentication successful\r\n");
    assert_eq!(factory.recorded().auth[2].1, "user3");
}

#[tokio::test]
async fn auth_failures() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.auth_ok = false);
    let addr = start_server(server_config(true, true), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(c.auth_plain("user", "pass").await, "535 Authentication credentials invalid\r\n");
    assert_eq!(c.command("AUTH CRAM-MD5").await, "504 Authentication mechanism not supported\r\n");
    assert_eq!(c.command("AUTH PLAIN not-base64!").await, "535 Authentication credentials invalid\r\n");
    assert_eq!(c.command("AUTH PLAIN").await, "334 \r\n");
    assert_eq!(c.command("").await, "500 confused authentication response\r\n");
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "530 Authentication required\r\n");
}

#[tokio::test]
async fn ehlo_after_auth_keeps_the_session_authenticated() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    c.login("user", "pass").await;
    assert!(c.command("EHLO again").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn bytes_sent_before_starttls_are_discarded() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    // A plaintext injection: STARTTLS and a command in the same packet.
    c.write_raw("STARTTLS\r\nNOOP\r\n").await;
    assert_eq!(c.read_reply().await, "220 Go ahead\r\n");
    // The NOOP must not be answered; the next thing the server does is the handshake.
    c.starttls_after_220().await;
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
}

#[tokio::test]
async fn failed_tls_handshake_closes_the_connection() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("STARTTLS").await, "220 Go ahead\r\n");
    c.write_raw("this is not a TLS ClientHello\r\n").await;
    assert!(c.expect_close().await);
    // The server still accepts new clients.
    let (mut c2, g) = RawClient::connect(addr).await;
    assert!(g.starts_with("220"));
    assert!(c2.command("NOOP").await.starts_with("250"));
}

#[tokio::test]
async fn smtplog_redacts_credentials_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    for credentials in [false, true] {
        let path = dir.path().join(format!("smtp-{credentials}.log"));
        let mut config = server_config(true, true);
        config.smtplog = Some(std::sync::Arc::new(smtp_proxy::smtplog::SmtpLog::open(&path, credentials).unwrap()));
        let addr = start_server(config, ScriptedFactory::default()).await;
        // One session with AUTH PLAIN, one with AUTH LOGIN.
        let (mut c, _) = RawClient::connect(addr).await;
        assert!(c.command("EHLO x").await.starts_with("250"));
        c.starttls().await;
        assert!(c.auth_plain("u", "p").await.starts_with("235"));
        c.command("QUIT").await;
        let (mut c, _) = RawClient::connect(addr).await;
        assert!(c.command("EHLO x").await.starts_with("250"));
        c.starttls().await;
        assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
        assert!(c.command("dXNlcg==").await.starts_with("334"));
        assert!(c.command("cGFzcw==").await.starts_with("235"));
        c.command("QUIT").await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(">>> EHLO x"));
        assert!(text.contains("<<< 220 Go ahead"));
        assert!(text.contains("<<< 334 VXNlcm5hbWU6"));
        if credentials {
            assert!(text.contains(">>> dXNlcg=="), "{text}");
            assert!(text.contains(">>> cGFzcw=="), "{text}");
        } else {
            assert!(!text.contains("dXNlcg=="), "{text}");
            assert!(!text.contains("cGFzcw=="), "{text}");
            assert!(text.contains(">>> [REDACTED]"), "{text}");
            assert!(text.contains(">>> AUTH PLAIN [REDACTED]"), "{text}");
        }
    }
}
```

Add to `RawClient` a `starttls_after_220()` method: the body of `starttls()` after the STARTTLS command has been sent and its 220 read (factor `starttls()` into `command("STARTTLS")` plus `starttls_after_220()`).

- [ ] **Step 2: Run, fix, commit**

Run: `cargo test --test server_tls_auth`
Expected: 7 passed. If the plaintext-discard test fails because the NOOP was answered, the buffer clear in `want_starttls` is misplaced.

```bash
git add -A && git commit -m "STARTTLS, AUTH, and smtplog integration tests"
```

---
### Task 11: API client (spec 5.3)

**Files:**
- Create: `src/api.rs`, `tests/common/fake_api.rs`, `tests/api.rs`
- Modify: `src/lib.rs` (add `pub mod api;`), `tests/common/mod.rs` (add `pub mod fake_api;`)

**Interfaces:**
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestHeader { pub name: String, pub value: String }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseHeader { pub name: String, pub value: Option<String> }

/// One RCPT TO as given, in order. Also the `rcptParameters` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient { pub address: String, pub parameters: Vec<Param> }

#[derive(Debug, Clone, Serialize)]
pub struct CheckRequest {
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub headers: Vec<RequestHeader>,
    #[serde(rename = "mailParameters")] pub mail_parameters: Vec<Param>,
    #[serde(rename = "rcptParameters")] pub rcpt_parameters: Vec<Recipient>,
}

impl CheckRequest {
    /// The request as JSON with the password replaced by `*******`, for logs.
    pub fn redacted_json(&self) -> String;
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CheckResponse {
    pub allow: bool,
    #[serde(default)] pub reason: Option<String>,
    #[serde(default)] pub headers: Vec<ResponseHeader>,
    #[serde(default)] pub from: Option<String>,
    #[serde(default, rename = "authId")] pub auth_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")] Transport(#[from] reqwest::Error),
    /// Non-2xx. The string is the HTTP reason phrase (Perl: `$tx->result->message`), e.g. `Internal Server Error`.
    #[error("{1}")] Status(u16, String),
    #[error("invalid JSON from the API: {0}")] Json(String),
}

#[derive(Clone)]
pub struct ApiClient { client: reqwest::Client, url: String }

impl ApiClient {
    /// 60 second timeout, as the Perl inactivity timeout.
    pub fn new(url: String) -> anyhow::Result<Self>;
    pub fn url(&self) -> &str;
    pub async fn check(&self, request: &CheckRequest) -> Result<CheckResponse, ApiError>;
}
```

- [ ] **Step 1: Fake API test helper** (`tests/common/fake_api.rs`, port of `FakeAPI.pm` as an HTTP server)

```rust
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};

#[derive(Clone)]
pub struct FakeApi {
    pub url: String,
    state: Arc<Mutex<FakeApiState>>,
}

pub struct FakeApiState {
    pub response: serde_json::Value,
    pub status: StatusCode,
    pub calls: Vec<serde_json::Value>,
}

async fn handle(State(state): State<Arc<Mutex<FakeApiState>>>, Json(body): Json<serde_json::Value>) -> (StatusCode, Json<serde_json::Value>) {
    let mut s = state.lock().unwrap();
    s.calls.push(body);
    (s.status, Json(s.response.clone()))
}

impl FakeApi {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(FakeApiState {
            response: serde_json::json!({ "allow": true, "headers": [] }),
            status: StatusCode::OK,
            calls: Vec::new(),
        }));
        let app = Router::new().route("/check", post(handle)).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/check", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, state }
    }

    pub fn respond(&self, response: serde_json::Value) {
        let mut s = self.state.lock().unwrap();
        s.response = response;
        s.status = StatusCode::OK;
    }

    pub fn fail_with(&self, status: StatusCode) {
        self.state.lock().unwrap().status = status;
    }

    pub fn calls(&self) -> Vec<serde_json::Value> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn clear(&self) {
        self.state.lock().unwrap().calls.clear();
    }
}
```

- [ ] **Step 2: Tests** (`tests/api.rs` and unit tests in `src/api.rs`)

`tests/api.rs`:
```rust
mod common;

use common::fake_api::FakeApi;
use smtp_proxy::api::{ApiClient, ApiError, CheckRequest, Recipient, RequestHeader};
use smtp_proxy::smtp::params::Param;

fn request() -> CheckRequest {
    CheckRequest {
        username: "u".into(),
        password: "secret".into(),
        from: "a@b.com".into(),
        to: vec!["x@baz.com".into(), "x@baz.com".into()],
        headers: vec![RequestHeader { name: "To".into(), value: "foo@bar.com".into() }],
        mail_parameters: vec![Param { keyword: "RET".into(), value: Some("HDRS".into()) }],
        rcpt_parameters: vec![
            Recipient { address: "x@baz.com".into(), parameters: vec![Param { keyword: "NOTIFY".into(), value: Some("SUCCESS".into()) }] },
            Recipient { address: "x@baz.com".into(), parameters: vec![Param { keyword: "SMTPUTF8".into(), value: None }] },
        ],
    }
}

#[tokio::test]
async fn request_body_matches_the_contract() {
    let api = FakeApi::start().await;
    let client = ApiClient::new(api.url.clone()).unwrap();
    let resp = client.check(&request()).await.unwrap();
    assert!(resp.allow);
    let call = &api.calls()[0];
    let expected = serde_json::json!({
        "username": "u", "password": "secret", "from": "a@b.com",
        "to": ["x@baz.com", "x@baz.com"],
        "headers": [{"name": "To", "value": "foo@bar.com"}],
        "mailParameters": [{"keyword": "RET", "value": "HDRS"}],
        "rcptParameters": [
            {"address": "x@baz.com", "parameters": [{"keyword": "NOTIFY", "value": "SUCCESS"}]},
            {"address": "x@baz.com", "parameters": [{"keyword": "SMTPUTF8", "value": null}]}
        ]
    });
    assert_eq!(call, &expected);
    // Field order is part of the contract.
    let raw = serde_json::to_string(&request()).unwrap();
    let keys: Vec<&str> = ["\"username\"", "\"password\"", "\"from\"", "\"to\"", "\"headers\"", "\"mailParameters\"", "\"rcptParameters\""].into();
    let positions: Vec<usize> = keys.iter().map(|k| raw.find(k).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{raw}");
}

#[tokio::test]
async fn deny_and_optional_fields() {
    let api = FakeApi::start().await;
    api.respond(serde_json::json!({ "allow": false, "reason": "sorry, not telling" }));
    let client = ApiClient::new(api.url.clone()).unwrap();
    let resp = client.check(&request()).await.unwrap();
    assert!(!resp.allow);
    assert_eq!(resp.reason.as_deref(), Some("sorry, not telling"));
    assert!(resp.headers.is_empty());
    api.respond(serde_json::json!({ "allow": true, "headers": [{"name": "X", "value": null}], "from": "o@b.com", "authId": "tok" }));
    let resp = client.check(&request()).await.unwrap();
    assert_eq!(resp.headers[0].value, None);
    assert_eq!(resp.from.as_deref(), Some("o@b.com"));
    assert_eq!(resp.auth_id.as_deref(), Some("tok"));
}

#[tokio::test]
async fn non_2xx_is_an_error_carrying_the_reason_phrase() {
    let api = FakeApi::start().await;
    api.fail_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let client = ApiClient::new(api.url.clone()).unwrap();
    match client.check(&request()).await {
        Err(ApiError::Status(500, reason)) => assert_eq!(reason, "Internal Server Error"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn unreachable_api_is_a_transport_error() {
    let client = ApiClient::new("http://127.0.0.1:1/check".into()).unwrap();
    assert!(matches!(client.check(&request()).await, Err(ApiError::Transport(_))));
}

#[test]
fn redacted_json_hides_the_password() {
    let json = request().redacted_json();
    assert!(json.contains("\"password\":\"*******\""), "{json}");
    assert!(!json.contains("secret"));
}
```

- [ ] **Step 3: Implement `src/api.rs`**

```rust
//! The authentication and header API: one POST per message.
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::smtp::params::Param;

// ... the type definitions from the Interfaces block ...

impl CheckRequest {
    pub fn redacted_json(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or_default();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("password".into(), serde_json::Value::String("*******".into()));
        }
        value.to_string()
    }
}

impl ApiClient {
    pub fn new(url: String) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("smtp-proxy/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client, url })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn check(&self, request: &CheckRequest) -> Result<CheckResponse, ApiError> {
        let response = self.client.post(&self.url).json(request).send().await?;
        let status = response.status();
        tracing::debug!("validation call to {} returned {}", self.url, status.as_u16());
        if !status.is_success() {
            tracing::debug!("Validation Failed");
            tracing::debug!("req: {}", request.redacted_json());
            let body = response.text().await.unwrap_or_default();
            tracing::debug!("res: {body}");
            let reason = status.canonical_reason().unwrap_or("").to_string();
            return Err(ApiError::Status(status.as_u16(), reason));
        }
        let body = response.text().await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Json(e.to_string()))
    }
}
```

Note: `serde_json`'s `preserve_order` feature is NOT needed for the request: field order follows the struct declaration. `redacted_json` goes through `Value`, which sorts keys alphabetically; that is fine for a debug line.

- [ ] **Step 4: Run, commit**

Run: `cargo test --test api --lib api`
Expected: 5 passed.

```bash
git add -A && git commit -m "API client with the fake API test server"
```

---

### Task 12: Relay client and the startup probe (spec 6, without 6.1)

**Files:**
- Create: `src/relay.rs`, `tests/common/upstream.rs`, `tests/relay.rs`
- Modify: `src/lib.rs` (add `pub mod relay;`), `tests/common/mod.rs` (add `pub mod upstream;`)

**Interfaces:**
- Produces:

```rust
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub host: String,
    pub port: u16,
    /// Perl: 60 s inactivity.
    pub timeout: std::time::Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("{0}")] Io(#[from] std::io::Error),
    /// The upstream answered outside the expected class. The string is the
    /// reply text without its code, which is what the client gets in its 550.
    #[error("{text}")] Rejected { command: &'static str, code: u16, text: String },
    #[error("Refusing to relay the address '{0}': it contains characters that cannot appear in an SMTP command line")]
    Address(String),
    #[error("timeout talking to the upstream")] Timeout,
}

pub struct Envelope<'a> {
    pub from: &'a str,
    pub mail_params: &'a [Param],
    pub recipients: &'a [Recipient],
}

/// Outcome of a relayed message.
pub struct Relayed {
    /// Text of the 250 reply to the final dot (the upstream queue id).
    pub message: String,
    pub upstream_dsn: bool,
}

pub fn assert_relayable(address: &str) -> Result<(), RelayError>;
pub fn dsn_suffix(params: &[Param], keep: fn(&str) -> bool, upstream_dsn: bool) -> String;

/// EHLO + QUIT. Returns whether the upstream announces DSN.
pub async fn probe(config: &RelayConfig) -> Result<bool, RelayError>;

/// A whole session: EHLO, MAIL, RCPT.., DATA, message, QUIT.
pub async fn relay(config: &RelayConfig, envelope: Envelope<'_>, message: &[u8]) -> Result<Relayed, RelayError>;
```

  `relay` decides DSN forwarding from the EHLO reply of its own session, so the shared `AtomicBool` is updated by the caller (proxy) from `Relayed::upstream_dsn`; that keeps `relay.rs` free of shared state.

- [ ] **Step 1: Recording upstream helper** (`tests/common/upstream.rs`, port of `RecordingSMTPServer.pm`)

```rust
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct RecordingUpstream {
    pub addr: SocketAddr,
    inner: Arc<Mutex<Inner>>,
}

pub struct Inner {
    pub extensions: Vec<String>,
    pub commands: Vec<String>,
    pub messages: Vec<String>,
    /// Reply to MAIL FROM with this 5xx text instead of 250.
    pub reject_mail: Option<String>,
    /// Reply to the final dot with this text after `250 `.
    pub accept_text: String,
}

impl RecordingUpstream {
    pub async fn start(extensions: &[&str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let inner = Arc::new(Mutex::new(Inner {
            extensions: extensions.iter().map(|s| s.to_string()).collect(),
            commands: Vec::new(),
            messages: Vec::new(),
            reject_mail: None,
            accept_text: "OK message accepted".into(),
        }));
        let state = inner.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_one(stream, state.clone()));
            }
        });
        Self { addr, inner }
    }

    pub fn commands(&self) -> Vec<String> {
        self.inner.lock().unwrap().commands.clone()
    }
    pub fn commands_matching(&self, prefix: &str) -> Vec<String> {
        self.commands().into_iter().filter(|c| c.starts_with(prefix)).collect()
    }
    pub fn messages(&self) -> Vec<String> {
        self.inner.lock().unwrap().messages.clone()
    }
    pub fn set_extensions(&self, extensions: &[&str]) {
        self.inner.lock().unwrap().extensions = extensions.iter().map(|s| s.to_string()).collect();
    }
    pub fn reject_mail(&self, text: Option<&str>) {
        self.inner.lock().unwrap().reject_mail = text.map(String::from);
    }
    pub fn accept_text(&self, text: &str) {
        self.inner.lock().unwrap().accept_text = text.into();
    }
    pub fn clear(&self) {
        let mut i = self.inner.lock().unwrap();
        i.commands.clear();
        i.messages.clear();
    }
}

async fn serve_one(stream: tokio::net::TcpStream, state: Arc<Mutex<Inner>>) {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    w.write_all(b"220 recording.upstream ESMTP ready\r\n").await.unwrap();
    let mut in_data = false;
    let mut message = String::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if in_data {
            if line == "." {
                in_data = false;
                let text = { let mut s = state.lock().unwrap(); s.messages.push(std::mem::take(&mut message)); s.accept_text.clone() };
                w.write_all(format!("250 {text}\r\n").as_bytes()).await.unwrap();
            } else {
                message.push_str(&line);
                message.push_str("\r\n");
            }
            continue;
        }
        state.lock().unwrap().commands.push(line.clone());
        let upper = line.to_ascii_uppercase();
        let reply = if upper.starts_with("EHLO") {
            let ext = state.lock().unwrap().extensions.clone();
            let mut r = String::from("250-recording.upstream\r\n");
            for (i, e) in ext.iter().enumerate() {
                let sep = if i + 1 == ext.len() { ' ' } else { '-' };
                r.push_str(&format!("250{sep}{e}\r\n"));
            }
            if ext.is_empty() { r.push_str("250 HELP\r\n"); }
            r
        } else if upper.starts_with("MAIL") {
            match state.lock().unwrap().reject_mail.clone() {
                Some(text) => format!("553 {text}\r\n"),
                None => "250 OK\r\n".into(),
            }
        } else if upper.starts_with("HELO") || upper.starts_with("RCPT") || upper.starts_with("RSET") || upper.starts_with("NOOP") {
            "250 OK\r\n".into()
        } else if upper.starts_with("DATA") {
            in_data = true;
            "354 Go ahead\r\n".into()
        } else if upper.starts_with("QUIT") {
            w.write_all(b"221 Bye\r\n").await.unwrap();
            return;
        } else {
            "502 Command not implemented\r\n".into()
        };
        w.write_all(reply.as_bytes()).await.unwrap();
    }
}
```

- [ ] **Step 2: Tests** (`tests/relay.rs`, port of `dsn.t` at relay level, plus unit tests in `src/relay.rs`)

```rust
mod common;

use common::upstream::RecordingUpstream;
use smtp_proxy::api::Recipient;
use smtp_proxy::relay::{Envelope, RelayConfig, RelayError, probe, relay};
use smtp_proxy::smtp::params::Param;

fn config(up: &RecordingUpstream) -> RelayConfig {
    RelayConfig { host: "127.0.0.1".into(), port: up.addr.port(), timeout: std::time::Duration::from_secs(5) }
}

fn p(k: &str, v: Option<&str>) -> Param {
    Param { keyword: k.into(), value: v.map(String::from) }
}

#[tokio::test]
async fn probe_reports_dsn() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    assert!(probe(&config(&up)).await.unwrap());
    assert_eq!(up.commands_matching("QUIT").len(), 1);
    up.set_extensions(&["SIZE 1000"]);
    assert!(!probe(&config(&up)).await.unwrap());
    assert!(probe(&RelayConfig { host: "127.0.0.1".into(), port: 1, timeout: std::time::Duration::from_secs(1) }).await.is_err());
}

#[tokio::test]
async fn full_session_and_dsn_forwarding() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let recipients = vec![
        Recipient { address: "x@baz.com".into(), parameters: vec![p("NOTIFY", Some("SUCCESS,FAILURE")), p("ORCPT", Some("rfc822;x@baz.com"))] },
        Recipient { address: "x@baz.com".into(), parameters: vec![p("NOTIFY", Some("NEVER")), p("SMTPUTF8", None)] },
    ];
    let env = Envelope { from: "a@b.com", mail_params: &[p("RET", Some("HDRS")), p("ENVID", Some("QQ")), p("SIZE", Some("5"))], recipients: &recipients };
    let out = relay(&config(&up), env, b"Subject: x\r\n\r\nbody\r\n.\r\nnot the end\r\n").await.unwrap();
    assert_eq!(out.message, "OK message accepted");
    assert!(out.upstream_dsn);
    let cmds = up.commands();
    assert!(cmds[0].starts_with("EHLO "));
    assert_eq!(cmds[1], "MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ");
    assert_eq!(cmds[2], "RCPT TO:<x@baz.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@baz.com");
    assert_eq!(cmds[3], "RCPT TO:<x@baz.com> NOTIFY=NEVER");
    assert_eq!(cmds[4], "DATA");
    assert_eq!(cmds[5], "QUIT");
    // The message is dot-stuffed on the way out and the upstream sees it intact.
    assert_eq!(up.messages()[0], "Subject: x\r\n\r\nbody\r\n..\r\nnot the end\r\n");
}

#[tokio::test]
async fn dsn_parameters_are_dropped_without_upstream_dsn() {
    let up = RecordingUpstream::start(&["SIZE 100000"]).await;
    let recipients = vec![Recipient { address: "x@baz.com".into(), parameters: vec![p("NOTIFY", Some("NEVER"))] }];
    let env = Envelope { from: "", mail_params: &[p("RET", Some("FULL"))], recipients: &recipients };
    let out = relay(&config(&up), env, b"Subject: x\r\n\r\n").await.unwrap();
    assert!(!out.upstream_dsn);
    assert_eq!(up.commands()[1], "MAIL FROM:<>");
    assert_eq!(up.commands()[2], "RCPT TO:<x@baz.com>");
}

#[tokio::test]
async fn upstream_rejection_carries_its_text() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.reject_mail(Some("Sorry, I don't send from there"));
    let recipients = vec![Recipient { address: "x@baz.com".into(), parameters: vec![] }];
    let env = Envelope { from: "a@b.com", mail_params: &[], recipients: &recipients };
    match relay(&config(&up), env, b"x\r\n").await {
        Err(RelayError::Rejected { command: "MAIL", code: 553, text }) => assert_eq!(text, "Sorry, I don't send from there"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn addresses_with_line_breaks_are_refused_before_any_write() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let recipients = vec![Recipient { address: "x@baz.com".into(), parameters: vec![] }];
    let env = Envelope { from: "a@b.com>\r\nRCPT TO:<evil@x.com", mail_params: &[], recipients: &recipients };
    assert!(matches!(relay(&config(&up), env, b"x\r\n").await, Err(RelayError::Address(_))));
    assert!(up.commands().is_empty());
}
```

Unit tests inside `src/relay.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::smtp::dsn::{is_mail_dsn_keyword, is_rcpt_dsn_keyword};

    fn p(k: &str, v: Option<&str>) -> Param {
        Param { keyword: k.into(), value: v.map(String::from) }
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
        let params = [p("RET", Some("HDRS")), p("SIZE", Some("1")), p("envid", Some("Q")), p("NOTIFY", None)];
        assert_eq!(dsn_suffix(&params, is_mail_dsn_keyword, true), " RET=HDRS envid=Q");
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
```

- [ ] **Step 3: Implement `src/relay.rs`**

```rust
//! A minimal SMTP client for the upstream: one session per message.
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, warn};

use crate::api::Recipient;
use crate::smtp::dsn::{is_mail_dsn_keyword, is_rcpt_dsn_keyword};
use crate::smtp::extensions::parse_extensions;
use crate::smtp::params::Param;

// ... RelayConfig, RelayError, Envelope, Relayed from the Interfaces block ...

/// RFC 5321 4.1.2 builds a path out of printable ASCII; the angle brackets
/// are excluded because this code supplies them. A CR or LF in an address
/// the API substituted would be a further command injected into an
/// authenticated upstream session.
pub fn assert_relayable(address: &str) -> Result<(), RelayError> {
    let ok = address.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'<' && b != b'>');
    if ok { Ok(()) } else { Err(RelayError::Address(address.to_string())) }
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
        let names: Vec<String> = wanted.iter().map(|p| p.keyword.to_ascii_uppercase()).collect();
        warn!("Upstream does not announce DSN; dropping {}", names.join(", "));
        return String::new();
    }
    wanted.iter().map(|p| match &p.value {
        Some(v) => format!(" {}={v}", p.keyword),
        None => format!(" {}", p.keyword),
    }).collect()
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

struct Upstream {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    timeout: Duration,
}

struct UpstreamReply {
    code: u16,
    /// Text of every line, without the codes, joined with "\n".
    text: String,
    raw: String,
}

impl Upstream {
    async fn connect(config: &RelayConfig) -> Result<Self, RelayError> {
        let stream = tokio::time::timeout(config.timeout, TcpStream::connect((config.host.as_str(), config.port)))
            .await
            .map_err(|_| RelayError::Timeout)??;
        let (r, w) = stream.into_split();
        Ok(Self { reader: BufReader::new(r), writer: w, timeout: config.timeout })
    }

    async fn read_reply(&mut self) -> Result<UpstreamReply, RelayError> {
        let mut raw = String::new();
        let mut texts = Vec::new();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(self.timeout, self.reader.read_line(&mut line)).await.map_err(|_| RelayError::Timeout)??;
            if n == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "upstream closed the connection").into());
            }
            raw.push_str(&line);
            let trimmed = line.trim_end_matches(['\r', '\n']);
            let b = trimmed.as_bytes();
            if b.len() < 3 || !b[..3].iter().all(u8::is_ascii_digit) {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("unparseable upstream reply: {trimmed}")).into());
            }
            let code: u16 = trimmed[..3].parse().unwrap();
            texts.push(trimmed.get(4..).unwrap_or("").to_string());
            if b.len() == 3 || b[3] == b' ' {
                return Ok(UpstreamReply { code, text: texts.join("\n"), raw });
            }
        }
    }

    /// Writes a command and requires a reply in the given class.
    async fn command(&mut self, name: &'static str, line: String, expect_class: u16) -> Result<UpstreamReply, RelayError> {
        debug!("upstream <- {line}");
        tokio::time::timeout(self.timeout, self.writer.write_all(format!("{line}\r\n").as_bytes())).await.map_err(|_| RelayError::Timeout)??;
        let reply = self.read_reply().await?;
        debug!("upstream -> {} {}", reply.code, reply.text.replace('\n', " / "));
        if reply.code / 100 != expect_class {
            return Err(RelayError::Rejected { command: name, code: reply.code, text: reply.text });
        }
        Ok(reply)
    }

    /// Greeting and EHLO (HELO fallback on 5xx). Returns the extension set.
    async fn open(&mut self) -> Result<std::collections::HashSet<String>, RelayError> {
        let greeting = self.read_reply().await?;
        if greeting.code / 100 != 2 {
            return Err(RelayError::Rejected { command: "CONNECT", code: greeting.code, text: greeting.text });
        }
        let host = local_hostname();
        match self.command("EHLO", format!("EHLO {host}"), 2).await {
            Ok(reply) => Ok(parse_extensions(&reply.raw)),
            Err(RelayError::Rejected { code, .. }) if code / 100 == 5 => {
                self.command("HELO", format!("HELO {host}"), 2).await?;
                Ok(Default::default())
            }
            Err(e) => Err(e),
        }
    }

    async fn quit(&mut self) {
        let _ = self.command("QUIT", "QUIT".into(), 2).await;
    }
}

fn local_hostname() -> String {
    nix::unistd::gethostname().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "localhost".into())
}

pub async fn probe(config: &RelayConfig) -> Result<bool, RelayError> {
    let mut up = Upstream::connect(config).await?;
    let extensions = up.open().await?;
    up.quit().await;
    Ok(extensions.contains("DSN"))
}

pub async fn relay(config: &RelayConfig, envelope: Envelope<'_>, message: &[u8]) -> Result<Relayed, RelayError> {
    assert_relayable(envelope.from)?;
    for r in envelope.recipients {
        assert_relayable(&r.address)?;
    }
    let mut up = Upstream::connect(config).await?;
    let extensions = up.open().await?;
    let upstream_dsn = extensions.contains("DSN");
    let mail = format!("MAIL FROM:<{}>{}", envelope.from, dsn_suffix(envelope.mail_params, is_mail_dsn_keyword, upstream_dsn));
    up.command("MAIL", mail, 2).await?;
    for r in envelope.recipients {
        let rcpt = format!("RCPT TO:<{}>{}", r.address, dsn_suffix(&r.parameters, is_rcpt_dsn_keyword, upstream_dsn));
        up.command("RCPT", rcpt, 2).await?;
    }
    up.command("DATA", "DATA".into(), 3).await?;
    let mut payload = dot_stuff(message);
    if !payload.ends_with(b"\r\n") {
        payload.extend_from_slice(b"\r\n");
    }
    payload.extend_from_slice(b".\r\n");
    tokio::time::timeout(config.timeout, up.writer.write_all(&payload)).await.map_err(|_| RelayError::Timeout)??;
    let accepted = up.read_reply().await?;
    if accepted.code / 100 != 2 {
        return Err(RelayError::Rejected { command: "DATA_END", code: accepted.code, text: accepted.text });
    }
    up.quit().await;
    Ok(Relayed { message: accepted.text, upstream_dsn })
}
```

`nix` needs the `hostname` feature: add it to `Cargo.toml` (`features = ["user", "hostname"]`).

- [ ] **Step 4: Run, commit**

Run: `cargo test --test relay --lib relay`
Expected: 8 passed.

```bash
git add -A && git commit -m "Upstream relay client with DSN forwarding and the startup probe"
```

---

### Task 13: The proxy handler and end-to-end tests (spec 2, 5, 6)

**Files:**
- Create: `src/proxy.rs`, `tests/proxy_end_to_end.rs`
- Modify: `src/lib.rs` (add `pub mod proxy;`)

**Interfaces:**
- Produces:

```rust
pub struct ProxyConfig {
    pub api: ApiClient,
    pub relay: RelayConfig,
}

#[derive(Clone)]
pub struct ProxyFactory {
    config: Arc<ProxyConfig>,
    upstream_dsn: Arc<AtomicBool>,
}

impl ProxyFactory {
    pub fn new(config: ProxyConfig) -> Self;
    pub fn upstream_dsn(&self) -> Arc<AtomicBool>;
    /// Runs the startup probe and records the answer; never fails.
    pub async fn probe_upstream(&self);
}

impl HandlerFactory for ProxyFactory { type Handler = ProxyHandler; .. }

pub struct ProxyHandler { .. }   // implements Handler

// Pure helpers, unit-tested:
pub fn parse_headers(block: &str) -> Vec<RequestHeader>;
pub fn merge_headers(existing: Vec<RequestHeader>, api: &[ResponseHeader]) -> Vec<RequestHeader>;
pub fn format_message(headers: &[RequestHeader], body: &[u8]) -> Vec<u8>;
```

- [ ] **Step 1: Unit tests for the pure helpers** (in `src/proxy.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: &str, v: &str) -> RequestHeader {
        RequestHeader { name: n.into(), value: v.into() }
    }

    #[test]
    fn headers_split_at_unfolded_crlf() {
        let block = "From: a@b.com\r\nSubject: long\r\n  folded line\r\nTo:x@y.com\r\nBroken header line\r\n";
        let parsed = parse_headers(block);
        assert_eq!(parsed, vec![h("From", "a@b.com"), h("Subject", "long\r\n  folded line"), h("To", "x@y.com")]);
    }

    #[test]
    fn merge_removes_named_then_appends_defined() {
        let existing = vec![h("To", "old"), h("Subject", "s"), h("X-Remove", "1")];
        let api = vec![
            ResponseHeader { name: "To".into(), value: Some("new".into()) },
            ResponseHeader { name: "X-Remove".into(), value: None },
            ResponseHeader { name: "Sender".into(), value: Some("bar@blah.com".into()) },
        ];
        assert_eq!(merge_headers(existing, &api), vec![h("Subject", "s"), h("To", "new"), h("Sender", "bar@blah.com")]);
    }

    #[test]
    fn message_layout() {
        let msg = format_message(&[h("A", "1"), h("B", "2")], b"body\r\n");
        assert_eq!(msg, b"A: 1\r\nB: 2\r\n\r\nbody\r\n");
    }
}
```

- [ ] **Step 2: End-to-end tests** (`tests/proxy_end_to_end.rs`, ports of `end-to-end.t`, `api-from-injection.t`, `upstream-acceptance.t`, `dsn.t`, `stale-transaction.t`, `raw-client-settle.t`)

```rust
mod common;

use std::sync::Arc;

use common::fake_api::FakeApi;
use common::raw_client::RawClient;
use common::upstream::RecordingUpstream;
use common::{server_config, start_server};
use smtp_proxy::api::ApiClient;
use smtp_proxy::proxy::{ProxyConfig, ProxyFactory};
use smtp_proxy::relay::RelayConfig;

struct Rig {
    api: FakeApi,
    upstream: RecordingUpstream,
    factory: ProxyFactory,
    addr: std::net::SocketAddr,
}

async fn rig(upstream_extensions: &[&str]) -> Rig {
    let api = FakeApi::start().await;
    let upstream = RecordingUpstream::start(upstream_extensions).await;
    let factory = ProxyFactory::new(ProxyConfig {
        api: ApiClient::new(api.url.clone()).unwrap(),
        relay: RelayConfig { host: "127.0.0.1".into(), port: upstream.addr.port(), timeout: std::time::Duration::from_secs(5) },
    });
    factory.probe_upstream().await;
    let mut config = server_config(true, true);
    config.service_name = "smtp.proxy.service".into();
    let addr = start_server(config, factory.clone()).await;
    Rig { api, upstream, factory, addr }
}

async fn send_mail(c: &mut RawClient, from: &str, to: &[&str], message: &str) -> String {
    assert_eq!(c.command(&format!("MAIL FROM:<{from}>")).await, "250 OK\r\n");
    for t in to {
        assert_eq!(c.command(&format!("RCPT TO:<{t}>")).await, "250 OK\r\n");
    }
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(message).await;
    c.write_raw(".\r\n").await;
    c.read_reply().await
}

const MESSAGE: &str = "From: sender@foobar.com\r\nTo: receiver@foobaz.com\r\nSubject: Hello\r\n\r\nHello there\r\n";

#[tokio::test]
async fn allowed_simple() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await;
    assert_eq!(reply, "250 OK: OK message accepted\r\n");
    let call = &r.api.calls()[0];
    assert_eq!(call["username"], "user");
    assert_eq!(call["password"], "pass");
    assert_eq!(call["from"], "sender@foobar.com");
    assert_eq!(call["to"], serde_json::json!(["receiver@foobaz.com"]));
    assert_eq!(call["headers"][2], serde_json::json!({"name": "Subject", "value": "Hello"}));
    assert_eq!(call["mailParameters"], serde_json::json!([]));
    assert_eq!(call["rcptParameters"], serde_json::json!([{"address": "receiver@foobaz.com", "parameters": []}]));
    assert_eq!(r.upstream.commands()[1], "MAIL FROM:<sender@foobar.com>");
    assert_eq!(r.upstream.messages()[0], MESSAGE);
    assert_eq!(c.command("QUIT").await, "221 smtp.proxy.service closing transmission channel\r\n");
}

#[tokio::test]
async fn denied_by_api() {
    let r = rig(&["DSN"]).await;
    r.api.respond(serde_json::json!({ "allow": false, "reason": "Weather too hot to email" }));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await;
    assert_eq!(reply, "550 Weather too hot to email\r\n");
    assert!(r.upstream.commands().is_empty());
    // The session is still usable.
    r.api.respond(serde_json::json!({ "allow": true, "headers": [] }));
    let reply = send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await;
    assert!(reply.starts_with("250"));
}

#[tokio::test]
async fn api_failure_is_reported_as_authentication_service_failed() {
    let r = rig(&["DSN"]).await;
    r.api.fail_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await;
    assert_eq!(reply, "550 authentication service failed\r\n");
}

#[tokio::test]
async fn headers_are_inserted_replaced_and_removed() {
    let r = rig(&["DSN"]).await;
    r.api.respond(serde_json::json!({ "allow": true, "headers": [
        { "name": "Sender", "value": "bar@blah.com" },
        { "name": "Subject", "value": "Replaced" },
        { "name": "To", "value": null }
    ]}));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert!(send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await.starts_with("250"));
    assert_eq!(r.upstream.messages()[0], "From: sender@foobar.com\r\nSender: bar@blah.com\r\nSubject: Replaced\r\n\r\nHello there\r\n");
}

#[tokio::test]
async fn api_can_change_the_envelope_sender_but_not_inject_commands() {
    let r = rig(&["DSN"]).await;
    r.api.respond(serde_json::json!({ "allow": true, "from": "other@foobar.com", "headers": [] }));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert!(send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await.starts_with("250"));
    assert_eq!(r.upstream.commands()[1], "MAIL FROM:<other@foobar.com>");
    r.upstream.clear();
    r.api.respond(serde_json::json!({ "allow": true, "from": "a@b.com>\r\nRCPT TO:<evil@x.com", "headers": [] }));
    let reply = send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await;
    assert!(reply.starts_with("550 Refusing to relay the address"), "{reply}");
    assert!(r.upstream.commands().is_empty());
}

#[tokio::test]
async fn relay_error_reaches_the_client() {
    let r = rig(&["DSN"]).await;
    r.upstream.reject_mail(Some("Sorry, I don't send from there"));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await;
    assert_eq!(reply, "550 Sorry, I don't send from there\r\n");
}

#[tokio::test]
async fn upstream_acceptance_text_is_relayed() {
    let r = rig(&["DSN"]).await;
    r.upstream.accept_text("2.0.0 Ok: queued as 4XyZ12");
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(&mut c, "sender@foobar.com", &["receiver@foobaz.com"], MESSAGE).await;
    assert_eq!(reply, "250 OK: 2.0.0 Ok: queued as 4XyZ12\r\n");
}

#[tokio::test]
async fn transparency_of_dots_and_multiple_mails_on_one_connection() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    // The client stuffs its dots; the proxy unstuffs them and stuffs them
    // again for the upstream, which records the wire form unchanged.
    let msg = "Subject: x\r\n\r\n..leading dot\r\n..\r\n";
    assert!(send_mail(&mut c, "a@b.com", &["x@y.com"], msg).await.starts_with("250"));
    assert_eq!(r.upstream.messages()[0], msg);
    // SECURITY (0.6.6): the second mail must not go to the first mail's recipients.
    assert!(send_mail(&mut c, "a@b.com", &["only@second.com"], MESSAGE).await.starts_with("250"));
    let rcpts = r.upstream.commands_matching("RCPT");
    assert_eq!(rcpts, vec!["RCPT TO:<x@y.com>", "RCPT TO:<only@second.com>"]);
    assert_eq!(r.api.calls()[1]["to"], serde_json::json!(["only@second.com"]));
    assert_eq!(r.api.calls()[1]["username"], "user");
}

#[tokio::test]
async fn login_auth_end_to_end() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
    assert!(c.command("dXNlcg==").await.starts_with("334"));
    assert!(c.command("cGFzcw==").await.starts_with("235"));
    assert!(send_mail(&mut c, "a@b.com", &["x@y.com"], MESSAGE).await.starts_with("250"));
    assert_eq!(r.api.calls()[0]["username"], "user");
    assert_eq!(r.api.calls()[0]["password"], "pass");
}

#[tokio::test]
async fn dsn_parameters_travel_to_the_api_and_the_upstream() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let ehlo = c.command("EHLO again").await;
    assert!(ehlo.contains("250 DSN") || ehlo.contains("250-DSN"), "{ehlo}");
    assert_eq!(c.command("MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<x@y.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@y.com").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<x@y.com> NOTIFY=NEVER").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(MESSAGE).await;
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
    let call = &r.api.calls()[0];
    assert_eq!(call["mailParameters"], serde_json::json!([{"keyword": "RET", "value": "HDRS"}, {"keyword": "ENVID", "value": "QQ314159"}]));
    assert_eq!(call["to"], serde_json::json!(["x@y.com", "x@y.com"]));
    assert_eq!(call["rcptParameters"][1]["parameters"][0]["value"], "NEVER");
    let cmds = r.upstream.commands();
    assert_eq!(cmds[1], "MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159");
    assert_eq!(cmds[2], "RCPT TO:<x@y.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@y.com");
    assert_eq!(cmds[3], "RCPT TO:<x@y.com> NOTIFY=NEVER");
}

#[tokio::test]
async fn dsn_follows_the_upstream() {
    let r = rig(&["SIZE 1000"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert!(!c.command("EHLO again").await.contains("DSN"));
    assert_eq!(c.command("MAIL FROM:<a@b.com> RET=HDRS").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<x@y.com> NOTIFY=NEVER").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(MESSAGE).await;
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
    assert_eq!(r.upstream.commands()[1], "MAIL FROM:<a@b.com>");
    assert_eq!(r.upstream.commands()[2], "RCPT TO:<x@y.com>");
    // The upstream gains DSN; the next relay notices and the next EHLO announces it.
    r.upstream.set_extensions(&["DSN"]);
    assert!(send_mail(&mut c, "a@b.com", &["x@y.com"], MESSAGE).await.starts_with("250"));
    assert!(r.factory.upstream_dsn().load(std::sync::atomic::Ordering::Relaxed));
    assert!(c.command("EHLO again").await.contains("DSN"));
}

#[tokio::test]
async fn slow_relay_reply_stays_in_its_transaction() {
    // The reply to DATA is awaited before the next command is read, so a
    // pipelined RSET after the terminator is answered after the 250.
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<x@y.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(&format!("{MESSAGE}.\r\nRSET\r\nMAIL FROM:<b@c.com>\r\n")).await;
    assert!(c.read_reply().await.starts_with("250 OK: "));
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert_eq!(c.read_reply().await, "250 OK\r\n");
}
```

- [ ] **Step 3: Implement `src/proxy.rs`**

```rust
//! The application behind the SMTP server: collect, ask the API, relay.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::api::{ApiClient, ApiError, CheckRequest, CheckResponse, Recipient, RequestHeader, ResponseHeader};
use crate::relay::{Envelope, RelayConfig, probe, relay};
use crate::server::{Handler, HandlerFactory};
use crate::smtp::params::Param;

pub struct ProxyConfig {
    pub api: ApiClient,
    pub relay: RelayConfig,
}

#[derive(Clone)]
pub struct ProxyFactory {
    config: Arc<ProxyConfig>,
    upstream_dsn: Arc<AtomicBool>,
    upstream_dsn_known: Arc<AtomicBool>,
}

impl ProxyFactory {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config: Arc::new(config),
            upstream_dsn: Arc::new(AtomicBool::new(false)),
            upstream_dsn_known: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn upstream_dsn(&self) -> Arc<AtomicBool> {
        self.upstream_dsn.clone()
    }

    fn where_(&self) -> String {
        format!("{}:{}", self.config.relay.host, self.config.relay.port)
    }

    /// Logs only when the answer changes. `known` is false until the first
    /// answer is in, which is the Perl's "undefined until asked" state.
    fn note_upstream_dsn(&self, supported: bool) {
        let previous = self.upstream_dsn.swap(supported, Ordering::Relaxed);
        let known = self.upstream_dsn_known.swap(true, Ordering::Relaxed);
        if !known || previous != supported {
            info!(
                "{} {}; the extension will {}be offered to clients",
                self.where_(),
                if supported { "announces DSN" } else { "does not announce DSN" },
                if supported { "" } else { "not " }
            );
        }
    }

    /// Asked once at startup and kept current from every relay afterwards,
    /// so an upstream that gains or loses DSN is noticed without polling.
    pub async fn probe_upstream(&self) {
        let where_ = self.where_();
        debug!("Asking {where_} which extensions it offers");
        match probe(&self.config.relay).await {
            Ok(dsn) => self.note_upstream_dsn(dsn),
            Err(e) => warn!("Could not ask {where_} which extensions it offers ({e}); DSN will not be announced until a mail is relayed"),
        }
    }
}

impl HandlerFactory for ProxyFactory {
    type Handler = ProxyHandler;
    fn create(&self, client: SocketAddr, _id: &str) -> ProxyHandler {
        ProxyHandler { factory: self.clone(), client, username: None, password: None, transaction: Transaction::default() }
    }
}

#[derive(Default)]
struct Transaction {
    from: String,
    mail_params: Vec<Param>,
    recipients: Vec<Recipient>,
    headers: Vec<RequestHeader>,
    api_call: Option<JoinHandle<Result<CheckResponse, ApiError>>>,
}

pub struct ProxyHandler {
    factory: ProxyFactory,
    client: SocketAddr,
    username: Option<String>,
    password: Option<String>,
    transaction: Transaction,
}

/// Splits at CRLF followed by a non-blank (folded lines stay whole), then at
/// the first colon. A line without a colon is logged and dropped.
pub fn parse_headers(block: &str) -> Vec<RequestHeader> {
    let mut lines: Vec<String> = Vec::new();
    for raw in block.split_inclusive("\r\n") {
        let continuation = raw.starts_with([' ', '\t']);
        match lines.last_mut() {
            Some(last) if continuation => last.push_str(raw),
            _ => lines.push(raw.to_string()),
        }
    }
    let mut out = Vec::new();
    for line in lines {
        let line = line.trim_end_matches("\r\n");
        match line.split_once(':') {
            Some((name, value)) if !name.is_empty() => {
                out.push(RequestHeader { name: name.to_string(), value: value.trim_start().to_string() })
            }
            _ => warn!("Could not parse header '{line}'"),
        }
    }
    out
}

/// Remove every header the API names, then append those with a value.
pub fn merge_headers(existing: Vec<RequestHeader>, api: &[ResponseHeader]) -> Vec<RequestHeader> {
    let mut out: Vec<RequestHeader> = existing.into_iter().filter(|h| !api.iter().any(|a| a.name == h.name)).collect();
    out.extend(api.iter().filter_map(|a| a.value.clone().map(|value| RequestHeader { name: a.name.clone(), value })));
    out
}

pub fn format_message(headers: &[RequestHeader], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 256);
    for h in headers {
        out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

impl ProxyHandler {
    fn check_request(&self) -> CheckRequest {
        let t = &self.transaction;
        CheckRequest {
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            from: t.from.clone(),
            to: t.recipients.iter().map(|r| r.address.clone()).collect(),
            headers: t.headers.clone(),
            mail_parameters: t.mail_params.clone(),
            rcpt_parameters: t.recipients.clone(),
        }
    }

    async fn relay_message(&mut self, outcome: CheckResponse, body: Vec<u8>) -> Result<String, String> {
        debug!("Relaying Mail to upstream SMTP Server");
        let headers = merge_headers(std::mem::take(&mut self.transaction.headers), &outcome.headers);
        let message = format_message(&headers, &body);
        let from = outcome.from.clone().unwrap_or_else(|| self.transaction.from.clone());
        let envelope = Envelope { from: &from, mail_params: &self.transaction.mail_params, recipients: &self.transaction.recipients };
        match relay(&self.factory.config.relay, envelope, &message).await {
            Ok(relayed) => {
                self.factory.note_upstream_dsn(relayed.upstream_dsn);
                debug!("Upstream server says: {}", relayed.message);
                match &outcome.auth_id {
                    Some(id) => info!("Relayed mail successfully for {} using token {id}", self.client),
                    None => info!("Relayed mail successfully for {} using no token", self.client),
                }
                Ok(relayed.message)
            }
            Err(e) => {
                info!("Mail refused by relay server ({e}) for {}", self.client);
                debug!("Mail {}", self.check_request().redacted_json());
                Err(e.to_string())
            }
        }
    }
}

impl Handler for ProxyHandler {
    async fn auth(&mut self, _authzid: &str, authcid: &str, password: &str) -> Result<(), String> {
        self.username = Some(authcid.to_string());
        self.password = Some(password.to_string());
        Ok(())
    }

    async fn mail(&mut self, from: &str, params: &[Param]) -> Result<(), String> {
        self.reset();
        self.transaction.from = from.to_string();
        self.transaction.mail_params = params.to_vec();
        Ok(())
    }

    async fn rcpt(&mut self, to: &str, params: &[Param]) -> Result<(), String> {
        self.transaction.recipients.push(Recipient { address: to.to_string(), parameters: params.to_vec() });
        Ok(())
    }

    async fn headers(&mut self, headers: String) -> Result<(), String> {
        self.transaction.headers = parse_headers(&headers);
        debug!("Making call to auth/headers API");
        let api = self.factory.config.api.clone();
        let request = self.check_request();
        self.transaction.api_call = Some(tokio::spawn(async move { api.check(&request).await }));
        Ok(())
    }

    async fn message(&mut self, body: Vec<u8>) -> Result<String, String> {
        let Some(call) = self.transaction.api_call.take() else {
            return Err("authentication service failed".into());
        };
        let outcome = match call.await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                return Err("authentication service failed".into());
            }
            Err(e) => {
                warn!("Failed to call API ({e}) for {}", self.client);
                return Err("authentication service failed".into());
            }
        };
        if !outcome.allow {
            let reason = outcome.reason.clone().unwrap_or_default();
            info!("Mail rejected by API ({reason}) for {}", self.client);
            debug!("INPUT {}", self.check_request().redacted_json());
            return Err(reason);
        }
        self.relay_message(outcome, body).await
    }

    fn reset(&mut self) {
        if let Some(call) = self.transaction.api_call.take() {
            call.abort();
        }
        self.transaction = Transaction::default();
    }

    fn dsn_available(&self) -> bool {
        self.factory.upstream_dsn.load(Ordering::Relaxed)
    }
}
```

- [ ] **Step 4: Run, commit**

Run: `cargo test --test proxy_end_to_end --lib proxy`
Expected: 15 passed.

```bash
git add -A && git commit -m "Proxy handler: API check, header merge, relay, end-to-end tests"
```

---
### Task 14: Configuration, CLI, privilege drop, and main (spec 7, 8, 9)

**Files:**
- Create: `src/config.rs`, `src/privdrop.rs`, `tests/cli.rs`
- Modify: `src/main.rs`, `src/lib.rs` (add `pub mod config; pub mod privdrop;`)

**Interfaces:**
- Produces in `config.rs`:

```rust
#[derive(clap::Parser, Debug, Clone)]
#[command(name = "smtp-proxy", version, about = "SMTP authentication and header injection proxy", long_about = LONG_ABOUT, disable_help_flag = true)]
pub struct Cli {
    #[arg(long, action = clap::ArgAction::Help, help = "show the full manual and exit")] pub man: (),
    #[arg(short = 'h', long, action = clap::ArgAction::HelpShort, help = "display this help and exit")] pub help: (),
    #[arg(long, value_name = "ip:port", help = "on which IP should we listen; use 0.0.0.0 to listen on all")] pub listen: Vec<String>,
    #[arg(long, help = "drop privileges and become this user after start")] pub user: Option<String>,
    #[arg(long, help = "host of the SMTP server to proxy to")] pub tohost: Option<String>,
    #[arg(long, help = "port of the SMTP server to proxy to")] pub toport: Option<u16>,
    #[arg(long = "tls_cert", help = "file containing a TLS certificate (for STARTTLS)")] pub tls_cert: Option<PathBuf>,
    #[arg(long = "tls_key", help = "file containing a TLS key (for STARTTLS)")] pub tls_key: Option<PathBuf>,
    #[arg(long, help = "URL of the authentication API")] pub api: Option<String>,
    #[arg(long, help = "where should the logfile be written to")] pub logpath: Option<PathBuf>,
    #[arg(long, default_value = "debug", help = "debug|info|warn|error|fatal")] pub loglevel: String,
    #[arg(long, help = "optional detailed log file of SMTP commands and responses")] pub smtplog: Option<PathBuf>,
    #[arg(long, help = "include username and password info in the smtplog")] pub credentials: bool,
    #[arg(long = "max_message_size", default_value_t = 1 << 30, help = "largest message accepted, in bytes")] pub max_message_size: usize,
}

pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub user: Option<String>,
    pub tohost: String,
    pub toport: u16,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub api: String,
    pub logpath: Option<PathBuf>,
    pub loglevel: String,
    pub smtplog: Option<PathBuf>,
    pub credentials: bool,
    pub max_message_size: usize,
}

/// Parses argv. Help and version exit 0. A usage error (missing mandatory
/// flag, unparseable value) prints the usage to stderr and exits 1, as
/// pod2usage does.
pub fn parse_args() -> Config;
pub fn parse_listen(s: &str) -> anyhow::Result<SocketAddr>;   // "ip:port"; port is the text after the last colon
```

  Mandatory flags are `listen`, `tohost`, `toport`, `tls_cert`, `tls_key`, `api`; they are `Option` in `Cli` so that `--help` works without them, and `parse_args` enforces presence.

- Produces in `privdrop.rs`: `pub fn drop_to(user: &str) -> anyhow::Result<()>` using `nix::unistd::{User, setgid, setuid}`. Logs `Dropped privileges to user <user>` at info.

- [ ] **Step 1: Unit tests**

`src/config.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_forms() {
        assert_eq!(parse_listen("127.0.0.1:2525").unwrap(), "127.0.0.1:2525".parse::<SocketAddr>().unwrap());
        assert_eq!(parse_listen("0.0.0.0:25").unwrap(), "0.0.0.0:25".parse::<SocketAddr>().unwrap());
        assert_eq!(parse_listen("::1:25").unwrap(), "[::1]:25".parse::<SocketAddr>().unwrap());
        assert_eq!(parse_listen("[::1]:25").unwrap(), "[::1]:25".parse::<SocketAddr>().unwrap());
        assert!(parse_listen("nonsense").is_err());
        assert!(parse_listen("127.0.0.1:notaport").is_err());
    }
}
```

`tests/cli.rs` (spawns the binary):
```rust
use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("smtp-proxy").unwrap()
}

#[test]
fn version_flag() {
    bin().arg("--version").assert().success().stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_the_perl_flags() {
    let out = bin().arg("--help").assert().success().get_output().stdout.clone();
    let text = String::from_utf8(out).unwrap();
    for flag in ["--listen", "--user", "--tohost", "--toport", "--tls_cert", "--tls_key", "--api", "--logpath", "--loglevel", "--smtplog", "--credentials", "--max_message_size", "--man"] {
        assert!(text.contains(flag), "missing {flag} in\n{text}");
    }
}

#[test]
fn missing_mandatory_flag_exits_1_with_usage() {
    bin().args(["--listen", "127.0.0.1:0"]).assert().code(1).stderr(predicates::str::contains("--tohost"));
}

#[test]
fn starts_binds_and_announces() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let certs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs");
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
        .args(["--listen", "127.0.0.1:0", "--tohost", "127.0.0.1", "--toport", "1", "--api", "http://127.0.0.1:1/check", "--loglevel", "info"])
        .arg("--tls_cert").arg(certs.join("server.crt"))
        .arg("--tls_key").arg(certs.join("server.key"))
        .stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(line.starts_with("Waiting for connections on 127.0.0.1:"), "{line}");
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "Will forward mails to 127.0.0.1:1");
    child.kill().unwrap();
    let stderr = { let mut s = String::new(); std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut s).unwrap(); s };
    assert!(stderr.contains("[warn] Could not ask 127.0.0.1:1 which extensions it offers"), "{stderr}");
    assert!(stderr.lines().next().unwrap().starts_with('['));
}
```

Add `predicates = "3"` to dev-dependencies (check the current version with `cargo info predicates`).

- [ ] **Step 2: Implement `config.rs`**

```rust
//! Command line, with the Perl flag names.
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{CommandFactory, Parser};

const LONG_ABOUT: &str = "Starts an SMTP server on the listen host and port. When a connection is \
established, communicates with the client up to the point it has both the envelope and the mail \
data headers. It requires STARTTLS to be used, and takes authentication details using the PLAIN \
mechanism. It then passes the authentication details, envelope headers, and data headers to a \
REST API, which determines if the mail is allowed to be sent and, if so, what additional headers \
should be inserted. Once the mail has been fully received, and if it is allowed to be sent, then \
an upstream connection to the target SMTP server is established. The mail is sent using that SMTP \
server, with the extra headers inserted. The outcome of this is then relayed to the client.";

// ... Cli and Config from the Interfaces block ...

pub fn parse_listen(s: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = s.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("Could not parse {s}"))?;
    let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("Could not parse {s}"))?;
    let ip: std::net::IpAddr = host.trim_matches(['[', ']']).parse().map_err(|_| anyhow::anyhow!("Could not parse {s}"))?;
    Ok(SocketAddr::new(ip, port))
}

fn usage_exit(message: &str) -> ! {
    eprintln!("{message}");
    eprintln!("{}", Cli::command().render_usage());
    eprintln!("Try '--help' for more information.");
    std::process::exit(1)
}

pub fn parse_args() -> Config {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) if e.use_stderr() => usage_exit(&e.to_string()),
        Err(e) => e.exit(), // --help, --man, --version
    };
    let listen = if cli.listen.is_empty() { usage_exit("--listen is required") } else {
        cli.listen.iter().map(|s| parse_listen(s)).collect::<Result<Vec<_>, _>>().unwrap_or_else(|e| usage_exit(&e.to_string()))
    };
    macro_rules! required {
        ($field:ident) => {
            cli.$field.clone().unwrap_or_else(|| usage_exit(concat!("--", stringify!($field), " is required")))
        };
    }
    Config {
        listen,
        user: cli.user.clone(),
        tohost: required!(tohost),
        toport: required!(toport),
        tls_cert: required!(tls_cert),
        tls_key: required!(tls_key),
        api: required!(api),
        logpath: cli.logpath.clone(),
        loglevel: cli.loglevel.clone(),
        smtplog: cli.smtplog.clone(),
        credentials: cli.credentials,
        max_message_size: cli.max_message_size,
    }
}
```

`stringify!(tls_cert)` yields `tls_cert`, which is the flag spelling, so the messages read `--tls_cert is required`.

- [ ] **Step 3: Implement `privdrop.rs`**

```rust
//! Drop root after binding the listen ports.
use nix::unistd::{User, setgid, setuid};

pub fn drop_to(user: &str) -> anyhow::Result<()> {
    let entry = User::from_name(user)?.ok_or_else(|| anyhow::anyhow!("Cannot resolve username '{user}'"))?;
    setgid(entry.gid).map_err(|e| anyhow::anyhow!("Failed to setgid to {}: {e}", entry.gid))?;
    setuid(entry.uid).map_err(|e| anyhow::anyhow!("Failed to setuid to {}: {e}", entry.uid))?;
    tracing::info!("Dropped privileges to user {user}");
    Ok(())
}
```

- [ ] **Step 4: Implement `main.rs`**

```rust
use std::sync::Arc;
use std::time::Duration;

use smtp_proxy::api::ApiClient;
use smtp_proxy::config::parse_args;
use smtp_proxy::proxy::{ProxyConfig, ProxyFactory};
use smtp_proxy::relay::RelayConfig;
use smtp_proxy::server::{ServerConfig, listener};
use smtp_proxy::smtplog::SmtpLog;

fn main() {
    let config = parse_args();
    if let Err(e) = smtp_proxy::logging::init(config.logpath.as_deref(), &config.loglevel) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().expect("tokio runtime");
    if let Err(e) = runtime.block_on(run(config)) {
        tracing::error!("{e:#}");
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

async fn run(config: smtp_proxy::config::Config) -> anyhow::Result<()> {
    let tls = ServerConfig::load_tls(&config.tls_cert, &config.tls_key)?;
    let smtplog = match &config.smtplog {
        Some(path) => Some(Arc::new(SmtpLog::open(path, config.credentials).map_err(|e| anyhow::anyhow!("Could not open {}: {e}", path.display()))?)),
        None => None,
    };
    let server_config = Arc::new(ServerConfig {
        service_name: "smtp-proxy".into(),
        require_starttls: true,
        require_auth: true,
        tls: Some(tls),
        max_message_size: config.max_message_size,
        smtplog,
        tls_idle_timeout: Duration::from_secs(600),
    });
    let listeners = listener::bind(&config.listen).await?;
    if let Some(user) = &config.user {
        smtp_proxy::privdrop::drop_to(user)?;
    }
    tracing::debug!("Starting smtp-proxy {}", env!("CARGO_PKG_VERSION"));
    let factory = ProxyFactory::new(ProxyConfig {
        api: ApiClient::new(config.api.clone())?,
        relay: RelayConfig { host: config.tohost.clone(), port: config.toport, timeout: Duration::from_secs(60) },
    });
    let listen_text: Vec<String> = listeners.iter().map(|l| l.local_addr().map(|a| a.to_string()).unwrap_or_default()).collect();
    println!("Waiting for connections on {}", listen_text.join(", "));
    println!("Will forward mails to {}:{}", config.tohost, config.toport);
    let probe = factory.clone();
    tokio::spawn(async move { probe.probe_upstream().await });
    tokio::select! {
        _ = listener::serve(listeners, server_config, factory) => {}
        _ = shutdown_signal() => tracing::info!("Shutting down"),
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
```

The two `println!` lines must be written after `bind` so the port is known for `--listen ...:0` (test) and after the privilege drop, matching the Perl order except that Perl prints before `setup`; nothing depends on that.

- [ ] **Step 5: Run, commit**

Run: `cargo test --test cli --lib config` and the whole suite `cargo test`, then `cargo clippy --all-targets -- -D warnings && cargo fmt --check`.
Expected: all green.

```bash
git add -A && git commit -m "CLI, configuration, privilege drop, and main"
```

---

### Task 15: Docker image, CHANGES, README

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `CHANGES`, `README.md`, `build-docker.sh`

- [ ] **Step 1: Dockerfile**

```dockerfile
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev cmake clang make perl
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked -j 4 && \
    strip target/release/smtp-proxy

FROM scratch
COPY --from=build /src/target/release/smtp-proxy /app/bin/smtp-proxy
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 3000/tcp
ENTRYPOINT ["/app/bin/smtp-proxy"]
```

`rust:1-alpine` targets musl natively, so no `--target` is needed. If aws-lc-rs fails to build there, switch to the `ring` provider: in `Cargo.toml` set `tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12", "logging"] }`, `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }`, `reqwest` features `["rustls-no-provider", ...]`, and replace `aws_lc_rs::default_provider()` with `ring::default_provider()` in `listener.rs` and the test client.

`.dockerignore`: `target`, `.git`, `docs`, `tests`.

`build-docker.sh`:
```bash
#!/bin/bash
set -eo pipefail
V=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
cargo test -j 4 2>&1 | tee smtp-proxy-${V}.test-output.txt
podman build --pull --tag smtp-proxy:${V} .
echo "you can now run 'podman run smtp-proxy:${V}'"
```

- [ ] **Step 2: Build the image**

Run: `podman build --tag smtp-proxy:dev .` (timeout 600000) and then `podman run --rm smtp-proxy:dev --version`.
Expected: prints `smtp-proxy 1.0.0`.

- [ ] **Step 3: CHANGES and README**

`CHANGES` starts with:
```
1.0.0 2026-09-10 Tobias Oetiker <tobi@oetiker.ch>

 - complete rewrite in Rust; a drop-in replacement for smtpproxy.pl 0.8.0:
   same flags, same API JSON, same SMTP replies, same log formats
 - TLS 1.0 and 1.1 are no longer offered (rustls)
 - new: --max_message_size, default 1 GiB; a larger message is answered 552
 - new: --version
 - debug-level data dumps are JSON instead of Perl dumper output
```
followed by the Perl `CHANGES` entries verbatim (copy from `../smtp-proxy/CHANGES`).

`README.md`: copy the Perl README's Request/Response sections verbatim, replace the Installation section with `cargo build --release` and the Docker instructions, and update the usage block with the flags from `--help`. Add a "Differences from the Perl version" section listing the four items from spec section 12.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "Docker image, CHANGES, and README"
```

---

## Self-review against the spec (part 1)

| Spec section | Task |
|---|---|
| 3 architecture, 3.1 Handler, 3.2 flow, 3.3 shared state | 9, 13 |
| 4.1 to 4.3 states, any-state commands, greetings | 9 |
| 4.4 STARTTLS, 4.5 AUTH | 9, 10 |
| 4.6 MAIL/RCPT, DSN validation | 3, 4, 9 |
| 4.7 DATA, size cap | 8, 9 |
| 4.8 reply formatting | 2 |
| 5.1 to 5.5 proxy handler | 13 |
| 5.3 API request | 11 |
| 6 relay, probe, DSN forwarding (not 6.1) | 12, 13 |
| 7 CLI (without the part-2 flags) | 14 |
| 8 logging, smtplog | 6, 10, 14 |
| 9 privilege drop, memory | 14, 8 |
| 10 Docker | 15 |
| 11.1, 11.2 tests | 2 to 14 |

Part 2 covers 6.1, 9.1 to 9.3, the remaining part of 10, 11.3, and the CLI flags for those.
