# smtp-proxy in Rust: design

Date: 2026-09-10
Status: approved in discussion, awaiting written review

## 1. Goal

Replace the Perl `smtpproxy.pl` (version 0.8.0, repository
`~/checkouts/smtp-proxy`) with a Rust binary that is a drop-in replacement.
"Drop-in" means all four of these stay identical:

1. The command line flags and the Docker entrypoint.
2. The JSON request and response exchanged with the authentication API.
3. The SMTP wire behaviour: state machine, reply codes, and reply texts.
4. The main log line format and the SMTP wire log format.

The new project starts at version 1.0.0. It lives in its own repository,
`smtp-proxy-rs`. The Perl repository is not changed. It serves as the source
of the conformance tests during the migration.

## 2. What the proxy does

A mail client connects, must issue STARTTLS, then authenticates with
AUTH PLAIN or AUTH LOGIN. The proxy accepts the credentials without
checking them. It collects the envelope (MAIL FROM, every RCPT TO, and their
ESMTP parameters) and the message. As soon as the message headers have
arrived, and while the body is still streaming in, it sends one HTTP POST
to the API with credentials, envelope, headers, and parameters. When the
body is complete and the API has answered:

- `allow: false`: the client gets `550 <reason>`.
- `allow: true`: the proxy opens a fresh SMTP session to the upstream
  server, sends the message with the headers merged as the API requested,
  and relays the upstream's acceptance text to the client as
  `250 OK: <text>`.

Several mails may be sent on one connection. Authentication is tied to the
session and survives RSET and EHLO. The recipient list is reset at every
MAIL, RSET, and EHLO.

## 3. Architecture

One Cargo crate, `smtp-proxy`, edition 2024, with a library and a thin
binary. The library holds all logic so that integration tests can drive it
in-process.

```
src/
  main.rs            parse CLI, build Config, start the tokio runtime
  lib.rs
  config.rs          Config: listen addrs, upstream host/port, TLS paths,
                     API URL, log settings, user, limits, upstream TLS
  logging.rs         tracing subscriber with a Mojo::Log compatible formatter
  smtplog.rs         optional wire log with credential redaction
  privdrop.rs        setgid/setuid after bind, via nix
  smtp/
    command.rs       one command line -> Command, or ParseError{code, text}
    params.rs        esmtp-param list -> Vec<Param{keyword, value: Option}>
    dsn.rs           RFC 3461 validation of MAIL and RCPT parameters
    reply.rs         Reply{code, lines} -> bytes; sanitised; 512 byte cap
    extensions.rs    EHLO reply text -> set of extension keywords
  server/
    listener.rs      bind every --listen, accept loop, one task per client
    session.rs       per-connection state machine, sequential async code
    data.rs          DATA reader: dot unstuffing, header/body split, size cap
    auth.rs          AUTH PLAIN and AUTH LOGIN decoding
  api.rs             reqwest client; CheckRequest / CheckResponse types
  relay.rs           minimal SMTP client to the upstream; DSN forwarding rule
  proxy.rs           Handler implementation: collects state, calls api, relays
tests/               Rust integration tests and their helpers
conformance/         adapted Perl end-to-end tests run against the binary
```

### 3.1 The Handler seam

`server::session` knows SMTP and nothing about the API or the upstream. It
calls a `Handler` trait:

```rust
pub trait Handler: Send {
    async fn auth(&mut self, authzid: &str, authcid: &str, password: &str)
        -> Result<(), String>;
    async fn mail(&mut self, from: &str, params: &[Param]) -> Result<(), String>;
    async fn rcpt(&mut self, to: &str, params: &[Param]) -> Result<(), String>;
    /// Called as soon as the header block is complete, while the body is
    /// still arriving. The proxy starts the API call here.
    async fn headers(&mut self, headers: String) -> Result<(), String>;
    /// Called when the terminator has arrived. Ok carries the text for
    /// `250 OK: <text>`, Err the text for `550 <text>`.
    async fn message(&mut self, body: Vec<u8>) -> Result<String, String>;
    /// Called at RSET, and at EHLO/HELO when a transaction is running.
    fn reset(&mut self);
    fn dsn_available(&self) -> bool;
}
```

Native `async fn` in traits (stable since Rust 1.75). The session is generic
over `H: Handler`, so no `dyn` dispatch and no `async_trait` crate is
needed. One handler instance exists per connection, created by a
`HandlerFactory` that the listener owns.

`proxy.rs` implements it. Tests implement a fake. This mirrors the Perl split
between `SMTPProxy::SMTPServer` and `SMTPProxy`.

### 3.2 Per-connection flow

One tokio task owns one client socket. It loops: read one command line,
handle it to completion (including any API or upstream wait), write the
reply, read the next line. Nothing runs concurrently inside a connection.
Consequences:

- Pipelined commands (RFC 2920) are handled in order, one at a time, which
  is what the Perl `_drain` loop does.
- There is no transaction epoch. The DATA reply is awaited before the next
  command is read, so a late upstream reply cannot land in a later
  transaction.
- The only concurrency inside a connection is the API call, which starts
  when the headers are complete and is awaited when the body is complete.

The socket is an enum over `TcpStream` and `tokio_rustls::server::TlsStream`.
STARTTLS replaces the inner stream in place.

### 3.3 Shared state

- `upstream_dsn: Arc<AtomicBool>`: whether the upstream announced DSN.
  Set by the startup probe and by every relay's EHLO reply. Read by the
  session when building the EHLO reply.
- The reqwest client is built once and shared.
- The smtplog file handle is shared behind a mutex.

## 4. SMTP behaviour

Service name is `smtp-proxy`, as in the Perl. Every reply text below is
verbatim from the Perl implementation. `<svc>` stands for the service name.

### 4.1 States

`WantGreeting`, `WantStartTls`, `WantAuth`, `WantMail`, `WantRcpt`,
`WantData`. `WantData` is `WantRcpt` with at least one recipient; it accepts
more RCPT commands.

### 4.2 Commands valid in any state

| Command | Behaviour |
|---|---|
| EHLO / HELO with domain | 250 reply, see 4.3. Resets the transaction if one is running (state >= WantMail). Never undoes authentication. Next state: WantMail if authenticated, WantAuth if TLS is up, else WantStartTls. |
| EHLO / HELO without domain | `501 domain required` |
| QUIT | `221 <svc> closing transmission channel`, then close. Nothing after QUIT is processed. |
| NOOP, with or without argument | `250 OK` |
| VRFY with string | `553 Unimplemented` |
| VRFY without string | `501 string required` |
| RSET | resets the transaction, `250 OK`. State goes to WantMail if it was beyond it. |
| unknown verb | `502 unknown command` |
| line that is not `VERB [args]CRLF` | `500 malformed command`; the line is consumed. |
| QUIT, STARTTLS, DATA, RSET with an argument | `501 no arguments allowed` |

### 4.3 Greeting replies

Connection open: `220 <svc> SMTP service ready`.

HELO: one line, `250 <svc> offers a warm hug of welcome` (or
`offers another warm hug of welcome` once TLS is up).

EHLO: the same first line, then extension lines:

- `STARTTLS` while TLS is not up.
- `AUTH PLAIN LOGIN` once TLS is up.
- `DSN` only when `upstream_dsn` is true.

### 4.4 STARTTLS

In `WantStartTls`:

- STARTTLS: reply `220 Go ahead`, then discard any bytes already in the
  read buffer (log at info: `Discarding N byte(s) received before STARTTLS
  from <client>`), then run the rustls server handshake with the configured
  cert and key. On success: state WantAuth, inactivity timeout 600 s, log
  debug `Successful TLS upgrade for <client>`. On failure: log info
  `Failed TLS upgrade for <client>: <err>` and close.
- Anything else: `530 Must issue a STARTTLS command first`.

Before TLS there is no inactivity timeout, as in the Perl.

TLS is rustls, TLS 1.2 and 1.3 only. Certificates and keys are PEM files
loaded with `rustls-pki-types` (`pem` feature). A client that needs TLS 1.0
or 1.1 cannot connect; this is a documented difference and a rollout check.

### 4.5 AUTH

In `WantAuth`:

- `AUTH PLAIN <base64>`: decode, split on NUL into authzid, authcid,
  password. Call `Handler::auth`.
- `AUTH PLAIN` without initial response: `334 ` (empty text), then read one
  line as the base64 token.
- `AUTH LOGIN`: `334 VXNlcm5hbWU6` (base64 of `Username:`), read a line,
  `334 UGFzc3dvcmQ6` (base64 of `Password:`), read a line. Call
  `Handler::auth("", username, password)`.
- A continuation line that contains a line break before its end:
  `500 confused authentication response`.
- Success: `235 Authentication successful`, state WantMail. Failure:
  `535 Authentication credentials invalid`, stay in WantAuth.
- Other mechanism: `504 Authentication mechanism not supported`.
- Any non-AUTH command: `530 Authentication required`.

The mechanism name is 1 to 20 characters of letters, digits, hyphen, or
underscore, matched without regard to case. Anything else on the AUTH line:
`501 invalid AUTH arguments`.

The proxy's Handler always accepts credentials. The API checks them later.

### 4.6 MAIL and RCPT

- `MAIL FROM:<addr> [params]`, keyword matched case-insensitively, optional
  whitespace after the colon, empty address allowed. In WantMail only;
  elsewhere `503 Bad sequence of commands`.
- `RCPT TO:<addr> [params]`, non-empty address. In WantRcpt or WantData;
  elsewhere 503.
- Parameter grammar: keyword `[A-Za-z0-9][A-Za-z0-9-]*`, optional
  `=value` where value is printable ASCII without `=`. Any bad parameter:
  `501 invalid MAIL parameters` / `501 invalid RCPT parameters`.
- Bad address syntax: `501 invalid MAIL arguments` / `501 invalid RCPT
  arguments`.
- DSN validation (RFC 3461) runs before the handler: RET and ENVID on MAIL,
  NOTIFY and ORCPT on RCPT. The error strings are those of
  `SMTPProxy::SMTPServer::DsnParameters`, answered as `501 <error>`.
- Success: `250 OK`. Handler rejection: `553 Requested action not taken:
  <err>` for MAIL, `550 Will not send mail to this user: <err>` for RCPT.
- Every RCPT is recorded as its own entry, in order, even for a repeated
  address.

### 4.7 DATA

In WantData only. Reply `354 End data with <CR><LF>.<CR><LF>`, then read
lines until a line that is exactly `.` (CRLF or LF). A leading dot on any
other line is removed. The first empty line separates headers from body.
The headers string (CRLF-joined, without the empty line) is handed to the
handler as soon as it is complete. The body is accumulated and delivered
when the terminator arrives. Bytes after the terminator in the same read
stay in the buffer and are parsed as the next command.

Size cap: the accumulated message (headers plus body) may not exceed
`--max_message_size` bytes, default 1 GiB (1073741824). When it is
exceeded, the reader keeps consuming and discarding lines until the
terminator, then replies `552 Message exceeds maximum size of N bytes`,
resets the transaction, and returns to WantMail. The API is not called.

Handler result: `250 OK: <message>` and state WantMail, or `550 <message>`
and state WantMail. If the client has gone away by then, the reply is
dropped and logged at info as the Perl does.

### 4.8 Reply formatting

`smtp::reply` is the only place that writes a reply. It enforces: code is
three digits 2xx to 5xx; at least one line; each line's text has every
character outside tab and printable ASCII replaced by a space, trailing
whitespace removed, and is truncated to 506 bytes with `...` so the whole
line stays under 512 octets. Multi-line replies use `code-` on every line
but the last.

## 5. The proxy handler

### 5.1 Collected state

Per connection: `username`, `password` (set at AUTH, kept for the whole
session), and per transaction: `from`, `mail_params`, `recipients: Vec<{
address, params }>`, `headers`, `body`. `reset()` clears the transaction
fields only.

### 5.2 Header parsing

The header block is split into lines at CRLF that is followed by a
non-whitespace character or by the end, so folded headers stay whole. Each
line is split at the first colon; whitespace after the colon is removed;
the rest, including any embedded fold, is the value. A line without a colon
is logged as warn `Could not parse header '<line>'` and dropped.

### 5.3 API request

One POST, `Content-Type: application/json`, timeout 60 s, to `--api`:

```json
{
  "username": "...", "password": "...",
  "from": "...", "to": ["..."],
  "headers": [{"name": "...", "value": "..."}],
  "mailParameters": [{"keyword": "...", "value": "..." | null}],
  "rcptParameters": [{"address": "...", "parameters": [...]}]
}
```

Field order is as above. Arrays keep wire order. `value` is `null` for a
parameter given without a value.

Response: `{"allow": bool, "reason"?: string, "headers"?: [...],
"from"?: string, "authId"?: string}`.

- Non-2xx HTTP status or transport error: the client gets
  `550 authentication service failed`; log warn `Failed to call API
  (<err>) for <client>`; log debug of the request with the password
  replaced by `*******`.
- `allow: false`: client gets `550 <reason>`; log info `Mail rejected by
  API (<reason>) for <client>`.

### 5.4 Header merge

Remove every header whose name appears in the API `headers` array. Then
append every API header that has a non-null value, in API order. Names are
compared exactly (case-sensitive), as in the Perl.

The relayed message is `name: value\r\n` for each header, then an empty
line, then the body as received.

### 5.5 Envelope sender override

If the response carries `from`, it replaces the envelope sender. It must be
printable ASCII without `<` or `>`; otherwise the relay is refused with an
error that reaches the client as a 550 and is logged. The same check runs on
every address the relay writes.

## 6. Relay to the upstream

`relay.rs` is a minimal SMTP client written for this project, inactivity
timeout 60 s. Sequence per mail: connect, read 220, EHLO (fall back to HELO
on a 5xx), STARTTLS and a second EHLO when TLS applies (see 6.1), MAIL FROM,
one RCPT TO per recipient entry, DATA, message, `.`, QUIT. Any reply outside the expected class aborts with an error
carrying the upstream's text; the client then gets `550 <text>` and the log
gets info `Mail refused by relay server (<text>) for <client>`.

### 6.1 TLS to the upstream

`--upstream_tls` selects the mode:

| Mode | Behaviour |
|---|---|
| `off` | plain TCP, what the Perl did |
| `opportunistic` (default) | STARTTLS if the upstream announces it; plain if it does not. If STARTTLS is announced but the handshake or the certificate check fails, the relay fails; there is no fallback to plain, so a downgrade cannot be forced by breaking the handshake. |
| `required` | STARTTLS must be announced and must succeed, else the relay fails |
| `implicit` | TLS from the first byte, for port 465 |

The certificate is verified against the system roots plus the PEM bundle
in `--upstream_tls_ca`, with `--tohost` as the server name.
`--upstream_tls_insecure` disables verification and logs a warning at
startup. rustls, TLS 1.2 and 1.3.

The extension set that counts, for DSN and for anything else, is the one
from the EHLO sent after STARTTLS, since an upstream may announce different
extensions inside TLS. The startup probe runs the same connect and TLS
sequence, so its DSN answer matches what a relay will see.

A relay that fails because of TLS reaches the client as `550 <error>` and
the log as info `Mail refused by relay server (<error>) for <client>`, the
same path as any other upstream failure.

DSN forwarding: on the EHLO reply, parse the extension keywords and store
`DSN` presence into `upstream_dsn`. When true, append the RET and ENVID
parameters to MAIL and NOTIFY and ORCPT to RCPT, in the form
` KEY=value` or ` KEY`. When false, drop them and log warn `Upstream does
not announce DSN; dropping <KEYS>`. Other parameters are never relayed.

The 250 text from the reply to the final dot is returned as the relay
result and reaches the client as `250 OK: <text>`. Log info `Relayed mail
successfully for <client> using token <authId>` or `... using no token`.

Startup probe: the same code with only EHLO and QUIT. Log info `<host:port>
announces DSN; the extension will be offered to clients` or `does not
announce DSN; the extension will not be offered to clients`, and only when
the answer changes. On failure log warn `Could not ask <host:port> which
extensions it offers (<err>); DSN will not be announced until a mail is
relayed`. The probe runs after the privilege drop and does not block
accepting connections.

## 7. Command line

Flags, spelled with underscores as in the Perl:

```
    --man                 show the full manual and exit
 -h,--help                show usage and exit
    --version             print the version and exit
    --listen=ip:port      may be given several times; mandatory
    --user=x              drop privileges to this user after binding
    --tohost=x            mandatory
    --toport=x            mandatory
    --tls_cert=x          PEM certificate file; mandatory
    --tls_key=x           PEM key file; mandatory
    --api=x               URL of the authentication API; mandatory
    --logpath=x           default /dev/stderr
    --loglevel=x          debug|info|warn|error|fatal, default debug
    --smtplog=x           optional wire log file
    --credentials         include credentials in the smtplog
    --max_message_size=n  bytes, default 1073741824 (1 GiB)
    --upstream_tls=mode   off|opportunistic|required|implicit,
                          default opportunistic
    --upstream_tls_ca=x   extra PEM CA bundle for the upstream certificate
    --upstream_tls_insecure
                          do not verify the upstream certificate
    --max_connections=n   default 1000; 0 means unlimited
    --max_connections_per_ip=n
                          default 50; 0 means unlimited
    --max_messages_per_minute=n
                          per authenticated username, default 60;
                          0 means unlimited
    --max_recipients=n    per message, default 1000; 0 means unlimited
    --drain_timeout=s     seconds to wait for sessions at shutdown,
                          default 30
```

A missing mandatory flag prints the usage to stderr and exits 1. On start
the binary prints to stdout `Waiting for connections on <a>, <b>` and
`Will forward mails to <host>:<port>`.

`--listen` accepts `ip:port` where ip may be IPv4 or IPv6; the port is the
text after the last colon.

## 8. Logging

### 8.1 Main log

A `tracing` subscriber with a custom event formatter that writes exactly:

```
[2026-09-10 14:13:51.12345] [<pid>] [<level>] [<connection id>] <message>
```

The connection id field is present only for connection-scoped messages.
The timestamp is local time with five fractional digits. Levels are
`debug`, `info`, `warn`, `error`, `fatal`. `--loglevel=fatal` silences
everything, since nothing is logged at fatal. The connection id is 32
lowercase hex characters, random per connection.

Info, warn, and error messages keep the Perl wording. Debug messages keep
their wording where they name an event; the Perl `dumper` data dumps become
one JSON line with the password redacted and the body replaced by `...`.

### 8.2 SMTP wire log

Only when `--smtplog` is set. Appended, flushed per entry. Format:

```
<connection id> <YYYY-MM-DD HH:MM:SS> >>> <line received>
<connection id> <YYYY-MM-DD HH:MM:SS> <<< <line sent>
```

One entry per wire line of a command or reply. The DATA payload is not
logged. AUTH lines have everything after the mechanism replaced by
`[REDACTED]`, and AUTH continuation lines are written as `[REDACTED]`,
unless `--credentials` is set.

## 9. Operations

- Privilege drop: after all listeners are bound, `setgid` then `setuid` to
  `--user`, resolved with `getpwnam`. Failure aborts startup. Log info
  `Dropped privileges to user <user>`.
- Memory: one message is held in memory per connection, up to the size
  cap.

### 9.1 Graceful drain

On SIGTERM or SIGINT:

1. Every listener is closed, so new connections are refused by the
   kernel. Log info `Shutting down; draining <n> connection(s)`.
2. A session that is waiting for a command (any state, no transaction in
   flight, or a transaction that has not reached DATA) is sent
   `421 <svc> Service not available, closing transmission channel` and
   closed. RFC 5321 3.8 allows 421 in place of any reply.
3. A session that is inside DATA, or waiting on the API or the upstream,
   is allowed to finish its reply and is then closed the same way.
4. After `--drain_timeout` seconds everything still open is closed
   without a reply, and the log gets warn `Drain timeout; closing <n>
   connection(s)`.
5. Exit code 0. A second signal during the drain exits immediately.

Implemented with a `CancellationToken` from `tokio-util` that every session
selects on between commands, and a `TaskTracker` that the main task waits
on with a timeout.

### 9.2 Connection limits

- `--max_connections`: total open client connections. Held as a semaphore;
  the permit lives as long as the session task.
- `--max_connections_per_ip`: open connections per client IP address, in
  a map that is pruned when a count reaches zero.

An accepted socket that exceeds either limit gets
`421 <svc> Too many connections, try again later` and is closed. Log info
`Connection limit reached (<which>) for <client>`. The counters are checked
before the 220 greeting is sent, so the client is never invited in.

### 9.3 Rate limits

- `--max_messages_per_minute`: a token bucket per authenticated username,
  capacity N, refilled at N per minute. Checked at MAIL FROM. Over the
  limit: `450 4.7.1 Rate limit exceeded, try again later`, state stays
  WantMail, and the log gets info `Message rate limit reached for user
  <username> from <client>`. Buckets are kept in a map that is pruned of
  entries idle for more than ten minutes, on a timer. The username is the
  one the client claimed at AUTH, which the API has not yet verified; the
  limit therefore bounds API calls per claimed identity, not per client.
- `--max_recipients`: number of RCPT entries per transaction, counted
  including repeats. The RCPT that would exceed it gets
  `452 4.5.3 Too many recipients` and is not recorded; the transaction
  stays valid with the recipients it has. RFC 5321 4.5.3.1.10 requires a
  minimum of 100, and the default of 1000 matches Postfix.

A value of 0 for any limit means unlimited.

## 10. Packaging

- Repository: `smtp-proxy-rs`, `main` branch, LICENSE and COPYRIGHT carried
  over from the Perl project, `CHANGES` continued with a 1.0.0 entry.
- Dockerfile: stage one `rust:1-alpine` with `musl-dev`, `cmake`, `clang`
  (for aws-lc-rs); `cargo build --release --target
  x86_64-unknown-linux-musl`. Stage two `FROM scratch`, copy the binary and
  the CA bundle, `EXPOSE 3000/tcp`, `ENTRYPOINT ["/app/bin/smtp-proxy"]`.
  If aws-lc-rs will not build for musl, switch rustls and reqwest to the
  `ring` provider; this is a feature flag change only.
- `cargo deb` metadata with a systemd unit template and an
  `/etc/default/smtp-proxy` file for the flags.
- A tag build that attaches the static binary to the release.
- Build and test jobs run with `-j4` and `--test-threads=4`.

## 11. Testing

### 11.1 Unit tests

Ported one to one from the Perl `t/` files:

- `command-parser.t` -> `smtp::command` and `smtp::params`
- `dsn-validation.t` -> `smtp::dsn`
- `reply-formatter.t` -> `smtp::reply`
- extension parsing from `RelayClient` -> `smtp::extensions`

### 11.2 Integration tests (Rust, in `tests/`)

Helpers mirroring the Perl ones:

- `FakeApi`: an axum server on an ephemeral port that records every
  request body and returns a configurable response or HTTP status.
- `RecordingUpstream`: a dumb SMTP server that records command lines,
  with a configurable extension list.
- `RawClient`: a scriptable SMTP client that sends exact lines, does
  STARTTLS with rustls and no certificate verification, and returns full
  replies.

Scenarios, each a port of the Perl file of the same name: commands,
connection lifecycle, pipelining, rset transaction, stale transaction,
repeated recipient, dsn, dsn forwarding to an upstream without DSN,
upstream acceptance text, api from injection, api log redaction, smtplog
redaction, starttls failure, raw client settle, end-to-end (simple, denied,
insert headers, relay error, transparency, change from, change headers,
login auth, multi mail). Plus new: size cap with a small override,
`--version`, TLS 1.2 handshake, upstream STARTTLS in each mode against a
TLS-capable recording upstream (with a certificate check failure case),
graceful drain (idle session gets 421, in-flight relay completes, timeout
closes), both connection limits, the per-username message rate, and the
recipient limit.

Any test that streams large or unbounded input runs under
`systemd-run --user --scope -p MemoryMax=2G`.

### 11.3 Conformance gate (Perl, in `conformance/`)

The Perl end-to-end tests, adapted to:

1. start a tiny Perl HTTP fake API (Mojolicious) on an ephemeral port,
2. spawn the Rust binary with the same flags the Perl tests would pass,
3. run the existing scenarios through `Mojo::SMTP::Client` and
   `RawSMTPClient` unchanged.

Run via `make conformance`, which needs the Perl toolchain from the old
repository (`../smtp-proxy/thirdparty`). It is a migration-time gate, not a
build dependency, and is expected to be retired once the Rust suite has
been trusted through a release.

## 12. Known differences from the Perl version

- TLS 1.0 and 1.1 are not offered.
- A message larger than 1 GiB (configurable) is refused with 552.
- Debug-level data dumps are JSON rather than Perl dumper output.
- The upstream session uses STARTTLS when the upstream offers it, with
  certificate verification. An upstream with a self-signed certificate
  needs `--upstream_tls_ca` or `--upstream_tls=off` to keep working.
- Connection, per-IP, per-username message rate, and recipient limits are
  on by default at 1000, 50, 60 per minute, and 1000.
- SIGTERM drains sessions for up to 30 seconds instead of dropping them.
- New flags: `--version`, `--max_message_size`, `--upstream_tls`,
  `--upstream_tls_ca`, `--upstream_tls_insecure`, `--max_connections`,
  `--max_connections_per_ip`, `--max_messages_per_minute`,
  `--max_recipients`, `--drain_timeout`.

## 13. Out of scope

- Any change to the API contract.
- Per-IP rate limiting (only counts and rates listed in 9.2 and 9.3).
- Client certificate authentication in either direction.
