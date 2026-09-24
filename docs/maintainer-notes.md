# Maintainer notes

Why smtp-proxy is the way it is, one decision per section. The README lists
what differs from the Perl proxy and the manual says what the program does;
this file keeps the reasons, so that whoever changes a default can see what it
was protecting. Each section names where the decision lives in the code by a
string you can grep for.

## DATA is a mirror of the upstream

During DATA an upstream that replies is relayed to the client verbatim, code
and text, and an upstream that drops the connection takes the client
connection with it, without a reply.

The Perl reads the whole message into memory and only then opens the
upstream, so it always has a `451` left to answer with. This proxy streams the
body straight through, so by the time an upstream can die the client has
already been told `354` and is in the middle of the message. There is nothing
left to say. A failure before the body (the connect, the envelope, the header
block) is still answered with a reply code. Streaming is also why the message
as a whole carries no proxy limit: nothing but the header block is held in
memory, and the upstream's `SIZE` is the limit. This design is settled; do not
reopen it.

Where: `src/server/session.rs`, `fn mirror` and `fn conclude`.

## The upstream's reply code reaches the client

A refusal from the upstream keeps its own code. The Perl answers every
refused message with `550` (`Connection.pm:682` in the Perl checkout), so an
upstream `451 4.3.2 Service not available` arrived at the client as
`550 4.3.2 Service not available`: a permanent reply code wrapping a transient
enhanced status, which a client reading the one deletes and a client reading
the other queues.

Where the upstream never answered at all (connection refused, timeout, TLS
failure, no STARTTLS where it is required) the client gets `451`, because a
fresh connection is opened per message and nothing about the message was
wrong. The proxy's own refusal of a malformed address stays `550`: that one is
permanent and it is not the upstream's opinion.

Only codes from 400 to 599 pass through. An upstream that answers `250` where
a refusal was expected broke the protocol, and relaying that code would tell
the client a message was accepted that never was.

Where: `src/relay.rs`, `fn client_code`; `src/proxy.rs`,
`fn relay_error_to_rejection`.

## An API without a verdict is a 451

A failed or unanswerable API call is answered
`451 authentication service failed`. The Perl answers
`550 authentication service failed` whatever went wrong, so a mail the API
never saw was refused permanently and destroyed for an outage of ours. The
reply text is unchanged and only the code moves, and only where the proxy
rather than the message is at fault. RFC 5321 4.2.3 defines `451` as "local
error in processing", which is what this is.

Both refusals share one text on purpose, so the code is the only thing that
tells them apart. A client that could tell them apart by text would stop
reading the code, and the code decides whether the mail is retried.

A header carrying an unfolded line break keeps the `550`: that fault is in the
message, and resending it unchanged cannot help. The API's own refusal
(`"allow": false`) is also permanent and stays `550`.

Where: `src/proxy.rs`, `fn auth_service_unavailable`, `fn auth_service_failed`,
`const AUTH_SERVICE_FAILED`.

## Header names from the API match without regard to case

The Perl compares header names exactly, so an API answering `subject` while
the client sent `Subject` removed nothing, and the relayed message carried
both. RFC 5322 3.6.8 makes field names case-insensitive.

Where: `src/proxy.rs`, `fn merge_headers` (`eq_ignore_ascii_case`).

## A header block with bare LF is split

The reader of both implementations accepts a bare LF as a line terminator, so
a header block written with LF instead of CRLF really does arrive in that
shape. The Perl splits headers only on CRLF, so such a block reached the API
as one opaque header whose value carried every remaining header, and API-side
header policy could be evaded by sending LF instead of CRLF. This proxy splits
on either.

Where: `src/proxy.rs`, `fn parse_headers`.

## An unfolded line break is not relayed

The Perl interpolates header values unchecked, so a value holding `CRLF CRLF`
split the relayed message and forged a body. A line break inside a value is
now accepted only as a proper fold (a break followed by a space or a tab), and
a header name may hold no break or colon at all. The mail is refused with
`550 authentication service failed`, a reply text the Perl already had, so
that no client sees a new text.

Where: `src/proxy.rs`, `fn assert_header_relayable`.

## The upstream connect overlaps the API call

The API's verdict is needed before `MAIL FROM`, which the API may rewrite with
its `from`, and before the headers go out. Both come ahead of the body, so the
connect to the upstream is the only thing that can run alongside the API call,
and it does. The cost is that a message the API refuses leaves the upstream a
connection that was greeted and then dropped. No envelope and no message
reach it.

Where: `src/proxy.rs`, `fn open_body` (`tokio::join!`).

## Bounds on what the upstream may send

A reply read from the upstream may hold 4096 bytes per line and 65536 bytes in
total. The Perl bounds neither, so a hostile or compromised upstream could
feed an endless reply and exhaust memory. RFC 5321 4.5.3.1.5 caps a reply line
at 512 octets, so no working upstream reaches either bound.

Where: `src/relay.rs`, `MAX_UPSTREAM_REPLY_LINE` and `MAX_REPLY_TOTAL`.

## The command line bound

A command line, or an AUTH continuation line, that reaches 64 KiB without a
line end is answered `500 Line too long` and the connection is closed. The
Perl grew its command buffer without any limit. RFC 5321 4.5.3.1.4 caps a
command line at 512 octets, so no working client reaches this.

Where: `src/server/session.rs`, `MAX_COMMAND_BUFFER`.

## Per-IP limit: IPv6 by /64, IPv4-mapped unwrapped first

`--max_connections_per_ip` counts an IPv6 client by its /64 prefix, which is
the ordinary allocation to one customer. Counted per exact address, such a
client has 2^64 addresses and the limit would never engage.

An IPv4-mapped address is unwrapped before the prefix is taken. A dual-stack
listener on `[::]` reports every IPv4 client as `::ffff:a.b.c.d`, and those
all share one 64-bit prefix: masked first, the whole IPv4 internet would
become a single bucket. Do not reorder the two steps.

Where: `src/server/listener.rs`, `fn limit_key`.

## Idle timeout in every phase, and the 30 s greeting timeout

A connection that sends nothing for ten minutes is closed in every phase of
the session. The Perl arms its ten-minute inactivity timer on the upgraded
stream alone and leaves the connection before STARTTLS untimed, so a client
that connects and then sends nothing stays connected indefinitely (measured:
still open after 90 seconds, with no close and no log line). That cost the
Perl one file descriptor, and it had no connection limit for the silent
client to occupy. Here it costs a slot in `--max_connections` and
`--max_connections_per_ip`, taken the moment the connection is accepted.
Without a timeout an unauthenticated client could hold every slot for ever by
sending nothing, and every legitimate client would be answered
`421 ... Too many connections, try again later` until the service was
restarted. No working client is idle that long between the TCP handshake and
its first command.

Ten minutes alone make that lockout self-healing, not impossible: 1000 slots
over 600 seconds is one new connection every twelve seconds from each of
twenty addresses, which costs an attacker nothing to sustain. So a connection
that has not yet sent a complete command is closed after
`--greeting_timeout` seconds, 30 by default. From the first command onwards
the ten-minute timeout governs the rest of the session, the EHLO after
STARTTLS included.

This is a deliberate narrowing of RFC 5321 4.5.3.2, which asks a server to
allow five minutes for a command (owner ruling). It is defensible because it
applies only to a connection that has said nothing at all: a real client sends
EHLO as soon as it has read the 220. `--greeting_timeout=0` gives that first
wait the full ten minutes again.

Where: `src/server/session.rs`, `fn next_line` (`greeting_timeout`,
`idle_timeout`); `src/main.rs`, `idle_timeout: Duration::from_secs(600)`.

## --max_header_size 0 is refused

The other limits (`--max_connections`, `--max_connections_per_ip`,
`--max_messages_per_minute`, `--max_recipients`) read `0` as unlimited, and
`--max_header_size` looks like one more of that family. It is not. The header
block is the one part of a message the proxy holds in memory (the body is
streamed so that nothing unbounded is held), so there is no unlimited setting
to offer. Taken literally, `0` is a cap the first header line of every message
exceeds. Either reading would be a silent surprise, so `0` is a startup error.

Where: `src/config.rs`, `fn check_limits` and `MAX_HEADER_SIZE_ZERO`.

## Connection cap answered with 421

`Mojo::IOLoop` also defaulted to 1000 concurrent connections
(`Mojo/IOLoop.pm:18,169`), but at the cap it simply stopped accepting, so a
client sat in the kernel's backlog with no greeting and no explanation. The
socket is now answered `421 <service> Too many connections, try again later`
and closed, before the 220 greeting, so the client knows to come back.

Where: `src/server/listener.rs`, `fn try_acquire` and
`Too many connections, try again later`.

## Rate limit per claimed username

`--max_messages_per_minute` counts per username given at AUTH. The Perl had no
rate limit at all. That username is the one claimed at AUTH, which the API has
not yet verified, so the budget bounds API calls per claimed identity rather
than per client. The bucket map holds at most 10 000 usernames and gives up
the idlest one when full, so a stream of invented usernames cannot grow it
without bound.

Where: `src/ratelimit.rs`, `MAX_BUCKETS` and `fn evict_idlest`;
`src/server/mod.rs`, `Rate limit exceeded, try again later`.

## 1000 recipients

The Perl counted no recipients. RFC 5321 4.5.3.1.10 requires a server to
accept at least 100, and 1000 matches Postfix, so no ordinary client reaches
the cap. The `RCPT TO` over the cap is not recorded and the transaction stays
valid, so a client that handles `452` can send the rest in a second
transaction.

Where: `src/server/session.rs`, `fn want_rcpt` (`max_recipients`).

## Drain on SIGTERM

The Perl exited on SIGTERM and every open session died mid-transaction. For a
session inside DATA that means a message the client had handed over and that
was never relayed. The proxy now closes its listeners, answers idle sessions
with `421`, and lets sessions inside DATA or waiting on the API or the
upstream finish. `--drain_timeout` bounds the wait, and a second signal exits
at once for an operator who cannot wait. The systemd unit's
`TimeoutStopSec=45` is longer than the 30 s default drain, so systemd does not
cut the drain short with SIGKILL.

Where: `src/server/session.rs`, `fn drained`; `src/main.rs`,
`Drain timeout; closing`; `src/shutdown.rs`.

## SIZE advertised and forwarded

The Perl announced no `SIZE` extension and dropped a client's `SIZE=` on
`MAIL FROM`. Advertising the upstream's stated limit lets a client learn the
real limit before it sends. Forwarding `SIZE=` lets the upstream refuse an
oversized message before the transfer instead of after it. When the upstream
never announced `SIZE`, the parameter is still dropped, with a warning logged,
because an upstream that never offered the extension may answer `555` to it.

Where: `src/relay.rs`, `fn size_suffix`; `src/proxy.rs`,
`fn upstream_size_limit`.

## EHLO lines with extra whitespace

An EHLO reply line whose keyword is preceded by extra whitespace, for example
`250- SIZE 10240000`, is malformed. The Perl's `/^\d{3}[- ](\S+)/` fails to
match such a line and drops it entirely. This proxy trims the whitespace and
accepts the keyword. The consequence: against such an upstream this proxy may
learn, and therefore advertise, an extension the Perl would have ignored.

Where: `src/smtp/extensions.rs`, `fn parse_extensions` (`trim_start`).

## AUTH username bound at 256 bytes

A username longer than 256 decoded bytes is refused with the existing
`535 Authentication credentials invalid`. The Perl applies no length check.
The username is the one unverified client-supplied string the process keeps
beyond a session, because the per-username rate limiter keys its buckets on
it. No real credential comes close to 256 bytes. The password is not bounded:
the process never retains it beyond the session.

Where: `src/server/auth.rs`, `MAX_USERNAME`.

## initgroups before setgid and setuid

The Perl drops the group and the user and nothing else, so a proxy started as
root kept root's supplementary groups for the life of the process.
`initgroups` gives the target user exactly the groups they would have on
login, which keeps working for an operator who grants certificate or key
access through a group.

Where: `src/privdrop.rs`, `fn drop_to`.

## Opportunistic upstream TLS by default, no plain-text fallback after STARTTLS

The Perl relayed to the upstream in plain text always. The default is now
`--upstream_tls=opportunistic`: STARTTLS whenever the upstream offers it, with
the certificate verified against the system trust store and `--tohost` as the
server name. This changes behaviour for an existing deployment the moment its
upstream announces STARTTLS, which is why the README names
`--upstream_tls_ca` and `--upstream_tls=off` for an upstream with a
self-signed or private-CA certificate.

There is no fallback to plain text once STARTTLS has been announced. A
fallback would let anyone on the path force a downgrade by breaking the
handshake.

Where: `src/relay.rs`, `fn upgrade` and `fn handshake`.

## Exit codes

Measured against the Perl `smtpproxy.pl`, two paths differ. A missing
mandatory option exits 1 on standard error here and 2 there. `--help`,
`--man` and `--version` exit 0 on standard output here, where the Perl's
`--help` exits 1. Section 7 of the rewrite design
(`docs/superpowers/specs/2026-09-10-rust-rewrite-design.md`) mandates exit 1
for a missing mandatory option, and a `--help` that exits non-zero breaks
scripts and Makefiles that call it. The divergence is deliberate (owner
ruling).

Where: `src/config.rs`, `fn usage_exit` and `fn parse_args`.

## ring rather than aws-lc-rs, and cross for the musl build

TLS uses rustls with the *ring* backend, pinned in `Cargo.toml`. That keeps
the build free of a C and assembly toolchain such as the one aws-lc-rs needs,
and keeps the static musl link straightforward. The cost is post-quantum key
exchange: rustls offers hybrid X25519MLKEM768 only through its aws-lc-rs
backend, so this build does not have it (owner ruling: ring over
post-quantum). Wanting it back means taking aws-lc-rs back with it, and every
`default-features = false` in `Cargo.toml` is what keeps it out today.

`make release` uses `cross` rather than a plain `cargo build --target`,
because ring assembles per-target assembly with a toolchain an ordinary host
does not carry, and cross's images do. `make verify-static` asserts the
result is static instead of trusting `crt-static`, which the linker is free to
ignore. `make lint test deb` is what the release workflow runs, so a CI
failure reproduces with one command locally.

Where: `Cargo.toml`, `TLS is ring-only`; `src/lib.rs`,
`ring::default_provider().install_default()`; `Makefile`, `CROSS ?= cross`.

## The container image

The image is built `FROM rust:1-alpine`, which is already a musl host, so it
needs no cross-compilation and shares nothing with `make release`. The runtime
stage is `FROM scratch` and holds only the static binary, the system CA bundle
needed to verify an `https://` API, and `/etc/passwd` and `/etc/group` so that
`--user` can resolve a name. `EXPOSE 3000/tcp` and the unqualified `FROM` are
kept as the Perl image had them.

Where: `Dockerfile`; `build-docker.sh`.

## The capability bounding set of the systemd unit

The unit has no `User=`, so `ExecStart` runs as root; the program binds its
listen ports first and drops to `--user` itself. An ambient
`CAP_NET_BIND_SERVICE` would be redundant before that drop and gone after it:
`setuid(2)` from uid 0 to a non-zero uid clears the permitted, effective and
ambient sets (capabilities(7), "Effect of user ID changes on capabilities").
What is worth bounding is the root phase, so the unit sets
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE`:
bind the ports, read the TLS key and open the log files (`CAP_DAC_OVERRIDE`
for a log directory owned by the service account), then `initgroups`,
`setgid` and `setuid`.

Do not narrow the set to `CAP_NET_BIND_SERVICE` alone. After `execve` a root
process's permitted set is its bounding set, so the privilege drop would fail
with `EPERM` and the service would not start. If the drop ever moves to
systemd with `User=`, it happens before the bind, and
`AmbientCapabilities=CAP_NET_BIND_SERVICE` has to come back.

This reasoning is argued, not yet measured on a host. The check, on a host
where the unit runs with `--user`: `grep Cap /proc/$(pidof smtp-proxy)/status`
should show `CapAmb` all zeros, and a start with `--listen=0.0.0.0:25
--user=smtp-proxy` should log no `Failed to setgid` or `Failed to initgroups`.
Repeat with `--logpath` in a `0750` directory owned by the service account,
which is the case `CAP_DAC_OVERRIDE` is there for.

Where: `packaging/smtp-proxy.service`, `CapabilityBoundingSet`.

## --man prints Markdown

`--man` exists because the Perl had it. It prints `docs/manual.md`, embedded
with `include_str!`, with the front matter stripped, so the static binary and
the container image, which have no man page installed, carry the whole manual,
and there is one text. The Markdown is printed as it is: the source is written
to be readable raw, and a terminal renderer would be a dependency for one
flag. A reader that closes the pipe early (`smtp-proxy --man | head`) is not
an error.

Where: `src/config.rs`, `fn manual`.
