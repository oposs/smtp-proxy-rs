# The Perl conformance gate

The Rust proxy is a drop-in replacement for the Perl `smtp-proxy`. The Rust test
suite says the Rust proxy does what we think it should. This gate says something
different and harder to fake: it takes the **original Perl test files** and runs
them, assertions and all, against the **compiled Rust binary** over a real
socket.

Nothing here is a reimplementation. Each file under `t/` is its Perl original
with the proxy in the middle swapped out: where the original built an
`SMTPProxy` object inside the test process, the adapted file starts
`smtp-proxy` as a child process and talks to its port. The helper modules
(`RawSMTPClient`, `RecordingSMTPServer`), the upstream servers, the fixtures and
the assertions are the Perl checkout's own, loaded from it directly rather than
copied, so they cannot drift from the authority they represent.

## Running it

From the repository root:

```sh
make conformance
```

That builds the debug binary and then runs `prove` over `t/`. To run it by hand:

```sh
cd conformance && make          # or: prove -w -j 4 -Ilib t/
```

### What it needs

| Variable | Meaning |
| --- | --- |
| `SMTP_PROXY_PERL` | The Perl `smtp-proxy` checkout. The suite borrows its modules and its test certificate, so it cannot run without one. |
| `SMTP_PROXY_BIN` | The binary to test. Only needed when the two fallbacks below miss. |
| `CARGO_TARGET_DIR` | Where the build went. Used to find the binary. |
| `TMPDIR` | Where each proxy's log file is written. Honoured through `File::Temp`; the files are unlinked when the test ends. |
| `JOBS` | Test files run at once. Defaults to 4. |

**The Perl checkout** is resolved as `$SMTP_PROXY_PERL`, then the sibling
`<repo>/../smtp-proxy`. A main checkout sits beside the Perl one, so the sibling
answers there. A git worktree does not sit beside anything, so `Makefile` asks
git which repository the worktree belongs to and looks beside *that* checkout,
exporting the result. A bare `make conformance` therefore works from both. When
neither guess is right the run stops with a message naming the variable.

**The binary** is resolved as `$SMTP_PROXY_BIN`, then
`$CARGO_TARGET_DIR/debug/smtp-proxy`, then `<repo>/target/debug/smtp-proxy`.
`<repo>/target` does not exist at all when `CARGO_TARGET_DIR` is set, which is
why the order matters. A failure names every path it tried.

> A shared `CARGO_TARGET_DIR` can hold a `debug/smtp-proxy` built from an
> **older revision, or another project**. Nothing in a path check can tell.
> `make conformance` is safe because it builds into the same directory it then
> reads. Running `prove` directly against a target dir you did not just build
> into is not. The symptom is a startup banner the harness does not recognise,
> and it says so rather than guessing.

## How the harness works

`lib/ConformancePaths.pm` resolves the three paths above and puts the Perl
checkout's `t/`, `lib/` and `thirdparty/lib/perl5` on `@INC`. It must be `use`d
before anything that lives over there, which is why every test file starts with
it.

`lib/ProxyUnderTest.pm` starts the binary with `--listen 127.0.0.1:0` and reads
the port back out of its startup banner, so parallel test files cannot collide
the way a pre-generated port can. It exposes `logpath` and `log` for the tests
that read the proxy's log, and `probeSettled_p` (below). On `stop` it sends
`SIGTERM`, waits, and falls back to `SIGKILL` rather than leaving a process
holding a port.

**Every limit is started at `0`.** The Perl has no rate limiting, no recipient
cap and no connection cap at all, so running ours at its production defaults
would make the gate measure a policy the authority does not have.

`lib/FakeHttpApi.pm` is the conformance counterpart of the Perl suite's
`FakeAPI`. `FakeAPI` is handed to the in-process proxy as an object and its
`check` method is called directly, so nothing it returns is ever serialised.
A binary can only be reached over HTTP, so this serves the same canned answers
from a real endpoint and records the decoded request bodies in `calledWith`,
under the same accessor names.

### Waiting for the upstream probe

The proxy asks its upstream at startup which extensions it offers, and only
announces `DSN` to clients once that answer is in. The in-process suite awaits
the proxy object's own `upstreamProbe` promise. A separate process has no such
handle, so `probeSettled_p` polls the proxy's log for the line that records the
answer. It polls on the reactor rather than blocking, because the upstream the
probe is talking to is served by that very event loop.

## What was adapted, and why

Every assertion of every copied file is the original's unless listed below.
Each entry is classified the way the task brief asks:

1. **approved divergence** — behaviour on the ruling list in
   `docs/superpowers/plans/2026-09-10-hardening.md`, section *"Known divergences
   for Task 21's conformance gate"*;
2. **Perl-only artefact** — a Perl bug, or something that can only be seen from
   inside the Perl process;
3. **a real defect in the Rust**, which is fixed on the Rust side.

**No category-1 adjustment was needed, and no category-3 defect was found.**
Every change below is category 2. What that means for coverage is set out in
*"What this gate does not measure"*.

### `connection-lifecycle.t` — three changes, all category 2

The original asserts on Perl's own `$SIG{__WARN__}` stream and on a Perl runtime
error string. Neither exists for a separate process. Each assertion is replaced
by the observable consequence it was standing in for, so the count is unchanged:

| Original | Replacement | Why |
| --- | --- | --- |
| `No unhandled rejected promise` | The proxy process survived the race | A rejection nobody handled is a Perl runtime concept. What it cost was the process. |
| `Nothing called a method on the departed connection` | The proxy still accepts new connections | Same: the damage such a call did was to stop the proxy serving. |
| `No method call errors logged` (`qr/Can't call method/`) | No `panicked` in the proxy's log | `Can't call method` is a Perl error string. The proxy's equivalent is a panic. |

The fourth assertion, `qr/left before/`, is **widened to
`qr/left before|hung up/`** and needs its own note. The Perl has one place that
can notice the client has gone, so it always logs `left before`. The proxy has
two, and which one fires is decided by TCP rather than by policy: the client
closes with a FIN, so the proxy's write of the rejection still succeeds into the
socket buffer and only the read that follows sees the EOF. Measured on this
branch, `Client <addr> hung up: ...` (`src/server/session.rs:143`) wins every
time and `Client <addr> left before the rejection could be sent`
(`src/server/session.rs:743`) is not reached. Both lines record the same fact at
`info`, which is what spec 4.7 asks for and what this assertion is there to
prove — that the race was exercised rather than passing vacuously. The widened
regex keeps that intent whole.

### `pipelining.t` — one assertion dropped, category 2

The original drives `SMTPProxy::SMTPServer` directly with `require_starttls` and
`require_auth` off, and injects a deliberately slow `mail` callback so it can
assert on the order the callbacks ran in (`is_deeply $got{order}, ['mail',
'rcpt']`). A binary that always requires STARTTLS and AUTH offers no way to
inject a callback, so the pipelined groups are sent after the session is
authenticated and that one assertion is dropped — 9 tests become 8.

What it was guarding is still measured, on the wire: the RCPT behind the MAIL is
answered `250` and not `503`, which is only true if the MAIL settled first.

### `starttls-failure.t` — one assertion adapted, category 2

Same reason. `is_deeply [grep { /Can't call method|undefined value/ } @warnings]`
reads Perl's warning stream for an undef access inside the reactor. It becomes
`unlike $proxy->log, qr/panicked/`. The other two assertions are the original's,
unchanged.

### `FakeAPI`'s `allow` field — category 2

The Perl tests spell the answer as `allow => 1`, a Perl truth value that never
went through JSON because `FakeAPI` was called in-process. On the wire `allow`
is a JSON boolean (README, *"the API answers"*), and the proxy decodes it as
one. `FakeHttpApi` translates it once, in `_encodable`, rather than making every
adapted test spell it differently from its original.

## Which files were copied

Nine of the Perl suite's eighteen test files drive the whole proxy and are here.
The other nine cannot be run against a binary:

| Not copied | Why |
| --- | --- |
| `command-parser.t`, `reply-formatter.t` | Unit tests calling `parseCommand` / `formatReply` directly. No socket involved. |
| `commands.t`, `smtp-server.t`, `dsn-validation.t`, `stale-transaction.t`, `smtplog-redaction.t` | Build `SMTPProxy::SMTPServer` directly with `require_starttls => 0` — a server-only configuration the binary does not offer. |
| `api-log-redaction.t` | Tests `SMTPProxy::API` as a library, with no proxy at all. |
| `raw-client-settle.t` | Tests the Perl suite's own `RawSMTPClient`, not the proxy. |

Those behaviours are covered by the Rust suite.

## What this gate does not measure

Reading a green result correctly matters as much as getting one.

**Four reply texts have no Perl counterpart at all**, because the Perl has no
rate limiting, no recipient cap, no max-connections flag and no signal handling:
`421` too-many-connections, `450` rate limit, `452` too many recipients, and
`421` drain. There is nothing to compare them against and no test here tries.
The Rust suite covers them.

**The approved divergences are, as it turns out, mostly outside these nine
files.** None of them forced an assertion change, which is a real result and not
a lucky one — but it also means this gate does not confirm them. Not exercised
here: the `451`/`550` split of `authentication service failed`; the upstream
reply code relayed verbatim (the Perl upstream in `end-to-end.t` rejects with
`550`, so verbatim relay and the Perl's rewrite agree and the difference is
invisible); the 256-byte AUTH username bound; the case-insensitive header merge;
bare-LF header splitting; the refusal of a relayed header carrying an unfolded
break; the reply-size caps; the exit codes; the `MAIL FROM` fallback on `"0"`;
the pipelined AUTH continuation; `QUIT 0`; and `500 Line too long`. Each is
covered by the Rust suite and recorded in the plan's ruling list.

The service name in greetings is `smtp-proxy`, not the Perl suite's
`smtp.proxy.service`. No copied assertion matches on it, so nothing needed
adjusting.
