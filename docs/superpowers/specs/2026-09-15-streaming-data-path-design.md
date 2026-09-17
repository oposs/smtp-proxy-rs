# Streaming the DATA path: design

Date: 2026-09-15
Status: approved in discussion, awaiting written review

## 1. Goal

Stop holding the message in memory. Today the proxy buffers a whole message
and holds it about three times over; after this change nothing larger than
the header block plus one 64 KiB write chunk is ever resident, per
connection. Message size stops being a memory question.

The change is not a micro-optimisation of the existing shape. It replaces
the store-and-forward DATA path with a streaming one, and with it the
interface between the SMTP server and the upstream relay.

## 2. Why the present design costs three copies

At the moment of relay three full-size buffers are alive at once:

1. `DataReader`'s accumulated body (`data.rs`, `self.body.extend_from_slice`).
2. The output of `format_message` (`proxy.rs`) -- headers plus a second copy
   of the body. The first copy is still owned by `relay_message`.
3. The output of `normalize_and_stuff` (`relay.rs`) -- the whole thing again,
   CRLF-normalised and re-dot-stuffed, alive while the other two still are.

Against the 1 GiB default `max_message_size` and a 1000-connection default
that is 3 GiB per connection on paper.

The buffering is inherited, not invented: the Perl accumulates the body the
same way (`Connection.pm`, `$handled .= $line`) and resolves a promise with
the complete string. But nothing requires it. The policy API is asked about
the headers only -- `CheckRequest` (`proxy.rs`, `fn check_request`) carries
`headers`, never the body -- so the verdict is available before the body
ends. And `SIZE=` is not forwarded upstream today, so no upstream command
needs the total length in advance.

## 3. Decisions taken

These were settled in discussion and are not reopened by the implementation.

**3.1 The proxy is a mirror.** During DATA, whatever the upstream does to
the proxy, the proxy does to the client. Upstream drops the connection ->
the proxy drops the client connection. Upstream sends an early reply ->
the proxy forwards it verbatim, mid-DATA, then discards to the terminator
and says nothing further, which is what a real server doing an early reject
does. The client is not insulated from failures it would have met talking
to the upstream directly.

Every upstream interaction now happens inside the client's DATA phase,
because the API verdict lands at headers-complete. So the mirror rule
covers `MAIL FROM`, `RCPT TO`, `DATA` and the body alike.

Proxy-*originated* failures have no upstream verdict to mirror -- API
unreachable, an unrelayable header, a header block over the cap. Those keep
today's codes and reply at the terminator, as they do now.

**3.2 The size limit is the upstream's, wired through.** The proxy stops
having an opinion about message size. See section 7.

**3.3 `--max_message_size` is replaced by `--max_header_size`.** The body is
governed by the upstream's `SIZE`. The header block is the only thing still
held whole and still needs a bound.

**3.4 The proxy blocks while the API answers, and connects upstream in
parallel.** From headers-complete until the verdict arrives there is nothing
the proxy may write, so it stops reading the client and lets TCP
backpressure hold it -- no buffer, nothing held. The upstream TCP connect
and TLS handshake run concurrently with the API call, taking them off the
critical path.

This is not a latency sacrifice. Today costs `T_body + T_relay`, because the
relay leg only starts once the body is complete. Streaming costs
`T_api + T_body`, because the relay leg is overlapped with the upload. It
wins whenever pushing the body upstream costs more than one API round trip,
and adds one round trip only to tiny messages.

## 4. Architecture

Seven components; three are new or reshaped.

**`ClientSession` (`server/session.rs`)** keeps its role: the client socket
and the SMTP state machine. It still owns line framing, because terminator
detection cannot live anywhere else. `read_message` stops being an
accumulate-then-hand-over loop and becomes a pump.

**`DataReader` (`server/data.rs`)** splits into what it always was: a header
collector bounded by `--max_header_size`, and a body framer that emits line
slices it does not retain. The `body` field goes with `DataReader`.

*Corrected during task 7.* `remaining_capacity`, `mark_too_large` and
`TERMINATOR_SLACK` do **not** go: they survive on the header collector,
rescoped to the header block. The argument for deleting them -- there is no
byte cap on the body any more -- is body-scoped and does not reach the header
block, which 3.3 says is still held whole and still needs a bound. Delete that
budget with no replacement and `next_line` has nothing to say while headers
are collected, so the same memory hole reopens on the session's own buffer.
The slack reconciles that surviving byte cap against a line reader, which is
still what the terminator and the blank line need.

**`Handler` (`server/mod.rs`)**: `headers()` and `message()` collapse into

```rust
fn open_body(&mut self, headers: String)
    -> impl Future<Output = Result<Self::Sink, Rejection>> + Send;
```

with a new associated type `Sink`. The parameter stays a `String`, parsed
by `parse_headers` inside the handler as it is today. `auth`, `mail`, `rcpt`, `reset` and
`dsn_available` are untouched. Merging the two calls is honest: they are the
same moment on the wire, and were two calls only because a buffer sat
between them.

**`BodySink` (`server/mod.rs`, new)**

```rust
fn write(&mut self, chunk: &[u8])
    -> impl Future<Output = Result<(), UpstreamVerdict>> + Send;
fn finish(self)
    -> impl Future<Output = Result<String, UpstreamVerdict>> + Send;
```

**`UpstreamSession` (`relay.rs`)** -- the `relay()` monolith becomes an SMTP
client that is driven: `connect()`, `open_transaction(envelope)`,
`write(chunk)`, `finish()`. `write_body`'s 64 KiB chunking and its per-chunk
inactivity timer survive unchanged; they were already the right shape.

**`ProxyHandler` (`proxy.rs`)** -- `open_body` does the whole gate in one
place: await the API, merge the API's headers, run
`assert_header_relayable`, finish the connect, send envelope and headers.
It returns a sink wrapping the `UpstreamSession`. `relay_message` is gone.

**`ProxyFactory`** gains `upstream_size: Arc<AtomicUsize>` beside
`upstream_dsn`, on the same probe and the same per-relay refresh.

### 4.1 The lifetime discipline this buys

The live upstream connection lives in the sink and nowhere else.
`finish(self)` consumes it on the success path. Every other path drops it --
client hangup, header rejection, a write error -- and dropping it closes the
connection with no terminator sent, so the upstream discards the partial
message.

**The abort semantics are obtained by not writing an abort path.** This is
why a sink beats start/chunk/end callbacks on the handler: callbacks would
park a live connection in `Transaction` across three independent calls,
where every error path has to remember to clean it up and nothing in the
type system says it must.

Rust has no async `Drop`, which is usually a problem for socket cleanup.
Here it is exactly right: the correct abort *is* a synchronous abrupt close.
A graceful `QUIT` would be a lie about a message being abandoned. So `Drop`
needs no code at all.

## 5. Data flow

EHLO answers `SIZE n` from the cached probe. `MAIL FROM` keeps the client's
`SIZE=` parameter instead of discarding it.

At headers-complete, inside `ProxyHandler::open_body`:

```rust
let (verdict, upstream) = tokio::join!(
    self.api.check(&request),
    UpstreamSession::connect(&self.config.relay),
);
```

This removes the `tokio::spawn` in today's `headers()` along with its
`.in_current_span()` workaround -- the spawn existed only to overlap the API
call with the body upload, and the overlap is now with the connect, in the
same task.

Then, in order: deny -> drop the connection, `550`. Merge the API's headers,
`assert_header_relayable` -> on failure drop, `550`.
`open_transaction(envelope)` sends `MAIL FROM` (API-replaced sender, DSN
parameters, and `SIZE=` when the upstream announces SIZE), the `RCPT TO`
list, and `DATA`, expecting `354`. Write the merged headers and the blank
line. Return the sink.

The session then pumps: body lines -> a 64 KiB staging buffer with line
endings normalised to CRLF -> `sink.write(buf)` on each fill. Terminator ->
flush the remainder, `sink.finish()`, which writes the terminator, reads the
upstream reply, sends `QUIT` and returns the text. The client gets
`250 OK: <text>`.

### 5.1 Body lines pass through verbatim

Today the body is unstuffed on read (`DataReader::push_line`,
`strip_prefix(b".")`) and re-stuffed on write (`normalize_and_stuff`). For
correctly stuffed input that round trip is the identity. For a broken client
sending `.foo` unstuffed, today yields `foo` at the far end and pass-through
also yields `foo`, because the upstream unstuffs it.

So body lines are passed through unchanged and only the line ending is
normalised to CRLF. `normalize_and_stuff` is deleted rather than made
incremental.

### 5.2 The framer must be able to flush a partial line

There is no body cap now, so a client can send gigabytes with no line break
at all. Today `next_line` would grow `self.buf` without bound; the old
`remaining_capacity` budget was the only thing stopping it, and it is gone.

The pump therefore flushes the staging buffer when full, complete line or
not. Its state is two small things:

- `at_line_start: bool` -- the terminator and dot-stuffing are meaningful
  only at a true line start, and a multi-gigabyte line is self-evidently not
  a three-byte terminator.
- a held-back trailing `\r` -- if the buffer ends in a lone `\r` we cannot
  yet know whether CRLF or a bare CR follows, so one byte carries over.

That is the whole normalisation problem, and it exists only because we flush
mid-line. Framing by lines is what keeps it this small.

### 5.3 smtplog is unaffected

`smtplog` records commands and replies only. Body lines are read by
`read_message`'s own loop and never reach it.

## 6. Error handling: two types, two voices

```rust
// The proxy's own voice. Only `open_body` can speak it.
struct Rejection { code: u16, text: String }

// The upstream's voice. Only the sink can speak it.
enum UpstreamVerdict {
    Dropped,                             // mirror: close the client connection
    Replied { code: u16, text: String }, // mirror: send this verbatim
}
```

The split is the mirror rule made into types: **once a sink exists, the
proxy has no opinions left.** A reviewer checks the rule by reading two
signatures instead of tracing every branch.

| Event | Proxy does |
|---|---|
| `write` -> `Dropped` | drop the client connection immediately |
| `write` -> `Replied` | forward the reply mid-DATA, then discard to the terminator and say nothing further |
| client EOF mid-body | drop the sink; upstream connection closes with no terminator, nothing is delivered |
| header block over `--max_header_size` | no upstream contacted yet: discard to the terminator, reply `552`, resync the transaction (today's `too_large` shape) |
| API unreachable, unrelayable header | proxy-originated: discard to the terminator, reply with today's codes |
| upstream connect or `MAIL`/`RCPT`/`DATA` refused in `open_body` | proxy-originated, no sink exists yet: today's relay-error mapping, replied at the terminator |
| `finish` -> `Replied` (upstream refused the terminator) | forward the upstream's code and text verbatim, as `relay.rs` does today |

An upstream I/O or TLS error that is not a reply collapses into `Dropped`. A
broken connection has no voice.

### 6.1 The one real hazard: an early reply must be noticed while writing

If `write` only ever writes, an upstream `552` sits unread in the socket
buffer until `finish()`. Worse, an upstream that rejects and stops reading
lets our send buffer fill, so we stall and eventually report a *timeout* --
the wrong thing, mirroring nothing.

So `write` must watch the upstream for readability concurrently with
writing: a `tokio::select!` between the chunk write and a read. This is the
genuine complexity this design buys with everything else it removes, and it
is the first thing to write a fault-injection test for.

### 6.2 Where the mirror rule under-determines

A *hung* upstream -- not dropped, not replying -- cannot be mirrored.
Talking to it directly the client would hang until its own timeout; the
proxy cannot do that without leaking a connection per hung upstream.

Ruling: the existing per-chunk inactivity timeout fires, the sink is
dropped, and the client sees `Dropped`. The client retries, which is the
right outcome for an undeliverable message. This is harsher than today's
`451` and is a deliberate choice.

## 7. Wiring the size through

The proxy stops inventing a limit. The only party with an opinion is the
upstream, and its opinion is carried in both directions.

**Upstream -> client.** The existing startup probe (`proxy.rs`,
`probe_upstream`; spawned from `main.rs`) learns the upstream's `SIZE n`.
It is cached on the factory and refreshed by every successful relay, exactly
as `note_upstream_dsn` does for DSN today. `greeting()` then announces
`SIZE n` to the client, beside the existing `DSN` line.

**Client -> upstream.** The client's `SIZE=` on `MAIL FROM` is forwarded, so
the upstream can refuse before a single body byte moves. Today it is
silently dropped: `dsn_suffix(envelope.mail_params, is_mail_dsn_keyword, ..)`
keeps DSN keywords only. Forwarding is guarded the same way DSN is -- only
when the upstream announces SIZE.

Three details:

- `parse_extensions` (`smtp/extensions.rs`) currently discards the value; it
  keeps only the uppercased keyword. It must keep SIZE's number.
- `SIZE 0` means "no stated limit" (RFC 1870). Treat as unlimited.
- Upstream announces no SIZE, or the probe has not answered yet: announce
  nothing, enforce nothing. `upstream_dsn_known` already models this
  "unknown until asked" state and SIZE takes the same default.

## 8. What is deleted

- `format_message` (`proxy.rs`)
- `normalize_and_stuff` (`relay.rs`)
- `relay_message` (`proxy.rs`), split across `open_body` and the sink
- `DataReader`'s `body` field (`remaining_capacity`, `mark_too_large` and
  `TERMINATOR_SLACK` survive, rescoped to the header block -- see section 4)
- the `tokio::spawn` and `.in_current_span()` in `headers()`
- `--max_message_size`

## 9. Testing

**`ScriptedHandler` (`tests/common/fake_handler.rs`)** gains a
`ScriptedSink`: a `Vec<u8>` plus a scripted `UpstreamVerdict`. This is where
the mirror rule is tested cheaply -- "upstream drops after two chunks" is a
one-line script with no sockets involved. Backs `server_commands.rs` and
`server_tls_auth.rs`.

**`RecordingUpstream` (`tests/common/upstream.rs`)** already has
`reject_data_end`, `stall_data`, `pace_data`, `reject_mail` and
`set_extensions`. `set_extensions` makes the SIZE wire-through testable as
it stands: announce `SIZE 12345`, assert the client EHLO carries it.

Two faults must be added, one per new failure mode:

- **reject mid-DATA and stop reading** -- proves the `select!` of section 6.1
  is not vacuous. Without it that hazard ships silently.
- **drop the connection mid-DATA** -- the `Dropped` mirror.

**The memory invariant needs its own test, and the assertion is peak RSS --
not an OOM kill.** With the body streaming, the resident set is the header
block (`--max_header_size`, ~1 MiB), one 64 KiB staging buffer, an 8 KiB
socket read chunk, rustls' bounded buffers, the tokio runtime and the
binary. Single-digit to low-double-digit MiB, and **none of it scales with
message size**. A ceiling loose enough to be safe is therefore loose enough
to pass a regression that buffers a few hundred MB, which would make the
test nearly vacuous -- the lax-fixture trap this project already has a rule
about.

So: stream **1 GiB** -- exactly what used to be the default
`--max_message_size` -- from a generator that allocates nothing, then read
`VmHWM` from `/proc/self/status` and assert it. The assertion is then a
statement worth reading: what used to be the largest permitted message now
passes through in a hundredth of its size. A failure prints
"peak 412 MiB, expected under N" instead of a kill.

`MemoryMax` stays, but as a backstop rather than the assertion, so a runaway
regression dies locally instead of eating into the 25 GiB slice every
session on this machine shares:

```
cargo test --no-run --test streaming        # build OUTSIDE the scope
systemd-run --user --scope -p MemoryMax=256M -- <the built binary> big_body
```

Building outside the scope matters. The project's usual pattern puts
`cargo test` under the scope, which is right for adversarial-input tests;
here it is wrong, because cargo's own footprint lands in the same ceiling
and blurs the measurement.

**Derive `N`, do not inherit it from this document.** Every number above is
an estimate. The implementation measures the actual steady-state peak first
and sets the assertion at a small multiple of it, with the measured baseline
written into the test as a comment -- so a later reader can tell a drift
from a regression.

For this one test `RecordingUpstream` needs a count-and-discard mode,
because it records raw bytes (`raw_messages`) and would otherwise buffer on
the fake's side what the proxy does not. **This is not the forbidden
relaxation of the fake.** The strict recording stays the default everywhere
else; this is a second mode used by one test. Say so in a comment at the
definition, because it will otherwise look exactly like the thing the
project has ruled out.

**Conformance gate.** Four of the nine files (`end-to-end.t`,
`upstream-acceptance.t`, `dsn.t`, `pipelining.t`) drive the DATA path end to
end, so ordinary delivery breaking goes red immediately, in the Perl's own
words. That is the regression net a rewrite this size needs.

Per R37 its coverage *is* the Perl's coverage, and the Perl buffers too, so
it structurally cannot see mid-stream upstream death, early rejection, the
SIZE advertisement, or the header cap. Those need Rust tests or they are
untested.

## 10. Divergences and CLI

Two new entries for the hardening plan's "Known divergences" section and the
README's differences list:

- **`SIZE` is advertised.** The Perl never did.
- **A dead upstream closes the client connection** instead of answering
  `451`.

`--max_message_size` -> `--max_header_size` is a flag change, but both are
part-2 additions the Perl never had, so the "same CLI flags as the Perl"
constraint is untouched. `tests/cli.rs` needs updating.

## 11. Risks

- **Section 6.1 is the whole risk surface.** Concurrent read-while-writing
  is the one genuinely new piece of concurrency. Everything else this design
  does is deletion.
- **The conformance gate cannot see the new behaviour** (section 9). A green
  gate means no regression in what the Perl tested, never that the mirror
  semantics are right.
- **Drain interacts differently.** A streaming transaction now spans the
  whole upload, so it can be much longer-lived than today's. The drain
  timeout may cut mid-stream more often; under the mirror rule that means
  dropping client connections. Worth a look during implementation, not a
  blocker.
