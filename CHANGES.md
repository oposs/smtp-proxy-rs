# Changes

## [Unreleased]

### New

### Changed

### Fixed

## 0.1.0 - 2026-09-24
### New
- The Debian package installs a manual page, `man smtp-proxy`, and
  `smtp-proxy --man` prints the same manual instead of the option list. A
  command-line error now ends in `For more information, try '--help'.` where
  it named `--man`
- `--max_header_size`, default 1 MiB; a header block larger than that is
  answered `552 Header block exceeds maximum size of <n> bytes`. It replaces
  the `--max_message_size` this section used to announce: the body is streamed
  to the upstream rather than held, so the proxy has no size opinion of its
  own about the message as a whole. The only stated limit is the upstream's
- the upstream's `SIZE` limit is advertised to clients on EHLO, and a client's
  own `SIZE=` on MAIL FROM is forwarded to the upstream. The Perl announced
  neither, so a client learned a message was too large only after sending it
- `--version`
- `--upstream_tls`, default opportunistic, so the connection to the upstream
  uses STARTTLS when the upstream offers it, with certificate verification
  against the system trust store. UPGRADE NOTE: this changes behaviour for a
  deployment whose upstream announces STARTTLS with a self-signed or private-CA
  certificate. Give it `--upstream_tls_ca` with a PEM bundle, or
  `--upstream_tls=off` to relay in plain text as before.
  `--upstream_tls_insecure` skips verification; required and implicit are the
  stricter modes
- `--max_connections` (1000) and `--max_connections_per_ip` (50). Over either
  limit the socket is answered
  `421 <service> Too many connections, try again later` and closed before the
  greeting. Mojo::IOLoop also capped at 1000 but simply stopped accepting,
  leaving the client in the backlog with no explanation
- `--max_messages_per_minute` (60) per authenticated username, checked at MAIL
  FROM; over the limit the reply is
  `450 4.7.1 Rate limit exceeded, try again later` and the session stays usable.
  The Perl had no rate limit
- `--max_recipients` (1000); the RCPT that would exceed it is answered
  `452 4.5.3 Too many recipients` and is not recorded, and the transaction stays
  valid with the recipients it already has
- `--greeting_timeout` (30). A connection that has sent no command at all is
  closed after this many seconds; from the first complete command onwards the
  ordinary ten-minute inactivity timeout governs the session. Without it the
  connection limit above is a lockout an attacker can hold with one connection
  every twelve seconds per address. 0 gives that first wait the ten-minute
  timeout too. A deliberate narrowing of RFC 5321 4.5.3.2, which applies only
  to a connection that has said nothing
- `--drain_timeout` (30). SIGTERM now closes the listeners, answers a session
  between transactions
  `421 <service> Service not available, closing transmission channel`, and lets
  a session inside DATA or waiting on the API or the upstream finish and reply.
  The Perl exited and dropped every session where it stood. A second signal
  exits at once
- 0 disables any of the four limits above
- `--max_header_size` is the exception: 0 there is refused at startup with a
  message naming the flag, rather than accepted and then applied literally
  as a cap that every message carrying any header at all exceeds. There is
  no unlimited setting for it, because the header block is the one part of a
  message the proxy holds in memory
- packaging: a release builds a statically linked musl binary, a Debian package
  carrying it together with a systemd unit and `/etc/default/smtp-proxy`, and a
  container image on ghcr.io
- `make conformance`: the original Perl test suite, run against the compiled
  binary over a real socket rather than against an in-process Perl proxy. Nine
  of the Perl suite's eighteen test files, with their own assertions and their
  own helper modules loaded from the Perl checkout. See `conformance/README.md`
  for what it does and does not measure

### Changed
- The first line of `smtp-proxy --help` now reads `SMTP submission proxy that
  lets a REST API control which sender addresses a user may use`, the same
  sentence the manual page opens with
- complete rewrite in Rust, replacing smtpproxy.pl 0.8.0. Every flag the Perl
  had is spelled the same way, and the API JSON and the log formats are
  unchanged. Some SMTP replies are NOT: the items below are the set an operator
  has to plan for, and README.md "Differences from the Perl version" carries
  all of them; docs/maintainer-notes.md gives the reasons
- TLS 1.0 and 1.1 are no longer offered (rustls)
- a command line that reaches 64 KiB without ending is answered
  `500 Line too long` and the connection is closed; the Perl grew its command
  buffer without a limit
- debug-level data dumps are JSON instead of Perl dumper output
- a missing mandatory option exits 1 instead of 2, and `--help`, `--man` and
  `--version` exit 0 on stdout instead of `--help` exiting 1
- the ten-minute inactivity timeout now covers the whole session. The Perl
  armed it only after STARTTLS, so a client that connected and then sent
  nothing stayed connected indefinitely. That cost the Perl a file descriptor;
  here it costs a `--max_connections` slot, which is taken at accept, so
  without this an unauthenticated client could hold every slot for ever by
  sending nothing at all. The wait for the client's *first* command has a
  shorter deadline of its own, `--greeting_timeout` above
- the systemd unit no longer hands the service an ambient
  CAP_NET_BIND_SERVICE, and instead limits it to the four capabilities the
  startup actually needs -- binding the listen ports, reading the certificate
  and the log files, and changing to the account given with `--user`. The
  service still starts as root and still binds privileged ports, so a
  deployment that uses the unit as shipped sees no change. An operator who
  has replaced `--user` with systemd's own `User=` in a drop-in has to put
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` back
- UPGRADE NOTE: an upstream that dies in the middle of a message now closes the
  client connection instead of answering `451` at the terminator. During DATA
  the proxy is a mirror: it has already relayed the body it received, so it
  cannot honestly promise to hold a message it no longer has, and a silent
  close is what RFC 5321 leaves a client to retry on. A client that expected a
  `451` sees a dropped connection instead; both mean "try again", but a client
  that treats an unexpected close as a hard failure has to be reconfigured. An
  upstream that *answers* mid-body is still relayed verbatim

### Fixed
- a client sending a non-ASCII character where `MAIL FROM:` or `RCPT TO:`
  belongs -- `MAIL FROMÖ`, for instance -- got no reply at all and the
  connection died, leaving a crash report in the log. Any client could do it
  before authenticating. The command is now answered
  `501 invalid MAIL arguments`
- a header carrying non-UTF-8 bytes, which mail programs still send for
  Western European text instead of encoding it, reached the recipient with
  every such byte replaced by a question-mark character. The header block is
  now relayed exactly as it arrived
- a header the API added with an empty name, or a name beginning with a space
  or a tab, disappeared into the value of the header above it instead of being
  added. Such a header is now refused with
  `550 authentication service failed` and named in the log
- `--max_connections_per_ip` never engaged for IPv6 clients: each connection
  arrived from a different address out of the client's own /64, so the count
  never rose. IPv6 connections are now counted per /64, IPv4 per address, and
  a dual-stack listener counts an IPv4 client as IPv4
- a second stop signal sent while the proxy was starting its drain could be
  ignored, so the documented way to cut a long drain short did not always
  work. Both signals are now heard

- the upstream server's own reply code now reaches the client. The Perl answered
  a refusal 550 whatever the upstream said, so an upstream 451 arrived as 550
  and the client deleted a mail it should have queued. Where the upstream never
  answered at all the client gets 451
- an auth API that gives no verdict is answered 451, not 550. The text
  `authentication service failed` is unchanged; only the code moves, and only
  where the proxy rather than the message is at fault. A mail the API never saw
  is no longer destroyed by an outage of ours
- an API-supplied header name is matched without regard to case (RFC 5322
  3.6.8); the Perl compared exactly, so an API answering `subject` to a client's
  `Subject` removed nothing
- a header block written with bare LF is split into individual headers. The Perl
  split only on CRLF, so API-side header policy could be evaded by sending LF
- a header value carrying an unfolded line break is refused with
  `550 authentication service failed`. The Perl interpolated header values
  unchecked, so a value holding CRLF CRLF split the relayed message and forged a
  body
- the upstream's reply is bounded at 4096 bytes per line and 65536 bytes in
  total; the Perl bounded neither, so a compromised upstream could feed an
  endless reply and exhaust memory
- an AUTH username longer than 256 decoded bytes is refused with the existing
  `535 Authentication credentials invalid`
- initgroups is called before setgid and setuid, so a proxy started as root no
  longer keeps root's supplementary groups for its whole life
- an accept loop that dies takes the process down with a non-zero exit instead
  of being swallowed. It used to exit 0, which `Restart=on-failure` leaves
  alone, or -- with several `--listen` addresses -- leave the process up and
  healthy-looking with one port silently closed
- when the API answered with an empty `authId`, the log line read
  `Relayed mail successfully for <client> using token` with nothing after it;
  it now reads `using no token`, as the Perl version did. An `authId` of `0`
  is treated the same way

## Earlier releases

Everything below predates this changelog format and the repo-infra release flow,
and is kept verbatim in the format smtpproxy.pl used.

The headings are DELIBERATELY not rewritten to `## X.Y.Z - YYYY-MM-DD`.
`lib/changes.js:latestRelease` returns the first heading in that shape, and
`release-publish.yml`'s `publish` job then fails the whole run when that version
disagrees with `version_files`. Converting `0.8.0` here would therefore make
every merge to main red -- `CHANGES.md says 0.8.0 but these disagree:
Cargo.toml, Cargo.lock` -- until the first release lands. Left as it is,
`latestRelease` returns nothing and the job says so and stops.

Once `0.1.0` has been released, its heading is the first match and this is moot;
converting the tail then is a cosmetic change and safe.

The Rust version numbers start again at `0.1.0` and do not continue the Perl
series below. A `0.1.0` here is newer than the Perl `0.8.0`.

0.8.0 2026-09-10 14:24:32 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - SMTP protocol conformance against the RFC 5321 4.5.1 minimum
   implementation. Reply codes a client can see have changed: HELO and NOOP
   are answered 250 rather than 502, NOOP takes the argument RFC 5321 4.1.1.9
   allows, PING is no longer a command and draws 502 rather than 503, and
   EHLO or HELO is now accepted at any point in a session and resets the
   transaction as RSET does (RFC 5321 4.1.4)
 - EHLO and HELO without a domain, and VRFY without a string, are now
   answered 501 rather than accepted
 - the MAIL FROM and RCPT TO keywords, and the AUTH verb and mechanism name,
   are matched without regard to case; an AUTH mechanism containing a hyphen
   is answered 504 rather than 501
 - MAIL FROM:<> is accepted, so a bounce or a DSN can be relayed
 - a group of commands sent in one write is processed in order, one at a time
 - DSN is announced, and the RFC 3461 parameters (RET, ENVID, NOTIFY, ORCPT)
   are relayed, only when the upstream server announces DSN itself. The proxy
   asks it once at startup and keeps the answer current from every mail it
   relays. The parameters are validated where they are given: a malformed one
   is answered 501 at the MAIL or RCPT that carried it
 - the upstream's acceptance text, which is its queue id, is relayed to the
   submitting client instead of an empty one
 - the API request carries two new fields, mailParameters and rcptParameters;
   see README.md
 - the submitting user's password is no longer written to the main log when
   the API answers with anything other than a 2xx

0.7.7 2023-07-21 14:34:38 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - further improve failure handling for connection problems with
   credmgr during auth phase

0.7.6 2023-07-12 17:24:04 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - raise credmgr timeout to 60 seconds
 - better handling of lost connections

0.7.5 2023-06-19 17:20:21 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - add catch rule to STARTTLS upgrade promise

0.7.4 2023-05-09 16:32:42 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - even more logging. log body size and body transfer

0.7.3 2023-05-02 17:00:36 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - actively close connection on QUIT
 - even more logging

0.7.2 2023-04-24 17:00:42 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - more logging for failure cases
 - increase stream timeout to 300s (from 15s)

0.7.1 2022-11-23 14:04:16 +0100 Tobias Oetiker <tobi@oetiker.ch>

 - actually enable libev event loop

0.7.0 2022-11-19 00:06:36 +0100 Tobias Oetiker <tobi@oetiker.ch>

 - added EV eventloop for better performance
 - SP-1 properly release connection after connection end
 - SP-2 log connection id, add more logging

0.6.8 2022-08-29 11:24:26 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - after forwarding a message, report the upstream server response

0.6.7 2022-08-29 10:48:52 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - added test to verify that the fix in 0.6.6 actually works
   it works ... 

0.6.6 2022-08-29 10:01:09 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - SECURITY! SMTP-Proxy did NOT clear the recipients list when
   several mails were sent over the same connection. So successive
   mails were sent to all previous recipients in mails submitted
   in the previous connection

0.6.5 2022-05-17 14:04:58 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - log more detail with authentication fails

0.6.4 2022-05-17 11:54:21 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - initial log must happen AFTER privilege drop

0.6.3 2022-05-17 11:40:28 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - update useragent implementation to be in sync with latest mojo recommentation

0.6.2 2022-05-16 16:10:21 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - fix 0.6.0 regression ... return should return the rejection!

0.6.1 2022-05-12 15:23:55 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - AUTH LOGIN should be Username: and Password: both with a colon at the end.

0.6.0 2021-04-06 Fritz Zaucker <fritz.zaucker@oetiker.ch>

 - updated build environment
 - fixed tests
 - write $apiResult->{authId} to log file on successful mail relay
 - fix some documentation typos

0.5.1 2019-06-04 12:10:28 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - update documentation

0.5.0 2019-06-04 12:05:58 +0200 Tobias Oetiker <tobi@oetiker.ch>

 - support --listen option instead of --listenhost and --listenport
   --listen=ip:port can be used multiple times

0.2.0 2018-06-14 Fritz Zaucker

* first test version for HIN


0.0.1 2018-05-29

* initial version
