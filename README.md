# SMTP Authentication Proxy

This non-blocking smtp proxy will use a REST call to determine if the incoming mail is 'OK' or not. In contrast to other implementations, for example the one present in nginx, it will only issue the REST call after receiving the login, and the headers of the email. This allows the external service to not only validate the username and password, but also to decide if the sender address is allowed to send mail to the recipient address.

## Request

```json
{
  "username": "...",
  "password": "...",
  "from": "blah@bar.com",
  "to": ["x@baz.com", "y@baz.com"],
  "headers": [
    { "name": "To", "value": "foo@bar.com"},
     ...
  ],
  "mailParameters": [
    { "keyword": "RET", "value": "HDRS" },
     ...
  ],
  "rcptParameters": [
    {
      "address": "x@baz.com",
      "parameters": [
        { "keyword": "NOTIFY", "value": "SUCCESS,FAILURE" },
         ...
      ]
    },
     ...
  ]
}
```

`mailParameters` and `rcptParameters` carry the ESMTP parameters the client
gave on `MAIL FROM` and `RCPT TO`, in the order they were received. A parameter
written without a value, which RFC 5321 permits, has a `value` of `null`.

`rcptParameters` has one entry per `RCPT TO` command rather than one per
address, and is in the same order as `to`: the same recipient may be given
twice with different parameters, and they are reported as the two separate
requests they are.

The RFC 3461 delivery status notification parameters (`RET` and `ENVID` on
`MAIL`, `NOTIFY` and `ORCPT` on `RCPT`) are validated against RFC 3461 before
the request is made -- a malformed one is refused with a 501 at the command
that carried it and no request is issued -- and are relayed to the upstream
server, provided it announces the `DSN` extension. Other parameters are
reported here but are not relayed.

## Response

```json
{
  "allow": true,
  "headers": [
    { "name": "To", "value": "foo@bar.com"},
     ...
  ]
}
```

or 

```json
{
  "allow": false,
  "reason": "sorry, not telling"
}
```

## Installation

```console
cargo build --release
```

The binary is written to `target/release/smtp-proxy`.

To build and run a container image instead:

```console
./build-docker.sh
podman run --rm smtp-proxy:1.0.0
```

`build-docker.sh` runs the test suite (`cargo test`), then builds
`smtp-proxy:<version>` from the `Dockerfile` with `podman build`. The image is
built `FROM rust:1-alpine` and produces a `FROM scratch` runtime image
containing only the statically-linked binary and the system CA bundle needed
to verify the `https://` authentication API.

## Usage

`smtp-proxy` *options*

```
    --man                                  show the full manual and exit
-h, --help                                 show usage and exit
    --version                              print the version and exit
    --listen <ip:port>                     on which IP should we listen; use 0.0.0.0 to listen on all
    --user <USER>                          drop privileges and become this user after start
    --tohost <TOHOST>                      host of the SMTP server to proxy to
    --toport <TOPORT>                      port of the SMTP server to proxy to
    --tls_cert <TLS_CERT>                  file containing a TLS certificate (for STARTTLS)
    --tls_key <TLS_KEY>                    file containing a TLS key (for STARTTLS)
    --api <API>                            URL of the authentication API
    --logpath <LOGPATH>                    where should the logfile be written to [default: /dev/stderr]
    --loglevel <LOGLEVEL>                  debug|info|warn|error|fatal [default: debug]
    --smtplog <SMTPLOG>                    optional detailed log file of SMTP commands and responses
    --credentials                          include username and password info in the smtplog
    --max_message_size <MAX_MESSAGE_SIZE>  largest message accepted, in bytes [default: 1073741824]
```

Starts an SMTP server on the listen host and port. When a connection is
established, communicates with the client up to the point it has both the
envelope and the mail data headers. It requires STARTTLS to be used, and takes
authentication details using the PLAIN mechanism.
It then passes the authentication details, envelope headers, and data headers
to a REST API, which determines if the mail is allowed to be sent and, if so,
what additional headers should be inserted.
Once the mail has been fully received, and if it is allowed to be sent, then
an upstream connection to the target SMTP server is established. The mail is
sent using that SMTP server, with the extra headers inserted. The outcome of
this is then relayed to the client.

## Differences from the Perl version

- TLS 1.0 and 1.1 are no longer offered (rustls only implements TLS 1.2 and
  1.3).
- A message larger than 1 GiB is refused with 552; the limit is configurable
  with `--max_message_size`.
- A command line that reaches 64 KiB without ending is answered
  `500 Line too long` and the connection is closed. The Perl grew its command
  buffer without any limit. RFC 5321 4.5.3.1.4 caps a command line at 512
  octets, so no working client can reach this.
- Debug-level data dumps are JSON rather than Perl `Data::Dumper` output.
- Two new flags: `--version` and `--max_message_size`.
- Exit codes differ from the Perl proxy on two paths, both measured against
  the Perl `smtpproxy.pl`: a missing mandatory option exits 1 on stderr here
  versus 2 there, and `--help`/`--man`/`--version` exit 0 on stdout here
  versus `--help` exiting 1 there. Spec section 7 mandates the exit-1 case
  for a missing mandatory option, and a `--help` that exits non-zero breaks
  scripts and Makefiles that call it, so this divergence is deliberate.
- **The upstream's own reply code reaches the client.** The Perl answers a
  refused message with `550` whatever the upstream said
  (`Connection.pm:682`), so an upstream `451 4.3.2 Service not available`
  arrived at the client as `550 4.3.2 Service not available` -- a permanent
  reply code wrapping a transient enhanced status, which a client reading the
  one deletes and a client reading the other queues. The code is now passed
  through unchanged. Where the upstream never answered at all (connection
  refused, timeout, TLS failure, no STARTTLS where it is required) the client
  gets `451`, because a fresh connection is opened per message and nothing
  about the message was wrong. Our own refusal of a malformed address stays
  `550`: that one is permanent and it is not the upstream's opinion.
- **An API-supplied header name is matched without regard to case.** The Perl
  compares header names exactly, so an API answering `subject` while the
  client sent `Subject` removed nothing and the relayed message carried both.
  RFC 5322 3.6.8 makes field names case-insensitive.
- **A header block written with bare LF is split into individual headers.**
  The Perl splits only on CRLF, so such a block reached the API as one opaque
  header whose value carried every remaining header -- and API-side header
  policy could therefore be evaded by sending LF instead of CRLF. The reader
  accepts bare LF as a line terminator in both implementations, so the block
  genuinely arrives in that shape.
- **A header carrying an unfolded line break is not relayed.** The Perl
  interpolates header values unchecked, so a value holding `CRLF CRLF` split
  the relayed message and forged a body. A line break inside a value is now
  accepted only as a proper fold (a break followed by a space or a tab) and a
  header name may hold no break or colon at all. The mail is refused with
  `550 authentication service failed`, an existing reply text.
- **An auth API that gives no verdict is answered `451`, not `550`.** The Perl
  answers `550 authentication service failed` whatever went wrong, so a mail
  the API never saw was refused permanently and destroyed for an outage of
  ours. The reply text is unchanged; only the code moves, and only where the
  proxy rather than the message is at fault -- a failed or unanswerable API
  call. RFC 5321 4.2.3 `451` is "local error in processing", which is what
  this is. A header carrying an unfolded line break keeps the `550` above:
  that fault is in the message, and resending it unchanged cannot help.
- **The upstream's reply is bounded** at 4096 bytes per line and 65536 bytes
  in total. The Perl bounds neither, so a hostile or compromised upstream
  could feed an endless reply and exhaust memory. RFC 5321 4.5.3.1.5 caps a
  reply line at 512 octets, so no working upstream reaches either bound.
- **An AUTH username longer than 256 decoded bytes is refused** with the
  existing `535 Authentication credentials invalid`. The Perl applies no
  length check, and the username is the one unverified client-supplied string
  the process stores -- the per-username rate limiter keys its buckets on it.
  No real credential comes close to 256 bytes. The password is not bounded:
  it is never retained.
- **`initgroups` is called before `setgid` and `setuid`.** The Perl drops the
  group and the user and nothing else, so a proxy started as root kept root's
  *supplementary* groups for the life of the process. `initgroups` gives the
  target user exactly the groups they would have on login, which keeps working
  for an operator who grants certificate or key access through a group.

The remaining differences from the Perl version -- upstream STARTTLS with
certificate verification, connection/per-IP/rate/recipient limits, the 30
second graceful drain on SIGTERM, and the flags that configure them -- land
in part 2 of the rewrite and are not part of this release.
