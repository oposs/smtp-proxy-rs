---
title: SMTP-PROXY
section: 1
header: smtp-proxy manual
footer: smtp-proxy
date: 2026-09-24
---

# NAME

smtp-proxy - SMTP submission proxy that lets a REST API control which sender addresses a user may use

# SYNOPSIS

**smtp-proxy** \[*OPTIONS*\]

# DESCRIPTION

**smtp-proxy** accepts mail submission over SMTP and asks a REST API, the
**--api** URL, which sender addresses an authenticated user may use.
For every message the API receives the credentials, the envelope and the
header block, `From:` included, and answers whether the message may be sent.
The answer may also name headers to add or remove and a replacement envelope
sender.
The API may refuse a message for its recipients as well.
A message the API allows is relayed to the SMTP server named by **--tohost**
and **--toport**.

At startup, once the listen sockets are bound and **--user** has taken effect,
the program prints `Waiting for connections on <address>` and
`Will forward mails to <host>:<port>` on standard output.

A session runs in this order:

1. The proxy greets the client with `220 smtp-proxy SMTP service ready`.
2. After EHLO, STARTTLS is required.
   Until TLS is active, every command other than EHLO, HELO, STARTTLS, NOOP,
   RSET, VRFY and QUIT is answered `530 Must issue a STARTTLS command first`.
3. Inside TLS the client authenticates with AUTH PLAIN or AUTH LOGIN, which
   EHLO then offers as `AUTH PLAIN LOGIN`.
   Until then, other commands are answered `530 Authentication required`.
   The proxy does not verify the password.
   Any credentials that decode, with a username of at most 256 bytes, are
   accepted, and the API judges them with each message.
4. MAIL FROM and RCPT TO are collected and answered `250 OK`.
   Nothing reaches the upstream yet.
5. After DATA the proxy reads the header block up to the empty line that ends
   it.
   It then posts the credentials, the envelope and the headers to **--api**
   (see **API**) and, at the same time, opens a new connection to the upstream.
6. A refusal by the API is answered `550` with the API's reason once the client
   has sent the rest of the message.
   The upstream connection opened for it is closed without a transaction.
7. An allowed message goes to the upstream: the envelope, with the sender the
   API named, then the header block merged with the API's headers, then the
   body as it arrives from the client.
8. The upstream's answer reaches the client.
   An accepted message is answered `250 OK:` followed by the upstream's reply
   text, and the upstream connection is closed with QUIT.
   A refusal keeps the upstream's code and text, and the upstream connection
   is closed without QUIT.

A session may send further messages, and each is checked and relayed on its
own.

The EHLO reply offers `DSN` when the upstream announces DSN, and `SIZE` with
the upstream's limit when the upstream states one.
The proxy asks the upstream at startup and notes the answer again with every
relayed message.
The proxy sets no limit of its own on the size of a message; only the header
block is bounded, by **--max_header_size**.
The DSN parameters `RET` and `ENVID` on MAIL FROM and `NOTIFY` and `ORCPT` on
RCPT TO are checked against RFC 3461, and a malformed one is answered `501`.
They are relayed when the upstream announces DSN and dropped with a warning in
the log otherwise.
A `SIZE=` parameter on MAIL FROM is relayed when the upstream announces SIZE
and dropped with a warning otherwise.
Other parameters reach the API and are not relayed.

A connection that has not sent a complete command within
**--greeting_timeout** seconds is closed.
After the first command, a connection that sends nothing for ten minutes is
closed, in every phase of the session.
Neither closes with a reply.
The API call may take 60 seconds.
On the upstream connection, the connect and each read and write may take 60
seconds.

# OPTIONS

**--listen**, **--tohost**, **--toport**, **--tls_cert**, **--tls_key** and
**--api** are required. A missing one, or a value that does not parse, ends
the program with exit status 1 and a usage message on standard error.

## Listening and TLS

- `--listen <ip:port>`: Accept connections on *ip* and *port*. The address is
  IPv4 or IPv6; `0.0.0.0` accepts on every IPv4 address. An IPv6 address is
  written `[::1]:25` or `::1:25`. The option may be given more than once.

- `--tls_cert <file>`: The certificate chain offered on STARTTLS, in PEM.

- `--tls_key <file>`: The private key of **--tls_cert**, in PEM.

- `--user <name>`: After the listen sockets are bound and the key and log files
  are open, switch to user *name*, its primary group and its supplementary groups.

## Upstream

- `--tohost <host>`: The SMTP server accepted mail is relayed to.

- `--toport <port>`: The port of **--tohost**.

- `--upstream_tls <mode>`: TLS on the connection to the upstream: `off`,
  `opportunistic` (STARTTLS when the upstream offers it), `required` (STARTTLS
  always) or `implicit` (TLS from the first byte). The certificate is verified
  against the system trust store, with **--tohost** as the server name.
  Default: opportunistic.

- `--upstream_tls_ca <file>`: Further CA certificates, in PEM, trusted for the
  upstream in addition to the system trust store.

- `--upstream_tls_insecure`: Do not verify the upstream certificate.

## API

- `--api <url>`: The URL the check request is posted to; see **API**.

## Logging

- `--logpath <file>`: Where the log is written. The file is opened for
  appending. Default: /dev/stderr.

- `--loglevel <level>`: `debug`, `info`, `warn`, `error` or `fatal`. `fatal`
  writes nothing. Default: debug.

- `--smtplog <file>`: Also write the SMTP commands received and the replies
  sent to *file*; see **LOGS**.

- `--credentials`: Write AUTH arguments to the **--smtplog** file in clear.

## Limits

- `--max_header_size <bytes>`: The largest header block accepted. A larger one
  is answered with `552`. The value is at least 1; `0` is refused at startup.
  Default: 1048576.

- `--max_connections <n>`: Concurrent connections in total. `0` means
  unlimited. Default: 1000.

- `--max_connections_per_ip <n>`: Concurrent connections from one client. An
  IPv6 client is counted by its /64 prefix; an IPv4-mapped IPv6 address counts as
  its IPv4 address. `0` means unlimited. Default: 50.

- `--max_messages_per_minute <n>`: Messages one client may start per minute,
  counted at MAIL FROM; the client is identified by the username given at
  AUTH, whether or not that username is later accepted. `0` means unlimited.
  Default: 60.

- `--max_recipients <n>`: Recipients in one message. `0` means unlimited.
  Default: 1000.

## Shutdown and timeouts

- `--drain_timeout <seconds>`: After SIGTERM or SIGINT, how long messages in
  flight may take to finish; see **SIGNALS**. `0` waits until they finish.
  Default: 30.

- `--greeting_timeout <seconds>`: How long a new connection may stay silent
  before its first command. `0` applies the ten-minute inactivity timeout to that
  wait as well. Default: 30.

## Information

- `--man`: Print this manual and exit.

- `-h, --help`: Print a usage summary and exit.

- `--version`: Print the version and exit.

# API

For every message the proxy sends one HTTP POST with a JSON body to the
**--api** URL, after the header block has arrived.
The call may take 60 seconds.
An `https` URL is verified against the system trust store; see
**ENVIRONMENT**.

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

- `username`: The username given at AUTH.

- `password`: The password given at AUTH, in clear.

- `from`: The address given at MAIL FROM, without the angle brackets.
  The null sender `<>` is the empty string.

- `to`: The addresses given at RCPT TO, in the order received.
  An address given twice appears twice.

- `headers`: The header block, one object with `name` and `value` per header,
  in message order.
  A folded header is one entry, and its value keeps the line breaks of the
  fold.
  Whitespace after the colon is not part of the value.
  A line without a colon, or with nothing after the colon, is left out here
  and in the relayed message.
  Bytes that are not UTF-8 appear here as U+FFFD; the relayed message keeps
  them.

- `mailParameters`: The ESMTP parameters given on MAIL FROM, in the order
  received, each an object with `keyword` and `value`.
  A parameter written without a value has a `value` of `null`.

- `rcptParameters`: One entry per RCPT TO command, in the same order as `to`,
  each with the `address` and its `parameters` in the form of
  `mailParameters`.
  A recipient given twice has two entries.
  A malformed DSN parameter (`RET`, `ENVID`, `NOTIFY`, `ORCPT`) is answered
  `501` at the command that carried it, and no request is made for it.

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

- `allow`: `true` relays the message, `false` refuses it with `550`.
  The field is required.

- `reason`: A string.
  With `allow` false, the text of the `550` reply and of the log line.

- `headers`: With `allow` true, headers for the relayed message, each an
  object with `name` and `value`.
  Every header of the message whose name matches an entry, without regard to
  case, is removed.
  Each entry with a string `value` is then added at the end of the header
  block, in the order given.
  An entry whose `value` is `null` removes the header and adds nothing.

- `from`: A string.
  With `allow` true, the envelope sender relayed to the upstream in place of
  the MAIL FROM address.
  When it is absent, `null` or empty, the MAIL FROM address is relayed.
  The `From:` header is not changed by this field.

- `authId`: A string naming the credentials that were used, written to the log
  line of a relayed message; see **LOGS**.

A `reason`, `from` or `authId` of another JSON type makes the whole answer
invalid.
Other fields are ignored.

## Failures

The call follows up to ten redirects.
After a `301`, `302` or `303` the request is repeated as a GET without a body;
after a `307` or `308` it is posted again.
The answer to the last request counts, and an eleventh redirect is a failure.

A call that fails to connect, gets no answer within 60 seconds, gets a final
status outside 2xx, or gets a body that is not the JSON object above is
answered `451 authentication service failed` and logged as
`Failed to call API`.
A header that cannot be relayed, one with a line break that is not a fold or
with an unusable name, is answered `550 authentication service failed`.
See **SMTP REPLIES**.

# SMTP REPLIES

The replies below are composed by the proxy.
A reply from the upstream reaches the client with the upstream's code and
text, and is not listed.

- `220 smtp-proxy SMTP service ready`: The greeting.

- `421 smtp-proxy Too many connections, try again later`: Sent instead of the
  greeting when **--max_connections** or **--max_connections_per_ip** is
  reached; the connection is then closed.

- `421 smtp-proxy Service not available, closing transmission channel`: Sent
  to a session waiting for a command after SIGTERM or SIGINT; the connection is
  then closed.
  See **SIGNALS**.

- `450 4.7.1 Rate limit exceeded, try again later`: A MAIL FROM beyond
  **--max_messages_per_minute** for the username given at AUTH.
  The session stays usable.

- `452 4.5.3 Too many recipients`: A RCPT TO beyond **--max_recipients**.
  The recipients already accepted stay in the transaction.

- `552 Header block exceeds maximum size of <n> bytes`: A header block larger
  than **--max_header_size**, which is *n*.
  The reply follows the end of the message.

- `550 <reason>`: The API refused the message; *reason* is the API's `reason`.
  Without one, the reply is `550` followed by a space.

- `451 authentication service failed`: The API gave no verdict; see
  **API**.

- `550 authentication service failed`: A header, from the client or from the
  API, carries a line break that is not a fold, or has an empty name or one
  with a colon or whitespace.

- `550 Refusing to relay the address '<address>': it contains characters that cannot appear in an SMTP command line`:
  An envelope address, from the client or from the API's `from`, holds a
  character outside printable ASCII, a space, `<` or `>`.

- `451 <text>`: The upstream could not be used: no connection, a timeout, a
  failed TLS handshake, no STARTTLS where **--upstream_tls** requires it, or a
  reply outside the expected class.
  *text* is the cause, for example `timeout talking to the upstream`,
  `TLS to the upstream failed: <error>` or `upstream does not offer STARTTLS`.

- `530 Must issue a STARTTLS command first`: A command that requires TLS,
  before STARTTLS.

- `530 Authentication required`: A command that requires authentication,
  before AUTH.

- `535 Authentication credentials invalid`: AUTH data that do not decode, or
  a username longer than 256 bytes.
  The password is not checked here.

- `504 Authentication mechanism not supported`: AUTH with a mechanism other
  than PLAIN or LOGIN.

- `500 confused authentication response`: An empty AUTH continuation line.

- `553 Unimplemented`: VRFY.

- `500 Line too long`: A command or AUTH line longer than 64 KiB without a
  line end; the connection is then closed.

Replies to malformed commands, unknown commands and commands out of sequence
(`500`, `501`, `502`, `503`) follow RFC 5321 and are not listed.
Once the body has started, an upstream that closes the connection or stops
answering takes the client connection with it, without a reply.

# LOGS

## Main log

The main log goes to **--logpath** and holds the lines at **--loglevel** and
above.
Each line has this form, in local time:

```text
[YYYY-MM-DD HH:MM:SS.fffff] [pid] [level] [connection id] message
```

*level* is `debug`, `info`, `warn` or `error`.
The connection id, 32 hexadecimal digits, appears only on lines written
within a connection, and is the same id the SMTP log uses.
*client* below is the client's IP address and port.
The lines of interest at `info` and above:

- `Relayed mail successfully for <client> using token <authId>`: The upstream
  accepted the message; *authId* is the API's `authId`.
  Without one, the line ends `using no token`.

- `Mail rejected by API (<reason>) for <client>`: The API refused the message.

- `Mail refused by relay server (<error>) for <client>`: The upstream refused
  the message or could not be used, or an envelope address could not be
  relayed; *error* is the upstream's reply text or the cause.

- `Failed to call API (<error>) for <client>`: The API gave no verdict, at
  `warn`; *error* is the connection error, the HTTP status text such as
  `Internal Server Error`, or `invalid JSON from the API: <detail>`.

- `Refusing to relay header '<name>' for <client>: unfolded line break or unusable name`:
  The `550 authentication service failed` case, at `warn`.

- `Connection limit reached (<which>) for <client>`: A connection was refused
  with `421`; *which* is `total` for **--max_connections** or `per-ip` for
  **--max_connections_per_ip**.

- `Message rate limit reached for user <name> from <client>`: A MAIL FROM was
  refused by **--max_messages_per_minute**.

- `Upstream closed during DATA for <client>; closing the client too`: The
  upstream was lost after the body had started.

- `Timeout on stream for <client>`: A connection was closed by
  **--greeting_timeout** or the ten-minute inactivity timeout, at `error`.

- `Shutting down; draining <n> connection(s)`: The first SIGTERM or SIGINT
  arrived.

- `Drain timeout; closing <n> connection(s)`: **--drain_timeout** ran out,
  at `warn`.

At `debug` the log also shows the progress of each session.
A message the API refuses adds the request as JSON after `INPUT`, with the
password replaced by `*******`.
A message the upstream refuses adds the same request after `Mail` and the
API's answer, also as JSON, after `ApiResult`.
A failed API call adds the request JSON on a line of its own.

## SMTP log

With **--smtplog**, every command and AUTH continuation line received from a
client and every reply sent to it are written to that file, in local time:

```text
<connection id> <YYYY-MM-DD HH:MM:SS> >>> <line received>
<connection id> <YYYY-MM-DD HH:MM:SS> <<< <line sent>
```

The arguments of AUTH after the mechanism, and every AUTH continuation line,
appear as `[REDACTED]` unless **--credentials** is given.
The message after DATA, the `421` sent to a connection over the limits, and
the lines exchanged with the upstream are not written.

# SIGNALS

- `SIGTERM, SIGINT`: The first one closes the listen sockets and logs
  `Shutting down; draining <n> connection(s)`.
  A session waiting for a command is answered
  `421 smtp-proxy Service not available, closing transmission channel` and
  closed.
  A session inside DATA, or waiting for the API or the upstream, finishes its
  message, replies, and is then answered the same `421` and closed.
  After **--drain_timeout** seconds the connections still open are closed
  without a reply, and the program exits.
  A second SIGTERM or SIGINT exits at once.

Before the two lines on standard output, SIGTERM and SIGINT end the program
at once.
SIGPIPE is ignored.
Other signals have their default effect.

# EXIT STATUS

- `0`: `--help`, `--man` or `--version`, and an exit after SIGTERM or SIGINT.

- `1`: A command line that cannot be used, a startup failure, or an accept
  loop that ended abnormally.
  Startup failures are a certificate or key that cannot be read, is not
  valid PEM or does not match the other, a listen address that cannot be
  bound, a **--user** that cannot be taken, a log file that
  cannot be opened, an unreadable **--upstream_tls_ca** file or a bad
  certificate in it, and an unknown **--loglevel**.
  The message goes to standard error.

- `101`: The program panicked, for example because the async runtime or a
  signal handler could not be set up.

# ENVIRONMENT

- `SSL_CERT_FILE`: A PEM file of CA certificates that replaces the system
  trust store for the upstream connection and for an `https` **--api**.

- `SSL_CERT_DIR`: A colon-separated list of directories of CA certificates
  that replaces the system trust store in the same way.
  When both are set, both are read.

- `HTTPS_PROXY, https_proxy`: An HTTP proxy for an `https` **--api**.

- `HTTP_PROXY, http_proxy`: An HTTP proxy for an `http` **--api**.

- `ALL_PROXY, all_proxy`: An HTTP proxy for an **--api** of either scheme,
  used when the more specific variable is not set.

- `NO_PROXY, no_proxy`: A comma-separated list of hosts reached without a
  proxy.

- `TZ`: The time zone of the timestamps in both logs.

`SMTP_PROXY_OPTS` belongs to the systemd unit; see **FILES**.

# FILES

- `/etc/default/smtp-proxy`: Sets `SMTP_PROXY_OPTS`, the command line of the
  service.

- `/usr/lib/systemd/system/smtp-proxy.service`: The unit.
  It starts **smtp-proxy** as root with `$SMTP_PROXY_OPTS`, and the program
  switches to **--user** itself.
  It sets `Restart=on-failure`, `TimeoutStopSec=45` and
  `ReadWritePaths=-/var/log/smtp-proxy`.
  The package installs it disabled.

- `/var/log/smtp-proxy`: Writable to the service when the directory exists,
  for **--logpath** and **--smtplog**.
  The package does not create it.

# SEE ALSO

The project: <https://github.com/oposs/smtp-proxy-rs>.

The Perl program this one replaces: <https://github.com/oposs/smtp-proxy>.
Its differences are listed in
<https://github.com/oposs/smtp-proxy-rs/blob/main/README.md#differences-from-the-perl-version>.
