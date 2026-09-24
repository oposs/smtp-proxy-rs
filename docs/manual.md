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

To be written.

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

- `--smtplog <file>`: Also write every SMTP line sent and received to *file*;
  see **LOGS**.

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

To be written.

# SMTP REPLIES

To be written.

# LOGS

To be written.

# SIGNALS

To be written.

# EXIT STATUS

To be written.

# ENVIRONMENT

To be written.

# FILES

To be written.

# SEE ALSO

To be written.
