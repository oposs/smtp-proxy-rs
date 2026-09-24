# smtp-proxy

smtp-proxy is an SMTP submission proxy that lets a REST API decide which sender addresses an authenticated user may use.
After AUTH (PLAIN or LOGIN, inside STARTTLS) and once the header block of a message has arrived, it posts the credentials, the envelope and the headers, `From:` included, to your API, which allows or refuses the message and may add or remove headers and replace the envelope sender; it can refuse on the recipients as well.
An allowed message is streamed to your SMTP server, and that server's answer goes back to the client; it is a Rust drop-in for the Perl [smtp-proxy](https://github.com/oposs/smtp-proxy).

## Install

The `.deb` from the [GitHub release](https://github.com/oposs/smtp-proxy-rs/releases), with a systemd unit installed but not enabled:

```sh
curl -LO https://github.com/oposs/smtp-proxy-rs/releases/download/v<version>/smtp-proxy_<version>-1_amd64.deb
sudo apt install ./smtp-proxy_<version>-1_amd64.deb
```

The container image:

```sh
podman run --rm ghcr.io/oposs/smtp-proxy:<version> --help
```

The static binary, for any x86_64 Linux:

```sh
curl -Lo smtp-proxy https://github.com/oposs/smtp-proxy-rs/releases/download/v<version>/smtp-proxy-<version>-x86_64-unknown-linux-musl
chmod +x smtp-proxy
```

## Quick start

Set the command line in `/etc/default/smtp-proxy`, then start the service:

```sh
SMTP_PROXY_OPTS="--listen=0.0.0.0:587 --tohost=mail.example.com --toport=25 --tls_cert=/etc/smtp-proxy/server.crt --tls_key=/etc/smtp-proxy/server.key --api=https://auth.example.com/check --user=smtp-proxy --loglevel=info"
```

```sh
sudo systemctl enable --now smtp-proxy
```

## Differences from the Perl version

Every flag the Perl had is still spelled the same way. New flags: `--version`, `--max_header_size`, `--upstream_tls`, `--upstream_tls_ca`, `--upstream_tls_insecure`, `--max_connections`, `--max_connections_per_ip`, `--max_messages_per_minute`, `--max_recipients`, `--drain_timeout` and `--greeting_timeout`.

- TLS 1.0 and 1.1 are no longer offered; rustls implements TLS 1.2 and 1.3 only.
- The upstream connection uses STARTTLS when the upstream offers it and verifies the certificate; the Perl relayed in plain text. For a self-signed or private-CA upstream set `--upstream_tls_ca` or `--upstream_tls=off`; `required` and `implicit` are stricter. There is no fallback to plain text once STARTTLS was announced.
- A header block over 1 MiB is refused with `552` (`--max_header_size`; `0` is refused at startup). The message as a whole has no proxy limit; the upstream's `SIZE` is the limit.
- `SIZE` is advertised with the upstream's limit, and a client's `SIZE=` on `MAIL FROM` is forwarded when the upstream announced `SIZE`. The Perl did neither.
- A refusal from the upstream keeps the upstream's reply code; the Perl turned every one into `550`. An upstream that never answered gives `451`; a malformed address the proxy refuses itself stays `550`.
- An API call that fails or gives no verdict is answered `451 authentication service failed`, not `550`.
- During DATA an upstream reply reaches the client verbatim, and an upstream that drops closes the client connection. A failure before the body is still answered with a reply code.
- A message the API refuses leaves the upstream one connection that was greeted and dropped, with no envelope and no message: the connect runs alongside the API call.
- Header names from the API are matched without regard to case.
- A header block written with bare LF is split into individual headers; the Perl passed it to the API as one header.
- A header with a line break that is not a fold is not relayed; the message is refused with `550 authentication service failed`.
- The upstream's reply is bounded at 4096 bytes per line and 65536 bytes in total; the Perl bounded neither.
- A command line that reaches 64 KiB without ending is answered `500 Line too long` and the connection is closed; the Perl's buffer grew without limit.
- An idle connection is closed after ten minutes in every phase; the Perl timed nothing before STARTTLS.
- A connection that has sent no complete command is closed after 30 seconds (`--greeting_timeout`; `0` gives that wait the ten minutes as well). The Perl timed neither wait, so a silent connection lived for ever.
- Concurrent connections are capped at 1000 (`--max_connections`) and 50 per client (`--max_connections_per_ip`, IPv6 counted by /64). The excess is answered `421 <service> Too many connections, try again later` before the greeting, where Mojo left it in the backlog unanswered.
- One username may start 60 messages per minute (`--max_messages_per_minute`); over that, `MAIL FROM` is answered `450 4.7.1 Rate limit exceeded, try again later`. The Perl had no rate limit.
- A message may name 1000 recipients (`--max_recipients`); the next `RCPT TO` is answered `452 4.5.3 Too many recipients`. The Perl counted none.
- An AUTH username over 256 bytes is refused with `535 Authentication credentials invalid`; the Perl had no bound.
- `initgroups` runs before `setgid` and `setuid` (`--user`); the Perl kept root's supplementary groups.
- SIGTERM drains: idle sessions get `421`, sessions inside DATA or waiting on the API or the upstream finish, and after `--drain_timeout` seconds the rest are closed. A second signal exits at once. The Perl exited and dropped every session.
- An EHLO reply line with extra whitespace before the keyword, such as `250- SIZE 10240000`, is read; the Perl ignored it, so this proxy may advertise an extension the Perl did not.
- Debug-level dumps are JSON rather than `Data::Dumper` output.
- `--man` prints the manual as Markdown.
- A missing mandatory option exits 1 here and 2 in the Perl; `--help`, `--man` and `--version` exit 0 on standard output, where the Perl's `--help` exited 1.

The reasons are in the [maintainer notes](https://github.com/oposs/smtp-proxy-rs/blob/main/docs/maintainer-notes.md).

## Documentation

```sh
man smtp-proxy
smtp-proxy --man
```

The same manual, with the API request and response, every option, reply and log line, is at <https://github.com/oposs/smtp-proxy-rs/blob/main/docs/manual.md>.
Why things are the way they are: <https://github.com/oposs/smtp-proxy-rs/blob/main/docs/maintainer-notes.md>.

## Development

```sh
cargo build --release   # target/release/smtp-proxy
make test               # also: make build, make lint
make conformance        # the Perl proxy's tests against this binary; needs ../smtp-proxy
make man                # man/smtp-proxy.1, needs pandoc
make deb                # static musl binary and .deb under target/x86_64-unknown-linux-musl/
make docker             # cargo test, then podman build of smtp-proxy:<version>
```

`make deb` needs `cross` (`cargo install cross --version 0.2.5 --locked`), `cargo-deb`, pandoc and a container engine; with podman, set `CROSS_CONTAINER_ENGINE=podman`.
It checks that the binary is static and packages that same file with the systemd unit and `/etc/default/smtp-proxy`.
`make lint test deb` is what the release workflow runs.
The container image is `FROM scratch` with the static binary and the CA bundle.

License: GPL-3.0-or-later, see [LICENSE](https://github.com/oposs/smtp-proxy-rs/blob/main/LICENSE).
