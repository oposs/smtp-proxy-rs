# The smtp-proxy manual — one source, three readers

Date: 2026-09-23
Status: design, awaiting review
Depends on: repo-infra D23 (`repo-infra/docs/superpowers/specs/2026-09-23-man-pages-design.md`)
— the `ci-man` block, `build/man.mk`, `build/man-deflist.lua`, and the
`writing-style` / `man-pages` skills
Blocks: the first release, 0.1.0

## 1. The problem

`README.md` is 375 lines and is the only reference. It carries the API request and
response, installation, the full `--help` output, and a long "Differences from the
Perl version" section in which most entries argue for the difference as well as
stating it. The `.deb` installs it as `/usr/share/doc/smtp-proxy/README.md`, and
there is no man page. `smtp-proxy --man` prints clap's long help, which is the
`--help` text with the Perl POD's DESCRIPTION paragraph in front.

## 2. The shape

| Artifact | Reader | Source? |
|---|---|---|
| `README.md` | someone deciding whether to use it, or installing it | authored |
| `docs/manual.md` | someone running it | **authored, the single source** |
| `man/smtp-proxy.1` | someone running it, in a terminal | built by `make man`, not in git |
| `docs/maintainer-notes.md` | someone changing it | authored |

Voice follows repo-infra's `writing-style` skill; the manual's structure follows its
`man-pages` skill. In short: the manual is present tense, third person, facts only,
no rationale; the README keeps its own voice without self-praise; rationale lives in
the maintainer notes.

## 3. What the manual contains

`docs/manual.md`, front matter `title: SMTP-PROXY`, `section: 1`,
`header: smtp-proxy manual`, `footer: smtp-proxy`, `date: <day of writing>`.

1. **NAME** — `smtp-proxy - SMTP submission proxy that lets a REST API control which sender addresses a user may use`
2. **SYNOPSIS** — `smtp-proxy [OPTIONS]`
3. **DESCRIPTION** — opens with the purpose: the proxy controls which sender
   addresses an authenticated user may use (owner, 2026-09-23); the API decides,
   and may also replace the envelope sender. Then the session from the client's side: STARTTLS required, AUTH
   PLAIN, the envelope and the header block go to the API, the API allows or refuses
   and may add headers, the body streams to the upstream, the upstream's answer
   reaches the client. From the POD's DESCRIPTION and README "Usage".
4. **OPTIONS** — every flag, as a bold-term list, with its default. Groups: listening
   and TLS; upstream; API; logging; limits; shutdown and timeouts.
5. **API** — the request JSON and the response JSON, field by field. From README
   "Request" and "Response". The example JSON blocks stay.
6. **SMTP REPLIES** — the replies the proxy itself sends (limits, rate, header size,
   API refusal, drain), with their text. Upstream replies are relayed and are not
   listed.
7. **LOGS** — the main log line format and the smtplog format, and what
   `--credentials` adds.
8. **SIGNALS** — SIGTERM and SIGINT start the drain; a second signal exits at once.
9. **EXIT STATUS**
10. **ENVIRONMENT** — `SSL_CERT_FILE` and `SSL_CERT_DIR`, which `rustls-native-certs`
    honours when it loads the system trust store for the upstream connection. The
    binary reads no other variable; the systemd unit's `EnvironmentFile` is covered
    under FILES.
11. **FILES** — `/etc/default/smtp-proxy`, `smtp-proxy.service`, and what each holds.
12. **SEE ALSO** — the project URL; the Perl original for migrators.

Sections 5 to 8 sit between OPTIONS and EXIT STATUS, as the `man-pages` skill allows
for sections `man-pages(7)` does not list.

## 4. What the README becomes

Target: about 100 lines.

1. Title, and three sentences of what it is, leading with sender-address control
   per user (not recipient policy).
2. **Install** — the `.deb`, the container image on ghcr.io, the static binary. Commands
   only.
3. **Quick start** — a minimal `/etc/default/smtp-proxy` and `systemctl enable --now`.
4. **Differences from the Perl version** — kept, because a migrator reads it before
   anything else, but as a list of facts: what changed and which flag controls it. The
   reasons move to the maintainer notes.
5. **Documentation** — `man smtp-proxy`, `smtp-proxy --man`, and the manual's URL.
6. **Development** — `make test`, `make conformance`, `make man`; license.

Links into `docs/` are absolute GitHub URLs, so they resolve from the copy the `.deb`
installs under `/usr/share/doc/smtp-proxy/` as well.

## 5. What the maintainer notes contain

`docs/maintainer-notes.md`, new: the rationale that leaves the README, one short
section per decision. The ones already known: DATA is a mirror of the upstream; the
per-IP limit counts IPv6 by /64 and unwraps IPv4-mapped addresses first; the 30 s
greeting timeout narrows RFC 5321 4.5.3.2 on purpose; `--max_header_size 0` is refused;
opportunistic upstream TLS as the default; the capability bounding set in the systemd
unit, including why it must not be narrowed to `CAP_NET_BIND_SERVICE` alone.

## 6. `--man` prints the manual

`--man` exists because the Perl had it. Today it prints clap's long help, so it is a
second, shorter manual that can disagree with the first.

With this change `--man` prints `docs/manual.md`, embedded with `include_str!`, as
plain text. The static binary and the container image, which have no man page
installed, then carry the whole manual, and there is one text. `--help` is unchanged.

The Markdown is printed as it is, front matter stripped. Rendering it for a terminal
is not attempted: the source is written to be readable raw, and a renderer would be a
dependency for one flag.

## 7. Build and packaging

- `Makefile`: `MAN_NAME = smtp-proxy`, `include build/man.mk`; `deb` depends on `man`.
- `.gitignore`: `/man/`.
- `Cargo.toml` `[package.metadata.deb]`: the asset
  `["man/smtp-proxy.1", "usr/share/man/man1/", "644"]`; `extended-description` ends
  with `See smtp-proxy(1).` in place of the README path.
- `.github/repo-infra.json`: `"ci": ["ci-rust-musl", "ci-man"]`, and the
  `publish_local` entry handoff §7 item 2 already requires. Then `apply` regenerates
  the workflows (`release-publish` v2 to v3, `workflow-lib` v2 to v3, `ci.yml` with the
  `man` job). The `publish-deb-container` block is kept through the merge.
- `publish-deb-container`: installs pandoc before `make lint test deb`. This is the
  one edit to a hand-owned block.

## 8. Keeping the manual true

- **Options drift test**, `tests/manual.rs`. It takes the flag set from clap
  (`Config::command()`), not from the rendered `--help` text, and the OPTIONS section
  from `include_str!("../docs/manual.md")`. It asserts, and names the offender on
  failure:
  - every flag clap knows has an entry in OPTIONS;
  - OPTIONS has no entry clap does not know;
  - where clap has a default, the manual's entry states the same value.
- **`ci-man`** proves on every pull request that the manual converts and that roff
  lays it out without warnings.
- **`--man` test**: the output equals the manual source minus front matter.

The API, SMTP REPLIES and LOGS sections are not tested for drift. Reply texts are
pinned by the existing tests and the conformance suite; the manual quotes them.

## 9. Acceptance

- `make man` builds `man/smtp-proxy.1` from a clean checkout with pandoc installed;
  `man/` is absent from git.
- `man --warnings -l man/smtp-proxy.1` shows no warning other than the two pandoc font
  warnings.
- The `.deb` from `make deb` contains `/usr/share/man/man1/smtp-proxy.1`, and the
  `publish-deb-container` content check asserts it.
- `smtp-proxy --man` prints the manual.
- `tests/manual.rs` passes, and fails when a flag is added to `Config` without an
  entry in the manual.
- README is about 100 lines; every fact removed from it is in the manual or the
  maintainer notes.
- CI on the pull request is green, including the new `man` job.

## 10. Out of scope

- The wording of the `--help` texts. They are the Perl's ("on which IP should we
  listen") and are CLI ergonomics, which the Perl does not bind; changing them is a
  separate change.
- A website. repo-infra's later `docs-site` skill would build one from the same
  manual.
- Converting the historical `CHANGES.md` headings (R33 still applies until 0.1.0 ships).

## 11. Changelog

One entry: "The Debian package installs a manual page, `man smtp-proxy`, and
`smtp-proxy --man` prints the same manual."
