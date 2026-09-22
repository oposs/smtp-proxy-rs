//! Relaying to the upstream: the full session, DSN forwarding and the
//! address guard. Ported from the relay half of the Perl `dsn.t`.
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::raw_client::NoVerify;
use common::upstream::RecordingUpstream;
use smtp_proxy::api::Recipient;
use smtp_proxy::relay::{
    Envelope, Io, MAX_REPLY_TOTAL, MAX_UPSTREAM_REPLY_LINE, RelayConfig, RelayError, UpstreamCaps,
    UpstreamSession, UpstreamTls, UpstreamTlsMode, assert_relayable, probe, probe_over,
};
// The convenience constructor these tests drive `UpstreamSession` through.
//
// It lives here rather than in the library because nothing in `src/` calls
// it: the proxy drives an `UpstreamSession` itself so that the body streams
// (`proxy.rs`, `fn open_body`), and a caller holding a whole message in
// memory is only ever a test. Shipped in the library it was `pub` API for
// every downstream consumer, and a standing "is this dead code?" question.
// The tests below exercise `UpstreamSession`; this is scaffolding they
// happen to call.

/// Outcome of a relayed message.
#[derive(Clone, Debug)]
struct Relayed {
    /// Text of the 250 reply to the final dot (the upstream queue id). A
    /// multi-line reply arrives here with its lines joined by `\n`;
    /// `smtp::reply::sanitize` folds those away before a client sees it.
    message: String,
    caps: UpstreamCaps,
}

/// A whole session: EHLO, MAIL, RCPT.., DATA, message, QUIT.
///
/// The convenience form, for a caller that has the whole message in hand.
/// The proxy does not: it drives an [`UpstreamSession`] itself so the body
/// streams (`proxy.rs`, `fn open_body`). See [`send_whole_message`] for what
/// the message has to already be.
async fn relay(
    config: &RelayConfig,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    // Before the connection, so that an address the API substituted cannot
    // even cost a TCP handshake.
    assert_relayable(envelope.from)?;
    for r in envelope.recipients {
        assert_relayable(&r.address)?;
    }
    send_whole_message(UpstreamSession::connect(config).await?, envelope, message).await
}

/// [`relay`] over a stream the caller supplies, without TLS. See
/// [`Io`].
async fn relay_over<S: Io + 'static>(
    stream: S,
    timeout: Duration,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    assert_relayable(envelope.from)?;
    for r in envelope.recipients {
        assert_relayable(&r.address)?;
    }
    send_whole_message(
        UpstreamSession::over(stream, timeout).await?,
        envelope,
        message,
    )
    .await
}

/// Drives an opened session through a message held whole in memory: what
/// [`relay`] and [`relay_over`] both do once they have an upstream.
///
/// The message goes out **verbatim**. The proxy dot-stuffs where the content
/// is assembled -- the client's body arrives already stuffed and the header
/// block is stuffed as it is written (`proxy.rs`, `fn header_block`) -- so a
/// second pass here would stuff everything twice. The caller therefore owns
/// the encoding: a `message` holding a line that is nothing but a dot ends
/// DATA where that line sits.
async fn send_whole_message(
    mut up: UpstreamSession,
    envelope: Envelope<'_>,
    message: &[u8],
) -> Result<Relayed, RelayError> {
    let caps = up.caps();
    up.open_transaction(envelope).await?;
    up.write(message)
        .await
        .map_err(|v| v.into_relay_error("DATA"))?;
    let message = up
        .finish()
        .await
        .map_err(|v| v.into_relay_error("DATA_END"))?;
    Ok(Relayed { message, caps })
}

use smtp_proxy::smtp::params::Param;

/// How many bytes may sit in flight on the in-memory connections the timing
/// tests use. Small and fixed, so "the write blocks" is a property of the
/// test rather than of the host's socket buffers.
const DUPLEX_CAPACITY: usize = 8 * 1024;

fn config_with_timeout(up: &RecordingUpstream, timeout: Duration) -> RelayConfig {
    RelayConfig {
        host: "127.0.0.1".into(),
        port: up.addr.port(),
        timeout,
        tls: UpstreamTls::off(),
        tls_server_name: None,
    }
}

fn config(up: &RecordingUpstream) -> RelayConfig {
    config_with_timeout(up, Duration::from_secs(5))
}

/// The TLS counterpart of [`config`]. The connection goes to 127.0.0.1 like
/// every other test's, while the certificate is checked against `localhost`,
/// the only name the generated test certificate carries. Keeping the two
/// apart is what makes this test independent of how the host resolves
/// `localhost` -- which of `127.0.0.1` and `::1` comes first differs per
/// host, and the recording upstream listens on the IPv4 address only.
fn tls_config(up: &RecordingUpstream, mode: UpstreamTlsMode, insecure: bool) -> RelayConfig {
    let ca = common::certs::dir().join("server.crt");
    RelayConfig {
        host: "127.0.0.1".into(),
        port: up.addr.port(),
        timeout: Duration::from_secs(5),
        tls: UpstreamTls::build(mode, if insecure { None } else { Some(&ca) }, insecure).unwrap(),
        tls_server_name: Some("localhost".into()),
    }
}

/// A body of exactly `len` bytes in 1 KiB CRLF-terminated lines. `len` must
/// be a multiple of 1024.
fn body(len: usize) -> Vec<u8> {
    let line = format!("{}\r\n", "x".repeat(1022));
    line.repeat(len / line.len()).into_bytes()
}

/// Only the recipient differs between the timing tests and the rest.
fn one_recipient() -> Vec<Recipient> {
    vec![Recipient {
        address: "x@baz.com".into(),
        parameters: vec![],
    }]
}

fn p(k: &str, v: Option<&str>) -> Param {
    Param {
        keyword: k.into(),
        value: v.map(String::from),
    }
}

#[tokio::test]
async fn probe_reports_dsn() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    assert!(probe(&config(&up)).await.unwrap().dsn);
    // One probe so far, so the all-connections view holds a single QUIT.
    assert_eq!(up.commands_matching("QUIT").len(), 1);
    up.set_extensions(&["SIZE 1000"]);
    let caps = probe(&config(&up)).await.unwrap();
    assert!(!caps.dsn);
    assert_eq!(caps.size, Some(1000));
    assert!(
        probe(&RelayConfig {
            host: "127.0.0.1".into(),
            port: 1,
            timeout: Duration::from_secs(1),
            tls: UpstreamTls::off(),
            tls_server_name: None,
        })
        .await
        .is_err()
    );
}

#[tokio::test]
async fn probe_reports_the_upstream_size_limit() {
    let up = RecordingUpstream::start(&["DSN", "SIZE 10240000"]).await;
    let caps = probe(&config(&up)).await.unwrap();
    assert!(caps.dsn);
    assert_eq!(caps.size, Some(10_240_000));
}

#[tokio::test]
async fn probe_reports_no_limit_when_size_is_absent() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let caps = probe(&config(&up)).await.unwrap();
    assert!(caps.dsn);
    assert_eq!(caps.size, None);
}

#[tokio::test]
async fn full_session_and_dsn_forwarding() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let recipients = vec![
        Recipient {
            address: "x@baz.com".into(),
            parameters: vec![
                p("NOTIFY", Some("SUCCESS,FAILURE")),
                p("ORCPT", Some("rfc822;x@baz.com")),
            ],
        },
        Recipient {
            address: "x@baz.com".into(),
            parameters: vec![p("NOTIFY", Some("NEVER")), p("SMTPUTF8", None)],
        },
    ];
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[
            p("RET", Some("HDRS")),
            p("ENVID", Some("QQ")),
            p("SIZE", Some("5")),
        ],
        recipients: &recipients,
    };
    let out = relay(&config(&up), env, b"Subject: x\r\n\r\nbody\r\n")
        .await
        .unwrap();
    assert_eq!(out.message, "OK message accepted");
    assert!(out.caps.dsn);
    let cmds = up.commands();
    // The greeting name is the Perl's fixed one, never this host's name.
    assert_eq!(cmds[0], "EHLO localhost.localdomain");
    assert_eq!(cmds[1], "MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ");
    assert_eq!(
        cmds[2],
        "RCPT TO:<x@baz.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@baz.com"
    );
    assert_eq!(cmds[3], "RCPT TO:<x@baz.com> NOTIFY=NEVER");
    assert_eq!(cmds[4], "DATA");
    assert_eq!(cmds[5], "QUIT");
    assert_eq!(up.messages()[0], "Subject: x\r\n\r\nbody\r\n");
}

/// The payload reaches the upstream **byte for byte**, and the terminator is
/// placed against what the last byte was.
///
/// Nothing rewrites the payload any more: the proxy dot-stuffs where the
/// content is assembled and the client's body is already stuffed, so a
/// second pass here would stuff everything twice (`relay.rs`, `fn
/// send_whole_message`). What survives of the old normalisation is the one
/// decision `finish` still makes -- whether the terminating dot needs a CRLF
/// in front of it. Asserted on the raw recording: a fake that rebuilt the
/// message from parsed lines could see neither half of this.
#[tokio::test]
async fn the_payload_is_relayed_verbatim_and_the_terminator_follows_its_last_byte() {
    let cases: [(&[u8], &[u8]); 4] = [
        // Bare LF throughout: passed on as it is, where the old write path
        // would have rewritten every one of them to CRLF.
        (b"Subject: x\n\nline\n", b"Subject: x\n\nline\n"),
        // Already CRLF-terminated: unchanged, and the terminator follows
        // immediately.
        (b"a\r\n", b"a\r\n"),
        // Ending in a bare LF is still ending a line, so no blank line is
        // manufactured in front of the dot.
        (b"a\r\nb\n", b"a\r\nb\n"),
        // No trailing newline at all: the terminator brings its own CRLF,
        // which the recording shows as the line ending of the last line.
        (b"a", b"a\r\n"),
    ];
    for (input, expected) in cases {
        let up = RecordingUpstream::in_memory(&["DSN"]);
        let recipients = one_recipient();
        let env = Envelope {
            from: "a@b.com",
            mail_params: &[],
            recipients: &recipients,
        };
        relay_over(
            up.connect_duplex(64 << 10),
            Duration::from_secs(5),
            env,
            input,
        )
        .await
        .unwrap();
        assert_eq!(
            up.raw_messages()[0],
            expected,
            "input {:?} relayed as {:?}",
            String::from_utf8_lossy(input),
            String::from_utf8_lossy(&up.raw_messages()[0])
        );
    }
}

/// An upstream that refuses EHLO gets a HELO, and no extensions are assumed
/// from a session that never listed any.
#[tokio::test]
async fn ehlo_refused_falls_back_to_helo() {
    let up = RecordingUpstream::in_memory(&["DSN"]);
    up.reject_ehlo(Some("I do not speak ESMTP"));
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[p("RET", Some("HDRS"))],
        recipients: &recipients,
    };
    let out = relay_over(
        up.connect_duplex(64 << 10),
        Duration::from_secs(5),
        env,
        b"Subject: x\r\n\r\nbody\r\n",
    )
    .await
    .unwrap();
    assert_eq!(out.message, "OK message accepted");
    assert!(!out.caps.dsn);
    let cmds = up.commands();
    assert_eq!(cmds[0], "EHLO localhost.localdomain");
    assert_eq!(cmds[1], "HELO localhost.localdomain");
    // No EHLO, so no DSN however the upstream is configured.
    assert_eq!(cmds[2], "MAIL FROM:<a@b.com>");
}

#[tokio::test]
async fn dsn_parameters_are_dropped_without_upstream_dsn() {
    let up = RecordingUpstream::start(&["SIZE 100000"]).await;
    let recipients = vec![Recipient {
        address: "x@baz.com".into(),
        parameters: vec![p("NOTIFY", Some("NEVER"))],
    }];
    let env = Envelope {
        from: "",
        mail_params: &[p("RET", Some("FULL"))],
        recipients: &recipients,
    };
    let out = relay(&config(&up), env, b"Subject: x\r\n\r\n")
        .await
        .unwrap();
    assert!(!out.caps.dsn);
    assert_eq!(up.commands()[1], "MAIL FROM:<>");
    assert_eq!(up.commands()[2], "RCPT TO:<x@baz.com>");
}

#[tokio::test]
async fn the_clients_size_is_forwarded_when_the_upstream_announces_size() {
    let up = RecordingUpstream::start(&["SIZE 10240000"]).await;
    let params = vec![Param {
        keyword: "SIZE".into(),
        value: Some("4096".into()),
    }];
    let recipients = vec![Recipient {
        address: "a@b.com".into(),
        parameters: vec![],
    }];
    relay(
        &config(&up),
        Envelope {
            from: "x@y.com",
            mail_params: &params,
            recipients: &recipients,
        },
        b"Subject: x\r\n\r\nbody\r\n",
    )
    .await
    .unwrap();
    assert_eq!(
        up.commands_matching("MAIL"),
        vec!["MAIL FROM:<x@y.com> SIZE=4096"]
    );
}

/// An upstream that never announced SIZE would answer 555 to the parameter.
#[tokio::test]
async fn the_clients_size_is_dropped_when_the_upstream_is_silent_about_size() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let params = vec![Param {
        keyword: "SIZE".into(),
        value: Some("4096".into()),
    }];
    let recipients = vec![Recipient {
        address: "a@b.com".into(),
        parameters: vec![],
    }];
    relay(
        &config(&up),
        Envelope {
            from: "x@y.com",
            mail_params: &params,
            recipients: &recipients,
        },
        b"Subject: x\r\n\r\nbody\r\n",
    )
    .await
    .unwrap();
    assert_eq!(up.commands_matching("MAIL"), vec!["MAIL FROM:<x@y.com>"]);
}

#[tokio::test]
async fn upstream_rejection_carries_its_text() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.reject_mail(Some("Sorry, I don't send from there"));
    let recipients = vec![Recipient {
        address: "x@baz.com".into(),
        parameters: vec![],
    }];
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    match relay(&config(&up), env, b"x\r\n").await {
        Err(RelayError::Rejected { code: 553, text }) => {
            assert_eq!(text, "Sorry, I don't send from there")
        }
        other => panic!("{other:?}"),
    }
}

/// Spec 6's 60 s is an *inactivity* timeout. A body bigger than what fits
/// in flight, handed to an upstream that drains it in steps, must go
/// through as long as every gap is shorter than the timeout — even though
/// the transfer as a whole takes longer than the timeout. With a single
/// deadline over the whole payload this fails with `RelayError::Timeout`,
/// which is exactly the bug being guarded against.
///
/// The connection is a `tokio::io::duplex` pair rather than a socket, so
/// how much data can sit unread is [`DUPLEX_CAPACITY`] and not whatever
/// `tcp_wmem` happens to be on the host.
#[tokio::test]
async fn a_slow_but_steady_upstream_is_not_timed_out() {
    let up = RecordingUpstream::in_memory(&["DSN"]);
    // Ten pauses of 60 ms while the first 640 KiB go in. The relay writes
    // in 64 KiB chunks, each under its own timer, and the upstream pauses
    // every 64 KiB it consumes, so one chunk can straddle at most two
    // pauses: 120 ms against a 500 ms timeout, a 4x margin. Their sum,
    // 600 ms, is longer than the timeout, so a whole-payload deadline
    // fails here.
    up.pace_data(64 << 10, Duration::from_millis(60), 10);
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    let timeout = Duration::from_millis(500);
    // Twelve write chunks against eight KiB of in-flight capacity: every
    // pause happens while the relay is still writing.
    let size = 768 << 10;
    let started = Instant::now();
    let out = relay_over(
        up.connect_duplex(DUPLEX_CAPACITY),
        timeout,
        env,
        &body(size),
    )
    .await
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(out.message, "OK message accepted");
    assert_eq!(up.messages()[0].len(), size);
    assert!(
        elapsed > timeout,
        "the upstream drained too fast for this to prove anything: {elapsed:?}"
    );
}

/// The other half of the same coin: an upstream that stops reading
/// altogether for longer than the timeout must still be given up on, so the
/// chunking has not simply removed the protection.
///
/// Spec 6.2: a hung upstream -- not dropped, not replying -- cannot be
/// mirrored, because mirroring "hangs forever" would leak a connection per
/// hung upstream. So the inactivity timer turns it into
/// `UpstreamVerdict::Dropped`, which reaches the caller as `Io` rather than
/// as `Timeout`. Both answer the client `451`, and the assertion below is no
/// weaker for it: paired with `elapsed < stall` it still pins the failure to
/// the write timer, because nothing but the write can fail while the
/// upstream is asleep.
#[tokio::test]
async fn an_upstream_that_stops_reading_is_given_up_on() {
    let up = RecordingUpstream::in_memory(&["DSN"]);
    // Far longer than the timeout, and — the point of the duplex — longer
    // than this test may take if the timer that fires is the right one.
    let stall = Duration::from_secs(5);
    up.stall_data(stall);
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    let timeout = Duration::from_millis(200);
    let started = Instant::now();
    // Eight times what fits in flight, so the write cannot complete before
    // the upstream reads, and the upstream reads nothing for `stall`.
    let err = relay_over(
        up.connect_duplex(DUPLEX_CAPACITY),
        timeout,
        env,
        &body(64 << 10),
    )
    .await
    .unwrap_err();
    let elapsed = started.elapsed();
    assert!(matches!(err, RelayError::Io(_)), "{err:?}");
    assert!(up.messages().is_empty());
    // Returning before the stall is over is what pins the timeout to the
    // write: nothing else can make progress until the upstream reads again.
    // Without a per-chunk write timer this waits out the whole stall and
    // then times out in `read_reply` instead, with both other assertions
    // still holding.
    assert!(
        elapsed < stall,
        "the timeout did not come from the write: {elapsed:?}"
    );
}

/// An upstream that refuses mid-body and stops reading. The relay has to
/// surface the upstream's own code rather than its own impatience: the
/// unread body fills the transport, so a relay that only writes blocks here
/// until its inactivity timer fires and reports a `Timeout` for a message
/// the upstream has already answered.
///
/// A `tokio::io::duplex` pair rather than a socket, for the same reason the
/// pacing tests use one: what blocks a write is then [`DUPLEX_CAPACITY`] and
/// not whatever `tcp_wmem` the host chose. The elapsed-time assertion is
/// what makes this test non-vacuous — it fails if the reply was noticed only
/// after the write timer gave up.
#[tokio::test]
async fn a_rejection_during_the_body_is_reported_as_the_upstreams_reply() {
    let up = RecordingUpstream::in_memory(&["DSN"]);
    // Four 1 KiB lines in, which is less than one write chunk and less than
    // half the body, so the refusal lands while the relay is still writing.
    up.reject_during_data(4096, (552, "5.3.4 too big"));
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    let timeout = Duration::from_secs(1);
    let started = Instant::now();
    let err = relay_over(
        up.connect_duplex(DUPLEX_CAPACITY),
        timeout,
        env,
        &body(512 << 10),
    )
    .await
    .unwrap_err();
    let elapsed = started.elapsed();
    match err {
        RelayError::Rejected { code, ref text, .. } => {
            assert_eq!(code, 552);
            assert_eq!(text, "5.3.4 too big");
        }
        other => panic!("expected the upstream's 552, got {other:?}"),
    }
    assert!(
        elapsed < timeout,
        "the reply was noticed only after the write timer: {elapsed:?}"
    );
}

/// The same refusal, over TLS -- and a plaintext fixture cannot stand in for
/// this one.
///
/// `tokio_rustls`' `poll_write` takes the plaintext into rustls' send buffer
/// and reports it written even when the socket took no ciphertext at all (see
/// `relay.rs`, `fn flush`). So against a TLS upstream `write_all` returns
/// straight away and the transfer does not actually block there: it blocks in
/// the *flush*. A relay that races only the write against the reader is
/// therefore still blind here -- it sits in an unwatched flush until its
/// inactivity timer fires and reports a dead connection, while the upstream's
/// `552` waits unread. Both halves of pushing a chunk out have to be inside
/// the race.
#[tokio::test]
async fn a_tls_rejection_during_the_body_is_reported_as_the_upstreams_reply() {
    let up = RecordingUpstream::in_memory_implicit_tls(&["DSN"]);
    up.reject_during_data(4096, (552, "5.3.4 too big"));
    let stream = tls_over_duplex(&up).await;
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    let timeout = Duration::from_secs(1);
    let started = Instant::now();
    let err = relay_over(stream, timeout, env, &body(512 << 10))
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    match err {
        RelayError::Rejected { code, ref text, .. } => {
            assert_eq!(code, 552);
            assert_eq!(text, "5.3.4 too big");
        }
        other => panic!("expected the upstream's 552, got {other:?}"),
    }
    assert!(
        elapsed < timeout,
        "the reply was noticed only after the write timer: {elapsed:?}"
    );
    // The session really was a TLS one; a plaintext duplex would not have
    // exercised any of this.
    assert!(up.tls_commands().iter().any(|c| c.starts_with("MAIL")));
}

/// The same shape, but the upstream simply goes away. That has no reply to
/// report, so it must not become a fabricated one.
#[tokio::test]
async fn a_drop_during_the_body_is_not_reported_as_a_rejection() {
    let up = RecordingUpstream::in_memory(&["DSN"]);
    up.drop_during_data(4096);
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    let timeout = Duration::from_secs(1);
    let started = Instant::now();
    let err = relay_over(
        up.connect_duplex(DUPLEX_CAPACITY),
        timeout,
        env,
        &body(512 << 10),
    )
    .await
    .unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        matches!(err, RelayError::Io(_)),
        "a dead connection has no verdict to report, got {err:?}"
    );
    assert!(
        elapsed < timeout,
        "the close was noticed only after the write timer: {elapsed:?}"
    );
}

/// Two properties nothing else in the suite reaches, in one session.
///
/// The upstream answers EHLO and the MAIL that follows it in a *single*
/// write, so the MAIL reply is already sitting in the handshake's `BufReader`
/// when `UpstreamSession::from_handshake` takes the stream apart. Those bytes
/// are carried across the split in front of the read half; without that carry
/// `into_inner` drops them and the session waits out its timeout for a reply
/// it has already been sent.
///
/// And the body is handed over in two `write` calls rather than one, which is
/// all any other test does — so the chunk loop and the record of the last
/// byte written are otherwise unproven across calls.
#[tokio::test]
async fn pipelined_bytes_survive_the_split_and_a_body_may_arrive_in_pieces() {
    let up = RecordingUpstream::in_memory(&["DSN"]);
    up.coalesce_mail_reply();
    let recipients = one_recipient();
    let mut session =
        UpstreamSession::over(up.connect_duplex(DUPLEX_CAPACITY), Duration::from_secs(5))
            .await
            .unwrap();
    session
        .open_transaction(Envelope {
            from: "a@b.com",
            mail_params: &[],
            recipients: &recipients,
        })
        .await
        .unwrap();
    session.write(b"Subject: x\r\n\r\nfirst\r\n").await.unwrap();
    session.write(b"second\r\n").await.unwrap();
    let accepted = session.finish().await.unwrap();
    assert_eq!(accepted, "OK message accepted");
    assert_eq!(
        up.messages(),
        vec!["Subject: x\r\n\r\nfirst\r\nsecond\r\n".to_string()]
    );
}

#[tokio::test]
async fn addresses_with_line_breaks_are_refused_before_any_write() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let recipients = vec![Recipient {
        address: "x@baz.com".into(),
        parameters: vec![],
    }];
    let env = Envelope {
        from: "a@b.com>\r\nRCPT TO:<evil@x.com",
        mail_params: &[],
        recipients: &recipients,
    };
    assert!(matches!(
        relay(&config(&up), env, b"x\r\n").await,
        Err(RelayError::Address(_))
    ));
    assert!(up.commands().is_empty());
}

#[tokio::test]
async fn opportunistic_uses_starttls_when_offered() {
    let up = RecordingUpstream::start_tls(&["DSN"], false).await;
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    relay(
        &tls_config(&up, UpstreamTlsMode::Opportunistic, false),
        env,
        b"x\r\n",
    )
    .await
    .unwrap();
    let cmds = up.commands();
    assert!(cmds[0].starts_with("EHLO"));
    assert_eq!(cmds[1], "STARTTLS");
    assert!(cmds[2].starts_with("EHLO"));
    // The envelope went out inside the TLS session, not before it.
    assert!(up.tls_commands().iter().any(|c| c.starts_with("MAIL")));
}

#[tokio::test]
async fn opportunistic_stays_plain_without_starttls_but_required_fails() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    relay(
        &tls_config(&up, UpstreamTlsMode::Opportunistic, false),
        env,
        b"x\r\n",
    )
    .await
    .unwrap();
    assert!(!up.commands().contains(&"STARTTLS".to_string()));
    assert!(up.tls_commands().is_empty());
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    assert!(matches!(
        relay(
            &tls_config(&up, UpstreamTlsMode::Required, false),
            env,
            b"x\r\n"
        )
        .await,
        Err(RelayError::NoStartTls)
    ));
    // Required gives up before the envelope: nothing went out in the clear.
    assert!(!up.commands().iter().any(|c| c.starts_with("MAIL")));
}

#[tokio::test]
async fn certificate_failure_does_not_fall_back_to_plain() {
    let up = RecordingUpstream::start_tls(&["DSN"], false).await;
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    // No extra CA: the self-signed test certificate is not trusted.
    let mut cfg = tls_config(&up, UpstreamTlsMode::Opportunistic, false);
    cfg.tls = UpstreamTls::build(UpstreamTlsMode::Opportunistic, None, false).unwrap();
    assert!(matches!(
        relay(&cfg, env, b"x\r\n").await,
        Err(RelayError::Tls(_))
    ));
    assert!(!up.commands().iter().any(|c| c.starts_with("MAIL")));
    assert!(up.tls_commands().is_empty());
    // Insecure mode accepts it.
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    relay(
        &tls_config(&up, UpstreamTlsMode::Opportunistic, true),
        env,
        b"x\r\n",
    )
    .await
    .unwrap();
    assert!(up.tls_commands().iter().any(|c| c.starts_with("MAIL")));
}

#[tokio::test]
async fn implicit_tls_and_dsn_from_the_tls_ehlo() {
    let up = RecordingUpstream::start_tls(&["DSN"], true).await;
    assert!(
        probe(&tls_config(&up, UpstreamTlsMode::Implicit, false))
            .await
            .unwrap()
            .dsn
    );
    // An upstream that announces DSN only inside TLS: reading the extension
    // list from the first EHLO would miss it.
    let up = RecordingUpstream::start_tls(&[], false).await;
    up.set_tls_extensions(&["DSN"]);
    assert!(
        probe(&tls_config(&up, UpstreamTlsMode::Opportunistic, false))
            .await
            .unwrap()
            .dsn
    );
}

/// A message big enough that the last [`smtp_proxy`] write chunk cannot fit
/// into the duplex in one go: 255 KiB of body plus the terminating dot line
/// is 261123 bytes, so the final chunk is 64515 bytes against a transport
/// that takes 8 KiB. Whatever a `write_all` fails to push out is left in
/// rustls' send buffer, which is exactly the condition under test.
const BLOCKING_BODY: usize = 255 * 1024;

/// The client half of an implicit-TLS connection to `up`, carried by a
/// duplex pair of `DUPLEX_CAPACITY` bytes.
async fn tls_over_duplex(up: &RecordingUpstream) -> impl smtp_proxy::relay::Io + 'static {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, up.connect_duplex(DUPLEX_CAPACITY))
        .await
        .unwrap()
}

/// A body whose tail is still inside rustls when the last `write_all`
/// returns has to be pushed out before the relay waits for the `250`.
///
/// `tokio_rustls` reports plaintext as written as soon as it is in rustls'
/// send buffer, even when the socket took none of the ciphertext, and
/// nothing on the read path pushes that buffer out. Without the flush in
/// `write_body` the upstream never sees the terminating dot, the relay waits
/// for a reply to a message it has not finished sending, and the inactivity
/// timeout turns a deliverable message into a `550`.
///
/// The transport is a duplex pair and not TCP on purpose: "the socket
/// blocks" has to be a property of the test rather than of the host's socket
/// buffers, which auto-tune into the megabytes and could swallow the whole
/// body.
#[tokio::test]
async fn a_tls_body_is_pushed_out_before_the_relay_waits_for_the_reply() {
    let up = RecordingUpstream::in_memory_implicit_tls(&["DSN"]);
    let stream = tls_over_duplex(&up).await;
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    let payload = body(BLOCKING_BODY);
    relay_over(stream, Duration::from_secs(5), env, &payload)
        .await
        .unwrap();
    // Byte for byte, so a flush that dropped or reordered the tail is not
    // mistaken for a delivery.
    assert_eq!(up.raw_messages(), vec![payload]);
    // The session really was a TLS one; a plaintext duplex would not have
    // exercised any of this.
    assert!(up.tls_commands().iter().any(|c| c.starts_with("MAIL")));
}

/// Mode Off is what part 1 did, and it has to stay that even in front of an
/// upstream that would happily upgrade: `--upstream_tls off` is the escape
/// hatch for a deployment whose upstream announces STARTTLS but cannot
/// actually complete it.
#[tokio::test]
async fn off_ignores_an_offered_starttls() {
    let up = RecordingUpstream::start_tls(&["DSN"], false).await;
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    relay(&config(&up), env, b"x\r\n").await.unwrap();
    assert!(!up.commands().contains(&"STARTTLS".to_string()));
    assert!(up.tls_commands().is_empty());
}

/// How much a hostile upstream is given the chance to send in the two tests
/// below. An unbounded reader swallows all of it; a bounded one gives up
/// three orders of magnitude earlier.
const HOSTILE_REPLY: usize = 1 << 20;

/// Feeds `chunk` into a duplex pair until [`HOSTILE_REPLY`] bytes have gone
/// in or the relay drops its end, and reports how many bytes it managed to
/// write. That count is the assertion: it says how much of the endless reply
/// the relay actually consumed.
///
/// A duplex pair and not a socket, for the same reason the timing tests use
/// one -- how much may sit in flight has to be a property of the test rather
/// than of the host's socket buffers, or "the relay stopped early" cannot be
/// told from "the kernel buffered the rest".
fn hostile_upstream(
    prefix: &'static [u8],
    chunk: Vec<u8>,
) -> (
    tokio::io::DuplexStream,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let (client, mut server) = tokio::io::duplex(HOSTILE_DUPLEX);
    let written = Arc::new(AtomicUsize::new(0));
    let count = written.clone();
    let fed = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        if server.write_all(prefix).await.is_err() {
            return;
        }
        count.fetch_add(prefix.len(), Ordering::Relaxed);
        while count.load(Ordering::Relaxed) < HOSTILE_REPLY {
            if server.write_all(&chunk).await.is_err() {
                return;
            }
            count.fetch_add(chunk.len(), Ordering::Relaxed);
        }
    });
    (client, written, fed)
}

/// Small and fixed, so the slack in the assertions below is arithmetic: at
/// most this much sits unread in the pair, and at most this much again sits
/// in the relay's own `BufReader`.
const HOSTILE_DUPLEX: usize = 1024;

/// An upstream that starts a reply line and never ends it must not be able
/// to grow the relay's memory by the length of what it sends.
#[tokio::test]
async fn endless_reply_line_is_refused_not_buffered() {
    let (client, written, fed) = hostile_upstream(b"220 ", vec![b'x'; HOSTILE_DUPLEX]);
    let err = probe_over(client, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("line exceeds 4096 bytes"),
        "{err:?}"
    );
    fed.await.unwrap();
    // The budget itself, plus what the relay's BufReader may have pulled in
    // on its last fill, plus what is still sitting unread in the pair, plus
    // the write the feeder was blocked in. Generous, and still two orders of
    // magnitude below the mebibyte an unbounded read_line would have taken.
    let written = written.load(Ordering::Relaxed);
    assert!(
        written <= MAX_UPSTREAM_REPLY_LINE + 8 * HOSTILE_DUPLEX,
        "the relay consumed {written} bytes of an endless line"
    );
}

/// The other dimension: every line is short and well-formed, but the reply
/// never reaches its final line. Only the running total can stop it.
#[tokio::test]
async fn endless_multiline_reply_is_refused() {
    let line = "220-a\r\n";
    let (client, written, fed) = hostile_upstream(b"", line.repeat(146).into_bytes());
    let err = probe_over(client, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceeds 65536 bytes"), "{err:?}");
    fed.await.unwrap();
    let written = written.load(Ordering::Relaxed);
    assert!(
        written <= MAX_REPLY_TOTAL + 8 * HOSTILE_DUPLEX,
        "the relay consumed {written} bytes of an endless multi-line reply"
    );
}
