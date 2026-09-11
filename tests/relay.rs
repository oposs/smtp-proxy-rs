//! Relaying to the upstream: the full session, DSN forwarding and the
//! address guard. Ported from the relay half of the Perl `dsn.t`.
mod common;

use std::time::{Duration, Instant};

use common::upstream::RecordingUpstream;
use smtp_proxy::api::Recipient;
use smtp_proxy::relay::{Envelope, RelayConfig, RelayError, probe, relay, relay_over};
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
    }
}

fn config(up: &RecordingUpstream) -> RelayConfig {
    config_with_timeout(up, Duration::from_secs(5))
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
    assert!(probe(&config(&up)).await.unwrap());
    // One probe so far, so the all-connections view holds a single QUIT.
    assert_eq!(up.commands_matching("QUIT").len(), 1);
    up.set_extensions(&["SIZE 1000"]);
    assert!(!probe(&config(&up)).await.unwrap());
    assert!(
        probe(&RelayConfig {
            host: "127.0.0.1".into(),
            port: 1,
            timeout: Duration::from_secs(1)
        })
        .await
        .is_err()
    );
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
    let out = relay(
        &config(&up),
        env,
        b"Subject: x\r\n\r\nbody\r\n.\r\nnot the end\r\n",
    )
    .await
    .unwrap();
    assert_eq!(out.message, "OK message accepted");
    assert!(out.upstream_dsn);
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
    // A line that is just a dot is stuffed on the way out, so the upstream
    // reads the message whole instead of ending it early.
    assert_eq!(
        up.messages()[0],
        "Subject: x\r\n\r\nbody\r\n..\r\nnot the end\r\n"
    );
}

/// I1. The Perl normalises and dot-stuffs in one regex *before* it decides
/// whether the terminating dot needs a CRLF in front of it
/// (`Mojo/SMTP/Client.pm:517,519`). Asserted on the raw recording: a fake
/// that rebuilds the message from parsed lines re-normalises it and can
/// therefore see neither half of this.
#[tokio::test]
async fn the_relayed_payload_is_line_ending_normalised() {
    let cases: [(&[u8], &[u8]); 5] = [
        // A body with bare LF throughout: the upstream must see CRLF.
        (b"Subject: x\n\nline\n", b"Subject: x\r\n\r\nline\r\n"),
        // Ending in a bare LF: normalised first, so the dot follows
        // immediately instead of after a spurious blank line.
        (b"a\r\nb\n", b"a\r\nb\r\n"),
        // Already CRLF-terminated: unchanged.
        (b"a\r\n", b"a\r\n"),
        // No trailing newline at all: the terminator brings its own CRLF.
        (b"a", b"a\r\n"),
        // A dot behind a bare LF is a line start too, so it is stuffed.
        (b"a\n.\n", b"a\r\n..\r\n"),
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
    assert!(!out.upstream_dsn);
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
    assert!(!out.upstream_dsn);
    assert_eq!(up.commands()[1], "MAIL FROM:<>");
    assert_eq!(up.commands()[2], "RCPT TO:<x@baz.com>");
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
        Err(RelayError::Rejected {
            command: "MAIL",
            code: 553,
            text,
        }) => assert_eq!(text, "Sorry, I don't send from there"),
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
#[tokio::test]
async fn an_upstream_that_stops_reading_still_times_out() {
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
    assert!(matches!(err, RelayError::Timeout), "{err:?}");
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
