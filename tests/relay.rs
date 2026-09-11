//! Relaying to the upstream: the full session, DSN forwarding and the
//! address guard. Ported from the relay half of the Perl `dsn.t`.
mod common;

use std::time::{Duration, Instant};

use common::upstream::RecordingUpstream;
use smtp_proxy::api::Recipient;
use smtp_proxy::relay::{Envelope, RelayConfig, RelayError, probe, relay};
use smtp_proxy::smtp::params::Param;

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
    assert!(cmds[0].starts_with("EHLO "));
    assert_eq!(cmds[1], "MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ");
    assert_eq!(
        cmds[2],
        "RCPT TO:<x@baz.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@baz.com"
    );
    assert_eq!(cmds[3], "RCPT TO:<x@baz.com> NOTIFY=NEVER");
    assert_eq!(cmds[4], "DATA");
    assert_eq!(cmds[5], "QUIT");
    // The message is dot-stuffed on the way out and the upstream sees it intact.
    assert_eq!(
        up.messages()[0],
        "Subject: x\r\n\r\nbody\r\n..\r\nnot the end\r\n"
    );
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

/// Spec 6's 60 s is an *inactivity* timeout. A body several times bigger
/// than the socket buffers, handed to an upstream that drains it in steps,
/// must go through as long as every gap is shorter than the timeout — even
/// though the transfer as a whole takes far longer than the timeout. With a
/// single deadline over the whole payload this fails with
/// `RelayError::Timeout`, which is exactly the bug being guarded against.
#[tokio::test]
async fn a_slow_but_steady_upstream_is_not_timed_out() {
    let up = RecordingUpstream::start(&["DSN"]).await;
    // Six pauses of 50 ms while the first 6 MiB go in: each gap is a
    // quarter of the timeout, their sum is one and a half times it. The
    // measured worst case for one 64 KiB chunk under this pacing is ~110 ms,
    // so the passing margin is about 2x.
    up.pace_data(1 << 20, Duration::from_millis(50), 6);
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    let timeout = Duration::from_millis(200);
    // 24 MiB is well past the ~10 MiB the loopback socket buffers can hold
    // even fully auto-tuned, so the relay's writes really do block on the
    // upstream's reads, and the upstream is certain to have passed the sixth
    // pause long before the last write returns.
    let size = 24 << 20;
    let started = Instant::now();
    let out = relay(&config_with_timeout(&up, timeout), env, &body(size))
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
    let up = RecordingUpstream::start(&["DSN"]).await;
    up.stall_data(Duration::from_secs(1));
    let recipients = one_recipient();
    let env = Envelope {
        from: "a@b.com",
        mail_params: &[],
        recipients: &recipients,
    };
    // Big enough that the write cannot simply disappear into the socket
    // buffers, so it is the write that gives up, not the wait for the 250.
    let err = relay(
        &config_with_timeout(&up, Duration::from_millis(200)),
        env,
        &body(24 << 20),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RelayError::Timeout), "{err:?}");
    assert!(up.messages().is_empty());
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
