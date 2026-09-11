//! Relaying to the upstream: the full session, DSN forwarding and the
//! address guard. Ported from the relay half of the Perl `dsn.t`.
mod common;

use common::upstream::RecordingUpstream;
use smtp_proxy::api::Recipient;
use smtp_proxy::relay::{Envelope, RelayConfig, RelayError, probe, relay};
use smtp_proxy::smtp::params::Param;

fn config(up: &RecordingUpstream) -> RelayConfig {
    RelayConfig {
        host: "127.0.0.1".into(),
        port: up.addr.port(),
        timeout: std::time::Duration::from_secs(5),
    }
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
            timeout: std::time::Duration::from_secs(1)
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
