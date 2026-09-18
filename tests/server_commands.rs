//! The session state machine over plain TCP. Ports of the Perl `commands.t`,
//! `pipelining.t`, `rset-transaction.t`, `repeated-recipient.t` and the
//! session half of `dsn-validation.t`. TLS and AUTH are exercised separately.
mod common;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};
use smtp_proxy::relay::UpstreamVerdict;
use smtp_proxy::server::Rejection;
use smtp_proxy::server::data::WRITE_CHUNK;

/// A connection that has been greeted. `require_starttls` and `require_auth`
/// are both off, so the very next command falls through to `WantMail`.
async fn open_session() -> (RawClient, ScriptedFactory) {
    let factory = ScriptedFactory::default();
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, greeting) = RawClient::connect(addr).await;
    assert_eq!(greeting, "220 test.service.name SMTP service ready\r\n");
    assert!(
        c.command("EHLO client.example.com")
            .await
            .starts_with("250")
    );
    (c, factory)
}

#[tokio::test]
async fn greeting_and_ehlo_reply() {
    let factory = ScriptedFactory::default();
    let addr = start_server(server_config(false, false), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let r = c.command("EHLO client.example.com").await;
    assert_eq!(
        r,
        "250-test.service.name offers a warm hug of welcome\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 DSN\r\n"
    );
    let r = c.command("HELO client.example.com").await;
    assert_eq!(r, "250 test.service.name offers a warm hug of welcome\r\n");
}

#[tokio::test]
async fn dsn_is_announced_only_when_available() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.dsn = false);
    let addr = start_server(server_config(false, false), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let r = c.command("EHLO client.example.com").await;
    assert!(!r.contains("DSN"), "{r}");
    assert!(r.ends_with("250 AUTH PLAIN LOGIN\r\n"), "{r}");
}

#[tokio::test]
async fn ehlo_announces_the_size_limit_the_handler_reports() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.size_limit = Some(10_240_000));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let reply = c.command("EHLO x").await;
    assert!(reply.contains("SIZE 10240000"), "got {reply:?}");
}

#[tokio::test]
async fn ehlo_omits_size_when_the_handler_reports_none() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.size_limit = None);
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let reply = c.command("EHLO x").await;
    assert!(!reply.contains("SIZE"), "got {reply:?}");
}

/// HELO takes no extension list at all, so the limit must not leak into it.
#[tokio::test]
async fn helo_never_announces_size() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.size_limit = Some(64));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let reply = c.command("HELO x").await;
    assert!(!reply.contains("SIZE"), "got {reply:?}");
}

#[tokio::test]
async fn commands_valid_in_any_state() {
    let (mut c, _) = open_session().await;
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
    assert_eq!(c.command("NOOP keep alive").await, "250 OK\r\n");
    assert_eq!(c.command("VRFY someone").await, "553 Unimplemented\r\n");
    assert_eq!(c.command("VRFY").await, "501 string required\r\n");
    assert_eq!(c.command("EHLO").await, "501 domain required\r\n");
    assert_eq!(c.command("PING").await, "502 unknown command\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(c.command("DATA now").await, "501 no arguments allowed\r\n");
    c.write_raw(" NOOP\r\n").await;
    assert_eq!(c.read_reply().await, "500 malformed command\r\n");
    assert_eq!(
        c.command("QUIT").await,
        "221 test.service.name closing transmission channel\r\n"
    );
    assert!(c.expect_close().await);
}

#[tokio::test]
async fn out_of_sequence_commands_draw_503() {
    let (mut c, _) = open_session().await;
    assert_eq!(
        c.command("RCPT TO:<a@b.com>").await,
        "503 Bad sequence of commands\r\n"
    );
    assert_eq!(c.command("DATA").await, "503 Bad sequence of commands\r\n");
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("DATA").await, "503 Bad sequence of commands\r\n");
    assert_eq!(
        c.command("MAIL FROM:<x@y.com>").await,
        "503 Bad sequence of commands\r\n"
    );
}

#[tokio::test]
async fn full_transaction_reaches_the_handler() {
    let (mut c, factory) = open_session().await;
    assert_eq!(c.command("MAIL FROM:<x@y.com> SIZE=10").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(
        c.command("RCPT TO:<c@d.com> NOTIFY=NEVER").await,
        "250 OK\r\n"
    );
    assert_eq!(
        c.command("DATA").await,
        "354 End data with <CR><LF>.<CR><LF>\r\n"
    );
    c.write_raw("Subject: hi\r\nTo: a@b.com\r\n\r\nbody line\r\n..dot line\r\n.\r\n")
        .await;
    assert_eq!(c.read_reply().await, "250 OK: queued\r\n");
    let rec = factory.recorded();
    assert_eq!(rec.mail[0].0, "x@y.com");
    assert_eq!(rec.mail[0].1[0].keyword, "SIZE");
    assert_eq!(rec.rcpt.len(), 2);
    assert_eq!(rec.rcpt[1].1[0].value.as_deref(), Some("NEVER"));
    assert_eq!(rec.headers[0], "Subject: hi\r\nTo: a@b.com\r\n");
    // The sink is given body lines verbatim (spec 5.1), so the client's
    // stuffing dot is still on `..dot line`. Undoing it is the business of
    // whoever writes the body upstream, not of the session.
    assert_eq!(rec.bodies[0], b"body line\r\n..dot line\r\n");
    // Next transaction on the same connection.
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn handler_rejections_use_the_perl_texts() {
    let (mut c, factory) = open_session().await;
    factory.set(|s| s.mail_error = Some(Rejection::mail("no")));
    assert_eq!(
        c.command("MAIL FROM:<x@y.com>").await,
        "553 Requested action not taken: no\r\n"
    );
    factory.set(|s| {
        s.mail_error = None;
        s.rcpt_error = Some(Rejection::rcpt("bad user"))
    });
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(
        c.command("RCPT TO:<a@b.com>").await,
        "550 Will not send mail to this user: bad user\r\n"
    );
    factory.set(|s| {
        s.rcpt_error = None;
        s.message_result = Err(smtp_proxy::server::Rejection {
            code: 550,
            text: "Weather too hot to email".into(),
        })
    });
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n.\r\n").await;
    assert_eq!(c.read_reply().await, "550 Weather too hot to email\r\n");
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn rset_and_ehlo_reset_the_transaction_but_not_the_session() {
    let (mut c, factory) = open_session().await;
    // The EHLO in open_session ran in WantGreeting, below WantMail, so it did
    // not reset anything: the count starts at zero.
    assert_eq!(factory.recorded().resets, 0);
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n"); // reset 1
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n"); // reset 2
    assert_eq!(
        c.command("RCPT TO:<a@b.com>").await,
        "503 Bad sequence of commands\r\n"
    );
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n"); // reset 3
    assert!(c.command("EHLO again.example.com").await.starts_with("250")); // reset 4
    assert_eq!(
        c.command("RCPT TO:<a@b.com>").await,
        "503 Bad sequence of commands\r\n"
    );
    // Four resets: MAIL, RSET, MAIL, EHLO. The greeting resets because it
    // arrived in WantRcpt, and spec 4.2 resets at state >= WantMail.
    assert_eq!(factory.recorded().resets, 4);
    // The session survives the greeting: state is WantMail, not WantAuth or
    // WantStartTls, so a MAIL is still accepted straight away. That state is
    // itself >= WantMail, so this second EHLO reports a reset of its own.
    assert!(c.command("EHLO again.example.com").await.starts_with("250")); // reset 5
    assert_eq!(factory.recorded().resets, 5);
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn pipelined_commands_are_answered_in_order() {
    let (mut c, _) = open_session().await;
    c.write_raw("MAIL FROM:<x@y.com>\r\nRCPT TO:<a@b.com>\r\nRCPT TO:<c@d.com>\r\nDATA\r\n")
        .await;
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert!(c.read_reply().await.starts_with("354"));
    // The QUIT arrives in the same read as the DATA terminator: it must stay
    // in the buffer and be parsed as the next command (spec 4.7).
    c.write_raw("Subject: x\r\n\r\nbody\r\n.\r\nQUIT\r\n").await;
    assert_eq!(c.read_reply().await, "250 OK: queued\r\n");
    assert!(c.read_reply().await.starts_with("221"));
}

#[tokio::test]
async fn repeated_recipient_is_recorded_twice() {
    let (mut c, factory) = open_session().await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(
        c.command("RCPT TO:<a@b.com> NOTIFY=SUCCESS").await,
        "250 OK\r\n"
    );
    assert_eq!(
        c.command("RCPT TO:<a@b.com> NOTIFY=NEVER").await,
        "250 OK\r\n"
    );
    let rec = factory.recorded();
    assert_eq!(rec.rcpt.len(), 2);
    assert_eq!(rec.rcpt[0].1[0].value.as_deref(), Some("SUCCESS"));
    assert_eq!(rec.rcpt[1].1[0].value.as_deref(), Some("NEVER"));
}

#[tokio::test]
async fn dsn_parameters_are_validated_at_the_command() {
    let (mut c, _) = open_session().await;
    let script: &[(&str, char)] = &[
        ("MAIL FROM:<a@b.com> RET=PARTIAL", '5'),
        ("MAIL FROM:<a@b.com> RET", '5'),
        ("MAIL FROM:<a@b.com> ENVID=has+zz", '5'),
        ("MAIL FROM:<a@b.com> ENVID=one ENVID=two", '5'),
        ("MAIL FROM:<a@b.com> RET=FULL RET=HDRS", '5'),
        ("MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159", '2'),
        ("RCPT TO:<c@d.com> NOTIFY=MAYBE", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=NEVER,SUCCESS", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=DELAY,DELAY", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=SUCCESS,", '5'),
        ("RCPT TO:<c@d.com> ORCPT=nosemicolon", '5'),
        ("RCPT TO:<c@d.com> NOTIFY=DELAY NOTIFY=NEVER", '5'),
        (
            "RCPT TO:<c@d.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;c@d.com",
            '2',
        ),
        ("RCPT TO:<c@d.com> NOTIFY=NEVER", '2'),
    ];
    for (line, expected) in script {
        let r = c.command(line).await;
        assert_eq!(r.chars().next().unwrap(), *expected, "{line} -> {r}");
        if *expected == '5' {
            assert!(r.starts_with("501 "), "{line} -> {r}");
        }
    }
    // The two accepted RCPTs left the session in WantData, where a MAIL is out
    // of sequence and never reaches DSN validation (spec 4.6). RSET first so
    // the exact 501 text can be checked.
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(
        c.command("MAIL FROM:<a@b.com> RET=PARTIAL").await,
        "501 RET requires a value of FULL or HDRS\r\n"
    );
}

#[tokio::test]
async fn auth_continuation_with_a_line_break_is_confused() {
    let (mut c, _) = open_session().await;
    assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
    // An empty continuation line carries nothing but the break itself.
    assert_eq!(
        c.command("").await,
        "500 confused authentication response\r\n"
    );
    assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
    // A bare CR inside the line is a break before the end of the line.
    c.write_raw("dXNlcg==\rdXNlcg==\r\n").await;
    assert_eq!(
        c.read_reply().await,
        "500 confused authentication response\r\n"
    );
    // The session goes on; the connection was not dropped.
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
}

#[tokio::test]
async fn header_block_over_the_cap_is_refused_with_552() {
    let factory = ScriptedFactory::default();
    let mut config = server_config(false, false);
    config.max_header_size = 64;
    let addr = start_server(config, factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    // The body is not capped any more, so the oversized part has to be a
    // header for the cap to see it at all.
    c.write_raw(&format!(
        "Subject: {}\r\n\r\nbody\r\n.\r\n",
        "y".repeat(100)
    ))
    .await;
    assert_eq!(
        c.read_reply().await,
        "552 Header block exceeds maximum size of 64 bytes\r\n"
    );
    assert!(factory.recorded().bodies.is_empty());
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn a_command_line_that_never_ends_is_cut_off() {
    let (mut c, _) = open_session().await;
    // 64 KiB is the command buffer, so the server must consume every one of
    // these 65537 bytes before it can decide the line is too long. Sending
    // no more than that keeps the socket clean: nothing is left unread when
    // the server closes, so the 500 cannot be lost to a reset.
    c.write_raw(&"x".repeat(64 * 1024)).await;
    c.write_raw("y").await;
    assert_eq!(c.read_reply().await, "500 Line too long\r\n");
    assert!(c.expect_close().await);
}

#[tokio::test]
async fn a_header_line_that_never_ends_is_capped_at_the_header_size() {
    let factory = ScriptedFactory::default();
    let mut config = server_config(false, false);
    config.max_header_size = 64;
    let addr = start_server(config, factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    // 256 KiB of header in a single line with no newline anywhere. The cap
    // is 64 bytes, so the server has to throw these away as they arrive
    // instead of buffering them while it waits for the end of the line.
    for _ in 0..4 {
        c.write_raw(&"y".repeat(64 * 1024)).await;
    }
    c.write_raw("\r\n.\r\n").await;
    assert_eq!(
        c.read_reply().await,
        "552 Header block exceeds maximum size of 64 bytes\r\n"
    );
    assert!(factory.recorded().bodies.is_empty());
    // The connection survives and the next transaction works.
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn a_header_block_that_fills_the_cap_exactly_still_ends_normally() {
    let factory = ScriptedFactory::default();
    let mut config = server_config(false, false);
    config.max_header_size = 64;
    let addr = start_server(config, factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    // "Subject: " plus 53 characters plus CRLF is exactly the 64 byte cap,
    // so the header block leaves no capacity at all for the terminator --
    // which costs nothing.
    let subject = format!("Subject: {}\r\n", "z".repeat(53));
    assert_eq!(subject.len(), 64);
    c.write_raw(&subject).await;
    // The terminator arrives split across two reads. The lone dot must not be
    // read as an over-cap line: doing so would discard the message, swallow
    // the rest of the terminator as a discarded tail, and leave the session
    // waiting for a terminator that has already been sent.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    c.write_raw(".").await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    c.write_raw("\r\n").await;
    assert_eq!(c.read_reply().await, "250 OK: queued\r\n");
    let rec = factory.recorded();
    assert_eq!(rec.headers[0], subject);
    assert!(rec.bodies[0].is_empty());
}

/// The body carries no cap any more, so a line longer than the reader will
/// hold while it waits for a newline is not an error: it is taken in pieces
/// and delivered whole -- one line at the sink, not two, and with the
/// stuffing dot that rode in on its first piece still in place.
#[tokio::test]
async fn a_body_line_longer_than_the_read_buffer_is_delivered_whole() {
    let factory = ScriptedFactory::default();
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n").await;
    // One body line of 128 KiB: twice the 64 KiB the reader holds before it
    // gives up on finding the end of the line.
    let long = "z".repeat(128 * 1024);
    c.write_raw(&format!("..{long}\r\n.\r\n")).await;
    assert_eq!(c.read_reply().await, "250 OK: queued\r\n");
    let rec = factory.recorded();
    assert_eq!(rec.bodies[0], format!("..{long}\r\n").into_bytes());
}

#[tokio::test]
async fn a_discarded_header_line_tail_is_not_mistaken_for_the_terminator() {
    let factory = ScriptedFactory::default();
    let mut config = server_config(false, false);
    config.max_header_size = 64;
    let addr = start_server(config, factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    // The first header line leaves 52 of the 64 bytes unspent, and the
    // collector holds two bytes of slack for a half-read terminator, so 55
    // bytes without a newline are what tips the block over the cap. Each
    // sleep lets the server consume what was sent and go back to waiting with
    // an empty buffer, which fixes where the discard falls.
    c.write_raw("Subject: x\r\n").await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    c.write_raw(&"y".repeat(55)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // The rest of that same header line now happens to be a lone dot. It ends
    // the line, but the line began 55 bytes ago, so this is not a dot on a
    // line of its own and must not end the message. Reading it as the
    // terminator would reply 552 here and leave the rest of the message to be
    // parsed as commands.
    c.write_raw(".\r\n").await;
    c.write_raw("still inside the message\r\n").await;
    c.write_raw(".\r\n").await;
    assert_eq!(
        c.read_reply().await,
        "552 Header block exceeds maximum size of 64 bytes\r\n"
    );
    assert!(factory.recorded().bodies.is_empty());
    // Nothing from the message body was taken for a command.
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn a_client_leaving_during_a_slow_message_does_not_stop_the_server() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.message_delay = std::time::Duration::from_millis(300));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n.\r\n").await;
    drop(c);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // The handler ran to completion even though the client had already gone.
    assert_eq!(factory.recorded().bodies.len(), 1);
    // Server still serves a new client.
    let (mut c2, greeting) = RawClient::connect(addr).await;
    assert!(greeting.starts_with("220"));
    assert!(c2.command("NOOP").await.starts_with("250"));
}

/// The mirror rule at its cheapest: an upstream that dies mid-body takes the
/// client connection with it, with no reply invented on its behalf.
///
/// It also pins the staged remainder down. The body here is six bytes, far
/// below `WRITE_CHUNK`, so the only write the sink ever sees is the flush
/// after the terminator. A pump that went straight from the terminator to
/// `finish` would never call `write`, never meet the verdict, and answer
/// `250` instead of closing.
#[tokio::test]
async fn an_upstream_that_drops_mid_body_closes_the_client_connection() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.sink_verdict = Some(UpstreamVerdict::Dropped));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\nbody\r\n.\r\n").await;
    assert!(
        c.expect_close().await,
        "a dead upstream must close the client too"
    );
}

/// A body of complete short lines whose total is the first at or above
/// `WRITE_CHUNK`, so the framer stages every line and hands the sink its one
/// and only `BodyPiece::Chunk` on the very last of them -- with nothing left
/// over after it.
///
/// Short lines rather than one long one on purpose. Every read then ends on a
/// line boundary, so the pump takes the `Line::Got` path each time and the
/// test cannot come out differently depending on where the socket happened to
/// split a 64 KiB write.
fn body_of_exactly_one_write_chunk() -> String {
    let line = format!("{}\r\n", "z".repeat(100));
    let body = line.repeat(WRITE_CHUNK.div_ceil(line.len()));
    assert!(body.len() >= WRITE_CHUNK);
    assert!(
        body.len() - line.len() < WRITE_CHUNK,
        "the last line has to be the one that fills the chunk"
    );
    body
}

/// The mirror rule with something to say, and the only route that reaches
/// `Session::mirror` at all: the sink has to be written *during* the body,
/// which takes a staged `WRITE_CHUNK`. A smaller message stages and writes
/// once, after the terminator, where there is nothing left to mirror -- which
/// is the road `an_upstream_that_drops_mid_body_closes_the_client_connection`
/// takes.
///
/// Three promises, one assertion each. The upstream's reply reaches the
/// client verbatim and where the upstream gave it. What the client goes on
/// writing is read away instead of being parsed as commands. And the
/// transaction is cleared, so the session is ready for the next one.
#[tokio::test]
async fn an_upstream_that_refuses_mid_body_is_mirrored_and_the_rest_read_away() {
    let factory = ScriptedFactory::default();
    factory.set(|s| {
        s.sink_verdict = Some(UpstreamVerdict::Replied {
            code: 451,
            text: "4.3.0 upstream had enough".into(),
        })
    });
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    // In WantGreeting, so this greeting resets nothing: the count starts at
    // zero.
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n"); // reset 1
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n").await;
    c.write_raw(&body_of_exactly_one_write_chunk()).await;
    assert_eq!(
        c.read_reply().await,
        "451 4.3.0 upstream had enough\r\n",
        "the upstream's own reply, sent where the upstream sent it"
    );
    // The client is still inside DATA and still writing. A server that has
    // already answered reads that only to resync, and a line that would draw
    // a reply of its own as a command is how the difference becomes visible.
    c.write_raw("this is body, not a command\r\n").await;
    c.write_raw(".\r\n").await;
    // So the next reply on the wire is this command's. Drop the drain from
    // the mirror and the line above earns a 502 that arrives here instead.
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
    // MAIL opened the transaction and the mirror cleared it; NOOP is not a
    // transaction boundary. Drop the `start_transaction` from the mirror and
    // this is 1.
    assert_eq!(factory.recorded().resets, 2);
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    // `finish` was never reached, so nothing was ever delivered.
    assert!(factory.recorded().bodies.is_empty());
}

/// The other verdict on that same route. Nothing is invented on a dead
/// upstream's behalf here either -- but here the client is still writing when
/// the connection goes, which is what tells this apart from
/// `an_upstream_that_drops_mid_body_closes_the_client_connection`.
#[tokio::test]
async fn an_upstream_that_drops_while_the_body_is_arriving_closes_the_client() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.sink_verdict = Some(UpstreamVerdict::Dropped));
    let addr = start_server(server_config(false, false), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n").await;
    // One chunk's worth and not a byte more. The server has read all of it by
    // the time the chunk is written, so nothing is left unread when it closes
    // -- unread bytes would draw a reset and the close would stop being
    // observable as a clean end of stream.
    c.write_raw(&body_of_exactly_one_write_chunk()).await;
    assert!(
        c.expect_close().await,
        "a dead upstream must close the client too, with no reply invented for it"
    );
    assert!(factory.recorded().bodies.is_empty());
}
