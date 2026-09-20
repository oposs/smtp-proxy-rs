//! The whole stack: a raw SMTP client, the server, the proxy handler, a
//! fake API and a recording upstream. Ports of the Perl `end-to-end.t`,
//! `api-from-injection.t`, `upstream-acceptance.t`, `dsn.t`,
//! `stale-transaction.t` and `raw-client-settle.t`.
mod common;

use common::raw_client::RawClient;
use common::{captured_log, rig, rig_relaying_to};

async fn send_mail(c: &mut RawClient, from: &str, to: &[&str], message: &str) -> String {
    assert_eq!(
        c.command(&format!("MAIL FROM:<{from}>")).await,
        "250 OK\r\n"
    );
    for t in to {
        assert_eq!(c.command(&format!("RCPT TO:<{t}>")).await, "250 OK\r\n");
    }
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(message).await;
    c.write_raw(".\r\n").await;
    c.read_reply().await
}

const MESSAGE: &str =
    "From: sender@foobar.com\r\nTo: receiver@foobaz.com\r\nSubject: Hello\r\n\r\nHello there\r\n";

#[tokio::test]
async fn allowed_simple() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "250 OK: OK message accepted\r\n");
    let call = &r.api.calls()[0];
    assert_eq!(call["username"], "user");
    assert_eq!(call["password"], "pass");
    assert_eq!(call["from"], "sender@foobar.com");
    assert_eq!(call["to"], serde_json::json!(["receiver@foobaz.com"]));
    assert_eq!(
        call["headers"][2],
        serde_json::json!({"name": "Subject", "value": "Hello"})
    );
    assert_eq!(call["mailParameters"], serde_json::json!([]));
    assert_eq!(
        call["rcptParameters"],
        serde_json::json!([{"address": "receiver@foobaz.com", "parameters": []}])
    );
    assert_eq!(r.upstream.commands()[1], "MAIL FROM:<sender@foobar.com>");
    assert_eq!(r.upstream.messages()[0], MESSAGE);
    assert_eq!(
        c.command("QUIT").await,
        "221 smtp.proxy.service closing transmission channel\r\n"
    );
}

#[tokio::test]
async fn denied_by_api() {
    let r = rig(&["DSN"]).await;
    r.api
        .respond(serde_json::json!({ "allow": false, "reason": "Weather too hot to email" }));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "550 Weather too hot to email\r\n");
    // The upstream connection is opened in parallel with the API call, so a
    // refused message costs one abandoned connection -- but no envelope and
    // no message (`proxy.rs`, `fn open_body`).
    assert_eq!(r.upstream.commands(), vec!["EHLO localhost.localdomain"]);
    assert!(r.upstream.messages().is_empty());
    // The session is still usable.
    r.api
        .respond(serde_json::json!({ "allow": true, "headers": [] }));
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert!(reply.starts_with("250"), "{reply}");
}

#[tokio::test]
async fn api_failure_is_reported_as_authentication_service_failed() {
    let r = rig(&["DSN"]).await;
    r.api
        .fail_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "451 authentication service failed\r\n");
}

#[tokio::test]
async fn headers_are_inserted_replaced_and_removed() {
    let r = rig(&["DSN"]).await;
    r.api
        .respond(serde_json::json!({ "allow": true, "headers": [
            { "name": "Sender", "value": "bar@blah.com" },
            { "name": "Subject", "value": "Replaced" },
            { "name": "To", "value": null }
        ]}));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert!(
        send_mail(
            &mut c,
            "sender@foobar.com",
            &["receiver@foobaz.com"],
            MESSAGE
        )
        .await
        .starts_with("250")
    );
    assert_eq!(
        r.upstream.messages()[0],
        "From: sender@foobar.com\r\nSender: bar@blah.com\r\nSubject: Replaced\r\n\r\nHello there\r\n"
    );
}

#[tokio::test]
async fn api_can_change_the_envelope_sender_but_not_inject_commands() {
    let r = rig(&["DSN"]).await;
    r.api
        .respond(serde_json::json!({ "allow": true, "from": "other@foobar.com", "headers": [] }));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert!(
        send_mail(
            &mut c,
            "sender@foobar.com",
            &["receiver@foobaz.com"],
            MESSAGE
        )
        .await
        .starts_with("250")
    );
    assert_eq!(r.upstream.commands()[1], "MAIL FROM:<other@foobar.com>");
    r.upstream.clear();
    r.api.respond(
        serde_json::json!({ "allow": true, "from": "a@b.com>\r\nRCPT TO:<evil@x.com", "headers": [] }),
    );
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert!(
        reply.starts_with("550 Refusing to relay the address"),
        "{reply}"
    );
    // The address is checked before the opened connection is used for
    // anything, so the injected RCPT never reaches the wire.
    assert_eq!(r.upstream.commands(), vec!["EHLO localhost.localdomain"]);
    assert!(r.upstream.messages().is_empty());
}

/// M1. The Perl's `$apiResult->{from} || $mail{from}` is a truthiness test,
/// so an API that answers with an empty sender leaves the client's own
/// sender in place. Relaying `MAIL FROM:<>` instead would send every bounce
/// for that message somewhere else.
#[tokio::test]
async fn an_empty_api_sender_keeps_the_client_sender() {
    let r = rig(&["DSN"]).await;
    r.api
        .respond(serde_json::json!({ "allow": true, "from": "", "headers": [] }));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert!(
        send_mail(
            &mut c,
            "sender@foobar.com",
            &["receiver@foobaz.com"],
            MESSAGE
        )
        .await
        .starts_with("250")
    );
    assert_eq!(r.upstream.commands()[1], "MAIL FROM:<sender@foobar.com>");
}

/// M2, end to end: a header the Perl could not parse reaches neither the
/// API nor the upstream.
#[tokio::test]
async fn a_header_with_an_empty_value_reaches_neither_the_api_nor_the_upstream() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let message = "From: sender@foobar.com\r\nX-Empty:\r\nSubject: Hello\r\n\r\nHello there\r\n";
    assert!(
        send_mail(
            &mut c,
            "sender@foobar.com",
            &["receiver@foobaz.com"],
            message
        )
        .await
        .starts_with("250")
    );
    assert_eq!(
        r.api.calls()[0]["headers"],
        serde_json::json!([
            {"name": "From", "value": "sender@foobar.com"},
            {"name": "Subject", "value": "Hello"},
        ])
    );
    assert_eq!(
        r.upstream.messages()[0],
        "From: sender@foobar.com\r\nSubject: Hello\r\n\r\nHello there\r\n"
    );
}

/// The upstream refused MAIL FROM with a `553`, so the client is told `553`.
/// Before the 2026-09-13 ruling this arrived as a `550`, as it still does in
/// the Perl (`Connection.pm:682`).
#[tokio::test]
async fn relay_error_reaches_the_client() {
    let r = rig(&["DSN"]).await;
    r.upstream
        .reject_mail(Some("Sorry, I don't send from there"));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "553 Sorry, I don't send from there\r\n");
}

/// Item 6. A transient upstream refusal reaches the client as transient. The
/// reply used to be `550 4.3.2 Service not available`: a permanent code
/// wrapping a transient enhanced status, so a client reading the one deleted
/// the mail the other asked it to queue.
#[tokio::test]
async fn an_upstream_4xx_reaches_the_client_as_4xx() {
    let r = rig(&["DSN"]).await;
    r.upstream
        .reject_data_end(Some((451, "4.3.2 Service not available")));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    // The reply code and the enhanced status agree.
    assert_eq!(reply, "451 4.3.2 Service not available\r\n");
}

/// Item 6, and the test that tells verbatim pass-through from
/// class-normalisation. A `552` collapsed to `550` would still be a 5xx and
/// would go unnoticed without this.
#[tokio::test]
async fn an_upstream_5xx_still_reaches_the_client_as_that_5xx() {
    let r = rig(&["DSN"]).await;
    r.upstream
        .reject_data_end(Some((552, "5.3.4 Message too big for system")));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "552 5.3.4 Message too big for system\r\n");
    // The session survives an upstream 552 like any other rejection: only
    // *our* size cap discards a transaction mid-flight.
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
}

/// Item 6. The upstream never answered, so there is no code to relay. A
/// fresh connection is opened per message, so an upstream restarted between
/// two messages lands here: nothing about the message was wrong and the
/// client should come back rather than discard it.
///
/// This is `open_body`'s `Err` path, the one the sink never gets to exist
/// on: the connect fails while the client is still writing headers, so the
/// proxy answers in its own voice and reads the body away first.
#[tokio::test]
async fn an_unreachable_upstream_is_a_451_not_a_550() {
    // Port 1 on the loopback: privileged, unbound, and reliably refused.
    let r = rig_relaying_to(&["DSN"], Some(1)).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    // Unique to this test, so its lines can be picked out of the log that
    // every test in this binary shares.
    let from = "unreachable-probe@foobar.com";
    let reply = send_mail(&mut c, from, &["receiver@foobaz.com"], MESSAGE).await;
    assert!(reply.starts_with("451 "), "{reply}");
    // The body was drained rather than parsed as commands, so the connection
    // is still in step and serves the next transaction.
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    // And the operator is told why. This line used to come from the sink;
    // a relay that fails before the body never reaches one, so without it
    // here an unreachable upstream refuses mail with nothing in the log
    // above debug level.
    let text = String::from_utf8(captured_log().lock().unwrap().clone()).unwrap();
    let cid = text
        .lines()
        .find(|l| l.contains("Mail {") && l.contains(from))
        .and_then(cid_of)
        .unwrap_or_else(|| panic!("no message dump for this test in:\n{text}"));
    assert!(
        text.lines()
            .any(|l| cid_of(l) == Some(cid) && l.contains("Mail refused by relay server")),
        "no refusal line for [{cid}] in:\n{text}"
    );
}

/// Item 5. An API-supplied header value carrying `\r\n\r\n` would split the
/// relayed message and forge a body. The mail is refused and nothing is
/// relayed at all -- the upstream connection that was opened alongside the
/// API call is abandoned without an envelope.
#[tokio::test]
async fn a_header_value_with_an_unfolded_break_is_not_relayed() {
    let r = rig(&["DSN"]).await;
    r.api
        .respond(serde_json::json!({ "allow": true, "headers": [
            { "name": "X-Injected", "value": "harmless\r\n\r\nForged body line" }
        ]}));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "550 authentication service failed\r\n");
    assert_eq!(
        r.upstream.commands(),
        vec!["EHLO localhost.localdomain"],
        "{:?}",
        r.upstream.commands()
    );
    assert!(r.upstream.messages().is_empty());
    // A properly folded value from the same API is relayed unchanged, so the
    // refusal is the unfolded break and not the presence of a line ending.
    r.api
        .respond(serde_json::json!({ "allow": true, "headers": [
            { "name": "X-Folded", "value": "first\r\n  second" }
        ]}));
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert!(reply.starts_with("250"), "{reply}");
    assert!(
        r.upstream.messages()[0].contains("X-Folded: first\r\n  second\r\n"),
        "{}",
        r.upstream.messages()[0]
    );
}

/// The two halves of `authentication service failed` are told apart by the
/// reply code, and one session sees both: an unreachable API is `451` so the
/// mail is retried, a malformed header is `550` so it is not. The text is
/// identical on purpose, so the code is the only thing carrying the
/// distinction and a regression cannot hide behind the wording.
#[tokio::test]
async fn an_api_outage_is_transient_but_a_malformed_header_is_permanent() {
    let r = rig(&["DSN"]).await;
    r.api
        .fail_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let outage = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    // The API said nothing about this mail, so nothing about it is known to
    // be wrong; the client is asked to come back.
    assert_eq!(outage, "451 authentication service failed\r\n");

    r.api
        .respond(serde_json::json!({ "allow": true, "headers": [
            { "name": "X-Injected", "value": "harmless\r\n\r\nForged body line" }
        ]}));
    let malformed = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    // A retry resends the same break, so there is nothing to come back for.
    assert_eq!(malformed, "550 authentication service failed\r\n");
    assert!(r.upstream.messages().is_empty());
}

/// Item 3, end to end: a header block written with bare LF reaches the API
/// as individual headers, so API-side header policy cannot be evaded by
/// sending LF where CRLF was expected.
#[tokio::test]
async fn a_bare_lf_header_block_reaches_the_api_as_separate_headers() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let message = "From: sender@foobar.com\nSubject: Hello\nX-Policy: evade\n\nHello there\r\n";
    assert!(
        send_mail(
            &mut c,
            "sender@foobar.com",
            &["receiver@foobaz.com"],
            message
        )
        .await
        .starts_with("250")
    );
    assert_eq!(
        r.api.calls()[0]["headers"],
        serde_json::json!([
            {"name": "From", "value": "sender@foobar.com"},
            {"name": "Subject", "value": "Hello"},
            {"name": "X-Policy", "value": "evade"},
        ])
    );
}

#[tokio::test]
async fn upstream_acceptance_text_is_relayed() {
    let r = rig(&["DSN"]).await;
    r.upstream.accept_text("2.0.0 Ok: queued as 4XyZ12");
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "250 OK: 2.0.0 Ok: queued as 4XyZ12\r\n");
}

#[tokio::test]
async fn transparency_of_dots_and_multiple_mails_on_one_connection() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    // The client stuffs its dots; the proxy unstuffs them and stuffs them
    // again for the upstream, which records the wire form unchanged.
    let msg = "Subject: x\r\n\r\n..leading dot\r\n..\r\n";
    assert!(
        send_mail(&mut c, "a@b.com", &["x@y.com"], msg)
            .await
            .starts_with("250")
    );
    assert_eq!(r.upstream.messages()[0], msg);
    // SECURITY (0.6.6): the second mail must not go to the first mail's recipients.
    assert!(
        send_mail(&mut c, "a@b.com", &["only@second.com"], MESSAGE)
            .await
            .starts_with("250")
    );
    let rcpts = r.upstream.commands_matching("RCPT");
    assert_eq!(
        rcpts,
        vec!["RCPT TO:<x@y.com>", "RCPT TO:<only@second.com>"]
    );
    assert_eq!(
        r.api.calls()[1]["to"],
        serde_json::json!(["only@second.com"])
    );
    assert_eq!(r.api.calls()[1]["username"], "user");
}

/// Streaming, stated as a property of the wire: the upstream has the whole
/// envelope while the client is still writing its body. Under the buffering
/// design MAIL FROM could not go out until the terminator had arrived,
/// because the API was not asked until then.
#[tokio::test]
async fn the_envelope_reaches_the_upstream_before_the_body_ends() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\npartial body, no terminator yet\r\n")
        .await;
    // The wait below is on the upstream's state, not on a reply, so nothing
    // else will push these bytes out of the client's TLS buffer.
    c.flush().await;
    // No terminator has been sent, so under a buffering proxy the upstream
    // would still be untouched.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while r.upstream.commands_matching("MAIL").is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "upstream never saw MAIL FROM"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
}

/// An upstream that refuses mid-body: its own code and text reach the
/// client, and the session stays usable afterwards.
///
/// The reply is read **before the client has sent its terminator**, which is
/// what makes this a test of streaming rather than of the reply mapping. A
/// buffering proxy has relayed nothing at that point and has nothing to say,
/// so the read would sit there until the client's own timeout. (The brief's
/// single-write form cannot fail that way: with the terminator already sent,
/// both designs answer `552`.)
#[tokio::test]
async fn an_upstream_rejection_mid_body_reaches_the_client_verbatim() {
    let r = rig(&["DSN"]).await;
    r.upstream.reject_during_data(4096, (552, "5.3.4 too big"));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    // Eight MiB, in lines: far past the upstream's patience, and far past
    // anything the session is willing to hold, so this also says that a body
    // bigger than memory would like survives the trip. Lines rather than one
    // enormous one because the upstream reads line by line and would not
    // reach its own rejection until the whole thing had arrived -- which is
    // the buffering this test exists to rule out.
    let line = format!("{}\r\n", "y".repeat(1022));
    c.write_raw(&format!(
        "Subject: x\r\n\r\n{}",
        line.repeat(8 * 1024 * 1024 / line.len())
    ))
    .await;
    assert_eq!(c.read_reply().await, "552 5.3.4 too big\r\n");
    // The proxy is draining to the terminator, so the message can still be
    // finished and the connection goes on serving.
    c.write_raw(".\r\n").await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert!(
        r.upstream.messages().is_empty(),
        "a refused message must not be recorded as delivered"
    );
}

/// The same refusal, read from the operator's side of the glass.
///
/// A refusal the upstream speaks mid-body never reaches `ProxySink::finish`:
/// `read_message` hands the verdict to `mirror`, whose only output is a
/// `debug!`. So the three-line report had to be added to `ProxySink::write`
/// as well. Without it an operator grepping `Mail refused by relay server` --
/// the line the README teaches and `conformance/t/connection-lifecycle.t`
/// greps for -- misses exactly the newest failure mode on this branch, and at
/// the default log level sees nothing about it at all.
///
/// The refusal text is unique to this test, so its line can be picked out of
/// the log every test in this binary shares -- and so the assertion need not
/// correlate through the `Mail {` dump, which the same fix emits and which
/// would therefore go missing under the negation and take the test red at the
/// wrong place.
#[tokio::test]
async fn a_refusal_mid_body_is_reported_to_the_operator() {
    const REFUSAL: &str = "5.3.4 mid-body-probe over the limit";
    let r = rig(&["DSN"]).await;
    r.upstream.reject_during_data(4096, (552, REFUSAL));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    let line = format!("{}\r\n", "y".repeat(1022));
    c.write_raw(&format!(
        "Subject: x\r\n\r\n{}",
        line.repeat(8 * 1024 * 1024 / line.len())
    ))
    .await;
    assert_eq!(c.read_reply().await, format!("552 {REFUSAL}\r\n"));
    c.write_raw(".\r\n").await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");

    let text = String::from_utf8(captured_log().lock().unwrap().clone()).unwrap();
    assert!(
        text.lines()
            .any(|l| l.contains("Mail refused by relay server") && l.contains(REFUSAL)),
        "a mid-body refusal left nothing above debug level; log:\n{text}"
    );
}

/// A client that abandons the message mid-body must not deliver it. The sink
/// is dropped without its terminator, so the upstream sees a connection that
/// closed inside DATA and discards the transaction.
#[tokio::test]
async fn a_client_that_hangs_up_mid_body_delivers_nothing() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\nhalf a body\r\n").await;
    // Puts the half body on the wire instead of leaving it in rustls'
    // output buffer; see `RawClient::flush` for why a write alone does not.
    // It is not what keeps this test honest: the framer stages everything
    // below `WRITE_CHUNK`, so `half a body\r\n` never reaches the upstream
    // either way, and the poll loop below fails hard if the client's bytes
    // are stuck, so nothing here can shrink silently.
    c.flush().await;
    // The envelope is already upstream, so this is the window the test is
    // about: everything but the terminator has been relayed.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while r.upstream.commands_matching("DATA").is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "upstream never saw DATA"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    drop(c);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        r.upstream.messages().is_empty(),
        "an abandoned message must not be delivered"
    );
}

/// The other half of the stuffing seam. `HeaderCollector` takes the client's
/// stuffing dot off every *header* line so that the API sees content rather
/// than wire form (`server::data`), so a header name beginning with a dot is
/// held here one character short of what the client sent. Written raw it
/// would reach the upstream as `X-Foo: y`; `header_block` stuffs it back
/// (`proxy.rs`).
#[tokio::test]
async fn a_stuffed_header_line_reaches_the_upstream_stuffed() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let msg = "..X-Foo: y\r\nSubject: x\r\n\r\nbody\r\n";
    assert!(
        send_mail(&mut c, "a@b.com", &["x@y.com"], msg)
            .await
            .starts_with("250")
    );
    assert_eq!(
        String::from_utf8(r.upstream.raw_messages()[0].clone()).unwrap(),
        msg,
        "the upstream must see exactly the bytes the client wrote"
    );
    // And the API was asked about the header the client really meant, which
    // is the unstuffed one.
    assert_eq!(r.api.calls()[0]["headers"][0]["name"], ".X-Foo");
}

/// Ruling 35. The header block is built out of parsed content, so it carries
/// whichever break the client folded with -- and a bare LF is a legal fold to
/// `folds_at` (`proxy.rs`). Inside DATA a line ends with CRLF and nothing
/// else (RFC 5321 2.3.8), so `header_block` normalises. `normalize_and_stuff`
/// used to do this for the whole message; the body keeps its own
/// normalisation in `BodyFramer` (`server::data`), and this is the other
/// path.
#[tokio::test]
async fn a_bare_lf_folded_header_reaches_the_upstream_as_crlf() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    // The reader takes a bare LF as a line ending, so this genuinely arrives
    // as two lines and folds back into one value carrying the LF.
    let msg = "Subject: a\n b\r\n\r\nbody\r\n";
    assert!(
        send_mail(&mut c, "a@b.com", &["x@y.com"], msg)
            .await
            .starts_with("250")
    );
    assert_eq!(
        String::from_utf8(r.upstream.raw_messages()[0].clone()).unwrap(),
        "Subject: a\r\n b\r\n\r\nbody\r\n",
        "a bare LF must not reach the upstream inside DATA"
    );
    // The API saw the value the client meant, break and all: only the wire
    // form is normalised.
    assert_eq!(r.api.calls()[0]["headers"][0]["value"], "a\n b");
}

/// Ruling 31(a). The Perl counts the body as the *message* holds it: it
/// strips the stuffing dot before accumulating (`Connection.pm`,
/// `$line =~ s/^\.//`), so its count excludes it. The bytes on the wire keep
/// theirs, so counting what goes upstream would report one byte per stuffed
/// line too many.
#[tokio::test]
async fn the_body_byte_count_excludes_the_stuffing_dots() {
    let r = rig(&["DSN"]).await;
    // Unique to this test, so its lines can be picked out of the log that
    // every test in this binary shares.
    r.upstream.accept_text("accepted for the byte count");
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    // `..stuffed\r\n` is eleven bytes on the wire and ten in the message;
    // `plain\r\n` is seven of each. The terminator is part of neither.
    let msg = "Subject: x\r\n\r\n..stuffed\r\nplain\r\n";
    assert!(
        send_mail(&mut c, "a@b.com", &["x@y.com"], msg)
            .await
            .starts_with("250")
    );
    let text = String::from_utf8(captured_log().lock().unwrap().clone()).unwrap();
    let cid = text
        .lines()
        .find(|l| l.contains("accepted for the byte count"))
        .and_then(cid_of)
        .unwrap_or_else(|| panic!("no acceptance line for this test in:\n{text}"));
    let counted: Vec<&str> = text
        .lines()
        .filter(|l| cid_of(l) == Some(cid) && l.contains("Body received"))
        .collect();
    assert_eq!(counted.len(), 1, "expected one count line in:\n{text}");
    assert!(
        counted[0].contains("Body received 17 Bytes."),
        "counted the stuffing dot: {}",
        counted[0]
    );
}

/// A reply code is three digits an upstream chose, and
/// `Reply::wire` panics outside `200..=599`. During DATA the verdict goes
/// straight at the client, so without the bound in
/// `UpstreamVerdict::replied` a broken upstream would kill the session
/// instead of the message.
#[tokio::test]
async fn an_upstream_reply_the_client_cannot_be_sent_becomes_451() {
    let r = rig(&["DSN"]).await;
    r.upstream
        .reject_data_end(Some((100, "not a refusal at all")));
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let reply = send_mail(
        &mut c,
        "sender@foobar.com",
        &["receiver@foobaz.com"],
        MESSAGE,
    )
    .await;
    assert_eq!(reply, "451 not a refusal at all\r\n");
    // The session lived through it, which is the half a panic would take.
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
}

/// Spec 5.1: the body is relayed **verbatim**. It arrives from `BodyFramer`
/// exactly as the client wrote it, stuffing dot included (`server::data`),
/// which is already the encoding the upstream wants -- so nothing on the way
/// out touches it. Anything that re-stuffed it here would give every stuffed
/// line a dot the client never sent, and anything that unstuffed it would
/// take one away.
///
/// Three stuffed lines, because one dot is the easy case: a line that is
/// nothing but a stuffed dot, one with text after it, and one whose dots
/// keep going.
#[tokio::test]
async fn a_stuffed_body_line_is_not_stuffed_a_second_time() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let msg = "Subject: x\r\n\r\n..foo\r\n..\r\n....bar\r\nplain\r\n";
    assert!(
        send_mail(&mut c, "a@b.com", &["x@y.com"], msg)
            .await
            .starts_with("250")
    );
    assert_eq!(
        String::from_utf8(r.upstream.raw_messages()[0].clone()).unwrap(),
        msg,
        "the upstream must see exactly the bytes the client wrote"
    );
}

#[tokio::test]
async fn login_auth_end_to_end() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
    assert!(c.command("dXNlcg==").await.starts_with("334"));
    assert!(c.command("cGFzcw==").await.starts_with("235"));
    assert!(
        send_mail(&mut c, "a@b.com", &["x@y.com"], MESSAGE)
            .await
            .starts_with("250")
    );
    assert_eq!(r.api.calls()[0]["username"], "user");
    assert_eq!(r.api.calls()[0]["password"], "pass");
}

#[tokio::test]
async fn dsn_parameters_travel_to_the_api_and_the_upstream() {
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    let ehlo = c.command("EHLO again").await;
    assert!(
        ehlo.contains("250 DSN") || ehlo.contains("250-DSN"),
        "{ehlo}"
    );
    assert_eq!(
        c.command("MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159")
            .await,
        "250 OK\r\n"
    );
    assert_eq!(
        c.command("RCPT TO:<x@y.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@y.com")
            .await,
        "250 OK\r\n"
    );
    assert_eq!(
        c.command("RCPT TO:<x@y.com> NOTIFY=NEVER").await,
        "250 OK\r\n"
    );
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(MESSAGE).await;
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
    let call = &r.api.calls()[0];
    assert_eq!(
        call["mailParameters"],
        serde_json::json!([{"keyword": "RET", "value": "HDRS"}, {"keyword": "ENVID", "value": "QQ314159"}])
    );
    assert_eq!(call["to"], serde_json::json!(["x@y.com", "x@y.com"]));
    assert_eq!(call["rcptParameters"][1]["parameters"][0]["value"], "NEVER");
    let cmds = r.upstream.commands();
    assert_eq!(cmds[1], "MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159");
    assert_eq!(
        cmds[2],
        "RCPT TO:<x@y.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@y.com"
    );
    assert_eq!(cmds[3], "RCPT TO:<x@y.com> NOTIFY=NEVER");
}

/// The whole path: the upstream's own SIZE line, learned at the probe,
/// reaches the client's EHLO.
#[tokio::test]
async fn the_upstream_size_limit_reaches_the_client() {
    let r = rig(&["DSN", "SIZE 10240000"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    let reply = c.command("EHLO x").await;
    assert!(reply.contains("SIZE 10240000"), "got {reply:?}");
}

#[tokio::test]
async fn dsn_follows_the_upstream() {
    let r = rig(&["SIZE 1000"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert!(!c.command("EHLO again").await.contains("DSN"));
    assert_eq!(
        c.command("MAIL FROM:<a@b.com> RET=HDRS").await,
        "250 OK\r\n"
    );
    assert_eq!(
        c.command("RCPT TO:<x@y.com> NOTIFY=NEVER").await,
        "250 OK\r\n"
    );
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(MESSAGE).await;
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
    assert_eq!(r.upstream.commands()[1], "MAIL FROM:<a@b.com>");
    assert_eq!(r.upstream.commands()[2], "RCPT TO:<x@y.com>");
    // The upstream gains DSN; the next relay notices and the next EHLO announces it.
    r.upstream.set_extensions(&["DSN"]);
    assert!(
        send_mail(&mut c, "a@b.com", &["x@y.com"], MESSAGE)
            .await
            .starts_with("250")
    );
    assert!(
        r.factory
            .upstream_dsn()
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    assert!(c.command("EHLO again").await.contains("DSN"));
}

/// Long enough to be unmistakably a wait, short enough to stay far below the
/// rig's 5 s relay timeout and the raw client's 30 s reply timeout.
const RELAY_STALL: std::time::Duration = std::time::Duration::from_millis(300);

#[tokio::test]
async fn slow_relay_reply_stays_in_its_transaction() {
    // The reply to DATA is awaited before the next command is read, so a
    // pipelined RSET after the terminator is answered after the 250.
    let r = rig(&["DSN"]).await;
    // The upstream stops reading right after its 354, so the relay -- and
    // with it the client's 250 -- is held up for as long as the stall lasts.
    // Meanwhile the RSET and the second MAIL are already sitting in the
    // session's socket, which is the window this test is about.
    r.upstream.stall_data(RELAY_STALL);
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<x@y.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    let started = std::time::Instant::now();
    c.write_raw(&format!("{MESSAGE}.\r\nRSET\r\nMAIL FROM:<b@c.com>\r\n"))
        .await;
    assert!(c.read_reply().await.starts_with("250 OK: "));
    let waited = started.elapsed();
    assert!(
        waited >= RELAY_STALL,
        "the relay was not actually slow: {waited:?}"
    );
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert_eq!(c.read_reply().await, "250 OK\r\n");
}

/// The `[cid]` of a main-log line (spec 8.1
/// `[ts] [pid] [level] [cid] message`), or None when the line carries no
/// span and so no bracket.
fn cid_of(line: &str) -> Option<&str> {
    let mut rest = line;
    for _ in 0..3 {
        rest = rest.strip_prefix('[')?.split_once("] ")?.1;
    }
    let id = rest.strip_prefix('[')?.split_once(']')?.0;
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then_some(id)
}

#[tokio::test]
async fn the_api_debug_dump_carries_the_connection_id() {
    let r = rig(&["DSN"]).await;
    r.api
        .fail_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    // Unique to this test, so its dump can be picked out of the shared log.
    let from = "cid-probe@foobar.com";
    let reply = send_mail(&mut c, from, &["receiver@foobaz.com"], MESSAGE).await;
    assert_eq!(reply, "451 authentication service failed\r\n");

    let text = String::from_utf8(captured_log().lock().unwrap().clone()).unwrap();
    // Spec 5.3: a failing call dumps the request with the password redacted.
    let dumps: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("\"password\":\"*******\"") && l.contains(from))
        .collect();
    assert_eq!(dumps.len(), 1, "expected one redacted dump in:\n{text}");
    // Spec 8.1: and it carries the connection id, even though `ApiClient`
    // writes it from a task the handler spawned.
    let cid = cid_of(dumps[0]).unwrap_or_else(|| panic!("no [cid] on: {}", dumps[0]));
    // It is this connection's id, not merely a well-formed one: the line the
    // handler logged just before spawning the call carries the same one.
    assert!(
        text.lines()
            .any(|l| cid_of(l) == Some(cid) && l.contains("Making call to auth/headers API")),
        "no matching handler line for [{cid}] in:\n{text}"
    );
}

/// Port of the Perl `t/api-log-redaction.t` (spec 11.2). The SMTP password
/// travels to the auth API as an ordinary request argument, and a non-2xx
/// answer makes the client dump the request it sent so an operator can see
/// what was refused. That dump lands in the main log, which is *not* the
/// `--credentials`-gated smtplog, so a plaintext password there would sit
/// outside the containment boundary the design draws around credentials.
/// The stock log level is `debug`, so this is the default configuration and
/// not one somebody had to turn on.
#[tokio::test]
async fn api_log_redaction() {
    // Unique to this test, so its absence from the shared log is this
    // test's own evidence and not some other test's luck.
    const PASSWORD: &str = "Sup3rSecretPassw0rd";
    const USERNAME: &str = "redaction-testuser";
    let r = rig(&["DSN"]).await;
    r.api
        .fail_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login(USERNAME, PASSWORD).await;
    let from = "redaction-probe@foobar.com";
    let reply = send_mail(&mut c, from, &["receiver@foobaz.com"], MESSAGE).await;
    assert_eq!(reply, "451 authentication service failed\r\n");

    let text = String::from_utf8(captured_log().lock().unwrap().clone()).unwrap();
    // 1. The leak itself: no plaintext password on any line, at any level.
    assert!(
        !text.contains(PASSWORD),
        "plaintext password reached the main log:\n{text}"
    );

    // The remaining four properties belong to this connection, so they are
    // read off every line this connection logged rather than off one picked
    // line -- and cannot be satisfied by a sibling test running in parallel.
    let dumps: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(&format!("\"from\":\"{from}\"")))
        .collect();
    assert_eq!(dumps.len(), 1, "expected one request dump in:\n{text}");
    let cid = cid_of(dumps[0]).unwrap_or_else(|| panic!("no [cid] on: {}", dumps[0]));
    let ours: String = text
        .lines()
        .filter(|l| cid_of(l) == Some(cid))
        .collect::<Vec<_>>()
        .join("\n");

    // 2. The failure is still reported (spec 5.3).
    assert!(
        ours.contains("Failed to call API (Internal Server Error) for "),
        "the failed call is not reported in:\n{ours}"
    );
    // 3. The field is still shown as having been sent.
    assert!(ours.contains("password"), "no password field in:\n{ours}");
    // 4. Its value is replaced by the redaction marker.
    assert!(ours.contains("*******"), "no redaction marker in:\n{ours}");
    // 5. The rest of the request is what makes the dump worth having.
    assert!(
        ours.contains(USERNAME),
        "the username is gone, so the dump is no longer diagnostic:\n{ours}"
    );
}
