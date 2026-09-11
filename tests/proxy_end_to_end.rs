//! The whole stack: a raw SMTP client, the server, the proxy handler, a
//! fake API and a recording upstream. Ports of the Perl `end-to-end.t`,
//! `api-from-injection.t`, `upstream-acceptance.t`, `dsn.t`,
//! `stale-transaction.t` and `raw-client-settle.t`.
mod common;

use common::fake_api::FakeApi;
use common::raw_client::RawClient;
use common::upstream::RecordingUpstream;
use common::{server_config, start_server};
use smtp_proxy::api::ApiClient;
use smtp_proxy::proxy::{ProxyConfig, ProxyFactory};
use smtp_proxy::relay::RelayConfig;

struct Rig {
    api: FakeApi,
    upstream: RecordingUpstream,
    factory: ProxyFactory,
    addr: std::net::SocketAddr,
}

async fn rig(upstream_extensions: &[&str]) -> Rig {
    let api = FakeApi::start().await;
    let upstream = RecordingUpstream::start(upstream_extensions).await;
    let factory = ProxyFactory::new(ProxyConfig {
        api: ApiClient::new(api.url.clone()).unwrap(),
        relay: RelayConfig {
            host: "127.0.0.1".into(),
            port: upstream.addr.port(),
            timeout: std::time::Duration::from_secs(5),
        },
    });
    factory.probe_upstream().await;
    // The probe's own EHLO and QUIT are a connection like any other; left in
    // place they would shift every command index the tests below assert on.
    upstream.clear();
    let mut config = server_config(true, true);
    config.service_name = "smtp.proxy.service".into();
    let addr = start_server(config, factory.clone()).await;
    Rig {
        api,
        upstream,
        factory,
        addr,
    }
}

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
    assert!(r.upstream.commands().is_empty());
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
    assert_eq!(reply, "550 authentication service failed\r\n");
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
    assert!(r.upstream.commands().is_empty());
}

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
    assert_eq!(reply, "550 Sorry, I don't send from there\r\n");
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

#[tokio::test]
async fn slow_relay_reply_stays_in_its_transaction() {
    // The reply to DATA is awaited before the next command is read, so a
    // pipelined RSET after the terminator is answered after the 250.
    let r = rig(&["DSN"]).await;
    let (mut c, _) = RawClient::connect(r.addr).await;
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<x@y.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw(&format!("{MESSAGE}.\r\nRSET\r\nMAIL FROM:<b@c.com>\r\n"))
        .await;
    assert!(c.read_reply().await.starts_with("250 OK: "));
    assert_eq!(c.read_reply().await, "250 OK\r\n");
    assert_eq!(c.read_reply().await, "250 OK\r\n");
}
