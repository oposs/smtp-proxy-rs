//! The whole stack: a raw SMTP client, the server, the proxy handler, a
//! fake API and a recording upstream. Ports of the Perl `end-to-end.t`,
//! `api-from-injection.t`, `upstream-acceptance.t`, `dsn.t`,
//! `stale-transaction.t` and `raw-client-settle.t`.
mod common;

use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::prelude::*;

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

/// Every line the binary logs, in the real Mojo format, so that a test can
/// assert on the `[cid]` bracket of spec 8.1.
///
/// It has to be a *global* subscriber installed before any server starts, not
/// a per-test `set_default`: `tracing` caches each callsite's interest process
/// wide, so once a test without a subscriber has evaluated the `conn` span
/// callsite in `listener.rs`, that span stays disabled for every later test on
/// every thread, and no connection gets a cid at all. Installing it from
/// `rig()` means the first test to build a rig installs it, and
/// `set_global_default` rebuilds the interest cache as it goes.
fn captured_log() -> &'static Mutex<Vec<u8>> {
    static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOG.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let sink = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .event_format(smtp_proxy::logging::MojoFormat)
                .with_writer(move || Capture(sink.clone()))
                .with_filter(tracing::level_filters::LevelFilter::DEBUG),
        );
        tracing::subscriber::set_global_default(subscriber)
            .expect("nothing else installs a subscriber in this binary");
        buffer
    })
}

/// Collects formatted log lines for [`captured_log`]. One `write_all` per
/// event, so lines from tests running in parallel interleave but never split.
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn rig(upstream_extensions: &[&str]) -> Rig {
    captured_log();
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
    assert_eq!(reply, "550 authentication service failed\r\n");

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
    assert_eq!(reply, "550 authentication service failed\r\n");

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
