//! Connection limits (spec 9.2), and message rate and recipient limits
//! (spec 9.3).
mod common;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};

#[tokio::test]
async fn total_connection_limit() {
    let mut config = server_config(false, false);
    config.max_connections = 2;
    let addr = start_server(config, ScriptedFactory::default()).await;
    let (_c1, g1) = RawClient::connect(addr).await;
    let (_c2, g2) = RawClient::connect(addr).await;
    assert!(g1.starts_with("220") && g2.starts_with("220"));
    let (mut c3, g3) = RawClient::connect(addr).await;
    assert_eq!(
        g3,
        "421 test.service.name Too many connections, try again later\r\n"
    );
    assert!(c3.expect_close().await);

    // Dropping _c1 releases its slot in the total-connection semaphore only
    // once the server's read on that socket returns EOF -- not instantly,
    // and not within any fixed delay this test could safely assume on a
    // loaded host. Poll for the release instead of sleeping a guessed
    // margin: a fixed sleep here would either go vacuous (padded so wide it
    // never proves the release is timely) on a fast host or flaky on a slow
    // one, and this project has been burned by exactly that kind of test
    // before.
    drop(_c1);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let (c4, g4) = RawClient::connect(addr).await;
        if g4.starts_with("220") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "slot was not freed within 5s of dropping a connection"
        );
        drop(c4);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn per_ip_connection_limit() {
    let mut config = server_config(false, false);
    config.max_connections_per_ip = 1;
    let addr = start_server(config, ScriptedFactory::default()).await;
    let (_c1, g1) = RawClient::connect(addr).await;
    assert!(g1.starts_with("220"));
    let (_c2, g2) = RawClient::connect(addr).await;
    assert!(g2.starts_with("421"));
}

#[tokio::test]
async fn per_ip_slot_is_released_after_quit() {
    let mut config = server_config(false, false);
    config.max_connections_per_ip = 1;
    let addr = start_server(config, ScriptedFactory::default()).await;
    let (mut c1, g1) = RawClient::connect(addr).await;
    assert!(g1.starts_with("220"));
    let quit_reply = c1.command("QUIT").await;
    assert!(quit_reply.starts_with("221"));
    assert!(c1.expect_close().await);
    drop(c1);

    // Same reasoning as `total_connection_limit`'s poll: the permit
    // releases once the session task notices QUIT closed the connection,
    // not on any margin this test could safely guess.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let (c2, g2) = RawClient::connect(addr).await;
        if g2.starts_with("220") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "per-ip slot was not freed within 5s of QUIT"
        );
        drop(c2);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn zero_means_unlimited() {
    let mut config = server_config(false, false);
    config.max_connections = 0;
    config.max_connections_per_ip = 0;
    let addr = start_server(config, ScriptedFactory::default()).await;
    let mut clients = Vec::new();
    for _ in 0..20 {
        let (c, g) = RawClient::connect(addr).await;
        assert!(g.starts_with("220"));
        clients.push(c);
    }
}

#[tokio::test]
async fn recipient_limit_answers_452_and_keeps_the_transaction() {
    let mut config = server_config(false, false);
    config.max_recipients = 2;
    let factory = ScriptedFactory::default();
    let addr = start_server(config, factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<1@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<2@b.com>").await, "250 OK\r\n");
    assert_eq!(
        c.command("RCPT TO:<3@b.com>").await,
        "452 4.5.3 Too many recipients\r\n"
    );
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("S: x\r\n\r\n.\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));
    // The handler never heard about the third recipient, so the message goes
    // to the two the transaction kept.
    assert_eq!(factory.recorded().rcpt.len(), 2);

    // The cap is per transaction, not per connection: the next MAIL starts
    // over with a full allowance.
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<4@b.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn message_rate_limit_per_username() {
    // Through the real proxy handler, which owns the limiter.
    let api = common::fake_api::FakeApi::start().await;
    let upstream = common::upstream::RecordingUpstream::start(&["DSN"]).await;
    let proxy_config = smtp_proxy::proxy::ProxyConfig {
        api: smtp_proxy::api::ApiClient::new(api.url.clone()).unwrap(),
        relay: smtp_proxy::relay::RelayConfig {
            host: "127.0.0.1".into(),
            port: upstream.addr.port(),
            timeout: std::time::Duration::from_secs(5),
            tls: smtp_proxy::relay::UpstreamTls::off(),
            tls_server_name: None,
        },
        messages_per_minute: 2,
    };
    let factory = smtp_proxy::proxy::ProxyFactory::new(proxy_config);
    let addr = start_server(server_config(true, true), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    c.login("alice", "pw").await;
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RSET").await, "250 OK\r\n");
    assert_eq!(
        c.command("MAIL FROM:<a@b.com>").await,
        "450 4.7.1 Rate limit exceeded, try again later\r\n"
    );
    // The state stays WantMail (spec 9.3), so the session is still usable
    // rather than wedged behind a refused command.
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
    // Another user is not affected.
    let (mut c2, _) = RawClient::connect(addr).await;
    c2.login("bob", "pw").await;
    assert_eq!(c2.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
}
