//! STARTTLS and AUTH over TLS (spec 4.4, 4.5). Ports of the Perl
//! `connection-lifecycle.t`, `starttls-failure.t`, `smtp-server.t` and
//! `smtplog-redaction.t`.
mod common;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};

#[tokio::test]
async fn starttls_is_required_before_anything_else() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    let r = c.command("EHLO client.example.com").await;
    assert_eq!(
        r,
        "250-test.service.name offers a warm hug of welcome\r\n250-STARTTLS\r\n250 DSN\r\n"
    );
    assert_eq!(
        c.command("MAIL FROM:<a@b.com>").await,
        "530 Must issue a STARTTLS command first\r\n"
    );
    assert_eq!(
        c.command("AUTH PLAIN AAB1AHA=").await,
        "530 Must issue a STARTTLS command first\r\n"
    );
    c.starttls().await;
    let r = c.command("EHLO client.example.com").await;
    assert_eq!(
        r,
        "250-test.service.name offers another warm hug of welcome\r\n250-AUTH PLAIN LOGIN\r\n250 DSN\r\n"
    );
    assert_eq!(
        c.command("MAIL FROM:<a@b.com>").await,
        "530 Authentication required\r\n"
    );
}

#[tokio::test]
async fn auth_plain_and_login_over_tls() {
    let factory = ScriptedFactory::default();
    let addr = start_server(server_config(true, true), factory.clone()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    // RFC 3207 says the client SHOULD re-EHLO; some do not, and AUTH must still work.
    assert_eq!(
        c.auth_plain("user", "pass").await,
        "235 Authentication successful\r\n"
    );
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(
        factory.recorded().auth[0],
        ("".into(), "user".into(), "pass".into())
    );

    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
    assert_eq!(c.command("dXNlcjI=").await, "334 UGFzc3dvcmQ6\r\n");
    assert_eq!(
        c.command("cGFzczI=").await,
        "235 Authentication successful\r\n"
    );
    assert_eq!(
        factory.recorded().auth[1],
        ("".into(), "user2".into(), "pass2".into())
    );

    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(c.command("AUTH PLAIN").await, "334 \r\n");
    assert_eq!(
        c.command("AHVzZXIzAHBhc3Mz").await,
        "235 Authentication successful\r\n"
    );
    assert_eq!(factory.recorded().auth[2].1, "user3");
}

#[tokio::test]
async fn auth_failures() {
    let factory = ScriptedFactory::default();
    factory.set(|s| s.auth_ok = false);
    let addr = start_server(server_config(true, true), factory).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    c.starttls().await;
    assert_eq!(
        c.auth_plain("user", "pass").await,
        "535 Authentication credentials invalid\r\n"
    );
    assert_eq!(
        c.command("AUTH CRAM-MD5").await,
        "504 Authentication mechanism not supported\r\n"
    );
    assert_eq!(
        c.command("AUTH PLAIN not-base64!").await,
        "535 Authentication credentials invalid\r\n"
    );
    assert_eq!(c.command("AUTH PLAIN").await, "334 \r\n");
    assert_eq!(
        c.command("").await,
        "500 confused authentication response\r\n"
    );
    assert_eq!(
        c.command("MAIL FROM:<a@b.com>").await,
        "530 Authentication required\r\n"
    );
}

#[tokio::test]
async fn ehlo_after_auth_keeps_the_session_authenticated() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    c.login("user", "pass").await;
    assert!(c.command("EHLO again").await.starts_with("250"));
    assert_eq!(c.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
}

#[tokio::test]
async fn bytes_sent_before_starttls_are_discarded() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    // A plaintext injection: STARTTLS and a command in the same packet.
    c.write_raw("STARTTLS\r\nNOOP\r\n").await;
    assert_eq!(c.read_reply().await, "220 Go ahead\r\n");
    // The NOOP must not be answered; the next thing the server does is the handshake.
    c.upgrade().await;
    assert_eq!(c.command("NOOP").await, "250 OK\r\n");
}

#[tokio::test]
async fn failed_tls_handshake_closes_the_connection() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("STARTTLS").await, "220 Go ahead\r\n");
    c.write_raw("this is not a TLS ClientHello\r\n").await;
    assert!(c.expect_close_after_failed_handshake().await);
    // The server still accepts new clients.
    let (mut c2, g) = RawClient::connect(addr).await;
    assert!(g.starts_with("220"));
    assert!(c2.command("NOOP").await.starts_with("250"));
}

/// Spec 11.2 calls for a TLS 1.2 handshake test: rustls supports both 1.2
/// and 1.3, and a client pinned to the floor version must still connect.
#[tokio::test]
async fn tls12_only_client_can_handshake() {
    let addr = start_server(server_config(true, true), ScriptedFactory::default()).await;
    let (mut c, _) = RawClient::connect(addr).await;
    assert!(c.command("EHLO x").await.starts_with("250"));
    assert_eq!(c.command("STARTTLS").await, "220 Go ahead\r\n");
    c.upgrade_tls12().await;
    assert!(c.command("EHLO x").await.starts_with("250"));
}

#[tokio::test]
async fn smtplog_redacts_credentials_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    for credentials in [false, true] {
        let path = dir.path().join(format!("smtp-{credentials}.log"));
        let mut config = server_config(true, true);
        config.smtplog = Some(std::sync::Arc::new(
            smtp_proxy::smtplog::SmtpLog::open(&path, credentials).unwrap(),
        ));
        let addr = start_server(config, ScriptedFactory::default()).await;
        // One session with AUTH PLAIN, one with AUTH LOGIN.
        let (mut c, _) = RawClient::connect(addr).await;
        assert!(c.command("EHLO x").await.starts_with("250"));
        c.starttls().await;
        assert!(c.auth_plain("u", "p").await.starts_with("235"));
        c.command("QUIT").await;
        let (mut c, _) = RawClient::connect(addr).await;
        assert!(c.command("EHLO x").await.starts_with("250"));
        c.starttls().await;
        assert_eq!(c.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6\r\n");
        assert!(c.command("dXNlcg==").await.starts_with("334"));
        assert!(c.command("cGFzcw==").await.starts_with("235"));
        c.command("QUIT").await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(">>> EHLO x"));
        assert!(text.contains("<<< 220 Go ahead"));
        assert!(text.contains("<<< 334 VXNlcm5hbWU6"));
        if credentials {
            assert!(text.contains(">>> dXNlcg=="), "{text}");
            assert!(text.contains(">>> cGFzcw=="), "{text}");
        } else {
            assert!(!text.contains("dXNlcg=="), "{text}");
            assert!(!text.contains("cGFzcw=="), "{text}");
            assert!(text.contains(">>> [REDACTED]"), "{text}");
            assert!(text.contains(">>> AUTH PLAIN [REDACTED]"), "{text}");
        }
    }
}
