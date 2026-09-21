//! Graceful drain on a shutdown signal (spec 9.1).
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::fake_handler::ScriptedFactory;
use common::raw_client::RawClient;
use common::{server_config, start_server};
use smtp_proxy::server::Drain;

const DRAINED: &str =
    "421 test.service.name Service not available, closing transmission channel\r\n";

/// Ten seconds against events that take microseconds, polled every 5 ms:
/// this waits for something to become true rather than guessing how long
/// it takes, and expiry is a failure rather than a quietly skipped
/// assertion. A fixed sleep in its place would go vacuous on a fast host --
/// passing while measuring nothing -- and flaky on a loaded one.
async fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited 10s for {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn idle_sessions_get_421_and_in_flight_messages_finish() {
    let drain = Drain::new();
    let mut config = server_config(false, false);
    config.drain = Some(drain.clone());
    // The handler parks in `message` until this is released, so the drain
    // below provably happens while a message is in flight -- no sleep, and
    // no window that a loaded host can close early.
    let hold = Arc::new(tokio::sync::Notify::new());
    let factory = ScriptedFactory::default();
    factory.set(|s| s.message_hold = Some(hold.clone()));
    let addr = start_server(config, factory.clone()).await;

    let (mut idle, _) = RawClient::connect(addr).await;
    assert!(idle.command("EHLO x").await.starts_with("250"));

    let (mut busy, _) = RawClient::connect(addr).await;
    assert!(busy.command("EHLO x").await.starts_with("250"));
    assert_eq!(busy.command("MAIL FROM:<a@b.com>").await, "250 OK\r\n");
    assert_eq!(busy.command("RCPT TO:<x@y.com>").await, "250 OK\r\n");
    assert!(busy.command("DATA").await.starts_with("354"));
    busy.write_raw("S: x\r\n\r\n.\r\n").await;
    // The wait is on the handler, not on a reply, so the message has to be
    // pushed out by hand.
    busy.flush().await;
    wait_until("the message to reach the handler", || {
        factory.recorded().message_started == 1
    })
    .await;

    drain.token.cancel();

    // The idle session goes now, while the other one is still mid-message.
    assert_eq!(idle.read_reply().await, DRAINED);
    assert!(idle.expect_close().await);
    // `expect_close` sees the socket shut down, which is a moment before
    // the task itself ends, so poll for the count rather than assert it.
    // Stopping at one is the point: the busy session is still tracked, and
    // it cannot have ended, because its handler is parked on a hold this
    // test has not released yet.
    wait_until("the idle session to end", || drain.connections() <= 1).await;
    assert_eq!(
        drain.connections(),
        1,
        "the session whose message is in flight was drained too"
    );

    // And the message that was in flight is answered in full before its
    // session is told the same thing.
    hold.notify_one();
    assert_eq!(busy.read_reply().await, "250 OK: queued\r\n");
    assert_eq!(busy.read_reply().await, DRAINED);
    assert!(busy.expect_close().await);
    assert_eq!(factory.recorded().bodies.len(), 1);

    tokio::time::timeout(Duration::from_secs(10), drain.tracker.wait())
        .await
        .expect("tracker drained");

    // The listening socket went with the accept loop, so nothing new gets in.
    wait_until("the listener to close", || {
        std::net::TcpStream::connect(addr).is_err()
    })
    .await;
}

/// A session that has sent nothing but a partial command line is waiting
/// inside the same read, and must drain rather than sit there until the
/// timeout kills the shutdown.
#[tokio::test]
async fn a_half_written_command_does_not_hold_the_drain() {
    let drain = Drain::new();
    let mut config = server_config(false, false);
    config.drain = Some(drain.clone());
    let addr = start_server(config, ScriptedFactory::default()).await;

    let (mut c, greeting) = RawClient::connect(addr).await;
    assert!(greeting.starts_with("220"));
    c.write_raw("EHL").await;

    drain.token.cancel();
    assert_eq!(c.read_reply().await, DRAINED);
    assert!(c.expect_close().await);
    tokio::time::timeout(Duration::from_secs(10), drain.tracker.wait())
        .await
        .expect("tracker drained");
}

/// A panicking accept loop has to reach the exit code. `serve` used to
/// discard `join_next`'s result, so a `JoinError` looked exactly like a
/// clean finish, `main` returned `Ok(())`, and `Restart=on-failure` in
/// packaging/smtp-proxy.service left the dead unit alone.
///
/// The panic is injected through `HandlerFactory::create`, which the accept
/// loop calls on its own task -- a real panic site on a real path, rather
/// than a fault the test invents. The panic message it prints is expected
/// output, not a failure.
#[tokio::test]
async fn a_panicking_accept_loop_reports_failure() {
    use smtp_proxy::server::listener::{ServeOutcome, bind, serve};

    #[derive(Clone)]
    struct PanicOnCreate;
    impl smtp_proxy::server::HandlerFactory for PanicOnCreate {
        type Handler = common::fake_handler::ScriptedHandler;
        fn create(&self, _client: std::net::SocketAddr, _id: &str) -> Self::Handler {
            panic!("injected accept-loop panic");
        }
    }

    let listeners = bind(&["127.0.0.1:0".parse().unwrap()]).await.unwrap();
    let addr = listeners[0].local_addr().unwrap();
    let serving = tokio::spawn(serve(
        listeners,
        Arc::new(server_config(false, false)),
        PanicOnCreate,
    ));

    // One connection is all it takes: `create` runs before the session is
    // spawned, so the accept loop itself is what dies.
    let _client = tokio::net::TcpStream::connect(addr).await.unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("serve returned after its only accept loop died")
        .expect("serve's own task did not panic");
    assert_eq!(outcome, ServeOutcome::ListenerFailed);
}

/// The case nothing used to surface: with several `--listen` addresses, one
/// panicking accept loop left the survivors running and the process looking
/// healthy while a port was silently closed. `serve` now reports the failure
/// straight away rather than waiting for the other loops -- which, short of a
/// drain, never end -- so the whole proxy goes down and comes back whole.
#[tokio::test]
async fn one_panicking_loop_takes_the_other_listeners_with_it() {
    use smtp_proxy::server::listener::{ServeOutcome, bind, serve};

    #[derive(Clone)]
    struct PanicOnCreate;
    impl smtp_proxy::server::HandlerFactory for PanicOnCreate {
        type Handler = common::fake_handler::ScriptedHandler;
        fn create(&self, _client: std::net::SocketAddr, _id: &str) -> Self::Handler {
            panic!("injected accept-loop panic");
        }
    }

    let listeners = bind(&[
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    ])
    .await
    .unwrap();
    let doomed = listeners[0].local_addr().unwrap();
    let survivor = listeners[1].local_addr().unwrap();
    let serving = tokio::spawn(serve(
        listeners,
        Arc::new(server_config(false, false)),
        PanicOnCreate,
    ));

    // Only the first address is touched, so the second loop is healthy and
    // would otherwise keep `serve` waiting for ever.
    let _client = tokio::net::TcpStream::connect(doomed).await.unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("serve reported the failure without waiting for the healthy loop")
        .expect("serve's own task did not panic");
    assert_eq!(outcome, ServeOutcome::ListenerFailed);

    // The survivor's socket went with its aborted task, so the process is not
    // left half-serving.
    wait_until("the surviving listener to close", || {
        std::net::TcpStream::connect(survivor).is_err()
    })
    .await;
}

/// The control for the test above: without a panic the very same shutdown
/// path reports `Clean`, so `ListenerFailed` is measuring the panic and not
/// merely the fact that `serve` returned.
#[tokio::test]
async fn a_drained_listener_reports_clean() {
    use smtp_proxy::server::listener::{ServeOutcome, bind, serve};

    let drain = Drain::new();
    let mut config = server_config(false, false);
    config.drain = Some(drain.clone());
    let listeners = bind(&["127.0.0.1:0".parse().unwrap()]).await.unwrap();
    let serving = tokio::spawn(serve(
        listeners,
        Arc::new(config),
        ScriptedFactory::default(),
    ));

    drain.token.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("serve returned once the drain stopped its accept loop")
        .expect("serve's own task did not panic");
    assert_eq!(outcome, ServeOutcome::Clean);
}
