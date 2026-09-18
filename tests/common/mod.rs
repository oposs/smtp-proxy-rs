//! Shared helpers for the integration test binaries. Each binary uses a
//! different subset, so the module as a whole is exempt from dead-code
//! warnings.
#![allow(dead_code)]
pub mod certs;
pub mod fake_api;
pub mod fake_handler;
pub mod raw_client;
pub mod upstream;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::prelude::*;

use fake_api::FakeApi;
use smtp_proxy::api::ApiClient;
use smtp_proxy::proxy::{ProxyConfig, ProxyFactory};
use smtp_proxy::relay::RelayConfig;
use smtp_proxy::server::{HandlerFactory, ServerConfig};
use upstream::RecordingUpstream;

pub fn test_tls() -> Arc<rustls::ServerConfig> {
    let dir = certs::dir();
    ServerConfig::load_tls(&dir.join("server.crt"), &dir.join("server.key")).unwrap()
}

pub fn server_config(require_starttls: bool, require_auth: bool) -> ServerConfig {
    ServerConfig {
        service_name: "test.service.name".into(),
        require_starttls,
        require_auth,
        tls: Some(test_tls()),
        max_header_size: 1 << 20,
        smtplog: None,
        idle_timeout: std::time::Duration::from_secs(600),
        // The production default is 30 s. Tests that care about the
        // greeting deadline set their own; the rest must not have a
        // 30 s clock running under them.
        greeting_timeout: std::time::Duration::from_secs(600),
        max_connections: 0,
        max_connections_per_ip: 0,
        max_recipients: 0,
        drain: None,
    }
}

/// Binds an ephemeral port, spawns the server, returns its address.
pub async fn start_server<F: HandlerFactory>(config: ServerConfig, factory: F) -> SocketAddr {
    let listeners = smtp_proxy::server::listener::bind(&["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    let addr = listeners[0].local_addr().unwrap();
    tokio::spawn(smtp_proxy::server::listener::serve(
        listeners,
        Arc::new(config),
        factory,
    ));
    addr
}

pub struct Rig {
    pub api: FakeApi,
    pub upstream: RecordingUpstream,
    pub factory: ProxyFactory,
    pub addr: std::net::SocketAddr,
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
///
/// One subscriber per *binary* is all the process allows, so a binary that
/// installs its own -- `tests/api.rs` keeps a private copy of this -- must
/// not also call this one: the second `set_global_default` panics on the
/// `expect` below.
pub fn captured_log() -> &'static Mutex<Vec<u8>> {
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

pub async fn rig(upstream_extensions: &[&str]) -> Rig {
    rig_relaying_to(upstream_extensions, None).await
}

/// [`rig`] with the relay pointed somewhere other than the recording
/// upstream, so that a test can see what the proxy answers when there is
/// nothing at the other end at all.
pub async fn rig_relaying_to(upstream_extensions: &[&str], relay_port: Option<u16>) -> Rig {
    captured_log();
    let api = FakeApi::start().await;
    let upstream = RecordingUpstream::start(upstream_extensions).await;
    let factory = ProxyFactory::new(ProxyConfig {
        api: ApiClient::new(api.url.clone()).unwrap(),
        relay: RelayConfig {
            host: "127.0.0.1".into(),
            port: relay_port.unwrap_or_else(|| upstream.addr.port()),
            timeout: std::time::Duration::from_secs(5),
            tls: smtp_proxy::relay::UpstreamTls::off(),
            tls_server_name: None,
        },
        // Unlimited, so that the rate limit is exercised only where a test
        // says so and never silently caps another test's mails.
        messages_per_minute: 0,
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
