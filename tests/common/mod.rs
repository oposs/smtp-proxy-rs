//! Shared helpers for the integration test binaries. Each binary uses a
//! different subset, so the module as a whole is exempt from dead-code
//! warnings.
#![allow(dead_code)]
pub mod fake_api;
pub mod fake_handler;
pub mod raw_client;
pub mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;

use smtp_proxy::server::{HandlerFactory, ServerConfig};

pub fn test_tls() -> Arc<rustls::ServerConfig> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs");
    ServerConfig::load_tls(&dir.join("server.crt"), &dir.join("server.key")).unwrap()
}

pub fn server_config(require_starttls: bool, require_auth: bool) -> ServerConfig {
    ServerConfig {
        service_name: "test.service.name".into(),
        require_starttls,
        require_auth,
        tls: Some(test_tls()),
        max_message_size: 1 << 30,
        smtplog: None,
        tls_idle_timeout: std::time::Duration::from_secs(600),
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
