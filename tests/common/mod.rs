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
use std::sync::Arc;

use smtp_proxy::server::{HandlerFactory, ServerConfig};

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
