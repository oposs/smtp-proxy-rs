//! Accept loop: one task per client connection.
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{Instrument, debug};

use crate::server::{HandlerFactory, ServerConfig, session};

pub async fn bind(addrs: &[SocketAddr]) -> std::io::Result<Vec<TcpListener>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut listeners = Vec::with_capacity(addrs.len());
    for addr in addrs {
        listeners.push(TcpListener::bind(addr).await?);
    }
    Ok(listeners)
}

/// 32 lowercase hex characters, like Mojo::IOLoop's md5-based ids.
pub fn new_connection_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn serve<F: HandlerFactory>(
    listeners: Vec<TcpListener>,
    config: Arc<ServerConfig>,
    factory: F,
) {
    let mut tasks = tokio::task::JoinSet::new();
    for listener in listeners {
        let config = config.clone();
        let factory = factory.clone();
        tasks.spawn(async move {
            loop {
                let (stream, client) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!("accept failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let id = new_connection_id();
                let span = tracing::info_span!("conn", cid = %id);
                let handler = factory.create(client, &id);
                let config = config.clone();
                tokio::spawn(
                    async move {
                        debug!("New incoming connection from {client}");
                        session::run(stream, client, id, config, handler).await;
                        debug!("connection closed");
                    }
                    .instrument(span),
                );
            }
        });
    }
    while tasks.join_next().await.is_some() {}
}
