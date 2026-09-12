//! Accept loop: one task per client connection.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{Instrument, debug, info};

use crate::server::{HandlerFactory, ServerConfig, session};
use crate::smtp::reply::Reply;

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

/// Total and per-IP concurrent connection limits (spec 9.2). Built once and
/// shared by every listener task, so the total limit applies across all
/// listen addresses.
///
/// `0` means unlimited for either limit, hence `total` being an `Option`:
/// with no cap there is nothing for a semaphore to enforce.
pub struct ConnectionLimits {
    total: Option<Arc<Semaphore>>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    per_ip_max: usize,
}

impl ConnectionLimits {
    pub fn new(max_connections: usize, max_connections_per_ip: usize) -> Self {
        Self {
            total: (max_connections != 0).then(|| Arc::new(Semaphore::new(max_connections))),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            per_ip_max: max_connections_per_ip,
        }
    }

    /// Tries to reserve one slot for `ip`. On success, the returned permit
    /// releases both counters when it is dropped. This happens whenever
    /// tokio drops the session task's future -- on normal completion, on a
    /// panic inside it, and on `JoinHandle::abort()` -- because in every one
    /// of those cases tokio's own task harness (`poll_future`'s `Guard`,
    /// which runs on unwind too) calls `drop_future_or_output()` on the
    /// task's stored future, and `_permit` sits in that future's state,
    /// not on any stack frame. A future graceful-drain rewrite of this
    /// accept loop that aborts idle sessions is therefore still covered.
    pub fn try_acquire(&self, ip: IpAddr) -> Result<ConnectionPermit, &'static str> {
        let total = match &self.total {
            Some(sem) => match Arc::clone(sem).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return Err("total"),
            },
            None => None,
        };
        if self.per_ip_max != 0 {
            let mut counts = self.per_ip.lock().unwrap();
            let count = counts.entry(ip).or_insert(0);
            if *count >= self.per_ip_max {
                // `total` (if any) drops here, releasing the slot it just
                // reserved -- this connection is refused after all.
                return Err("per-ip");
            }
            *count += 1;
        }
        Ok(ConnectionPermit {
            _total: total,
            per_ip: self.per_ip.clone(),
            ip,
            counted: self.per_ip_max != 0,
        })
    }
}

/// Held for the lifetime of one connection. Dropping it releases the total
/// semaphore slot (via `_total`'s own `Drop`) and decrements -- removing the
/// entry at zero -- the per-IP count.
pub struct ConnectionPermit {
    _total: Option<OwnedSemaphorePermit>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
    counted: bool,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut counts = self.per_ip.lock().unwrap();
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

pub async fn serve<F: HandlerFactory>(
    listeners: Vec<TcpListener>,
    config: Arc<ServerConfig>,
    factory: F,
) {
    let limits = Arc::new(ConnectionLimits::new(
        config.max_connections,
        config.max_connections_per_ip,
    ));
    let mut tasks = tokio::task::JoinSet::new();
    for listener in listeners {
        let config = config.clone();
        let factory = factory.clone();
        let limits = limits.clone();
        tasks.spawn(async move {
            loop {
                let (mut stream, client) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!("accept failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // --- connection limit gate (spec 9.2) -----------------------
                // Total and per-IP caps, checked before the session is ever
                // spawned. Task 19 rewrites this accept loop into a
                // `tokio::select!` for graceful drain: keep this block intact
                // across that rewrite, permit and all.
                let permit = match limits.try_acquire(client.ip()) {
                    Ok(p) => p,
                    Err(which) => {
                        info!("Connection limit reached ({which}) for {client}");
                        let reply = Reply::new(
                            421,
                            format!(
                                "{} Too many connections, try again later",
                                config.service_name
                            ),
                        )
                        .wire();
                        tokio::spawn(async move {
                            let _ = stream.write_all(reply.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        });
                        continue;
                    }
                };
                // --- end connection limit gate ------------------------------
                let id = new_connection_id();
                let span = tracing::info_span!("conn", cid = %id);
                let handler = factory.create(client, &id);
                let config = config.clone();
                tokio::spawn(
                    async move {
                        // Held until the session ends, so the permit's Drop
                        // releases both counters at that point.
                        let _permit = permit;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Pins the invariant a refusal depends on: `or_insert(0)` inside
    /// `try_acquire` can never itself trip `count >= per_ip_max` (that
    /// branch only runs when `per_ip_max != 0`), so a refused connection
    /// never leaves an orphan zero entry behind, and every granted permit's
    /// release brings the count back down to exactly zero -- removing the
    /// map entry rather than leaving it to accumulate.
    #[test]
    fn per_ip_map_is_empty_once_every_permit_drops() {
        let limits = ConnectionLimits::new(0, 2);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let p1 = limits.try_acquire(ip).unwrap();
        let p2 = limits.try_acquire(ip).unwrap();
        assert_eq!(limits.try_acquire(ip).err(), Some("per-ip"));
        assert_eq!(limits.per_ip.lock().unwrap().get(&ip), Some(&2));

        drop(p1);
        assert_eq!(limits.per_ip.lock().unwrap().get(&ip), Some(&1));
        drop(p2);
        assert!(limits.per_ip.lock().unwrap().is_empty());
    }
}
