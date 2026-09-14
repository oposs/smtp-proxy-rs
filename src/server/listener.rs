//! Accept loop: one task per client connection.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{Instrument, debug, info};

use crate::server::{Drain, HandlerFactory, ServerConfig, session};
use crate::smtp::reply::Reply;

pub async fn bind(addrs: &[SocketAddr]) -> std::io::Result<Vec<TcpListener>> {
    crate::install_crypto_provider();
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
    /// releases both counters when it is dropped. `_permit` lives in the
    /// session task's stored future (it is moved in as `let _permit =
    /// permit;` at the top of that future), not on any stack frame, and
    /// that future is guaranteed to be dropped -- releasing the permit --
    /// whether the session ends normally, panics, or the task is aborted.
    /// The abort case matters here: a future graceful-drain rewrite of this
    /// accept loop that aborts idle sessions is still covered.
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
        // Not `unwrap()`: this runs inside a `Drop`, and a panic there while
        // another panic is unwinding aborts the process outright. The map's
        // invariant does not depend on the poisoning critical section having
        // finished -- every one of them is a single counter edit -- so
        // recovering the guard is strictly better than refusing to release
        // the slot.
        let mut counts = self
            .per_ip
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Resolves when a drain begins, and never when this server has no `Drain`
/// configured -- so the accept loop's `select!` arm on it is simply never
/// taken and the loop behaves as it did before spec 9.1.
async fn cancelled(drain: &Option<Drain>) {
    match drain {
        Some(d) => d.token.cancelled().await,
        None => std::future::pending().await,
    }
}

/// How `serve` ended.
///
/// An accept loop only ever leaves its `loop` on a drain, so in production
/// `serve` returning at all, other than at shutdown, means a task died on
/// its own -- which is exactly the case that used to be invisible.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum ServeOutcome {
    /// Every accept loop ended the way it was asked to.
    Clean,
    /// At least one accept loop panicked; its port is closed and nothing
    /// else in the process notices. The caller has to turn this into a
    /// non-zero exit: with several `--listen` addresses the survivors keep
    /// the process looking healthy, and `Restart=on-failure` in the shipped
    /// systemd unit does nothing about an exit 0.
    ListenerFailed,
}

pub async fn serve<F: HandlerFactory>(
    listeners: Vec<TcpListener>,
    config: Arc<ServerConfig>,
    factory: F,
) -> ServeOutcome {
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
                // Spec 9.1: a drain ends the loop, and dropping `listener`
                // with it closes the port -- new connections are refused
                // while the sessions already running are left to finish.
                // `biased`, so that a listener with a permanent backlog
                // cannot starve the drain; `accept` is cancel-safe, so a
                // connection cannot be lost half-accepted here.
                let accepted = tokio::select! {
                    biased;
                    _ = cancelled(&config.drain) => break,
                    r = listener.accept() => r,
                };
                let (mut stream, client) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!("accept failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // --- connection limit gate (spec 9.2) -----------------------
                // Total and per-IP caps, checked before the session is ever
                // spawned. This block survived the drain rewrite of the
                // accept loop above unchanged, permit and all; keep it that
                // way.
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
                let session_config = config.clone();
                let session = async move {
                    // Held until the session ends, so the permit's Drop
                    // releases both counters at that point.
                    let _permit = permit;
                    debug!("New incoming connection from {client}");
                    session::run(stream, client, id, session_config, handler).await;
                    debug!("connection closed");
                }
                .instrument(span);
                // Tracked, so that shutdown can wait for exactly the live
                // sessions and nothing else.
                match &config.drain {
                    Some(drain) => drain.tracker.spawn(session),
                    None => tokio::spawn(session),
                };
            }
        });
    }
    // Closing only allows `wait` to return once the tracker is empty; it
    // does not stop the loops above from spawning into it.
    if let Some(drain) = &config.drain {
        drain.tracker.close();
    }
    // `join_next` reports a panicked task as `Some(Err(JoinError))`, which
    // the discarded-result form of this loop could not tell from a clean
    // finish. Say so in the log and carry it out to the exit code.
    let mut outcome = ServeOutcome::Clean;
    while let Some(joined) = tasks.join_next().await {
        if let Err(e) = joined {
            tracing::error!("Accept loop ended abnormally: {e}");
            outcome = ServeOutcome::ListenerFailed;
            // Give up the surviving listeners too, rather than serve on with
            // one port silently closed. That partial state is the one nothing
            // surfaces -- the process stays up and looks healthy while mail
            // to the dead address is refused by the kernel -- and waiting for
            // the others to finish would hold this report back until a
            // shutdown that may never come. Returning now makes `main` exit
            // non-zero at once, so `Restart=on-failure` brings back a whole
            // proxy. Sessions already running are not in this `JoinSet`; the
            // process exiting is what ends those.
            tasks.abort_all();
            break;
        }
    }
    outcome
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
