use std::sync::Arc;
use std::time::Duration;

use smtp_proxy::api::ApiClient;
use smtp_proxy::config::parse_args;
use smtp_proxy::proxy::{ProxyConfig, ProxyFactory};
use smtp_proxy::relay::{RelayConfig, UpstreamTls};
use smtp_proxy::server::{Drain, ServerConfig, listener};
use smtp_proxy::smtplog::SmtpLog;

/// How often the idle rate-limit buckets are swept (spec 9.3).
const RATE_LIMIT_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// A username's bucket is forgotten once it has been idle this long.
const RATE_LIMIT_IDLE: Duration = Duration::from_secs(600);

fn main() {
    let config = parse_args();
    if let Err(e) = smtp_proxy::logging::init(config.logpath.as_deref(), &config.loglevel) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    // Built by hand rather than with `#[tokio::main]` so that the logging
    // is up before anything can log, and so that a configuration error
    // exits before a runtime is even started. The worker count is tokio's
    // default, one per core.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = runtime.block_on(run(config)) {
        tracing::error!("{e:#}");
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

async fn run(config: smtp_proxy::config::Config) -> anyhow::Result<()> {
    let tls = ServerConfig::load_tls(&config.tls_cert, &config.tls_key)?;
    // Before the listeners: a bad CA file or an unusable trust store has to
    // be a startup error, not a surprise on the first message.
    let upstream_tls = UpstreamTls::build(
        config.upstream_tls,
        config.upstream_tls_ca.as_deref(),
        config.upstream_tls_insecure,
    )?;
    let smtplog = match &config.smtplog {
        Some(path) => Some(Arc::new(
            SmtpLog::open(path, config.credentials)
                .map_err(|e| anyhow::anyhow!("Could not open {}: {e}", path.display()))?,
        )),
        None => None,
    };
    let drain = Drain::new();
    let server_config = Arc::new(ServerConfig {
        service_name: "smtp-proxy".into(),
        require_starttls: true,
        require_auth: true,
        tls: Some(tls),
        max_message_size: config.max_message_size,
        smtplog,
        idle_timeout: Duration::from_secs(600),
        // 0 means "no separate greeting deadline", so the ordinary
        // inactivity timeout governs that first wait too -- the same
        // reading of 0 that every other limit here uses.
        greeting_timeout: match config.greeting_timeout {
            0 => Duration::from_secs(600),
            secs => Duration::from_secs(secs),
        },
        max_connections: config.max_connections,
        max_connections_per_ip: config.max_connections_per_ip,
        max_recipients: config.max_recipients,
        drain: Some(drain.clone()),
    });
    let listeners = listener::bind(&config.listen).await?;
    if let Some(user) = &config.user {
        smtp_proxy::privdrop::drop_to(user)?;
    }
    tracing::debug!("Starting smtp-proxy {}", env!("CARGO_PKG_VERSION"));
    let factory = ProxyFactory::new(ProxyConfig {
        api: ApiClient::new(config.api.clone())?,
        relay: RelayConfig {
            host: config.tohost.clone(),
            port: config.toport,
            timeout: Duration::from_secs(60),
            tls: upstream_tls,
            tls_server_name: None,
        },
        messages_per_minute: config.max_messages_per_minute,
    });
    // Spec 9.3: without this the bucket map keeps an entry for every
    // username ever seen. The first tick of an `interval` fires at once, on
    // an empty map, which costs nothing.
    //
    // Deliberately a plain `tokio::spawn` rather than `drain.tracker.spawn`:
    // this loop never ends, so a tracked one would make the drain's wait
    // never return. Only sessions are tracked, which is also what makes
    // `drain.connections()` a connection count. The same goes for the probe
    // below; the runtime drops both when `run` returns.
    let pruner = factory.clone();
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(RATE_LIMIT_PRUNE_INTERVAL);
        loop {
            ticks.tick().await;
            pruner.prune_rate_limits(RATE_LIMIT_IDLE);
        }
    });
    // Spec 6: the probe runs after the privilege drop and does not block
    // accepting connections. A client that connects before the answer is in
    // is simply not offered DSN, exactly as the Perl `probeUpstream` does
    // it -- binding, announcing and serving must never wait on an upstream
    // that may be blackholed rather than merely refusing.
    let probe = factory.clone();
    tokio::spawn(async move { probe.probe_upstream().await });
    // After `bind`, so that `--listen ...:0` reports the port the kernel
    // picked, and after the privilege drop.
    let listen_text: Vec<String> = listeners
        .iter()
        .map(|l| l.local_addr().map(|a| a.to_string()).unwrap_or_default())
        .collect();
    println!("Waiting for connections on {}", listen_text.join(", "));
    println!("Will forward mails to {}:{}", config.tohost, config.toport);
    // Pinned rather than spawned, so that a panic in `serve` itself still
    // reaches this thread as a panic instead of becoming a `JoinError` that
    // nobody reads.
    let mut serve = std::pin::pin!(listener::serve(listeners, server_config, factory));
    tokio::select! {
        // Every listener gave up on its own: there is nothing left to drain.
        // An accept loop only leaves its loop on a drain, so short of one
        // this arm means the loops died, and `ListenerFailed` says at least
        // one of them died by panicking. That has to be a non-zero exit:
        // `Restart=on-failure` in packaging/smtp-proxy.service leaves an
        // exit 0 alone, and the unit then reads as cleanly stopped while no
        // mail is being delivered.
        outcome = &mut serve => return listener_outcome(outcome),
        _ = shutdown_signal() => {}
    }
    // Spec 9.1. Cancelling stops the accept loops -- which closes the
    // listening sockets, so `serve` returns -- and closes every session
    // that is waiting for a command. What is left is the messages already
    // in flight, and those are what the wait is for.
    tracing::info!(
        "Shutting down; draining {} connection(s)",
        drain.connections()
    );
    drain.token.cancel();
    let timeout = (config.drain_timeout != 0).then(|| Duration::from_secs(config.drain_timeout));
    // Carried out of the `select!` because the second arm never sets it: an
    // operator's second signal cuts the drain short before `serve` has been
    // awaited, so there is nothing to report either way.
    let mut outcome = listener::ServeOutcome::Clean;
    tokio::select! {
        drained = async {
            let ended = serve.await;
            (ended, drain.wait_drained(timeout).await)
        } => {
            let (ended, drained) = drained;
            outcome = ended;
            if !drained {
                tracing::warn!("Drain timeout; closing {} connection(s)", drain.connections());
            }
        }
        // A second signal from an operator who is not prepared to wait.
        _ = shutdown_signal() => {}
    }
    // A listener that panicked earlier is still a failure, even though the
    // shutdown itself went to plan.
    listener_outcome(outcome)
}

/// Turns `serve`'s outcome into this process's exit status.
fn listener_outcome(outcome: listener::ServeOutcome) -> anyhow::Result<()> {
    match outcome {
        listener::ServeOutcome::Clean => Ok(()),
        listener::ServeOutcome::ListenerFailed => {
            Err(anyhow::anyhow!("An accept loop ended abnormally"))
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
