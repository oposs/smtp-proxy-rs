//! SMTP authentication and header injection proxy.

/// Makes ring the process-wide rustls crypto provider.
///
/// Guarantee: once this returns, `rustls::crypto::CryptoProvider::get_default()`
/// is `Some`, however often and from however many threads it was called.
///
/// Skipping it is not a build error and not a clippy warning -- it is a panic
/// out of `reqwest::ClientBuilder::build`, at runtime, on the first API call.
/// So it has to run before anything that speaks TLS is constructed, and every
/// such construction site is responsible for calling it, not for assuming
/// someone earlier did.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub mod api;
pub mod config;
pub mod logging;
pub mod privdrop;
pub mod proxy;
pub mod ratelimit;
pub mod relay;
pub mod server;
pub mod smtp;
pub mod smtplog;
