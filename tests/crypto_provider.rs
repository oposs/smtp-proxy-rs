//! Pins the rustls crypto provider to ring.
//!
//! Nothing else in the suite reports a regression here in a readable way: a
//! *missing* provider surfaces only as a panic from deep inside reqwest, and a
//! *swapped* provider does not surface at all -- the suite would stay green
//! while aws-lc-rs, and the C toolchain it needs, came back into the build.
//! See the TLS block in `Cargo.toml` for why that must not happen.

use rustls::crypto::CryptoProvider;

/// Guarantee: calling it is enough. No caller has to check a return value, and
/// no caller has to know whether someone else called it first.
#[test]
fn installing_twice_still_leaves_a_default_installed() {
    smtp_proxy::install_crypto_provider();
    smtp_proxy::install_crypto_provider();

    assert!(
        CryptoProvider::get_default().is_some(),
        "no default crypto provider is installed"
    );
}

/// Guarantee: the default that ends up installed is ring's own.
///
/// A `CryptoProvider` carries no name to compare, and ring's marker type is
/// private and zero-sized, so its address proves nothing. What it does carry
/// is its algorithm lists, and those differ between backends: aws-lc-rs offers
/// X25519MLKEM768 and secp521r1 key exchange, which ring has no implementation
/// of. Comparing against `ring::default_provider()` rather than a written-out
/// list keeps this from failing the next time ring gains an algorithm.
#[test]
fn the_installed_default_is_rings_own_provider() {
    smtp_proxy::install_crypto_provider();
    let installed = CryptoProvider::get_default().expect("a default provider is installed");
    let ring = rustls::crypto::ring::default_provider();

    let kx_groups = |p: &CryptoProvider| p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>();
    assert_eq!(
        kx_groups(installed),
        kx_groups(&ring),
        "key exchange groups are not ring's"
    );

    let cipher_suites = |p: &CryptoProvider| {
        p.cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        cipher_suites(installed),
        cipher_suites(&ring),
        "cipher suites are not ring's"
    );
}
