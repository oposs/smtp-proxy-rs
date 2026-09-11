//! A self-signed TLS certificate for the tests, generated fresh on first use.
//!
//! Committing a certificate to the repository means committing its private
//! key, and it means the suite starts failing on the day the certificate
//! expires — for a reason the error message does not explain. Nothing in the
//! tests depends on the certificate's identity: `raw_client` installs a
//! verifier that accepts any chain, because these tests exercise our SMTP
//! state machine and not rustls' path validation. So a fresh certificate per
//! run is strictly better than a committed fixture.
//!
//! The files are real files on disk because `tests/cli.rs` starts the actual
//! binary, which takes `--cert` and `--key` as paths.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Directory holding `server.crt` and `server.key`, written on first call.
///
/// One directory per test binary: `cargo test` runs the binaries in sequence
/// today, but a shared path would be a race if that ever changed.
pub fn dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(env!("CARGO_CRATE_NAME"));
        std::fs::create_dir_all(&dir).expect("create the test certificate directory");
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate a self-signed certificate for localhost");
        std::fs::write(dir.join("server.crt"), issued.cert.pem()).expect("write server.crt");
        std::fs::write(dir.join("server.key"), issued.signing_key.serialize_pem())
            .expect("write server.key");
        dir
    })
    .as_path()
}
