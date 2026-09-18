//! The memory invariant: a gigabyte of mail must not cost a gigabyte of
//! memory.
//!
//! **This binary holds exactly one test, and it must stay that way.**
//! [`peak_rss`] reads `VmHWM`, the high-water mark of the whole *process*,
//! which never falls. The client, the proxy, the fake API and the fake
//! upstream all run inside this one process, so the number only belongs to
//! the proxy because `discard_body` stops the fake from storing the body --
//! and only while nothing else in the binary has ever allocated more. A
//! second `#[tokio::test]` here would pollute the high-water mark of this
//! one, whichever order they ran in, and the assertion would stop meaning
//! what it says. A new memory test belongs in a new test binary.
mod common;

use common::raw_client::RawClient;
use common::rig;

/// Peak RSS, in bytes.
fn peak_rss() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").expect("linux only");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: usize = rest
                .split_ascii_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .expect("VmHWM has a number");
            return kb * 1024;
        }
    }
    panic!("no VmHWM in /proc/self/status");
}

/// A small multiple of what the streaming path actually costs, so that the
/// assertion catches a body being held without tripping over the ordinary
/// jitter of buffers, TLS state and the test runtime.
///
/// Measured baseline: 15 to 16 MiB peak over three runs on 2026-09-18, for
/// the 1024 MiB body below, on a debug build. The same test with
/// `ProxySink::write` accumulating into a `Vec` instead of forwarding peaked
/// at 1034 MiB, so the gap between passing and holding the body is about
/// sixty-fold and the ceiling can sit well clear of both. A later reader who
/// sees 30 or 40 MiB here is looking at drift, not at the body being held.
const PEAK_CEILING: usize = 64 * 1024 * 1024;

const BODY: usize = 1024 * 1024 * 1024; // what --max_message_size used to allow

/// A gigabyte through a proxy that holds none of it.
///
/// The old design held the message about three times over, so this body
/// would have cost roughly 3 GiB. The assertion is the whole point of the
/// streaming rewrite, stated as a number.
#[tokio::test]
async fn a_gigabyte_body_does_not_become_a_gigabyte_of_memory() {
    let r = rig(&["DSN"]).await;
    // Only sets a flag, which the fake reads as each body line arrives --
    // so configuring it after the rig is built is in time. Without it the
    // fake would hold the gigabyte the proxy does not, and the measurement
    // below would be about the fake.
    r.upstream.discard_body();

    let (mut c, _) = RawClient::connect(r.addr).await;
    // The rig's server requires STARTTLS and AUTH, so the body travels
    // encrypted on the client leg. That is the proxy's real configuration;
    // rustls' own buffers are bounded and part of what is being measured.
    c.login("user", "pass").await;
    assert_eq!(c.command("MAIL FROM:<x@y.com>").await, "250 OK\r\n");
    assert_eq!(c.command("RCPT TO:<a@b.com>").await, "250 OK\r\n");
    assert!(c.command("DATA").await.starts_with("354"));
    c.write_raw("Subject: x\r\n\r\n").await;

    // One reused line, so the sender allocates nothing per iteration and
    // the peak measured belongs to the proxy.
    let line = "y".repeat(1022) + "\r\n";
    let mut sent = 0usize;
    while sent < BODY {
        c.write_raw(&line).await;
        sent += line.len();
    }
    c.write_raw(".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"));

    assert!(
        r.upstream.discarded_bytes() >= BODY,
        "the upstream did not receive the body: {} of {BODY} bytes",
        r.upstream.discarded_bytes()
    );

    let peak = peak_rss();
    println!(
        "peak RSS {} MiB for a {} MiB body",
        peak / 1048576,
        BODY / 1048576
    );
    assert!(
        peak < PEAK_CEILING,
        "peak RSS {} MiB exceeds the {} MiB ceiling: the body is being held",
        peak / 1048576,
        PEAK_CEILING / 1048576
    );
}
