//! The operator's stop signals (spec 9.1): SIGTERM and SIGINT.
//!
//! Moved out of `main.rs` so the "a second signal exits at once" contract
//! (`config.rs`, `--drain_timeout` help text) has somewhere to be tested.

use tokio::signal::unix::{Signal, SignalKind, signal};

/// Both stop signals, registered once and waited on repeatedly.
///
/// **One value serves the whole shutdown, and that is the point.** A signal
/// is delivered to the receivers registered at the moment it arrives and to
/// nobody else -- there is no queue a later receiver can read. So a shutdown
/// that built a fresh receiver per wait would be deaf between the two,
/// which is exactly the window the drain handover sits in: the first wait
/// has returned, the log line and `token.cancel()` have yet to run, and an
/// operator's second signal has nowhere to land.
pub struct Signals {
    term: Signal,
    interrupt: Signal,
}

impl Signals {
    /// Registers both handlers. Panics if the process cannot install them,
    /// which at startup is a failure to honour the unit's `ExecStop`.
    pub fn new() -> Self {
        Self {
            term: signal(SignalKind::terminate()).expect("SIGTERM handler"),
            interrupt: signal(SignalKind::interrupt()).expect("SIGINT handler"),
        }
    }

    /// Waits for the next SIGTERM or SIGINT.
    pub async fn recv(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

impl Default for Signals {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// `kill -TERM` on this process, the way `tests/cli.rs` does it, rather
    /// than a new dependency for one call. Safe only once [`Signals::new`]
    /// has run: until tokio installs the handler, SIGTERM still terminates
    /// the test binary.
    fn raise_term() {
        assert!(
            std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    /// Raises SIGTERM and does not return until the runtime has processed
    /// it. **The settling is what gives this test teeth.** Raise and wait in
    /// one step, and a signal still in flight is picked up by whatever
    /// receiver registers next -- which hides a receiver that was built too
    /// late. Settled first, a signal that arrived while nothing was
    /// registered is gone for good, which is the failure being tested for.
    async fn raise_term_and_settle() {
        raise_term();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// The drain handover waits twice, and between the two waits it logs and
    /// cancels. Both waits have to be heard, or the documented escape hatch
    /// -- a second signal for an operator who is not prepared to wait out
    /// the drain -- silently is not one.
    #[tokio::test]
    async fn a_second_signal_is_observed_after_the_first() {
        let mut signals = Signals::new();

        raise_term_and_settle().await;
        tokio::time::timeout(Duration::from_secs(5), signals.recv())
            .await
            .expect("the first signal was never observed");

        raise_term_and_settle().await;
        tokio::time::timeout(Duration::from_secs(5), signals.recv())
            .await
            .expect("the second signal was lost");
    }
}
