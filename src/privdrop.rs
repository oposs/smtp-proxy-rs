//! Drop root after binding the listen ports.
use nix::unistd::{User, setgid, setuid};

/// `setgid` then `setuid` to `user`, resolved with `getpwnam` (spec 9). The
/// group goes first: after `setuid` the process can no longer change it.
pub fn drop_to(user: &str) -> anyhow::Result<()> {
    // `getpwnam` reports "no such user" as `Ok(None)`, but an unreadable or
    // missing `/etc/passwd` is an errno. A `FROM scratch` image without the
    // file took that second path and aborted the start with a bare `ENOENT`
    // that named neither the user nor the operation.
    let entry = User::from_name(user)
        .map_err(|e| anyhow::anyhow!("Cannot resolve username '{user}': {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Cannot resolve username '{user}'"))?;
    setgid(entry.gid).map_err(|e| anyhow::anyhow!("Failed to setgid to {}: {e}", entry.gid))?;
    setuid(entry.uid).map_err(|e| anyhow::anyhow!("Failed to setuid to {}: {e}", entry.uid))?;
    tracing::info!("Dropped privileges to user {user}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unresolvable name fails before `setgid`/`setuid` are reached, so
    /// this needs no root and changes nothing about the test process. The
    /// successful drop is deliberately not tested: it is irreversible and
    /// would poison every later test in the binary.
    #[test]
    fn unknown_user_is_reported_by_name() {
        let e = drop_to("no-such-user-xyz").unwrap_err();
        assert!(e.to_string().contains("Cannot resolve username"), "{e:#}");
    }
}
