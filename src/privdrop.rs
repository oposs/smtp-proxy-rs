//! Drop root after binding the listen ports.
use nix::unistd::{User, setgid, setuid};

/// `setgid` then `setuid` to `user`, resolved with `getpwnam` (spec 9). The
/// group goes first: after `setuid` the process can no longer change it.
pub fn drop_to(user: &str) -> anyhow::Result<()> {
    let entry = User::from_name(user)?
        .ok_or_else(|| anyhow::anyhow!("Cannot resolve username '{user}'"))?;
    setgid(entry.gid).map_err(|e| anyhow::anyhow!("Failed to setgid to {}: {e}", entry.gid))?;
    setuid(entry.uid).map_err(|e| anyhow::anyhow!("Failed to setuid to {}: {e}", entry.uid))?;
    tracing::info!("Dropped privileges to user {user}");
    Ok(())
}
