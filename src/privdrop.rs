//! Drop root after binding the listen ports.
use std::ffi::{CStr, CString};

use nix::unistd::{Gid, Uid, User, initgroups, setgid, setuid};

/// The three syscalls of a privilege drop, behind a trait so that a test can
/// assert the *order* they are made in. The success path is irreversible --
/// once the process is the unprivileged user it cannot become root again --
/// so it cannot be exercised in the test binary itself.
pub(crate) trait PrivOps {
    fn init_groups(&self, user: &CStr, gid: Gid) -> nix::Result<()>;
    fn set_gid(&self, gid: Gid) -> nix::Result<()>;
    fn set_uid(&self, uid: Uid) -> nix::Result<()>;
}

struct Syscalls;

impl PrivOps for Syscalls {
    fn init_groups(&self, user: &CStr, gid: Gid) -> nix::Result<()> {
        initgroups(user, gid)
    }

    fn set_gid(&self, gid: Gid) -> nix::Result<()> {
        setgid(gid)
    }

    fn set_uid(&self, uid: Uid) -> nix::Result<()> {
        setuid(uid)
    }
}

/// `initgroups`, then `setgid`, then `setuid` to `user`, resolved with
/// `getpwnam` (spec 9). The order is the whole point and it is one-way: after
/// `setuid` the process can change neither its group nor its supplementary
/// groups, and after `setgid` it can no longer call `initgroups`.
///
/// **Divergence from the Perl, approved 2026-09-12.** The Perl drops the
/// group and the user and nothing else (`SMTPProxy.pm:212-217`), so a proxy
/// started as root keeps *root's* supplementary groups for the life of the
/// process -- the user is unprivileged, the group set is not.
///
/// `initgroups` rather than `setgroups(&[])`: it gives the target user
/// exactly the groups they would have on login, which is what a conventional
/// daemon `--user` flag does. Dropping every supplementary group would be
/// more restrictive, but it would silently break an operator who grants
/// read access to a certificate or key file through a group.
pub fn drop_to(user: &str) -> anyhow::Result<()> {
    // `getpwnam` reports "no such user" as `Ok(None)`, but an unreadable or
    // missing `/etc/passwd` is an errno. A `FROM scratch` image without the
    // file took that second path and aborted the start with a bare `ENOENT`
    // that named neither the user nor the operation.
    let entry = User::from_name(user)
        .map_err(|e| anyhow::anyhow!("Cannot resolve username '{user}': {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Cannot resolve username '{user}'"))?;
    drop_with(&Syscalls, user, entry.uid, entry.gid)
}

/// [`drop_to`] once the user is resolved, with the syscalls supplied. `uid`
/// and `gid` are passed rather than the whole `User` so that a test needs no
/// `/etc/passwd` entry to exercise the ordering.
fn drop_with(ops: &dyn PrivOps, user: &str, uid: Uid, gid: Gid) -> anyhow::Result<()> {
    let name =
        CString::new(user).map_err(|e| anyhow::anyhow!("Cannot resolve username '{user}': {e}"))?;
    ops.init_groups(&name, gid)
        .map_err(|e| anyhow::anyhow!("Failed to initgroups for '{user}': {e}"))?;
    ops.set_gid(gid)
        .map_err(|e| anyhow::anyhow!("Failed to setgid to {gid}: {e}"))?;
    ops.set_uid(uid)
        .map_err(|e| anyhow::anyhow!("Failed to setuid to {uid}: {e}"))?;
    tracing::info!("Dropped privileges to user {user}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records what was called instead of calling it, so the ordering is
    /// observable in an unprivileged test process. `fail_at` makes one
    /// operation return an errno, to check that the sequence stops there.
    struct Recorder {
        calls: RefCell<Vec<&'static str>>,
        fail_at: Option<&'static str>,
    }

    impl Recorder {
        fn new(fail_at: Option<&'static str>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_at,
            }
        }

        fn record(&self, what: &'static str) -> nix::Result<()> {
            self.calls.borrow_mut().push(what);
            if self.fail_at == Some(what) {
                return Err(nix::errno::Errno::EPERM);
            }
            Ok(())
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl PrivOps for Recorder {
        fn init_groups(&self, _user: &CStr, _gid: Gid) -> nix::Result<()> {
            self.record("init_groups")
        }

        fn set_gid(&self, _gid: Gid) -> nix::Result<()> {
            self.record("set_gid")
        }

        fn set_uid(&self, _uid: Uid) -> nix::Result<()> {
            self.record("set_uid")
        }
    }

    fn drop_recording(fail_at: Option<&'static str>) -> (Recorder, anyhow::Result<()>) {
        let ops = Recorder::new(fail_at);
        let result = drop_with(&ops, "nobody", Uid::from_raw(65534), Gid::from_raw(65534));
        (ops, result)
    }

    /// The supplementary groups have to go first: `setgid` is the last chance
    /// to call `initgroups`, and `setuid` is the last chance to call either.
    #[test]
    fn privileges_drop_in_the_order_groups_gid_uid() {
        let (ops, result) = drop_recording(None);
        assert!(result.is_ok(), "{:#}", result.unwrap_err());
        assert_eq!(ops.calls(), ["init_groups", "set_gid", "set_uid"]);
    }

    /// A failed `initgroups` must abort the drop rather than carry on and
    /// leave the process running as the unprivileged user with root's groups
    /// -- which is exactly the state this item exists to prevent.
    #[test]
    fn a_failing_initgroups_aborts_before_setgid() {
        let (ops, result) = drop_recording(Some("init_groups"));
        let e = result.unwrap_err();
        assert!(e.to_string().contains("initgroups"), "{e:#}");
        assert_eq!(ops.calls(), ["init_groups"]);
    }

    /// An unresolvable name fails before any of the three is reached, so this
    /// needs no root and changes nothing about the test process. The
    /// successful drop is deliberately not tested through `drop_to`: it is
    /// irreversible and would poison every later test in the binary.
    #[test]
    fn unknown_user_is_reported_by_name() {
        let e = drop_to("no-such-user-xyz").unwrap_err();
        assert!(e.to_string().contains("Cannot resolve username"), "{e:#}");
    }
}
