//! Process-level security hardening.
//!
//! Called early in daemon startup before any key material is loaded.

use rustix::process::{DumpableBehavior, Resource, Rlimit};

/// Disable core dumps and mark the process as non-dumpable.
///
/// - `PR_SET_DUMPABLE(0)`: Prevents ptrace-attach by non-root processes.
///   Also prevents core dumps from containing process memory.
/// - `RLIMIT_CORE(0,0)`: Belt-and-suspenders with `PR_SET_DUMPABLE`.
///   Prevents core files even if dumpable is re-enabled by setuid.
///
/// Logs errors via tracing but does not fail — these are best-effort hardening.
/// A daemon should still apply Landlock/seccomp even if these calls fail.
pub fn harden_process() {
    if let Err(e) = rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        tracing::error!(
            error = %e,
            "prctl(PR_SET_DUMPABLE, 0) failed — process may be ptrace-attachable"
        );
    }
    if let Err(e) = rustix::process::setrlimit(Resource::Core, fixed(0)) {
        tracing::error!(
            error = %e,
            "setrlimit(RLIMIT_CORE, 0) failed — core dumps may still be enabled"
        );
    }
    tracing::debug!("process hardening applied: non-dumpable, no core dumps");
}

/// A limit whose soft and hard values are both `value`.
fn fixed(value: u64) -> Rlimit {
    Rlimit {
        current: Some(value),
        maximum: Some(value),
    }
}

/// Resource limits for a daemon, applied via setrlimit (POSIX).
///
/// This makes resource limits application-owned rather than solely relying
/// on systemd `LimitNOFILE=`/`LimitMEMLOCK=`. On platforms without systemd
/// (macOS launchd, Windows Task Scheduler, bare metal), the application
/// still enforces its own resource boundaries.
pub struct ResourceLimits {
    /// Maximum open file descriptors (`RLIMIT_NOFILE`).
    pub nofile: u64,
    /// Maximum locked memory in bytes (`RLIMIT_MEMLOCK`). 0 = don't set.
    pub memlock_bytes: u64,
}

/// Apply resource limits via setrlimit.
///
/// Should be called early in daemon startup, before sandbox application.
/// Logs warnings on failure but does not panic — systemd limits provide
/// a fallback on Linux, and the daemon can still run with defaults.
pub fn apply_resource_limits(limits: &ResourceLimits) {
    match rustix::process::setrlimit(Resource::Nofile, fixed(limits.nofile)) {
        Ok(()) => tracing::info!(nofile = limits.nofile, "RLIMIT_NOFILE set"),
        Err(e) => tracing::warn!(
            nofile = limits.nofile,
            error = %e,
            "setrlimit(RLIMIT_NOFILE) failed — using system default"
        ),
    }
    if limits.memlock_bytes > 0 {
        match rustix::process::setrlimit(Resource::Memlock, fixed(limits.memlock_bytes)) {
            Ok(()) => tracing::info!(memlock_bytes = limits.memlock_bytes, "RLIMIT_MEMLOCK set"),
            Err(e) => tracing::warn!(
                memlock_bytes = limits.memlock_bytes,
                error = %e,
                "setrlimit(RLIMIT_MEMLOCK) failed — using system default"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SECURITY INVARIANT: After harden_process(), the process must not be
    // dumpable. PR_GET_DUMPABLE == 0 prevents ptrace-attach by non-root
    // and prevents core dumps from containing process memory.
    #[test]
    fn harden_process_disables_dumpable() {
        harden_process();
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            DumpableBehavior::NotDumpable,
            "process must be non-dumpable after harden_process()"
        );
    }

    // SECURITY INVARIANT: After harden_process(), RLIMIT_CORE must be zero
    // (both soft and hard limits). This prevents core dumps even if dumpable
    // is re-enabled by setuid (belt-and-suspenders).
    #[test]
    fn harden_process_sets_rlimit_core_zero() {
        harden_process();
        assert_eq!(rustix::process::getrlimit(Resource::Core), fixed(0));
    }
}
