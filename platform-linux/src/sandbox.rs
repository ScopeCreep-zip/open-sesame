//! Filesystem and syscall sandboxing via Landlock and seccomp-bpf.
//!
//! Each daemon calls `apply_landlock()` after opening all needed file
//! descriptors, then `apply_seccomp()` to restrict syscalls. Order matters:
//! seccomp is applied AFTER landlock because landlock setup requires
//! syscalls that seccomp would block.
//!
//! Landlock: unprivileged filesystem sandboxing (kernel >= 5.13, ABI V1+).
//! seccomp-bpf: syscall filtering via libseccomp (C library).

use landlock::{
    Access, AccessFs, AccessNet, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};

/// Filesystem access rights for Landlock rules.
#[derive(Debug, Clone, Copy)]
pub enum FsAccess {
    ReadOnly,
    ReadWrite,
    /// Read-write for non-directory paths (sockets, regular files).
    /// Excludes directory-only flags (ReadDir, MakeDir, etc.) that would
    /// cause landlock to report PartiallyEnforced on non-directory fds.
    ReadWriteFile,
    Execute,
}

/// A single Landlock filesystem rule: path + access rights.
#[derive(Debug, Clone)]
pub struct LandlockRule {
    pub path: std::path::PathBuf,
    pub access: FsAccess,
}

/// Result of applying a Landlock ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// All rules enforced at requested ABI level.
    FullyEnforced,
    /// Some rules degraded due to older kernel ABI.
    PartiallyEnforced,
    /// Landlock not available on this kernel.
    NotEnforced,
}

/// Apply Landlock filesystem sandbox with the given rules.
///
/// Calls `landlock_restrict_self()` which implicitly sets `PR_SET_NO_NEW_PRIVS`.
/// Once applied, the process cannot gain additional filesystem access.
///
/// Returns an error if Landlock is not fully enforced — callers MUST treat
/// non-full enforcement as fatal. There is no graceful degradation.
pub fn apply_landlock(rules: &[LandlockRule]) -> core_types::Result<EnforcementStatus> {
    let abi = ABI::V6; // Linux 6.12+: ioctl_dev, scope

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| core_types::Error::Platform(format!("landlock handle_access(fs) failed: {e}")))?
        .handle_access(AccessNet::from_all(abi))
        .map_err(|e| core_types::Error::Platform(format!("landlock handle_access(net) failed: {e}")))?
        .scope(Scope::from_all(abi))
        .map_err(|e| core_types::Error::Platform(format!("landlock scope failed: {e}")))?
        .create()
        .map_err(|e| core_types::Error::Platform(format!("landlock create failed: {e}")))?;

    for rule in rules {
        let access = match rule.access {
            FsAccess::ReadOnly => AccessFs::from_read(abi),
            FsAccess::ReadWrite => AccessFs::from_all(abi),
            FsAccess::ReadWriteFile => AccessFs::from_file(abi),
            FsAccess::Execute => AccessFs::Execute.into(),
        };
        let path_fd = PathFd::new(&rule.path)
            .map_err(|e| core_types::Error::Platform(format!(
                "landlock PathFd::new({}) failed: {e}", rule.path.display()
            )))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd, access))
            .map_err(|e| core_types::Error::Platform(format!(
                "landlock add_rule({}) failed: {e}", rule.path.display()
            )))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| core_types::Error::Platform(format!("landlock restrict_self failed: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("landlock: fully enforced");
            Ok(EnforcementStatus::FullyEnforced)
        }
        RulesetStatus::PartiallyEnforced => {
            Err(core_types::Error::Platform(
                "landlock partially enforced — kernel ABI too old, refusing to run".into(),
            ))
        }
        RulesetStatus::NotEnforced => {
            Err(core_types::Error::Platform(
                "landlock not enforced — kernel does not support landlock, refusing to run".into(),
            ))
        }
    }
}

/// Predefined seccomp-bpf profile for a daemon.
///
/// Each daemon declares its required syscall set. The profile is translated
/// to a seccomp filter that kills the process on disallowed syscalls.
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    pub daemon_name: String,
    pub allowed_syscalls: Vec<String>,
}

/// Apply a seccomp-bpf syscall filter.
///
/// Must be called AFTER `apply_landlock()` — landlock setup requires
/// syscalls that seccomp would block.
///
/// Default action: `KillProcess` for disallowed syscalls. This is the only
/// acceptable action for a secrets daemon — `Errno` or `Log` would allow
/// an attacker to probe for allowed syscalls.
pub fn apply_seccomp(profile: &SeccompProfile) -> core_types::Result<()> {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

    // Default action: kill the process on any disallowed syscall.
    let mut filter = ScmpFilterContext::new(ScmpAction::KillProcess)
        .map_err(|e| core_types::Error::Platform(format!("seccomp new_filter failed: {e}")))?;

    for syscall_name in &profile.allowed_syscalls {
        let syscall = ScmpSyscall::from_name(syscall_name)
            .map_err(|e| core_types::Error::Platform(format!(
                "seccomp unknown syscall '{syscall_name}': {e}"
            )))?;
        filter
            .add_rule(ScmpAction::Allow, syscall)
            .map_err(|e| core_types::Error::Platform(format!(
                "seccomp add_rule({syscall_name}) failed: {e}"
            )))?;
    }

    filter
        .load()
        .map_err(|e| core_types::Error::Platform(format!("seccomp load failed: {e}")))?;

    tracing::info!(
        daemon = %profile.daemon_name,
        allowed_count = profile.allowed_syscalls.len(),
        "seccomp: filter loaded (KillProcess default action)"
    );

    Ok(())
}

/// Apply the full sandbox stack for a daemon: Landlock then seccomp.
///
/// Returns an error if either sandbox layer fails. Callers MUST treat
/// errors as fatal — the daemon MUST NOT start unsandboxed.
pub fn apply_sandbox(
    landlock_rules: &[LandlockRule],
    seccomp_profile: &SeccompProfile,
) -> core_types::Result<EnforcementStatus> {
    let status = apply_landlock(landlock_rules)?;
    apply_seccomp(seccomp_profile)?;
    Ok(status)
}
