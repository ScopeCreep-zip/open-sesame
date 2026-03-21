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
    ABI, Access, AccessFs, AccessNet, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope,
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

/// Scope restrictions for Landlock V6.
///
/// `Full` enables both `AbstractUnixSocket` and `Signal` — use for daemons
/// that do NOT need D-Bus or abstract Unix sockets (e.g., daemon-secrets).
///
/// `SignalOnly` enables only `Signal` — use for daemons that need D-Bus
/// communication via abstract Unix sockets (e.g., daemon-wm with GTK4).
#[derive(Debug, Clone, Copy, Default)]
pub enum LandlockScope {
    /// Block abstract Unix sockets AND cross-process signals.
    #[default]
    Full,
    /// Block cross-process signals only. Allows abstract Unix sockets (D-Bus).
    SignalOnly,
}

/// Apply Landlock filesystem sandbox with the given rules.
///
/// Calls `landlock_restrict_self()` which implicitly sets `PR_SET_NO_NEW_PRIVS`.
/// Once applied, the process cannot gain additional filesystem access.
///
/// Returns an error if Landlock is not fully enforced — callers MUST treat
/// non-full enforcement as fatal. There is no graceful degradation.
pub fn apply_landlock(
    rules: &[LandlockRule],
    scope: LandlockScope,
) -> core_types::Result<EnforcementStatus> {
    // Use highest ABI the crate supports (V6) to handle all access types:
    // V5 IoctlDev, V6 Scope (AbstractUnixSocket, Signal), V4 AccessNet.
    // Kernel V7 is capped to V6 by landlock 0.4.4. Requesting V6 flags
    // with V6 kernel avoids PartiallyEnforced from unhandled access types.
    let abi = ABI::V6;

    let scope_flags: landlock::BitFlags<Scope> = match scope {
        LandlockScope::Full => Scope::from_all(abi),
        LandlockScope::SignalOnly => Scope::Signal.into(),
    };

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| {
            core_types::Error::Platform(format!("landlock handle_access(fs) failed: {e}"))
        })?
        .handle_access(AccessNet::from_all(abi))
        .map_err(|e| {
            core_types::Error::Platform(format!("landlock handle_access(net) failed: {e}"))
        })?
        .scope(scope_flags)
        .map_err(|e| core_types::Error::Platform(format!("landlock scope failed: {e}")))?
        .create()
        .map_err(|e| core_types::Error::Platform(format!("landlock create failed: {e}")))?;

    // File-only access flags: the landlock crate stats each PathBeneath fd and
    // returns PartiallyEnforced if directory-only flags (ReadDir, MakeDir, etc.)
    // are applied to non-directory inodes. We must strip them ourselves.
    let access_file: landlock::BitFlags<AccessFs> = AccessFs::from_file(abi);

    for rule in rules {
        let mut access = match rule.access {
            FsAccess::ReadOnly => AccessFs::from_read(abi),
            FsAccess::ReadWrite => AccessFs::from_all(abi),
            FsAccess::ReadWriteFile => AccessFs::from_file(abi),
            FsAccess::Execute => AccessFs::Execute.into(),
        };
        let path_fd = PathFd::new(&rule.path).map_err(|e| {
            core_types::Error::Platform(format!(
                "landlock PathFd::new({}) failed: {e}",
                rule.path.display()
            ))
        })?;
        // fstat the already-open fd to avoid TOCTOU vs the crate's internal stat.
        // Strip directory-only flags on non-directory inodes to prevent the crate's
        // PathBeneath::try_compat_inner from returning PartiallyEnforced.
        {
            use std::os::unix::io::{AsFd, AsRawFd};
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstat(path_fd.as_fd().as_raw_fd(), &mut stat) };
            if rc == 0 && (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                access &= access_file;
            }
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd, access))
            .map_err(|e| {
                core_types::Error::Platform(format!(
                    "landlock add_rule({}) failed: {e}",
                    rule.path.display()
                ))
            })?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| core_types::Error::Platform(format!("landlock restrict_self failed: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("landlock: fully enforced");
            Ok(EnforcementStatus::FullyEnforced)
        }
        RulesetStatus::PartiallyEnforced => Err(core_types::Error::Platform(
            "landlock partially enforced — kernel ABI too old, refusing to run".into(),
        )),
        RulesetStatus::NotEnforced => Err(core_types::Error::Platform(
            "landlock not enforced — kernel does not support landlock, refusing to run".into(),
        )),
    }
}

/// Install a SIGSYS signal handler that logs the blocked syscall number.
///
/// When seccomp uses `KillThread` (SECCOMP_RET_KILL_THREAD), the kernel
/// sends SIGSYS to the offending thread with `si_syscall` set to the
/// syscall number. This handler writes the number to stderr before the
/// thread dies, giving operators visibility into which syscall to add.
#[allow(unsafe_code)]
fn install_sigsys_handler() {
    /// SIGSYS handler: async-signal-safe only, no allocator.
    ///
    /// Extracts the syscall number from `siginfo_t._sifields._sigsys.si_syscall`
    /// on Linux x86_64. The `si_syscall` field is at byte offset 16 within
    /// the `si_fields` union (offset 0x18 from siginfo_t base on glibc/musl).
    #[allow(unsafe_code)]
    extern "C" fn handler(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
        // SAFETY: signal handler context — only async-signal-safe calls.
        #[allow(unsafe_code)]
        let syscall_nr = unsafe {
            if info.is_null() {
                -1_i32
            } else {
                // On Linux x86_64, si_syscall is at offset 8 within si_value
                // area of siginfo_t. The portable way: cast to bytes and read
                // at the known ABI offset. glibc/musl both place si_syscall
                // at siginfo_t byte offset 0x10 (16) into the union area,
                // which starts at field offset 0x10 from the struct base.
                // Total offset from struct base: 0x20 (32 bytes) on x86_64.
                let base = info.cast::<u8>();
                // si_syscall offset: confirmed by `offsetof(siginfo_t, _sifields._sigsys._syscall)`
                // = 16 (union start) + 8 (after si_call_addr pointer) = 24 from union start
                // = 0x10 (si_fields offset) + 0x18 = 0x28 = 40 bytes from struct start.
                // But actually on glibc x86_64: fields before union are 16 bytes
                // (si_signo:4 + si_errno:4 + si_code:4 + padding:4), union starts at 16.
                // Inside _sigsys: si_call_addr(ptr, 8 bytes) + si_syscall(int, 4 bytes).
                // So si_syscall is at 16 + 8 = 24 bytes from struct start.
                base.add(24).cast::<libc::c_int>().read_unaligned()
            }
        };

        // Format: "SECCOMP VIOLATION: syscall=NNN\n"
        let mut buf = *b"SECCOMP VIOLATION: syscall=          \n";
        let mut n = syscall_nr as u64;
        let mut pos = buf.len() - 2; // before the newline
        if n == 0 {
            buf[pos] = b'0';
        } else {
            while n > 0 {
                buf[pos] = b'0' + (n % 10) as u8;
                n /= 10;
                if pos == 0 {
                    break;
                }
                pos -= 1;
            }
        }
        let start = pos;
        #[allow(unsafe_code)]
        unsafe {
            let _ = libc::write(2, buf[..27].as_ptr().cast(), 27);
            let _ = libc::write(2, buf[start..].as_ptr().cast(), buf.len() - start);
            libc::signal(libc::SIGSYS, libc::SIG_DFL);
            libc::raise(libc::SIGSYS);
        }
    }

    #[allow(unsafe_code)]
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut());
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

    // Install a SIGSYS handler that logs the offending syscall number before
    // the process terminates. KillThread (SECCOMP_RET_KILL_THREAD) sends
    // SIGSYS to the violating thread, allowing the handler to fire.
    // KillProcess would skip the handler entirely.
    install_sigsys_handler();

    let default_action = ScmpAction::KillThread;
    let mut filter = ScmpFilterContext::new(default_action)
        .map_err(|e| core_types::Error::Platform(format!("seccomp new_filter failed: {e}")))?;

    for syscall_name in &profile.allowed_syscalls {
        let syscall = ScmpSyscall::from_name(syscall_name).map_err(|e| {
            core_types::Error::Platform(format!("seccomp unknown syscall '{syscall_name}': {e}"))
        })?;
        filter.add_rule(ScmpAction::Allow, syscall).map_err(|e| {
            core_types::Error::Platform(format!("seccomp add_rule({syscall_name}) failed: {e}"))
        })?;
    }

    filter
        .load()
        .map_err(|e| core_types::Error::Platform(format!("seccomp load failed: {e}")))?;

    tracing::info!(
        daemon = %profile.daemon_name,
        allowed_count = profile.allowed_syscalls.len(),
        default_action = %format!("{default_action:?}"),
        "seccomp: filter loaded"
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
    let status = apply_landlock(landlock_rules, LandlockScope::Full)?;
    apply_seccomp(seccomp_profile)?;
    Ok(status)
}

/// Apply the full sandbox stack with explicit Landlock scope control.
///
/// Use `LandlockScope::SignalOnly` for daemons that need D-Bus (GTK4).
/// Use `LandlockScope::Full` for daemons that do not need D-Bus.
pub fn apply_sandbox_with_scope(
    landlock_rules: &[LandlockRule],
    seccomp_profile: &SeccompProfile,
    scope: LandlockScope,
) -> core_types::Result<EnforcementStatus> {
    let status = apply_landlock(landlock_rules, scope)?;
    apply_seccomp(seccomp_profile)?;
    Ok(status)
}
