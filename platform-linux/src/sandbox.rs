//! Filesystem and syscall sandboxing via Landlock and seccomp-bpf.
//!
//! [`apply_sandbox`] applies Landlock, then seccomp. Order matters:
//! Landlock setup requires syscalls the seccomp filter blocks.
//!
//! Landlock: unprivileged filesystem, network, and IPC sandboxing. The
//! ruleset requests every access right and scope of Landlock ABI 10
//! (Linux 7.2) best-effort, as the kernel's Landlock documentation and the
//! landlock crate prescribe: the running kernel enforces the part it
//! supports, so a newer kernel tightens the sandbox with no change here
//! and an older one runs under its own subset. What the kernel does not
//! enforce is a `core_types::SandboxProtection` reported by
//! [`landlock_gaps`], at startup and by `sesame status --doctor`; the
//! protections a configuration requires (`[global.sandbox] require`) are a
//! hard requirement, and a kernel lacking one is refused. Below ABI 9
//! (Linux 7.1) Landlock does not mediate `connect(2)` to pathname Unix
//! sockets: a sandboxed process reaches every such socket on the system,
//! the session D-Bus bus (and through it systemd's `StartTransientUnit`)
//! among them, where the unit's `InaccessiblePaths=-%t/bus` does not hide
//! it.
//! seccomp-bpf: syscall filtering via libseccomp (C library); sockets of
//! any family but `AF_UNIX` kill the process.

use core_types::SandboxProtection;
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, LandlockStatus,
    PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
    Scope,
};

/// The Landlock ABI the ruleset is written against: every right and scope
/// it defines is requested. Raising it requests the next ABI's rights; the
/// `SandboxProtection` table then names them (a test checks that the table
/// covers every requested right).
const SANDBOX_ABI: ABI = ABI::V10;

/// The Landlock rights and scopes that make `protection`.
fn rights(
    protection: SandboxProtection,
) -> (BitFlags<AccessFs>, BitFlags<AccessNet>, BitFlags<Scope>) {
    let none = (BitFlags::EMPTY, BitFlags::EMPTY, BitFlags::EMPTY);
    match protection {
        SandboxProtection::Filesystem => (AccessFs::from_all(ABI::V1), none.1, none.2),
        SandboxProtection::Reparenting => (AccessFs::Refer.into(), none.1, none.2),
        SandboxProtection::Truncation => (AccessFs::Truncate.into(), none.1, none.2),
        SandboxProtection::Tcp => (none.0, AccessNet::from_all(ABI::V4), none.2),
        SandboxProtection::DeviceIoctl => (AccessFs::IoctlDev.into(), none.1, none.2),
        SandboxProtection::Scopes => (none.0, none.1, Scope::from_all(ABI::V6)),
        SandboxProtection::PathnameSockets => (AccessFs::ResolveUnix.into(), none.1, none.2),
        SandboxProtection::Udp => (
            none.0,
            AccessNet::BindUdp | AccessNet::ConnectSendUdp,
            none.2,
        ),
    }
}

/// `ruleset` also handling `protection`'s rights under its current
/// compatibility level.
fn handle(ruleset: Ruleset, protection: SandboxProtection) -> Result<Ruleset, RulesetError> {
    let (fs, net, scope) = rights(protection);
    let ruleset = if fs.is_empty() {
        ruleset
    } else {
        ruleset.handle_access(fs)?
    };
    let ruleset = if net.is_empty() {
        ruleset
    } else {
        ruleset.handle_access(net)?
    };
    if scope.is_empty() {
        Ok(ruleset)
    } else {
        ruleset.scope(scope)
    }
}

/// Whether the running kernel enforces `protection`: a ruleset handling its
/// rights as a hard requirement can be built. Builds nothing in the kernel
/// and restricts nothing.
fn enforced(protection: SandboxProtection) -> bool {
    handle(
        Ruleset::default().set_compatibility(CompatLevel::HardRequirement),
        protection,
    )
    .is_ok()
}

/// The protections the running kernel does not enforce, in ABI order:
/// empty on Linux 7.2 or later, every protection without Landlock.
/// Restricts nothing.
#[must_use]
pub fn landlock_gaps() -> Vec<SandboxProtection> {
    SandboxProtection::ALL
        .into_iter()
        .filter(|protection| !enforced(*protection))
        .collect()
}

/// The protections of `required` among `gaps`: a configured floor the
/// kernel does not meet.
#[must_use]
pub fn unmet(required: &[SandboxProtection], gaps: &[SandboxProtection]) -> Vec<SandboxProtection> {
    SandboxProtection::ALL
        .into_iter()
        .filter(|p| required.contains(p) && gaps.contains(p))
        .collect()
}

/// The status [`apply_landlock`] returns on a kernel with `gaps`.
#[must_use]
pub fn landlock_enforcement(gaps: &[SandboxProtection]) -> EnforcementStatus {
    if gaps.is_empty() {
        EnforcementStatus::FullyEnforced
    } else if gaps.contains(&SandboxProtection::Filesystem) {
        EnforcementStatus::NotEnforced
    } else {
        EnforcementStatus::PartiallyEnforced
    }
}

/// Filesystem access rights for Landlock rules.
#[derive(Debug, Clone, Copy)]
pub enum FsAccess {
    ReadOnly,
    ReadWrite,
    /// Read-write for non-directory paths (sockets, regular files).
    /// Excludes directory-only flags (`ReadDir`, `MakeDir`, etc.) that would
    /// cause landlock to report `PartiallyEnforced` on non-directory fds.
    ReadWriteFile,
    Execute,
}

/// A single Landlock filesystem rule: path + access rights.
#[derive(Debug, Clone)]
pub struct LandlockRule {
    pub path: std::path::PathBuf,
    pub access: FsAccess,
}

/// How much of the requested ruleset the kernel enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// Every right and scope of Landlock ABI 10: the kernel lacks no
    /// protection.
    FullyEnforced,
    /// The rights and scopes of the kernel's ABI; [`landlock_gaps`] names
    /// the rest.
    PartiallyEnforced,
    /// None: the kernel has no Landlock.
    NotEnforced,
}

impl std::fmt::Display for EnforcementStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FullyEnforced => "fully enforced",
            Self::PartiallyEnforced => "partially enforced",
            Self::NotEnforced => "not enforced",
        })
    }
}

/// Apply the Landlock sandbox with `rules` to the calling thread and the
/// threads it starts afterwards: every protection of `required` as a hard
/// requirement, and every other right and scope of Landlock ABI 10 that the
/// kernel supports.
///
/// Where the kernel enforces the scopes, the sandboxed process can neither
/// connect to an abstract-namespace Unix socket nor signal a process
/// created outside its domain; where it enforces `ResolveUnix`, it reaches
/// only the pathname sockets granted by a rule (`NOTIFY_SOCKET` of the user
/// service manager is `$XDG_RUNTIME_DIR/systemd/notify`). The status is
/// logged with the kernel's ABI and, below full enforcement, what is not
/// enforced.
///
/// Sets `PR_SET_NO_NEW_PRIVS` before `landlock_restrict_self()`. Once
/// applied, the thread cannot gain additional access.
///
/// # Errors
///
/// When the kernel does not enforce a protection of `required`, naming
/// each one, before anything is restricted; when the ruleset cannot be
/// built or applied (a rule's path cannot be opened or inspected, a
/// Landlock system call fails). A kernel's other missing rights are not an
/// error.
pub fn apply_landlock(
    rules: &[LandlockRule],
    required: &[SandboxProtection],
) -> core_types::Result<EnforcementStatus> {
    let abi = SANDBOX_ABI;
    let gaps = landlock_gaps();
    let below = unmet(required, &gaps);
    if !below.is_empty() {
        return Err(core_types::Error::Platform(format!(
            "the kernel does not enforce the sandbox protections the configuration requires \
             ([global.sandbox] require): {}",
            SandboxProtection::describe(&below)
        )));
    }
    let landlock_error = |what: &str, e: RulesetError| {
        core_types::Error::Platform(format!("landlock {what} failed: {e}"))
    };
    // The floor as a hard requirement, then everything else best-effort:
    // the landlock crate's pattern for a minimum with opportunistic
    // additions (`Compatible::set_compatibility`).
    let mut ruleset = required
        .iter()
        .try_fold(
            Ruleset::default().set_compatibility(CompatLevel::HardRequirement),
            |ruleset, protection| handle(ruleset, *protection),
        )
        .map(|r| r.set_compatibility(CompatLevel::BestEffort))
        .and_then(|r| r.handle_access(AccessFs::from_all(abi)))
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.scope(Scope::from_all(abi)))
        .and_then(Ruleset::create)
        .map_err(|e| landlock_error("ruleset", e))?;

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
        // Skip rules for paths that don't exist yet (e.g., vaults directory
        // before `sesame init` creates it). Landlock denies access to any path
        // not in the ruleset, so omitting a missing path is strictly more
        // restrictive than granting it — not a security degradation. A path
        // whose existence cannot be determined is an error, not absent.
        let exists = rule.path.try_exists().map_err(|e| {
            core_types::Error::Platform(format!(
                "landlock: cannot check {}: {e}",
                rule.path.display()
            ))
        })?;
        if !exists {
            tracing::info!(
                path = %rule.path.display(),
                "landlock: skipping rule for non-existent path"
            );
            continue;
        }
        let path_fd = PathFd::new(&rule.path).map_err(|e| {
            core_types::Error::Platform(format!(
                "landlock PathFd::new({}) failed: {e}",
                rule.path.display()
            ))
        })?;
        // fstat the already-open fd to avoid TOCTOU vs the crate's internal stat.
        // Strip directory-only flags on non-directory inodes to prevent the crate's
        // PathBeneath::try_compat_inner from returning PartiallyEnforced.
        let stat = rustix::fs::fstat(&path_fd).map_err(|e| {
            core_types::Error::Platform(format!(
                "landlock fstat({}) failed: {e}",
                rule.path.display()
            ))
        })?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
            access &= access_file;
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd, access))
            .map_err(|e| landlock_error(&format!("add_rule({})", rule.path.display()), e))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| landlock_error("restrict_self", e))?;
    let kernel_abi = match status.landlock {
        LandlockStatus::Available {
            kernel_abi: Some(newer),
            ..
        } => newer.to_string(),
        LandlockStatus::Available { effective_abi, .. } => effective_abi.to_string(),
        LandlockStatus::NotEnabled => "not enabled at boot".to_owned(),
        LandlockStatus::NotImplemented => "not built into the kernel".to_owned(),
    };
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!(%kernel_abi, "landlock: fully enforced");
            EnforcementStatus::FullyEnforced
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!(
                %kernel_abi,
                unenforced = %SandboxProtection::describe(&gaps),
                "landlock: partially enforced; this kernel does not enforce every protection"
            );
            EnforcementStatus::PartiallyEnforced
        }
        RulesetStatus::NotEnforced => {
            tracing::warn!(
                %kernel_abi,
                "landlock: not enforced; the process is confined by seccomp and its unit only"
            );
            EnforcementStatus::NotEnforced
        }
    })
}

/// Predefined seccomp-bpf profile for a daemon.
///
/// Each daemon declares its required syscall set. The profile is translated
/// to a seccomp filter that kills the process on disallowed syscalls.
/// `socket` and `socketpair` are admitted only for `AF_UNIX`: every socket
/// a daemon opens is Unix-domain (the bus, Wayland, SSH agents, D-Bus,
/// systemd notification), so no daemon reaches the network.
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    pub daemon_name: String,
    pub allowed_syscalls: Vec<String>,
}

/// Apply a seccomp-bpf syscall filter to every thread of the process.
///
/// Must be called AFTER `apply_landlock()` — landlock setup requires
/// syscalls that seccomp would block.
///
/// A syscall outside the allow-list, or one made through another
/// architecture's ABI, kills the whole process (`SECCOMP_RET_KILL_PROCESS`).
/// Killing only the offending thread would leave the daemon running without
/// it, and returning an error (`Errno`, `Log`) would let a compromised
/// process probe the allow-list. No signal handler runs; the kernel records
/// the kill with the syscall number in the audit log (`type=SECCOMP`) when
/// `kill_process` is listed in `/proc/sys/kernel/seccomp/actions_logged`.
///
/// The filter is synchronized onto every existing thread (`TSYNC`): threads
/// started before this call (the async runtime's workers and blocking pool)
/// are filtered too, and a thread that cannot be synchronized fails the
/// load.
///
/// # Errors
///
/// `core_types::Error::Platform` when a syscall name is unknown or the
/// filter cannot be built or loaded; the daemon must not start unfiltered.
pub fn apply_seccomp(profile: &SeccompProfile) -> core_types::Result<()> {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall, scmp_cmp};

    /// The calls that create sockets, admitted for `AF_UNIX` (argument 0)
    /// only.
    const SOCKET_CALLS: [&str; 2] = ["socket", "socketpair"];
    let unix_only = [scmp_cmp!($arg0 == u64::from(rustix::net::AddressFamily::UNIX.as_raw()))];

    let filter_error = |what: &str, e: libseccomp::error::SeccompError| {
        core_types::Error::Platform(format!("seccomp {what} failed: {e}"))
    };
    let mut filter =
        ScmpFilterContext::new(ScmpAction::KillProcess).map_err(|e| filter_error("init", e))?;
    filter
        .set_act_badarch(ScmpAction::KillProcess)
        .map_err(|e| filter_error("bad-architecture action", e))?;
    filter
        .set_ctl_tsync(true)
        .map_err(|e| filter_error("thread synchronization", e))?;

    for syscall_name in &profile.allowed_syscalls {
        let syscall = ScmpSyscall::from_name(syscall_name).map_err(|e| {
            core_types::Error::Platform(format!("seccomp unknown syscall '{syscall_name}': {e}"))
        })?;
        let conditions: &[_] = if SOCKET_CALLS.contains(&syscall_name.as_str()) {
            &unix_only
        } else {
            &[]
        };
        filter
            .add_rule_conditional(ScmpAction::Allow, syscall, conditions)
            .map_err(|e| {
                core_types::Error::Platform(format!("seccomp add_rule({syscall_name}) failed: {e}"))
            })?;
    }

    filter.load().map_err(|e| filter_error("load", e))?;

    tracing::info!(
        daemon = %profile.daemon_name,
        allowed_count = profile.allowed_syscalls.len(),
        "seccomp: filter loaded on every thread; other syscalls kill the process"
    );

    Ok(())
}

/// Apply the full sandbox stack for a daemon: Landlock, then seccomp.
///
/// Landlock restricts the calling thread and the threads it starts later,
/// not threads that already exist: call this while the calling thread is
/// the process's only thread (`core_daemon::sandbox::apply` checks).
///
/// # Errors
///
/// When the kernel does not enforce a protection of `required`, or either
/// layer cannot be applied. Callers treat errors as fatal: the daemon does
/// not start below its floor or unsandboxed.
pub fn apply_sandbox(
    landlock_rules: &[LandlockRule],
    required: &[SandboxProtection],
    seccomp_profile: &SeccompProfile,
) -> core_types::Result<EnforcementStatus> {
    let status = apply_landlock(landlock_rules, required)?;
    apply_seccomp(seccomp_profile)?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;

    /// Marks the re-run child and carries what it acts on.
    const CHILD: &str = "PDS_SANDBOX_TEST_CHILD";

    /// A child's exit code: the operation under test succeeded, or was
    /// refused.
    const PERMITTED: i32 = 10;
    const DENIED: i32 = 11;

    const UNGRANTED: &str =
        "sandbox::tests::an_ungranted_pathname_socket_is_refused_where_enforced";
    const GRANTED: &str = "sandbox::tests::a_granted_pathname_socket_is_reachable";
    const FAMILIES: &str = "sandbox::tests::only_unix_domain_sockets_can_be_created";
    const ABSTRACT: &str =
        "sandbox::tests::an_abstract_socket_outside_the_domain_is_refused_where_enforced";
    const STATUS: &str = "sandbox::tests::the_status_is_the_kernels_coverage";

    /// The child exit code of each status `apply_landlock` returns.
    const FULL: i32 = 20;
    const PARTIAL: i32 = 21;
    const NONE: i32 = 22;

    /// The child's exit code for `protection`'s operation: refused where the
    /// kernel enforces it, permitted where it does not.
    fn expected(protection: SandboxProtection) -> i32 {
        if enforced(protection) {
            DENIED
        } else {
            PERMITTED
        }
    }

    /// The calls the seccomp child makes after the filter loads: socket
    /// creation, `bind`, the fd check std makes on a new socket (`fcntl`),
    /// and what process exit and the allocator use.
    const CHILD_SYSCALLS: &[&str] = &[
        "socket",
        "socketpair",
        "bind",
        "fcntl",
        "close",
        "write",
        "brk",
        "mmap",
        "munmap",
        "madvise",
        "futex",
        "rt_sigprocmask",
        "sigaltstack",
        "exit",
        "exit_group",
    ];

    #[expect(
        clippy::disallowed_methods,
        reason = "PDS_SANDBOX_TEST_CHILD is this module's test marker"
    )]
    fn child_input() -> Option<PathBuf> {
        std::env::var_os(CHILD).map(PathBuf::from)
    }

    /// Re-run the test `name` as a child given `input`. Both layers apply
    /// to the process for good, so each test sandboxes a child.
    fn run_child(name: &str, input: &Path) -> ExitStatus {
        std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", name, "--test-threads=1", "--nocapture"])
            .env(CHILD, input)
            .status()
            .expect("run child test")
    }

    /// In the child: connect to `socket` under `rules`, exiting with
    /// whether the connection was permitted.
    fn connect_under(rules: &[LandlockRule], socket: &Path) -> ! {
        apply_landlock(rules, &[]).expect("landlock applies");
        std::process::exit(match UnixStream::connect(socket) {
            Ok(_) => PERMITTED,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => DENIED,
            Err(e) => panic!("connect {}: {e}", socket.display()),
        })
    }

    /// No rule can grant an abstract socket: where the kernel enforces the
    /// scopes (Linux 6.12), every daemon runs with the abstract-socket scope
    /// (Xwayland and some session buses listen on abstract addresses).
    #[test]
    fn an_abstract_socket_outside_the_domain_is_refused_where_enforced() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;

        if let Some(name) = child_input() {
            let addr = SocketAddr::from_abstract_name(name.as_os_str().as_encoded_bytes())
                .expect("abstract address");
            apply_landlock(&[], &[]).expect("landlock applies");
            std::process::exit(match UnixStream::connect_addr(&addr) {
                Ok(_) => PERMITTED,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => DENIED,
                Err(e) => panic!("connect @{}: {e}", name.display()),
            });
        }
        let name = format!("pds-sandbox-test-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
        let _server = UnixListener::bind_addr(&addr).expect("bind abstract server");
        assert_eq!(
            run_child(ABSTRACT, Path::new(&name)).code(),
            Some(expected(SandboxProtection::Scopes))
        );
    }

    /// The child exit code of `status`.
    fn code_of(status: EnforcementStatus) -> i32 {
        match status {
            EnforcementStatus::FullyEnforced => FULL,
            EnforcementStatus::PartiallyEnforced => PARTIAL,
            EnforcementStatus::NotEnforced => NONE,
        }
    }

    /// `apply_landlock` succeeds on every kernel without a floor, and its
    /// status is the one `landlock_enforcement` predicts from the kernel's
    /// gaps.
    #[test]
    fn the_status_is_the_kernels_coverage() {
        if child_input().is_some() {
            std::process::exit(code_of(apply_landlock(&[], &[]).expect("landlock applies")));
        }
        let gaps = landlock_gaps();
        assert_eq!(
            run_child(STATUS, Path::new("status")).code(),
            Some(code_of(landlock_enforcement(&gaps))),
            "gaps: {gaps:?}"
        );
    }

    /// A floor the kernel meets is enforced as a hard requirement; one it
    /// does not meet is refused before anything is restricted, naming the
    /// unmet protections.
    #[test]
    fn a_floor_is_enforced_or_refused() {
        let gaps = landlock_gaps();
        let met: Vec<SandboxProtection> = SandboxProtection::ALL
            .into_iter()
            .filter(|p| !gaps.contains(p))
            .collect();
        assert!(unmet(&met, &gaps).is_empty());
        let floor = met.iter().try_fold(
            Ruleset::default().set_compatibility(CompatLevel::HardRequirement),
            |ruleset, protection| handle(ruleset, *protection),
        );
        assert!(floor.is_ok(), "{floor:?}");
        if let Some(missing) = gaps.first() {
            let error = apply_landlock(&[], &[*missing]).unwrap_err().to_string();
            assert!(error.contains(missing.name()), "{error}");
        }
    }

    #[test]
    fn unmet_is_the_floor_the_gaps_cover() {
        use SandboxProtection::{Filesystem, PathnameSockets, Scopes, Udp};
        assert_eq!(
            unmet(
                &[Udp, PathnameSockets, Filesystem],
                &[Scopes, PathnameSockets, Udp]
            ),
            [PathnameSockets, Udp]
        );
        assert!(unmet(&[Filesystem], &[Udp]).is_empty());
        assert!(unmet(&[], &SandboxProtection::ALL).is_empty());
        assert_eq!(landlock_enforcement(&[]), EnforcementStatus::FullyEnforced);
        assert_eq!(
            landlock_enforcement(&[Udp]),
            EnforcementStatus::PartiallyEnforced
        );
        assert_eq!(
            landlock_enforcement(&SandboxProtection::ALL),
            EnforcementStatus::NotEnforced
        );
    }

    /// The table names every right and scope the ruleset requests, each
    /// once: a raised `SANDBOX_ABI` fails here until its rights are named.
    #[test]
    fn the_protections_are_every_requested_right_once() {
        let (mut fs, mut net, mut scope) = (
            BitFlags::<AccessFs>::EMPTY,
            BitFlags::<AccessNet>::EMPTY,
            BitFlags::<Scope>::EMPTY,
        );
        for protection in SandboxProtection::ALL {
            let (f, n, s) = rights(protection);
            assert!(
                (fs & f).is_empty() && (net & n).is_empty() && (scope & s).is_empty(),
                "{protection:?} repeats a right"
            );
            assert!(
                !(f.is_empty() && n.is_empty() && s.is_empty()),
                "{protection:?} has no right"
            );
            fs |= f;
            net |= n;
            scope |= s;
        }
        assert_eq!(fs, AccessFs::from_all(SANDBOX_ABI));
        assert_eq!(net, AccessNet::from_all(SANDBOX_ABI));
        assert_eq!(scope, Scope::from_all(SANDBOX_ABI));
    }

    /// A kernel enforces a protection only with every earlier one (each
    /// ABI includes the previous): the gaps are a suffix of the table.
    #[test]
    fn the_gaps_are_the_protections_after_the_kernels_last() {
        let gaps = landlock_gaps();
        let all = SandboxProtection::ALL;
        assert_eq!(gaps.as_slice(), &all[all.len() - gaps.len()..]);
    }

    #[test]
    fn an_ungranted_pathname_socket_is_refused_where_enforced() {
        if let Some(socket) = child_input() {
            connect_under(&[], &socket);
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("server.sock");
        let _server = UnixListener::bind(&socket).expect("bind server");
        assert_eq!(
            run_child(UNGRANTED, &socket).code(),
            Some(expected(SandboxProtection::PathnameSockets))
        );
    }

    #[test]
    fn a_granted_pathname_socket_is_reachable() {
        if let Some(socket) = child_input() {
            let rule = LandlockRule {
                path: socket.clone(),
                access: FsAccess::ReadWriteFile,
            };
            connect_under(&[rule], &socket);
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("server.sock");
        let _server = UnixListener::bind(&socket).expect("bind server");
        assert_eq!(run_child(GRANTED, &socket).code(), Some(PERMITTED));
    }

    /// The child creates an `AF_UNIX` socket, then (given `inet`) an
    /// `AF_INET` one. The `unix` run proves the filter admits everything
    /// before the `AF_INET` call, so the `inet` run's kill is that call.
    #[test]
    fn only_unix_domain_sockets_can_be_created() {
        if let Some(phase) = child_input() {
            apply_seccomp(&SeccompProfile {
                daemon_name: "sandbox-test".into(),
                allowed_syscalls: CHILD_SYSCALLS.iter().map(|s| (*s).to_owned()).collect(),
            })
            .expect("seccomp loads");
            drop(UnixDatagram::unbound().expect("an AF_UNIX socket is created"));
            if phase == Path::new("unix") {
                std::process::exit(PERMITTED);
            }
            let inet = std::net::UdpSocket::bind("127.0.0.1:0");
            std::process::exit(if inet.is_ok() { PERMITTED } else { DENIED });
        }
        assert_eq!(
            run_child(FAMILIES, Path::new("unix")).code(),
            Some(PERMITTED),
            "the filter admits the child's calls up to the AF_INET socket"
        );
        let status = run_child(FAMILIES, Path::new("inet"));
        assert_eq!(
            status.signal(),
            Some(rustix::process::Signal::SYS.as_raw()),
            "socket(AF_INET) kills the process: {status}"
        );
    }
}
