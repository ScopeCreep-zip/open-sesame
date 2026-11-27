//! Filesystem and syscall sandboxing via Landlock and seccomp-bpf.
//!
//! [`apply_sandbox`] applies Landlock, then seccomp. Order matters:
//! Landlock setup requires syscalls the seccomp filter blocks.
//!
//! Landlock: unprivileged filesystem sandboxing; this sandbox handles the
//! Landlock ABI V9 access set (Linux 7.1) and refuses to run on a kernel
//! that enforces only part of it. V9 is the first ABI that restricts
//! `connect(2)` to pathname Unix sockets (`ResolveUnix`); below it, a
//! sandboxed process reaches every such socket on the system, the session
//! D-Bus bus (and through it systemd's `StartTransientUnit`) among them.
//! seccomp-bpf: syscall filtering via libseccomp (C library); sockets of
//! any family but `AF_UNIX` kill the process.

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus, Scope,
};

/// The Landlock ABI whose whole access set the sandbox handles: V4
/// `AccessNet`, V5 `IoctlDev`, V6 scopes, V9 `ResolveUnix` (a pathname
/// socket is reachable only under a rule granting it:
/// `FsAccess::ReadWriteFile` on the socket, or `FsAccess::ReadWrite` on its
/// directory).
const REQUIRED_ABI: ABI = ABI::V9;

/// The ruleset every daemon is sandboxed under, before its rules: every
/// right and scope of [`REQUIRED_ABI`], each a hard requirement, so a
/// kernel lacking one is an error naming it rather than a partial sandbox.
/// Building it probes the kernel and restricts nothing.
fn required_ruleset() -> Result<Ruleset, RulesetError> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED_ABI))?
        .handle_access(AccessNet::from_all(REQUIRED_ABI))?
        .scope(Scope::from_all(REQUIRED_ABI))
}

/// The error of a kernel that does not enforce [`required_ruleset`].
fn unsupported_kernel(e: &RulesetError) -> core_types::Error {
    core_types::Error::Platform(format!(
        "the kernel's Landlock does not enforce the access set the sandbox requires \
         (Landlock ABI {REQUIRED_ABI}, Linux 7.1 or later): {e}"
    ))
}

/// Whether the running kernel enforces the whole Landlock access set
/// [`apply_landlock`] handles. Restricts nothing; `sesame status --doctor`
/// reports it.
///
/// # Errors
///
/// `core_types::Error::Platform` naming the first right or scope the
/// kernel lacks, or Landlock's absence.
pub fn landlock_support() -> core_types::Result<()> {
    required_ruleset()
        .map(drop)
        .map_err(|e| unsupported_kernel(&e))
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

/// Apply Landlock filesystem sandbox with the given rules to the calling
/// thread and the threads it starts afterwards.
///
/// Every scope is enforced: the sandboxed process can neither connect to
/// an abstract-namespace Unix socket nor signal a process created outside
/// its domain. Every socket a daemon connects to is a pathname socket
/// granted by a rule (`NOTIFY_SOCKET` of the user service manager is
/// `$XDG_RUNTIME_DIR/systemd/notify`).
///
/// Sets `PR_SET_NO_NEW_PRIVS` before `landlock_restrict_self()`. Once
/// applied, the thread cannot gain additional filesystem access.
///
/// # Errors
///
/// When the kernel does not enforce the whole access set
/// ([`landlock_support`]), or the ruleset cannot be built or applied:
/// there is no partial sandbox.
pub fn apply_landlock(rules: &[LandlockRule]) -> core_types::Result<EnforcementStatus> {
    let abi = REQUIRED_ABI;
    let mut ruleset = required_ruleset()
        .map_err(|e| unsupported_kernel(&e))?
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
        // Unreachable under the hard requirement, refused all the same.
        RulesetStatus::PartiallyEnforced => Err(core_types::Error::Platform(
            "landlock partially enforced, refusing to run".into(),
        )),
        RulesetStatus::NotEnforced => Err(core_types::Error::Platform(
            "landlock not enforced, refusing to run".into(),
        )),
    }
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
/// When either layer cannot be applied. Callers treat errors as fatal:
/// the daemon does not start unsandboxed.
pub fn apply_sandbox(
    landlock_rules: &[LandlockRule],
    seccomp_profile: &SeccompProfile,
) -> core_types::Result<EnforcementStatus> {
    let status = apply_landlock(landlock_rules)?;
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

    const UNGRANTED: &str = "sandbox::tests::an_ungranted_pathname_socket_is_refused";
    const GRANTED: &str = "sandbox::tests::a_granted_pathname_socket_is_reachable";
    const FAMILIES: &str = "sandbox::tests::only_unix_domain_sockets_can_be_created";
    const ABSTRACT: &str = "sandbox::tests::an_abstract_socket_outside_the_domain_is_refused";

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
        apply_landlock(rules).expect("landlock applies");
        std::process::exit(match UnixStream::connect(socket) {
            Ok(_) => PERMITTED,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => DENIED,
            Err(e) => panic!("connect {}: {e}", socket.display()),
        })
    }

    /// No rule can grant an abstract socket: every daemon runs with the
    /// abstract-socket scope (Xwayland and some session buses listen on
    /// abstract addresses).
    #[test]
    fn an_abstract_socket_outside_the_domain_is_refused() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;

        if let Some(name) = child_input() {
            let addr = SocketAddr::from_abstract_name(name.as_os_str().as_encoded_bytes())
                .expect("abstract address");
            apply_landlock(&[]).expect("landlock applies");
            std::process::exit(match UnixStream::connect_addr(&addr) {
                Ok(_) => PERMITTED,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => DENIED,
                Err(e) => panic!("connect @{}: {e}", name.display()),
            });
        }
        let name = format!("pds-sandbox-test-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
        let _server = UnixListener::bind_addr(&addr).expect("bind abstract server");
        assert_eq!(run_child(ABSTRACT, Path::new(&name)).code(), Some(DENIED));
    }

    /// The probe and the sandbox share one ruleset: where the probe
    /// passes, a sandbox applies (this machine runs Linux 7.2, ABI 10).
    #[test]
    fn the_kernel_enforces_the_required_access_set() {
        landlock_support().expect("Landlock ABI 9 or later");
    }

    #[test]
    fn an_ungranted_pathname_socket_is_refused() {
        if let Some(socket) = child_input() {
            connect_under(&[], &socket);
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("server.sock");
        let _server = UnixListener::bind(&socket).expect("bind server");
        assert_eq!(run_child(UNGRANTED, &socket).code(), Some(DENIED));
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
