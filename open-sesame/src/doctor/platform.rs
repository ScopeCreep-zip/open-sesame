//! Platform checks — kernel version, ptrace scope, session type, input
//! group membership.

use anyhow::Context;
use core_layout::Layout;

use super::probe;
use super::{Check, Status};

const CATEGORY: &str = "platform";

/// The running kernel's release (`uname(2)`).
pub(super) fn kernel_release() -> anyhow::Result<String> {
    rustix::system::uname()
        .release()
        .to_str()
        .map(str::to_owned)
        .context("kernel release is not UTF-8")
}

/// The verdict on a kernel that does not enforce `gaps`, under the floor
/// `require` (`[global.sandbox] require`): failing below the floor (the
/// daemons refuse to start), a warning naming each protection the kernel
/// lacks (the daemons run without them), passing when it lacks none.
#[cfg(target_os = "linux")]
fn landlock_verdict(
    gaps: &[core_types::SandboxProtection],
    require: &[core_types::SandboxProtection],
) -> (Status, String) {
    use core_types::SandboxProtection;
    let below = platform_linux::sandbox::unmet(require, gaps);
    if !below.is_empty() {
        let floor = require
            .iter()
            .map(|p| p.name())
            .collect::<Vec<_>>()
            .join(", ");
        return (
            Status::Fail,
            format!(
                "below the configured sandbox floor ([global.sandbox] require = {floor}); \
                 the daemons refuse to start: {}",
                SandboxProtection::describe(&below)
            ),
        );
    }
    match gaps.first() {
        None => (
            Status::Pass,
            "Landlock enforces every sandbox protection".to_owned(),
        ),
        Some(SandboxProtection::Filesystem) => (
            Status::Warn,
            "the kernel has no Landlock: the daemons run confined by seccomp and their units \
             only; [global.sandbox] require makes a protection a floor"
                .to_owned(),
        ),
        Some(_) => (
            Status::Warn,
            format!(
                "the daemons run without what this kernel's Landlock lacks: {}; \
                 [global.sandbox] require makes a protection a floor",
                SandboxProtection::describe(gaps)
            ),
        ),
    }
}

/// The kernel release and the daemons' Landlock sandbox on it
/// (`platform_linux::sandbox::landlock_gaps`, asked of the kernel, not
/// inferred from the release) under the configured floor: the value is the
/// release and the enforcement every sandboxed daemon reports
/// (`landlock_verdict` judges it). `memfd_secret` is the memory category's
/// check.
fn kernel_check(layout: &Layout) -> anyhow::Result<Check> {
    let release = kernel_release()?;
    #[cfg(target_os = "linux")]
    let (status, value, description) = {
        let config = core_config::load_config(layout).context("cannot read the sandbox floor")?;
        let gaps = platform_linux::sandbox::landlock_gaps();
        let (status, description) = landlock_verdict(&gaps, &config.global.sandbox.require);
        let enforcement = platform_linux::sandbox::landlock_enforcement(&gaps);
        (
            status,
            format!("{release}, Landlock {enforcement}"),
            description,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let (status, value, description) = {
        let _ = layout;
        (
            Status::Warn,
            release,
            "this platform has no Landlock; the daemons run without it".to_owned(),
        )
    };
    Ok(Check::new(
        "platform.kernel",
        CATEGORY,
        status,
        value,
        description,
    ))
}

fn ptrace_check(layout: &Layout) -> anyhow::Result<Check> {
    let description = "Yama LSM restricts ptrace attach to protect secret memory";
    let Some(raw) = probe::proc_file(layout, "sys/kernel/yama/ptrace_scope")? else {
        return Ok(Check::new(
            "platform.ptrace_scope",
            CATEGORY,
            Status::Warn,
            "Yama LSM not enabled",
            description,
        ));
    };
    let (status, value) = match raw.trim() {
        "0" => (
            Status::Warn,
            "0 (classic: any same-user process can attach)",
        ),
        "1" => (Status::Pass, "1 (restricted: parent only)"),
        "2" => (Status::Pass, "2 (admin only)"),
        "3" => (Status::Pass, "3 (no attach)"),
        other => anyhow::bail!("unknown ptrace_scope value '{other}'"),
    };
    Ok(Check::new(
        "platform.ptrace_scope",
        CATEGORY,
        status,
        value,
        description,
    ))
}

fn session_check(layout: &Layout) -> Check {
    let session = layout
        .session_type()
        .map(|s| s.to_string_lossy().into_owned());
    Check::new(
        "platform.wayland",
        CATEGORY,
        if session.as_deref() == Some("wayland") {
            Status::Pass
        } else {
            Status::Warn
        },
        session.unwrap_or_else(|| "$XDG_SESSION_TYPE not set".into()),
        "Wayland required for overlay, clipboard, and input capture",
    )
}

/// The GID of group `name` in a group(5) database; `None` when the
/// database has no such group.
fn group_gid(database: &str, name: &str) -> anyhow::Result<Option<u32>> {
    for line in database
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }
        let gid = fields
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("group entry '{line}' has no GID"))?;
        return gid
            .parse()
            .map(Some)
            .with_context(|| format!("group {name} GID '{gid}'"));
    }
    Ok(None)
}

fn input_group_check(layout: &Layout) -> anyhow::Result<Check> {
    let path = layout
        .group_database()
        .ok_or_else(|| anyhow::anyhow!("this platform has no group database"))?;
    let database = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let Some(gid) = group_gid(&database, "input")? else {
        return Ok(Check::new(
            "platform.input_group",
            CATEGORY,
            Status::Warn,
            "no input group",
            "the system defines no input group; keyboard capture needs evdev access",
        ));
    };
    let member = rustix::process::getgroups()
        .context("failed to read the process groups")?
        .iter()
        .chain(std::iter::once(&rustix::process::getgid()))
        .any(|g| g.as_raw() == gid);
    Ok(if member {
        Check::new("platform.input_group", CATEGORY, Status::Pass, "member", "")
    } else {
        Check::new(
            "platform.input_group",
            CATEGORY,
            Status::Warn,
            "not member",
            "sudo usermod -aG input $USER, then log in again (required for keyboard capture)",
        )
    })
}

pub fn checks(layout: &Layout) -> Vec<Check> {
    vec![
        kernel_check(layout)
            .unwrap_or_else(|e| Check::probe_failed("platform.kernel", CATEGORY, &e)),
        ptrace_check(layout)
            .unwrap_or_else(|e| Check::probe_failed("platform.ptrace_scope", CATEGORY, &e)),
        session_check(layout),
        input_group_check(layout)
            .unwrap_or_else(|e| Check::probe_failed("platform.input_group", CATEGORY, &e)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_check_reports_this_kernels_coverage_and_enforcement() {
        use platform_linux::sandbox::{landlock_enforcement, landlock_gaps};
        let root = tempfile::tempdir().unwrap();
        let check = kernel_check(&Layout::under(root.path())).unwrap();
        let gaps = landlock_gaps();
        assert_eq!(
            check.value,
            format!(
                "{}, Landlock {}",
                kernel_release().unwrap(),
                landlock_enforcement(&gaps)
            )
        );
        assert_eq!(
            (check.status, check.description),
            landlock_verdict(&gaps, &[])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_below_the_floor_fails_and_one_without_a_floor_warns() {
        use core_types::SandboxProtection::{Filesystem, PathnameSockets, Scopes, Udp};
        let (status, description) = landlock_verdict(&[PathnameSockets, Udp], &[PathnameSockets]);
        assert_eq!(status, Status::Fail);
        assert!(description.contains("pathname-sockets"), "{description}");
        assert!(description.contains("refuse to start"), "{description}");
        assert!(
            !description.contains("udp ("),
            "only the unmet floor: {description}"
        );

        let (status, description) = landlock_verdict(&[PathnameSockets, Udp], &[Scopes]);
        assert_eq!(status, Status::Warn);
        assert!(description.contains("pathname-sockets"), "{description}");
        assert!(description.contains("udp"), "{description}");

        assert_eq!(
            landlock_verdict(&core_types::SandboxProtection::ALL, &[]).0,
            Status::Warn,
            "no Landlock and no floor: the daemons run, and it is reported"
        );
        assert_eq!(
            landlock_verdict(&core_types::SandboxProtection::ALL, &[Filesystem]).0,
            Status::Fail
        );
        assert_eq!(landlock_verdict(&[], &[Filesystem, Udp]).0, Status::Pass);
    }

    #[test]
    fn group_lookup_matches_whole_names() {
        let db = "root:x:0:\ninputx:x:7:\ninput:x:104:user\n";
        assert_eq!(group_gid(db, "input").unwrap(), Some(104));
        assert_eq!(group_gid(db, "video").unwrap(), None);
        assert!(group_gid("input:x:\n", "input").is_err());
    }
}
