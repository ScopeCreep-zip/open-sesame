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

/// The kernel release, passing when the kernel enforces the whole Landlock
/// access set the daemon sandboxes require
/// (`platform_linux::sandbox::landlock_support`, asked of the kernel, not
/// inferred from the release): on a kernel that does not, every sandboxed
/// daemon refuses to start. `memfd_secret` is the memory category's check.
fn kernel_check() -> anyhow::Result<Check> {
    let release = kernel_release()?;
    #[cfg(target_os = "linux")]
    let (status, description) = match platform_linux::sandbox::landlock_support() {
        Ok(()) => (
            Status::Pass,
            "Landlock enforces every sandbox restriction (ABI 9, Linux 7.1 or later)".to_owned(),
        ),
        Err(e) => (Status::Fail, format!("{e}; the daemons refuse to start")),
    };
    #[cfg(not(target_os = "linux"))]
    let (status, description) = (
        Status::Warn,
        "this platform has no Landlock; the daemons run without it".to_owned(),
    );
    Ok(Check::new(
        "platform.kernel",
        CATEGORY,
        status,
        release,
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
        kernel_check().unwrap_or_else(|e| Check::probe_failed("platform.kernel", CATEGORY, &e)),
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
    fn the_kernel_check_asks_the_kernel_for_the_sandbox_access_set() {
        let check = kernel_check().unwrap();
        assert_eq!(check.value, kernel_release().unwrap());
        assert_eq!(
            check.status == Status::Pass,
            platform_linux::sandbox::landlock_support().is_ok(),
            "{check:?}"
        );
    }

    #[test]
    fn group_lookup_matches_whole_names() {
        let db = "root:x:0:\ninputx:x:7:\ninput:x:104:user\n";
        assert_eq!(group_gid(db, "input").unwrap(), Some(104));
        assert_eq!(group_gid(db, "video").unwrap(), None);
        assert!(group_gid("input:x:\n", "input").is_err());
    }
}
