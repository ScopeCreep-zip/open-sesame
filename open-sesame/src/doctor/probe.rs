//! The system probes every check category shares: the daemon table,
//! systemd unit properties, and `/proc` reads.

use anyhow::Context;
use core_layout::Layout;
use std::path::{Path, PathBuf};

/// Property `prop` of user unit `unit` (`systemctl --user show`); `None`
/// when systemd reports it empty or `[not set]`.
///
/// # Errors
///
/// When systemctl cannot be run or exits non-zero.
pub(super) fn unit_property(unit: &str, prop: &str) -> anyhow::Result<Option<String>> {
    let output = std::process::Command::new("systemctl")
        .args(["--user", "show", unit, &format!("-p{prop}"), "--value"])
        .output()
        .context("failed to run systemctl")?;
    anyhow::ensure!(
        output.status.success(),
        "systemctl show {unit} -p{prop} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok((!value.is_empty() && value != "[not set]").then_some(value))
}

/// The main PID of `unit`; `None` when it is not running (systemd reports
/// `0`).
///
/// # Errors
///
/// The [`unit_property`] errors, and a PID that does not parse.
pub(super) fn main_pid(unit: &str) -> anyhow::Result<Option<u32>> {
    match unit_property(unit, "MainPID")? {
        None => Ok(None),
        Some(raw) => {
            let pid: u32 = raw
                .parse()
                .with_context(|| format!("{unit} MainPID '{raw}' is not a PID"))?;
            Ok((pid != 0).then_some(pid))
        }
    }
}

/// Core daemons are always expected. Desktop daemons are expected while
/// their target is active, or individually when started or failed.
/// An unavailable service manager is a probe error, never evidence of headless mode.
pub(super) fn expected_daemons() -> anyhow::Result<Vec<core_types::Daemon>> {
    let output = std::process::Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "--all",
            "--output=json",
            "open-sesame-*",
        ])
        .output()
        .context("failed to list daemon units")?;
    anyhow::ensure!(
        output.status.success(),
        "systemctl list-units failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let units: Vec<UnitState> = serde_json::from_slice(&output.stdout)
        .context("systemctl list-units returned invalid JSON")?;
    Ok(expected_from_units(&units))
}

#[derive(serde::Deserialize)]
struct UnitState {
    unit: String,
    active: String,
}

fn expected_from_units(units: &[UnitState]) -> Vec<core_types::Daemon> {
    let required = |name: &str| {
        units
            .iter()
            .any(|unit| unit.unit == name && unit.active != "inactive")
    };
    let desktop = required("open-sesame-desktop.target");
    core_types::Daemon::ALL
        .into_iter()
        .filter(|daemon| !daemon.desktop() || desktop || required(&daemon.unit()))
        .collect()
}

/// The main PIDs of every running daemon.
///
/// # Errors
///
/// The [`main_pid`] errors of any daemon.
pub(super) fn running_daemon_pids() -> anyhow::Result<Vec<(&'static str, u32)>> {
    let mut pids = Vec::new();
    for daemon in expected_daemons()? {
        if let Some(pid) = main_pid(&daemon.unit())? {
            pids.push((daemon.short_name(), pid));
        }
    }
    Ok(pids)
}

/// `relative` beneath the process filesystem.
///
/// # Errors
///
/// When the platform has no process filesystem.
fn proc_path(layout: &Layout, relative: &str) -> anyhow::Result<PathBuf> {
    Ok(layout
        .proc_root()
        .ok_or_else(|| anyhow::anyhow!("this platform has no process filesystem"))?
        .join(relative))
}

/// The bytes of `path`; `None` when it does not exist.
///
/// # Errors
///
/// When it exists but cannot be read.
pub(super) fn read_optional(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// The bytes of `relative` beneath the process filesystem; `None` when it
/// does not exist (a process that exited, an absent kernel feature).
///
/// # Errors
///
/// When the platform has no process filesystem, or the file exists but
/// cannot be read.
pub(super) fn proc_bytes(layout: &Layout, relative: &str) -> anyhow::Result<Option<Vec<u8>>> {
    read_optional(&proc_path(layout, relative)?)
}

/// The text of `relative` beneath the process filesystem; `None` when it
/// does not exist.
///
/// # Errors
///
/// The [`proc_bytes`] errors, and contents that are not UTF-8.
pub(super) fn proc_file(layout: &Layout, relative: &str) -> anyhow::Result<Option<String>> {
    proc_bytes(layout, relative)?
        .map(|bytes| {
            String::from_utf8(bytes)
                .with_context(|| format!("{relative} in the process filesystem is not UTF-8"))
        })
        .transpose()
}

/// The running daemons, or the failed check `id` of `category` when none
/// can be inspected: an error listing them, or no daemon running.
pub(super) fn inspectable_daemons(
    id: &str,
    category: &'static str,
) -> Result<Vec<(&'static str, u32)>, super::Check> {
    match running_daemon_pids() {
        Err(e) => Err(super::Check::probe_failed(id, category, &e)),
        Ok(pids) if pids.is_empty() => Err(super::Check::new(
            id,
            category,
            super::Status::Warn,
            "no daemon running",
            "start the daemons to inspect them: systemctl --user start open-sesame-headless.target",
        )),
        Ok(pids) => Ok(pids),
    }
}

/// The value of field `key` in a `/proc/<pid>/status`-format document.
pub(super) fn status_field<'s>(status: &'s str, key: &str) -> Option<&'s str> {
    status.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| *name == key)
            .map(|(_, value)| value.trim())
    })
}

/// Field `key` of process `pid`'s status; `None` when the process is gone
/// or has no such field.
///
/// # Errors
///
/// The [`proc_file`] errors.
pub(super) fn process_status_field(
    layout: &Layout,
    pid: u32,
    key: &str,
) -> anyhow::Result<Option<String>> {
    Ok(proc_file(layout, &format!("{pid}/status"))?
        .and_then(|status| status_field(&status, key).map(str::to_owned)))
}

/// A `kB` quantity of a status field (`VmRSS:  1234 kB`).
///
/// # Errors
///
/// When the value is not a number of kB.
pub(super) fn kib(value: &str) -> anyhow::Result<u64> {
    let number = value
        .strip_suffix("kB")
        .map(str::trim)
        .ok_or_else(|| anyhow::anyhow!("'{value}' is not a kB quantity"))?;
    number
        .parse()
        .with_context(|| format!("'{value}' is not a kB quantity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_desktop_units_are_optional_but_failures_are_not() {
        use core_types::Daemon;
        let headless: Vec<_> = Daemon::ALL
            .into_iter()
            .filter(|daemon| !daemon.desktop())
            .collect();
        assert_eq!(expected_from_units(&[]), headless);
        assert_eq!(
            expected_from_units(&[UnitState {
                unit: Daemon::Wm.unit(),
                active: "inactive".into(),
            }]),
            headless
        );
        for state in [
            "active",
            "activating",
            "deactivating",
            "reloading",
            "failed",
        ] {
            assert!(
                expected_from_units(&[UnitState {
                    unit: Daemon::Wm.unit(),
                    active: state.into(),
                }])
                .contains(&Daemon::Wm),
                "{state}"
            );
            assert_eq!(
                expected_from_units(&[UnitState {
                    unit: "open-sesame-desktop.target".into(),
                    active: state.into(),
                }]),
                Daemon::ALL,
                "{state}"
            );
        }
    }

    #[test]
    fn status_fields_match_whole_names() {
        let status = "Name:\tdaemon-wm\nVmSwap:\t       0 kB\nVmRSS:\t   12345 kB\nSeccomp:\t2\n";
        assert_eq!(status_field(status, "VmRSS"), Some("12345 kB"));
        assert_eq!(status_field(status, "Seccomp"), Some("2"));
        assert_eq!(status_field(status, "Vm"), None);
        assert_eq!(kib("12345 kB").unwrap(), 12345);
        assert!(kib("12345").is_err());
    }

    #[test]
    fn absent_process_files_are_none() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        assert_eq!(proc_file(&layout, "42/status").unwrap(), None);
        let dir = layout.proc_root().unwrap().join("42");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("status"), "NoNewPrivs:\t1\n").unwrap();
        assert_eq!(
            process_status_field(&layout, 42, "NoNewPrivs")
                .unwrap()
                .as_deref(),
            Some("1")
        );
    }
}
