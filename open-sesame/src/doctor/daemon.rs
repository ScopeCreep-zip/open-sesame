//! Daemon health checks — running state, uptime, memory, restarts.

use super::{Check, Status};

/// All open-sesame systemd user units to check.
const DAEMONS: &[(&str, &str)] = &[
    ("profile", "open-sesame-profile.service"),
    ("secrets", "open-sesame-secrets.service"),
    ("wm", "open-sesame-wm.service"),
    ("launcher", "open-sesame-launcher.service"),
    ("clipboard", "open-sesame-clipboard.service"),
    ("input", "open-sesame-input.service"),
    ("snippets", "open-sesame-snippets.service"),
];

pub fn checks() -> Vec<Check> {
    let mut results = Vec::new();

    for &(name, unit) in DAEMONS {
        let active = systemctl_prop(unit, "ActiveState");
        let pid = systemctl_prop(unit, "MainPID");
        let restarts = systemctl_prop(unit, "NRestarts");
        let memory_max = systemctl_prop(unit, "MemoryMax");

        // Running check.
        let is_active = active.as_deref() == Some("active");
        results.push(Check {
            id: format!("daemon.{name}.running"),
            category: "daemon",
            status: if is_active {
                Status::Pass
            } else {
                Status::Fail
            },
            value: active.clone().unwrap_or_else(|| "unknown".into()),
            description: if is_active {
                String::new()
            } else {
                format!("systemctl --user status {unit}")
            },
        });

        // Skip remaining checks if not running.
        let Some(pid_str) = &pid else { continue };
        let pid_num: u32 = match pid_str.parse() {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        // Memory check.
        let vmrss_kb = read_proc_status(pid_num, "VmRSS");
        let vmrss_mb = vmrss_kb.unwrap_or(0) / 1024;
        let max_bytes: u64 = memory_max
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        let max_mb = if max_bytes == u64::MAX {
            "∞".to_string()
        } else {
            format!("{} MB", max_bytes / (1024 * 1024))
        };

        let mem_status = if max_bytes != u64::MAX && vmrss_mb * 1024 * 1024 >= max_bytes {
            Status::Fail
        } else if max_bytes != u64::MAX && vmrss_mb * 1024 * 1024 >= max_bytes / 2 {
            Status::Warn
        } else {
            Status::Pass
        };

        results.push(Check {
            id: format!("daemon.{name}.memory"),
            category: "daemon",
            status: mem_status,
            value: format!("{vmrss_mb} MB / {max_mb}"),
            description: if mem_status != Status::Pass {
                "Memory usage approaching MemoryMax ceiling".into()
            } else {
                String::new()
            },
        });

        // Restart count.
        let restart_count: u32 = restarts
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let restart_status = match restart_count {
            0 => Status::Pass,
            1..=3 => Status::Warn,
            _ => Status::Fail,
        };
        results.push(Check {
            id: format!("daemon.{name}.restarts"),
            category: "daemon",
            status: restart_status,
            value: restart_count.to_string(),
            description: if restart_count > 0 {
                format!("Restarted {restart_count} times since last daemon-reload")
            } else {
                String::new()
            },
        });

        // Uptime.
        let uptime = read_proc_uptime(pid_num);
        results.push(Check {
            id: format!("daemon.{name}.uptime"),
            category: "daemon",
            status: if uptime.as_deref() == Some("0s") {
                Status::Fail
            } else {
                Status::Pass
            },
            value: uptime.unwrap_or_else(|| "unknown".into()),
            description: String::new(),
        });
    }

    results
}

/// Read a property from a systemd user unit via `systemctl --user show`.
fn systemctl_prop(unit: &str, prop: &str) -> Option<String> {
    let output = std::process::Command::new("systemctl")
        .arg("--user")
        .arg("show")
        .arg(unit)
        .arg(format!("-p{prop}"))
        .arg("--value")
        .output()
        .ok()?;
    if output.status.success() {
        let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if val.is_empty() || val == "[not set]" {
            None
        } else {
            Some(val)
        }
    } else {
        None
    }
}

/// Read a value from /proc/<pid>/status by key (e.g. "VmRSS").
/// Returns the value in kB.
fn read_proc_status(pid: u32, key: &str) -> Option<u64> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start_matches(':').trim();
            // Parse "12345 kB" → 12345
            let num_str = rest.split_whitespace().next()?;
            return num_str.parse().ok();
        }
    }
    None
}

/// Read process uptime from /proc/<pid>/stat and format as human-readable.
fn read_proc_uptime(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let uptime_secs = std::fs::read_to_string("/proc/uptime").ok()?;
    let system_uptime: f64 = uptime_secs.split_whitespace().next()?.parse().ok()?;

    // Field 22 (0-indexed from after comm) is starttime in clock ticks.
    // We need to find it after the (comm) field which may contain spaces.
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    // starttime is field index 19 (0-indexed from after state field).
    let starttime_ticks: u64 = fields.get(19)?.parse().ok()?;
    // SAFETY: sysconf(_SC_CLK_TCK) is always safe — no side effects,
    // returns the kernel's USER_HZ for /proc timing field interpretation.
    #[allow(unsafe_code)]
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;

    let start_secs = starttime_ticks as f64 / clk_tck as f64;
    let elapsed = system_uptime - start_secs;
    if elapsed < 0.0 {
        return Some("0s".into());
    }

    let hours = elapsed as u64 / 3600;
    let minutes = (elapsed as u64 % 3600) / 60;
    if hours > 0 {
        Some(format!("{hours}h {minutes}m"))
    } else if minutes > 0 {
        Some(format!("{minutes}m"))
    } else {
        Some(format!("{}s", elapsed as u64))
    }
}
