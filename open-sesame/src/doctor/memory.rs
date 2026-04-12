//! Memory protection checks — memfd_secret, core limits, swap exposure.

use super::{Check, Status};

pub fn checks() -> Vec<Check> {
    let mut results = Vec::new();

    // mem.backend — memfd_secret vs mmap fallback.
    let backend = match core_memory::ProtectedAlloc::new(1) {
        Ok(probe) if probe.is_secret_mem() => (
            "memfd_secret",
            Status::Pass,
            "Pages removed from kernel direct map",
        ),
        Ok(_) => (
            "mmap fallback",
            Status::Fail,
            "Secret pages visible in kernel direct map — CONFIG_SECRETMEM may be disabled",
        ),
        Err(_) => (
            "allocation failed",
            Status::Fail,
            "Secure memory probe failed — check RLIMIT_MEMLOCK",
        ),
    };
    results.push(Check {
        id: "mem.backend".into(),
        category: "memory",
        status: backend.1,
        value: backend.0.into(),
        description: backend.2.into(),
    });

    // mem.config_secretmem — kernel config check.
    let secretmem = check_kernel_config("CONFIG_SECRETMEM");
    results.push(Check {
        id: "mem.config_secretmem".into(),
        category: "memory",
        status: match secretmem.as_deref() {
            Some("y") => Status::Pass,
            _ => Status::Fail,
        },
        value: secretmem.unwrap_or_else(|| "unknown".into()),
        description: "Kernel CONFIG_SECRETMEM enables memfd_secret syscall".into(),
    });

    // mem.core_limit — check each daemon's core dump limit.
    let core_ok = check_all_daemon_limits("Max core file size", "0");
    results.push(Check {
        id: "mem.core_limit".into(),
        category: "memory",
        status: if core_ok { Status::Pass } else { Status::Fail },
        value: if core_ok {
            "0 (disabled)".into()
        } else {
            "nonzero (core dumps possible)".into()
        },
        description: "LimitCORE=0 prevents secret material in core dumps".into(),
    });

    // mem.swap_usage — check if any daemon has pages in swap.
    let swap_kb = total_daemon_swap();
    results.push(Check {
        id: "mem.swap_usage".into(),
        category: "memory",
        status: if swap_kb == 0 {
            Status::Pass
        } else {
            Status::Warn
        },
        value: format!("{swap_kb} kB"),
        description: if swap_kb > 0 {
            "Daemon pages in swap — secret material may be on disk".into()
        } else {
            String::new()
        },
    });

    results
}

/// Check a kernel config option from /proc/config.gz or /boot/config-*.
fn check_kernel_config(key: &str) -> Option<String> {
    // Try /proc/config.gz first (requires CONFIG_IKCONFIG_PROC).
    if let Ok(output) = std::process::Command::new("zgrep")
        .arg(format!("^{key}="))
        .arg("/proc/config.gz")
        .output()
        && output.status.success()
    {
        let line = String::from_utf8_lossy(&output.stdout);
        return line.trim().split('=').nth(1).map(|v| v.to_string());
    }

    // Fallback: /boot/config-$(uname -r).
    let uname = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()?;
    let release = String::from_utf8_lossy(&uname.stdout).trim().to_string();
    let config_path = format!("/boot/config-{release}");
    let content = std::fs::read_to_string(config_path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Check that all daemon PIDs have a specific /proc/<pid>/limits value.
fn check_all_daemon_limits(limit_name: &str, expected: &str) -> bool {
    let pids = daemon_pids();
    if pids.is_empty() {
        return false;
    }
    pids.iter().all(|pid| {
        let path = format!("/proc/{pid}/limits");
        let Ok(content) = std::fs::read_to_string(path) else {
            return false;
        };
        content
            .lines()
            .any(|line| line.contains(limit_name) && line.contains(expected))
    })
}

/// Sum VmSwap across all daemon PIDs.
fn total_daemon_swap() -> u64 {
    daemon_pids()
        .iter()
        .filter_map(|pid| {
            let path = format!("/proc/{pid}/status");
            let content = std::fs::read_to_string(path).ok()?;
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("VmSwap:") {
                    let num = rest.split_whitespace().next()?;
                    return num.parse::<u64>().ok();
                }
            }
            None
        })
        .sum()
}

/// Get PIDs of all running open-sesame daemons.
fn daemon_pids() -> Vec<u32> {
    let binaries = [
        "daemon-profile",
        "daemon-secrets",
        "daemon-wm",
        "daemon-launcher",
        "daemon-clipboard",
        "daemon-input",
        "daemon-snippets",
    ];
    binaries
        .iter()
        .filter_map(|name| {
            let output = std::process::Command::new("pidof")
                .arg(name)
                .output()
                .ok()?;
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout)
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            } else {
                None
            }
        })
        .collect()
}
