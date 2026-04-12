//! Platform checks — kernel version, ptrace scope, display server.

use super::{Check, Status};

pub fn checks() -> Vec<Check> {
    let mut results = Vec::new();

    // platform.kernel — check kernel version for feature support.
    let kernel = kernel_version();
    let kernel_status = match &kernel {
        Some(v) if version_at_least(v, 5, 14) => Status::Pass, // memfd_secret
        Some(v) if version_at_least(v, 5, 4) => Status::Warn,  // Landlock only
        _ => Status::Fail,
    };
    results.push(Check {
        id: "platform.kernel".into(),
        category: "platform",
        status: kernel_status,
        value: kernel.clone().unwrap_or_else(|| "unknown".into()),
        description: match kernel_status {
            Status::Pass => "Kernel >= 5.14 (memfd_secret + Landlock)".into(),
            Status::Warn => "Kernel >= 5.4 (Landlock only, no memfd_secret)".into(),
            Status::Fail => "Kernel < 5.4 (missing Landlock and memfd_secret)".into(),
        },
    });

    // platform.ptrace_scope — Yama LSM ptrace restriction.
    let ptrace = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .map(|s| s.trim().to_string());
    results.push(Check {
        id: "platform.ptrace_scope".into(),
        category: "platform",
        status: match ptrace.as_deref() {
            Some("1") | Some("2") | Some("3") => Status::Pass,
            Some("0") => Status::Warn,
            _ => Status::Warn,
        },
        value: match ptrace.as_deref() {
            Some("0") => "0 (classic — any process can ptrace)".into(),
            Some("1") => "1 (restricted — parent only)".into(),
            Some("2") => "2 (admin only)".into(),
            Some("3") => "3 (no attach)".into(),
            other => other.map(String::from).unwrap_or_else(|| "unknown".into()),
        },
        description: "Yama LSM restricts ptrace attach to protect secret memory".into(),
    });

    // platform.wayland — display server type.
    let session_type = std::env::var("XDG_SESSION_TYPE").ok();
    results.push(Check {
        id: "platform.wayland".into(),
        category: "platform",
        status: match session_type.as_deref() {
            Some("wayland") => Status::Pass,
            _ => Status::Warn,
        },
        value: session_type.unwrap_or_else(|| "unknown".into()),
        description: "Wayland required for overlay, clipboard, and input capture".into(),
    });

    // platform.input_group — user membership for evdev access.
    let in_input = std::process::Command::new("groups")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("input"))
        .unwrap_or(false);
    results.push(Check {
        id: "platform.input_group".into(),
        category: "platform",
        status: if in_input { Status::Pass } else { Status::Warn },
        value: if in_input {
            "member".into()
        } else {
            "not member".into()
        },
        description: if in_input {
            String::new()
        } else {
            "sudo usermod -aG input $USER (required for keyboard capture)".into()
        },
    });

    results
}

fn kernel_version() -> Option<String> {
    let output = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn version_at_least(version: &str, major: u32, minor: u32) -> bool {
    let parts: Vec<u32> = version
        .split(|c: char| !c.is_ascii_digit())
        .take(2)
        .filter_map(|s| s.parse().ok())
        .collect();
    match parts.as_slice() {
        [maj, min, ..] => (*maj > major) || (*maj == major && *min >= minor),
        [maj] => *maj > major,
        _ => false,
    }
}
