//! Sandbox checks — seccomp, no_new_privs, Landlock.

use super::{Check, Status};

pub fn checks() -> Vec<Check> {
    let mut results = Vec::new();
    let pids = daemon_pids();

    // sandbox.seccomp — check seccomp filter mode for all daemons.
    let all_filtered = !pids.is_empty()
        && pids
            .iter()
            .all(|pid| read_proc_field(*pid, "Seccomp").as_deref() == Some("2"));
    results.push(Check {
        id: "sandbox.seccomp".into(),
        category: "sandbox",
        status: if all_filtered {
            Status::Pass
        } else {
            Status::Fail
        },
        value: if all_filtered {
            "filter mode (all daemons)".into()
        } else {
            "not all daemons have seccomp filter".into()
        },
        description: "Seccomp BPF restricts available syscalls per daemon".into(),
    });

    // sandbox.no_new_privs — check NoNewPrivs for all daemons.
    let all_nnp = !pids.is_empty()
        && pids
            .iter()
            .all(|pid| read_proc_field(*pid, "NoNewPrivs").as_deref() == Some("1"));
    results.push(Check {
        id: "sandbox.no_new_privs".into(),
        category: "sandbox",
        status: if all_nnp { Status::Pass } else { Status::Warn },
        value: if all_nnp {
            "set (all daemons)".into()
        } else {
            "not set on all daemons".into()
        },
        description: "NoNewPrivileges prevents privilege escalation via setuid/capabilities".into(),
    });

    results
}

fn read_proc_field(pid: u32, field: &str) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            return Some(rest.trim_start_matches(':').trim().to_string());
        }
    }
    None
}

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
