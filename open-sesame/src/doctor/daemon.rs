//! Daemon health checks — running state, memory, restarts, uptime.

use anyhow::Context;
use core_layout::Layout;

use super::probe::{self, DAEMONS};
use super::{Check, Status};

const CATEGORY: &str = "daemon";

pub fn checks(layout: &Layout) -> Vec<Check> {
    let mut results = Vec::new();
    for daemon in DAEMONS {
        let id = |check: &str| format!("daemon.{}.{check}", daemon.name);

        let active = match probe::unit_property(daemon.unit, "ActiveState") {
            Ok(active) => active,
            Err(e) => {
                results.push(Check::probe_failed(id("running"), CATEGORY, &e));
                continue;
            }
        };
        let running = active.as_deref() == Some("active");
        results.push(Check::new(
            id("running"),
            CATEGORY,
            if running { Status::Pass } else { Status::Fail },
            active.unwrap_or_else(|| "not loaded".into()),
            if running {
                String::new()
            } else {
                format!("systemctl --user status {}", daemon.unit)
            },
        ));
        if !running {
            continue;
        }

        let pid = match probe::main_pid(daemon.unit) {
            Ok(Some(pid)) => pid,
            Ok(None) => {
                results.push(Check::new(
                    id("pid"),
                    CATEGORY,
                    Status::Fail,
                    "none",
                    "the unit is active but has no main process",
                ));
                continue;
            }
            Err(e) => {
                results.push(Check::probe_failed(id("pid"), CATEGORY, &e));
                continue;
            }
        };

        results.push(
            memory_check(layout, daemon.unit, pid)
                .unwrap_or_else(|e| Check::probe_failed(id("memory"), CATEGORY, &e))
                .with_id(id("memory")),
        );
        results.push(
            restart_check(daemon.unit)
                .unwrap_or_else(|e| Check::probe_failed(id("restarts"), CATEGORY, &e))
                .with_id(id("restarts")),
        );
        results.push(
            uptime_check(layout, pid)
                .unwrap_or_else(|e| Check::probe_failed(id("uptime"), CATEGORY, &e))
                .with_id(id("uptime")),
        );
    }
    results
}

impl Check {
    fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }
}

/// Resident memory against the unit's `MemoryMax`.
fn memory_check(layout: &Layout, unit: &str, pid: u32) -> anyhow::Result<Check> {
    let rss = probe::process_status_field(layout, pid, "VmRSS")?
        .ok_or_else(|| anyhow::anyhow!("process {pid} has no VmRSS (it exited)"))?;
    let rss_bytes = probe::kib(&rss)? * 1024;
    let limit = match probe::unit_property(unit, "MemoryMax")?.as_deref() {
        None | Some("infinity") => None,
        Some(raw) => Some(
            raw.parse::<u64>()
                .with_context(|| format!("{unit} MemoryMax '{raw}' is not a byte count"))?,
        ),
    };
    let mib = |bytes: u64| bytes / (1024 * 1024);
    let (status, value) = match limit {
        None => (Status::Pass, format!("{} MB / unlimited", mib(rss_bytes))),
        Some(max) => {
            let status = if rss_bytes >= max {
                Status::Fail
            } else if rss_bytes >= max / 2 {
                Status::Warn
            } else {
                Status::Pass
            };
            (status, format!("{} MB / {} MB", mib(rss_bytes), mib(max)))
        }
    };
    Ok(Check::new(
        String::new(),
        CATEGORY,
        status,
        value,
        if status == Status::Pass {
            ""
        } else {
            "memory usage approaching the MemoryMax ceiling"
        },
    ))
}

/// Restarts since the unit was last loaded.
fn restart_check(unit: &str) -> anyhow::Result<Check> {
    let restarts: u32 = match probe::unit_property(unit, "NRestarts")? {
        None => 0,
        Some(raw) => raw
            .parse()
            .with_context(|| format!("{unit} NRestarts '{raw}' is not a count"))?,
    };
    let status = match restarts {
        0 => Status::Pass,
        1..=3 => Status::Warn,
        _ => Status::Fail,
    };
    Ok(Check::new(
        String::new(),
        CATEGORY,
        status,
        restarts.to_string(),
        if restarts == 0 {
            String::new()
        } else {
            format!("restarted {restarts} times since the unit was loaded")
        },
    ))
}

/// Clock ticks after boot at which process `pid` started
/// (`/proc/<pid>/stat` field 22, proc(5)).
fn start_ticks(layout: &Layout, pid: u32) -> anyhow::Result<u64> {
    let stat = probe::proc_file(layout, &format!("{pid}/stat"))?
        .ok_or_else(|| anyhow::anyhow!("process {pid} exited"))?;
    // The command name (field 2) may contain spaces and parentheses; the
    // fields after its last ')' are space-separated, starttime the 20th.
    stat.rfind(')')
        .map(|i| &stat[i + 1..])
        .ok_or_else(|| anyhow::anyhow!("process {pid} stat has no command field"))?
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow::anyhow!("process {pid} stat has no starttime"))?
        .parse()
        .with_context(|| format!("process {pid} starttime"))
}

/// Seconds process `pid` has run: system uptime (`sysinfo(2)`) minus its
/// start time in seconds after boot.
fn process_uptime_secs(layout: &Layout, pid: u32) -> anyhow::Result<u64> {
    let started = start_ticks(layout, pid)? / rustix::param::clock_ticks_per_second();
    let system = u64::try_from(rustix::system::sysinfo().uptime)
        .context("sysinfo reported a negative uptime")?;
    Ok(system.saturating_sub(started))
}

fn uptime_check(layout: &Layout, pid: u32) -> anyhow::Result<Check> {
    let secs = process_uptime_secs(layout, pid)?;
    let (hours, minutes) = (secs / 3600, secs % 3600 / 60);
    let value = if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{secs}s")
    };
    Ok(Check::new(
        String::new(),
        CATEGORY,
        if secs == 0 {
            Status::Warn
        } else {
            Status::Pass
        },
        value,
        if secs == 0 {
            "started within the last second"
        } else {
            ""
        },
    ))
}
