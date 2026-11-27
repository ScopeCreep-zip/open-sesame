//! Memory protection checks — `memfd_secret`, kernel support, core limits,
//! swap exposure.

use std::io::Read;

use anyhow::Context;
use core_layout::Layout;

use super::probe;
use super::{Check, Status};

const CATEGORY: &str = "memory";

/// A check over the running daemons.
type DaemonCheck = fn(&Layout, &[(&'static str, u32)]) -> anyhow::Result<Check>;

/// Check `id` over the running daemons, or the check reporting why none
/// can be inspected.
fn over_daemons(layout: &Layout, id: &str, check: DaemonCheck) -> Check {
    match probe::inspectable_daemons(id, CATEGORY) {
        Err(check) => check,
        Ok(pids) => check(layout, &pids).unwrap_or_else(|e| Check::probe_failed(id, CATEGORY, &e)),
    }
}

pub fn checks(layout: &Layout) -> Vec<Check> {
    vec![
        backend_check(),
        secretmem_check(layout)
            .unwrap_or_else(|e| Check::probe_failed("mem.config_secretmem", CATEGORY, &e)),
        over_daemons(layout, "mem.core_limit", core_limit_check),
        over_daemons(layout, "mem.swap_usage", swap_check),
    ]
}

/// Whether this process obtains `memfd_secret` pages.
fn backend_check() -> Check {
    let (status, value, description) = match core_memory::ProtectedAlloc::new(1) {
        Ok(alloc) if alloc.is_secret_mem() => (
            Status::Pass,
            "memfd_secret".to_owned(),
            "pages removed from the kernel direct map",
        ),
        Ok(_) => (
            Status::Fail,
            "mmap fallback".to_owned(),
            "secret pages visible in the kernel direct map; CONFIG_SECRETMEM may be disabled",
        ),
        Err(e) => (
            Status::Fail,
            format!("allocation failed: {e}"),
            "secure memory probe failed; check RLIMIT_MEMLOCK",
        ),
    };
    Check::new("mem.backend", CATEGORY, status, value, description)
}

/// The value of option `key` in kernel build configuration `config`:
/// `Some("y")` for `KEY=y`, `None` when it is unset (`# KEY is not set`
/// or absent).
fn kernel_option<'c>(config: &'c str, key: &str) -> Option<&'c str> {
    config.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

/// The running kernel's build configuration: `/proc/config.gz`
/// (`CONFIG_IKCONFIG_PROC`), else the distribution's
/// `/boot/config-<release>`; `None` when neither exists.
fn kernel_config(layout: &Layout) -> anyhow::Result<Option<String>> {
    if let Some(compressed) = probe::proc_bytes(layout, "config.gz")? {
        let mut config = String::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .read_to_string(&mut config)
            .context("failed to decompress config.gz in the process filesystem")?;
        return Ok(Some(config));
    }
    let release = super::platform::kernel_release()?;
    let Some(path) = layout.kernel_config_file(&release) else {
        return Ok(None);
    };
    probe::read_optional(&path)?
        .map(|bytes| {
            String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))
        })
        .transpose()
}

fn secretmem_check(layout: &Layout) -> anyhow::Result<Check> {
    let description = "kernel CONFIG_SECRETMEM enables the memfd_secret syscall";
    let Some(config) = kernel_config(layout)? else {
        return Ok(Check::new(
            "mem.config_secretmem",
            CATEGORY,
            Status::Warn,
            "kernel configuration unavailable",
            "neither config.gz in the process filesystem nor the boot configuration exists; mem.backend reports the effective backend",
        ));
    };
    Ok(match kernel_option(&config, "CONFIG_SECRETMEM") {
        Some("y") => Check::new(
            "mem.config_secretmem",
            CATEGORY,
            Status::Pass,
            "y",
            description,
        ),
        Some(other) => Check::new(
            "mem.config_secretmem",
            CATEGORY,
            Status::Fail,
            other,
            description,
        ),
        None => Check::new(
            "mem.config_secretmem",
            CATEGORY,
            Status::Fail,
            "not set",
            description,
        ),
    })
}

/// The soft and hard values of limit `name` in a `/proc/<pid>/limits`
/// table, proc(5); `None` when the table has no such limit.
fn limit_values<'t>(table: &'t str, name: &str) -> Option<(&'t str, &'t str)> {
    table.lines().find_map(|line| {
        let mut values = line.strip_prefix(name)?.split_whitespace();
        Some((values.next()?, values.next()?))
    })
}

fn core_limit_check(layout: &Layout, pids: &[(&'static str, u32)]) -> anyhow::Result<Check> {
    let mut dumping = Vec::new();
    for &(name, pid) in pids {
        let Some(table) = probe::proc_file(layout, &format!("{pid}/limits"))? else {
            continue;
        };
        let (soft, hard) = limit_values(&table, "Max core file size")
            .ok_or_else(|| anyhow::anyhow!("process {pid} limits have no core file size"))?;
        if soft != "0" {
            dumping.push(format!("{name} (soft {soft}, hard {hard})"));
        }
    }
    Ok(if dumping.is_empty() {
        Check::new(
            "mem.core_limit",
            CATEGORY,
            Status::Pass,
            "0 (disabled)",
            "LimitCORE=0 prevents secret material in core dumps",
        )
    } else {
        Check::new(
            "mem.core_limit",
            CATEGORY,
            Status::Fail,
            format!("core dumps possible: {}", dumping.join(", ")),
            "set LimitCORE=0 in the daemon units",
        )
    })
}

fn swap_check(layout: &Layout, pids: &[(&'static str, u32)]) -> anyhow::Result<Check> {
    let mut swapped = Vec::new();
    let mut total = 0;
    for &(name, pid) in pids {
        let Some(swap) = probe::process_status_field(layout, pid, "VmSwap")? else {
            continue;
        };
        let kib = probe::kib(&swap)?;
        if kib > 0 {
            swapped.push(name);
            total += kib;
        }
    }
    Ok(if swapped.is_empty() {
        Check::new("mem.swap_usage", CATEGORY, Status::Pass, "0 kB", "")
    } else {
        Check::new(
            "mem.swap_usage",
            CATEGORY,
            Status::Warn,
            format!("{total} kB ({})", swapped.join(", ")),
            "daemon pages in swap; secret material may be on disk",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_options_match_whole_keys() {
        let config = "CONFIG_SECRETMEM_X=y\n# CONFIG_FOO is not set\nCONFIG_SECRETMEM=y\n";
        assert_eq!(kernel_option(config, "CONFIG_SECRETMEM"), Some("y"));
        assert_eq!(kernel_option(config, "CONFIG_FOO"), None);
        assert_eq!(
            kernel_option("# CONFIG_SECRETMEM is not set\n", "CONFIG_SECRETMEM"),
            None
        );
    }

    #[test]
    fn core_limits_read_soft_and_hard_columns() {
        let table = "Limit                     Soft Limit           Hard Limit           Units     \n\
                     Max cpu time              unlimited            unlimited            seconds   \n\
                     Max core file size        1024000              unlimited            bytes     \n";
        assert_eq!(
            limit_values(table, "Max core file size"),
            Some(("1024000", "unlimited"))
        );
        assert_eq!(limit_values(table, "Max open files"), None);
    }

    #[test]
    fn gzip_kernel_config_is_read_from_the_process_filesystem() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let proc_root = layout.proc_root().unwrap();
        std::fs::create_dir_all(proc_root).unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"CONFIG_SECRETMEM=y\n").unwrap();
        std::fs::write(proc_root.join("config.gz"), gz.finish().unwrap()).unwrap();
        let check = secretmem_check(&layout).unwrap();
        assert_eq!((check.status, check.value.as_str()), (Status::Pass, "y"));
    }

    #[test]
    fn boot_kernel_config_is_read_when_config_gz_is_absent() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let path = layout
            .kernel_config_file(&super::super::platform::kernel_release().unwrap())
            .unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# CONFIG_SECRETMEM is not set\n").unwrap();
        let check = secretmem_check(&layout).unwrap();
        assert_eq!(
            (check.status, check.value.as_str()),
            (Status::Fail, "not set")
        );
        std::fs::remove_file(&path).unwrap();
        assert_eq!(secretmem_check(&layout).unwrap().status, Status::Warn);
    }
}
