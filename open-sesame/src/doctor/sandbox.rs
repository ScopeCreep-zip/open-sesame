//! Sandbox checks — seccomp filter mode and `no_new_privs` on every running
//! daemon.

use core_layout::Layout;

use super::probe;
use super::{Check, Status};

const CATEGORY: &str = "sandbox";

/// One sandbox property: a `/proc/<pid>/status` field and the value it
/// holds on a confined daemon.
struct Property {
    id: &'static str,
    field: &'static str,
    expected: &'static str,
    pass: &'static str,
    /// The severity when a daemon lacks the property.
    missing: Status,
    description: &'static str,
}

const PROPERTIES: [Property; 2] = [
    Property {
        id: "sandbox.seccomp",
        field: "Seccomp",
        expected: "2",
        pass: "filter mode (all daemons)",
        missing: Status::Fail,
        description: "seccomp BPF restricts the syscalls available to each daemon",
    },
    Property {
        id: "sandbox.no_new_privs",
        field: "NoNewPrivs",
        expected: "1",
        pass: "set (all daemons)",
        missing: Status::Warn,
        description: "NoNewPrivileges prevents privilege escalation through setuid and capabilities",
    },
];

/// The daemons among `pids` whose `property` does not hold. A daemon that
/// exited between listing and reading is skipped.
fn lacking(
    layout: &Layout,
    pids: &[(&'static str, u32)],
    property: &Property,
) -> anyhow::Result<Vec<String>> {
    let mut lacking = Vec::new();
    for &(name, pid) in pids {
        let Some(status) = probe::proc_file(layout, &format!("{pid}/status"))? else {
            continue;
        };
        match probe::status_field(&status, property.field) {
            Some(value) if value == property.expected => {}
            Some(value) => lacking.push(format!("{name} ({}={value})", property.field)),
            None => lacking.push(format!("{name} (no {})", property.field)),
        }
    }
    Ok(lacking)
}

fn property_check(layout: &Layout, pids: &[(&'static str, u32)], property: &Property) -> Check {
    match lacking(layout, pids, property) {
        Err(e) => Check::probe_failed(property.id, CATEGORY, &e),
        Ok(lacking) if lacking.is_empty() => Check::new(
            property.id,
            CATEGORY,
            Status::Pass,
            property.pass,
            property.description,
        ),
        Ok(lacking) => Check::new(
            property.id,
            CATEGORY,
            property.missing,
            format!("not confined: {}", lacking.join(", ")),
            property.description,
        ),
    }
}

pub fn checks(layout: &Layout) -> Vec<Check> {
    PROPERTIES
        .iter()
        .map(
            |property| match probe::inspectable_daemons(property.id, CATEGORY) {
                Err(check) => check,
                Ok(pids) => property_check(layout, &pids, property),
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfined_daemons_are_named() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        for (pid, status) in [(10, "Seccomp:\t2\nNoNewPrivs:\t1\n"), (11, "Seccomp:\t0\n")] {
            let dir = layout.proc_root().unwrap().join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("status"), status).unwrap();
        }
        let pids = [("wm", 10), ("secrets", 11), ("gone", 12)];
        let seccomp = property_check(&layout, &pids, &PROPERTIES[0]);
        assert_eq!(seccomp.status, Status::Fail);
        assert_eq!(seccomp.value, "not confined: secrets (Seccomp=0)");
        let nnp = property_check(&layout, &pids, &PROPERTIES[1]);
        assert_eq!(nnp.status, Status::Warn);
        assert_eq!(nnp.value, "not confined: secrets (no NoNewPrivs)");
        let confined = property_check(&layout, &pids[..1], &PROPERTIES[0]);
        assert_eq!(confined.status, Status::Pass);
    }
}
