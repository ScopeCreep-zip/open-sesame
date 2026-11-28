//! `sesame status --doctor` — system health and security posture diagnostics.
//!
//! Each check category is a module returning its checks. A probe that
//! cannot be completed is a failed check carrying the error as its value,
//! never a guessed value.

mod config;
mod daemon;
mod memory;
mod network;
mod platform;
mod probe;
mod sandbox;

use std::process::ExitCode;

use core_layout::Layout;
use owo_colors::OwoColorize;

use open_sesame::cli::{DoctorCategory, DoctorFormat};

/// Result of a single diagnostic check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    /// Unique identifier (e.g. "daemon.wm.running").
    pub id: String,
    /// Category for grouping.
    pub category: &'static str,
    /// Pass / Warn / Fail.
    pub status: Status,
    /// Human-readable value (e.g. "active", "19 MB / 128 MB").
    pub value: String,
    /// What the check verifies, or the remedy when it does not pass.
    pub description: String,
}

impl Check {
    pub fn new(
        id: impl Into<String>,
        category: &'static str,
        status: Status,
        value: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category,
            status,
            value: value.into(),
            description: description.into(),
        }
    }

    /// The failed check of a probe that could not be completed.
    pub fn probe_failed(
        id: impl Into<String>,
        category: &'static str,
        error: &anyhow::Error,
    ) -> Self {
        Self::new(
            id,
            category,
            Status::Fail,
            format!("{error:#}"),
            "the probe could not be completed",
        )
    }
}

/// Check result severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

/// The categories `selection` names, in their canonical order, each once.
fn expand(selection: &[DoctorCategory]) -> Vec<DoctorCategory> {
    const ORDER: [DoctorCategory; 6] = [
        DoctorCategory::Daemon,
        DoctorCategory::Config,
        DoctorCategory::Memory,
        DoctorCategory::Network,
        DoctorCategory::Sandbox,
        DoctorCategory::Platform,
    ];
    if selection.contains(&DoctorCategory::All) {
        return ORDER.to_vec();
    }
    ORDER
        .into_iter()
        .filter(|category| selection.contains(category))
        .collect()
}

/// Run the checks of `categories` and print them in `format`. With
/// `exit_code`, the exit status is 1 when any check fails and 2 when any
/// warns.
///
/// # Errors
///
/// When the clock is before the Unix epoch or JSON cannot be written.
pub async fn cmd_doctor(
    layout: &Layout,
    categories: &[DoctorCategory],
    format: DoctorFormat,
    exit_code: bool,
    quiet: bool,
) -> anyhow::Result<ExitCode> {
    let mut checks = Vec::new();
    for category in expand(categories) {
        checks.extend(match category {
            DoctorCategory::Daemon => daemon::checks(layout),
            DoctorCategory::Config => config::checks(layout).await,
            DoctorCategory::Memory => memory::checks(layout),
            DoctorCategory::Network => network::checks(),
            DoctorCategory::Sandbox => sandbox::checks(layout),
            DoctorCategory::Platform => platform::checks(layout),
            DoctorCategory::All => unreachable!("expand resolves All"),
        });
    }

    let count = |status| checks.iter().filter(|c| c.status == status).count();
    let (pass, warn, fail) = (
        count(Status::Pass),
        count(Status::Warn),
        count(Status::Fail),
    );

    if !quiet {
        match format {
            DoctorFormat::Text => print_text(&checks, pass, warn, fail),
            DoctorFormat::Json => print_json(&checks, pass, warn, fail)?,
        }
    }

    Ok(match (exit_code, fail, warn) {
        (false, ..) | (true, 0, 0) => ExitCode::SUCCESS,
        (true, 0, _) => ExitCode::from(2),
        (true, ..) => ExitCode::from(1),
    })
}

fn print_text(checks: &[Check], pass: usize, warn: usize, fail: usize) {
    let mut current_category = "";
    for check in checks {
        if check.category != current_category {
            if !current_category.is_empty() {
                println!();
            }
            println!("{}", check.category.to_uppercase().bold());
            current_category = check.category;
        }
        let (icon, value) = match check.status {
            Status::Pass => ("✓".green().to_string(), check.value.green().to_string()),
            Status::Warn => ("⚠".yellow().to_string(), check.value.yellow().to_string()),
            Status::Fail => ("✗".red().to_string(), check.value.red().to_string()),
        };
        println!("  {icon} {:<32} {value}", check.id);
        if check.status != Status::Pass && !check.description.is_empty() {
            println!("    {}", check.description.dimmed());
        }
    }

    println!();
    let summary = format!("{pass} passed, {warn} warnings, {fail} failures");
    if fail > 0 {
        println!("{}", summary.red());
    } else if warn > 0 {
        println!("{}", summary.yellow());
    } else {
        println!("{}", summary.green());
    }
}

fn print_json(checks: &[Check], pass: usize, warn: usize, fail: usize) -> anyhow::Result<()> {
    let output = serde_json::json!({
        "timestamp": rfc3339_utc(std::time::SystemTime::now())?,
        "version": env!("CARGO_PKG_VERSION"),
        "summary": { "pass": pass, "warn": warn, "fail": fail },
        "checks": checks,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// `time` as an RFC 3339 UTC timestamp with second precision
/// (`2026-11-25T08:15:00Z`).
///
/// # Errors
///
/// When `time` is before the Unix epoch.
fn rfc3339_utc(time: std::time::SystemTime) -> anyhow::Result<String> {
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock is before the Unix epoch: {e}"))?
        .as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil_from_days(days);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// The proleptic Gregorian date `days` after 1970-01-01 (H. Hinnant's
/// `civil_from_days`, restricted to non-negative day counts).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_rfc3339_utc() {
        let at = |secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
        assert_eq!(rfc3339_utc(at(0)).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339_utc(at(951_782_400)).unwrap(),
            "2000-02-29T00:00:00Z"
        );
        assert_eq!(
            rfc3339_utc(at(1_798_761_599)).unwrap(),
            "2026-12-31T23:59:59Z"
        );
        assert!(rfc3339_utc(at(0) - std::time::Duration::from_secs(1)).is_err());
    }

    #[test]
    fn categories_expand_in_canonical_order_once() {
        assert_eq!(
            expand(&[
                DoctorCategory::Platform,
                DoctorCategory::Daemon,
                DoctorCategory::Platform
            ]),
            [DoctorCategory::Daemon, DoctorCategory::Platform]
        );
        assert_eq!(expand(&[DoctorCategory::All]).len(), 6);
    }
}
