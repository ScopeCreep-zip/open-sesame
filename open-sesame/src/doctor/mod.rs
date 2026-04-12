//! `sesame status --doctor` — system health and security posture diagnostics.
//!
//! Each check category is a separate module returning `Vec<Check>`.
//! The runner collects, filters, formats, and optionally sets the exit code.

mod daemon;
mod memory;
mod platform;
mod sandbox;

use owo_colors::OwoColorize;

/// Result of a single diagnostic check.
#[derive(Debug, Clone)]
pub struct Check {
    /// Unique identifier (e.g. "daemon.wm.running").
    pub id: String,
    /// Category for grouping and filtering.
    pub category: &'static str,
    /// Pass / Warn / Fail.
    pub status: Status,
    /// Human-readable value (e.g. "active", "19 MB / 128 MB").
    pub value: String,
    /// Description of what this check verifies.
    pub description: String,
}

/// Check result severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Warn => write!(f, "WARN"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

/// Known check categories.
const ALL_CATEGORIES: &[&str] = &["daemon", "memory", "sandbox", "platform"];

/// Run diagnostic checks and produce output.
pub fn cmd_doctor(
    categories: &str,
    output_format: &str,
    exit_code: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let selected: Vec<&str> = if categories == "all" {
        ALL_CATEGORIES.to_vec()
    } else {
        categories.split(',').map(str::trim).collect()
    };

    let mut checks = Vec::new();

    for cat in &selected {
        match *cat {
            "daemon" => checks.extend(daemon::checks()),
            "memory" => checks.extend(memory::checks()),
            "sandbox" => checks.extend(sandbox::checks()),
            "platform" => checks.extend(platform::checks()),
            other => {
                eprintln!("Unknown doctor category: {other}");
                eprintln!("Available: {}", ALL_CATEGORIES.join(", "));
            }
        }
    }

    let pass_count = checks.iter().filter(|c| c.status == Status::Pass).count();
    let warn_count = checks.iter().filter(|c| c.status == Status::Warn).count();
    let fail_count = checks.iter().filter(|c| c.status == Status::Fail).count();

    match output_format {
        "json" => print_json(&checks, pass_count, warn_count, fail_count, quiet),
        _ => print_text(&checks, pass_count, warn_count, fail_count, quiet),
    }

    if exit_code {
        if fail_count > 0 {
            std::process::exit(1);
        } else if warn_count > 0 {
            std::process::exit(2);
        }
    }

    Ok(())
}

fn print_text(checks: &[Check], pass: usize, warn: usize, fail: usize, quiet: bool) {
    if quiet {
        return;
    }

    let mut current_category = "";
    for check in checks {
        if check.category != current_category {
            if !current_category.is_empty() {
                println!();
            }
            println!("{}", check.category.to_uppercase().bold());
            current_category = check.category;
        }

        let icon = match check.status {
            Status::Pass => "✓".green().to_string(),
            Status::Warn => "⚠".yellow().to_string(),
            Status::Fail => "✗".red().to_string(),
        };

        let value_display = match check.status {
            Status::Pass => check.value.green().to_string(),
            Status::Warn => check.value.yellow().to_string(),
            Status::Fail => check.value.red().to_string(),
        };

        println!("  {icon} {:<32} {value_display}", check.id,);
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

fn print_json(checks: &[Check], pass: usize, warn: usize, fail: usize, quiet: bool) {
    if quiet {
        return;
    }

    let checks_json: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "category": c.category,
                "status": c.status.to_string().to_lowercase(),
                "value": c.value,
                "description": c.description,
            })
        })
        .collect();

    let output = serde_json::json!({
        "timestamp": chrono_now(),
        "version": env!("CARGO_PKG_VERSION"),
        "summary": { "pass": pass, "warn": warn, "fail": fail },
        "checks": checks_json,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

fn chrono_now() -> String {
    // Simple ISO 8601 without pulling in chrono crate.
    let output = std::process::Command::new("date")
        .arg("-Iseconds")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    output.trim().to_string()
}
