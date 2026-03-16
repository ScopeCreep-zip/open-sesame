//! CLI integration tests for `sesame`.
//!
//! Tests CLI argument parsing, validation errors, exit codes, and help output.
//! These tests do NOT require a running daemon — they verify the CLI boundary.

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

fn sesame() -> assert_cmd::Command {
    cargo_bin_cmd!("sesame")
}

// ===== T2.3: CLI Argument Parsing and Validation =====

#[test]
fn help_flag_exits_zero() {
    sesame()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("sesame").or(predicate::str::contains("Sesame")));
}

#[test]
fn version_flag_exits_zero() {
    sesame().arg("--version").assert().success();
}

#[test]
fn unknown_subcommand_exits_nonzero() {
    sesame()
        .arg("nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error").or(predicate::str::contains("unrecognized")));
}

#[test]
fn missing_required_args_exits_nonzero() {
    // `sesame secret get` without --profile and key should fail
    sesame()
        .args(["secret", "get"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

#[test]
fn secret_subcommand_help_exits_zero() {
    sesame()
        .args(["secret", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret").or(predicate::str::contains("Secret")));
}

#[test]
fn profile_subcommand_help_exits_zero() {
    sesame()
        .args(["profile", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("profile").or(predicate::str::contains("Profile")));
}

#[test]
fn launch_search_help_exits_zero() {
    sesame()
        .args(["launch", "search", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("query").or(predicate::str::contains("Search")));
}

#[test]
fn launch_run_help_exits_zero() {
    sesame()
        .args(["launch", "run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entry").or(predicate::str::contains("Launch")));
}

#[test]
fn env_requires_profile_and_command() {
    sesame()
        .arg("env")
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

#[test]
fn env_help_exits_zero() {
    sesame().args(["env", "--help"]).assert().success().stdout(
        predicate::str::contains("environment")
            .or(predicate::str::contains("secrets"))
            .or(predicate::str::contains("SESAME_PROFILE")),
    );
}

// ===== WM subcommand tests =====

#[test]
fn wm_help_exits_zero() {
    sesame()
        .args(["wm", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wm").or(predicate::str::contains("Window")));
}

#[test]
fn wm_list_help_exits_zero() {
    sesame()
        .args(["wm", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("List").or(predicate::str::contains("window")));
}

#[test]
fn wm_switch_help_exits_zero() {
    sesame()
        .args(["wm", "switch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Switch").or(predicate::str::contains("backward")));
}

#[test]
fn wm_focus_requires_window_id() {
    sesame()
        .args(["wm", "focus"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

// ===== SSH subcommand tests =====

#[test]
fn ssh_help_exits_zero() {
    sesame()
        .args(["ssh", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SSH").or(predicate::str::contains("ssh")));
}

#[test]
fn ssh_enroll_help_exits_zero() {
    sesame()
        .args(["ssh", "enroll", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Enroll").or(predicate::str::contains("enroll")));
}

#[test]
fn ssh_list_help_exits_zero() {
    sesame()
        .args(["ssh", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("List").or(predicate::str::contains("list")));
}

#[test]
fn ssh_revoke_help_exits_zero() {
    sesame()
        .args(["ssh", "revoke", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Revoke").or(predicate::str::contains("revoke")));
}
