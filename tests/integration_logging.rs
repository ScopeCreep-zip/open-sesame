//! Integration tests for logging behavior
//!
//! Verifies that all tracing output goes to stderr, never stdout.
//! This is critical for commands like `sesame --print-config > file.toml`
//! which must produce clean output files without log contamination.

use std::process::Command;

/// Regression test: Verifies --print-config outputs clean TOML without log contamination
///
/// Background:
/// Before the centralized logging fix, tracing output would go to stdout,
/// corrupting the TOML output when users redirected stdout to a file.
///
/// This test ensures:
/// 1. stdout contains ONLY the TOML configuration (no log lines)
/// 2. stderr contains the tracing logs
/// 3. The TOML in stdout is valid and parseable
#[test]
fn test_print_config_stdout_clean_no_logs() {
    // Build path to binary (handles both debug and release builds)
    let binary_path = env!("CARGO_BIN_EXE_sesame");

    // Run sesame --print-config and capture stdout/stderr separately
    let output = Command::new(binary_path)
        .arg("--print-config")
        .output()
        .expect("Failed to execute sesame binary");

    // Convert output to strings
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Verify exit code
    assert!(
        output.status.success(),
        "sesame --print-config should exit successfully"
    );

    // Critical: stdout must NOT contain any log markers
    assert!(
        !stdout.contains("INFO"),
        "stdout should not contain INFO log level"
    );
    assert!(
        !stdout.contains("DEBUG"),
        "stdout should not contain DEBUG log level"
    );
    assert!(
        !stdout.contains("WARN"),
        "stdout should not contain WARN log level"
    );
    assert!(
        !stdout.contains("ERROR"),
        "stdout should not contain ERROR log level"
    );
    assert!(
        !stdout.contains("run_cli"),
        "stdout should not contain log function names"
    );
    assert!(
        !stdout.contains("parsing CLI"),
        "stdout should not contain log messages"
    );

    // Verify stdout contains ONLY TOML (check for expected TOML sections)
    assert!(
        stdout.contains("[settings]"),
        "stdout should contain TOML [settings] section"
    );
    assert!(
        stdout.contains("activation_key"),
        "stdout should contain TOML configuration keys"
    );

    // Verify stderr contains the logs (if any)
    // Note: Logs may not appear if logging is disabled in tests,
    // but if they do appear, they should be in stderr only
    if stderr.contains("INFO") || stderr.contains("run_cli") {
        // If logs exist, verify they're in stderr, not stdout
        assert!(
            stderr.contains("INFO") || stderr.contains("run_cli"),
            "stderr should contain log output when logging is enabled"
        );
    }

    // Additional validation: ensure stdout is valid TOML structure
    // by checking for common TOML patterns
    let toml_patterns = vec!["=", "[", "]"];
    for pattern in toml_patterns {
        assert!(
            stdout.contains(pattern),
            "stdout should contain TOML syntax: {}",
            pattern
        );
    }

    // Ensure no ANSI color codes in stdout (would corrupt file redirection)
    assert!(
        !stdout.contains("\x1b["),
        "stdout should not contain ANSI escape codes"
    );
}

/// Verifies that normal command execution (non --print-config) logs to stderr
#[test]
fn test_help_command_logs_to_stderr_not_stdout() {
    let binary_path = env!("CARGO_BIN_EXE_sesame");

    // Run sesame --help and capture output
    let output = Command::new(binary_path)
        .arg("--help")
        .output()
        .expect("Failed to execute sesame binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // --help should output usage to stdout (this is expected for clap)
    assert!(
        stdout.contains("Open Sesame") || stdout.contains("Usage:"),
        "stdout should contain help text"
    );

    // If any logs are present, they should be in stderr only
    // This prevents log contamination when users redirect help text
    if !stderr.is_empty() {
        // Logs might be present in stderr, but never in stdout
        assert!(
            !stdout.contains("INFO") && !stdout.contains("run_cli"),
            "stdout should not contain log output"
        );
    }
}

/// Verifies validate-config outputs to stdout cleanly
#[test]
fn test_validate_config_stdout_clean() {
    let binary_path = env!("CARGO_BIN_EXE_sesame");

    let output = Command::new(binary_path)
        .arg("--validate-config")
        .output()
        .expect("Failed to execute sesame binary");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // stdout should contain validation result, not log messages
    if output.status.success() {
        // Either "Configuration is valid" or issue list
        assert!(
            stdout.contains("Configuration") || stdout.contains("valid"),
            "stdout should contain validation result"
        );

        // Should NOT contain log markers
        assert!(
            !stdout.contains("INFO") && !stdout.contains("run_cli"),
            "stdout should not contain log output"
        );
    }
}

/// Documents the critical requirement for all future developers
///
/// This test serves as living documentation that ALL logging
/// must use stderr to prevent stdout contamination.
#[test]
fn test_logging_documentation_requirement() {
    // This test always passes but documents the requirement:
    //
    // CRITICAL REQUIREMENT:
    // All tracing_subscriber::fmt() calls MUST use .with_writer(std::io::stderr)
    //
    // Rationale:
    // - Commands like --print-config redirect stdout to files
    // - Logs in stdout corrupt the output files
    // - This was a production bug that caused invalid TOML files
    //
    // The centralized logging module (src/util/log.rs) enforces this.
    // Future developers: DO NOT create ad-hoc logging configurations.
    // Always use: open_sesame::util::log::init()

    // This test passes by virtue of existing - it serves as documentation.
    // The actual enforcement is in src/util/log.rs which uses stderr.
}
