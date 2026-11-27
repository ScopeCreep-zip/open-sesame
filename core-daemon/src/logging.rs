//! The tracing subscriber every PDS process installs.

use anyhow::Context;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

/// Log output format, selected by `--log-format` / `PDS_LOG_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    /// One JSON object per event (journald, log shippers).
    Json,
    /// Human-readable lines.
    Pretty,
}

/// Install the global tracing subscriber of a daemon: events to stdout,
/// filtered by `RUST_LOG`; unset or empty means `info`.
///
/// # Errors
///
/// When `RUST_LOG` contains an invalid directive, or a global subscriber
/// is already installed.
pub fn init_logging(format: LogFormat) -> anyhow::Result<()> {
    let builder = tracing_subscriber::fmt().with_env_filter(filter(LevelFilter::INFO)?);
    match format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.try_init(),
    }
    .map_err(|e| anyhow::anyhow!("failed to install the tracing subscriber: {e}"))
}

/// Install the global tracing subscriber of the `sesame` CLI: human-readable
/// events to stderr, so they never mix with command output on stdout,
/// filtered by `RUST_LOG`; unset or empty means off.
///
/// # Errors
///
/// When `RUST_LOG` contains an invalid directive, or a global subscriber
/// is already installed.
pub fn init_cli_logging() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(filter(LevelFilter::OFF)?)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to install the tracing subscriber: {e}"))
}

/// The `RUST_LOG` filter, with `default` when it is unset or empty.
fn filter(default: LevelFilter) -> anyhow::Result<EnvFilter> {
    EnvFilter::builder()
        .with_default_directive(default.into())
        .from_env()
        .context("invalid RUST_LOG")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    #[test]
    fn log_format_accepts_known_names_only() {
        assert_eq!(LogFormat::from_str("json", false), Ok(LogFormat::Json));
        assert_eq!(LogFormat::from_str("pretty", false), Ok(LogFormat::Pretty));
        assert!(LogFormat::from_str("jsno", false).is_err());
    }
}
