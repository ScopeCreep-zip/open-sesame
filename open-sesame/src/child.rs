//! Running a command with secrets in its environment: the commands
//! `sesame env` and `sesame workspace shell` share.

use std::ffi::OsStr;
use std::process::{Command, ExitCode, ExitStatus};

use anyhow::Context;

use crate::ipc::SecretEnv;

/// A secret's bytes as an environment value, byte-exact. Unix environment
/// values are arbitrary bytes; elsewhere they must be Unicode, and a
/// non-UTF-8 secret is an error rather than a lossy replacement.
#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature for every platform; conversion fails off Unix"
)]
fn secret_env_value<'v>(_name: &str, value: &'v [u8]) -> anyhow::Result<&'v OsStr> {
    use std::os::unix::ffi::OsStrExt;
    Ok(OsStr::from_bytes(value))
}

#[cfg(not(unix))]
fn secret_env_value<'v>(name: &str, value: &'v [u8]) -> anyhow::Result<&'v OsStr> {
    std::str::from_utf8(value).map(OsStr::new).map_err(|_| {
        anyhow::anyhow!(
            "secret {name} is not valid UTF-8 and cannot be an environment value on this platform"
        )
    })
}

/// The exit status a command's status maps to: its exit code, or
/// 128 + signal when a signal terminated it (the shell convention).
fn exit_code(status: ExitStatus) -> u8 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return u8::try_from(128 + signal).unwrap_or(u8::MAX);
        }
    }
    // Unix exit codes are 0..=255 (WEXITSTATUS); a status without a code
    // is only produced by a signal, handled above.
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1)
}

/// Run `command` with `secrets` added to its environment and wait for it.
/// The secret values are zeroized when this returns.
///
/// # Errors
///
/// When a value cannot be an environment value on this platform, or the
/// command cannot be spawned or waited for.
pub(crate) fn run_with_secrets(
    mut command: Command,
    secrets: SecretEnv,
) -> anyhow::Result<ExitCode> {
    for (name, value) in &secrets {
        command.env(name, secret_env_value(name, value)?);
    }
    let program = command.get_program().to_string_lossy().into_owned();
    let status = command
        .status()
        .with_context(|| format!("failed to run {program}"))?;
    drop(secrets);
    Ok(ExitCode::from(exit_code(status)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn secret_env_value_is_byte_exact() {
        use std::os::unix::ffi::OsStrExt;
        let bytes = [0x66, 0xFF, 0x00, 0xC3, 0x28];
        assert_eq!(secret_env_value("K", &bytes).unwrap().as_bytes(), &bytes);
    }

    #[cfg(unix)]
    #[test]
    fn signal_exit_uses_shell_convention() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 128 + 9);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_secrets_reach_the_child_unchanged() {
        let secrets: SecretEnv = vec![(
            "SESAME_TEST_VALUE".into(),
            zeroize::Zeroizing::new(vec![b'a', 0xFF, b'b']),
        )];
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "test \"$(printf '%s' \"$SESAME_TEST_VALUE\" | od -An -tx1 | tr -d ' ')\" = 61ff62",
        ]);
        assert_eq!(
            run_with_secrets(command, secrets).unwrap(),
            ExitCode::SUCCESS
        );
    }
}
