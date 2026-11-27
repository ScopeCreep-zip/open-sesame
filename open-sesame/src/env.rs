//! `sesame env` and `sesame export`: secrets as environment variables.

use std::process::ExitCode;

use core_layout::Layout;

use crate::ipc::{SecretEnv, connect, fetch_multi_profile_secrets};
use open_sesame::cli::{ExportFormat, ProfileSpecs};

/// `sesame env`: run `command` with the secrets of `specs` in its
/// environment and `SESAME_PROFILES` naming them.
pub(crate) async fn cmd_env(
    layout: &Layout,
    specs: &ProfileSpecs,
    prefix: Option<&str>,
    command: &[String],
) -> anyhow::Result<ExitCode> {
    let Some((program, args)) = command.split_first() else {
        anyhow::bail!("no command specified");
    };
    let client = connect(layout).await?;
    let secrets = fetch_multi_profile_secrets(&client, specs, prefix).await?;
    client.shutdown().await;

    let mut child = std::process::Command::new(program);
    child.args(args).env("SESAME_PROFILES", specs.to_string());
    crate::child::run_with_secrets(child, secrets)
}

/// A secret value as text for an export format. Formats are text, so a
/// non-UTF-8 value is an error, and NUL cannot be an environment value.
fn export_text<'v>(name: &str, value: &'v [u8]) -> anyhow::Result<&'v str> {
    let text = std::str::from_utf8(value).map_err(|_| {
        anyhow::anyhow!("secret {name} is not UTF-8 and cannot be exported as text")
    })?;
    anyhow::ensure!(
        !text.contains('\0'),
        "secret {name} contains a NUL byte, which no environment value can hold"
    );
    Ok(text)
}

/// POSIX single-quoted word: every byte literal, `'` written as `'\''`.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Double-quoted dotenv value with `\`, `"`, newline and carriage return
/// escaped.
fn dotenv_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The export document of `secrets` in `format`.
fn render_export(
    secrets: &SecretEnv,
    format: ExportFormat,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use std::fmt::Write as _;
    let mut out = zeroize::Zeroizing::new(String::new());
    match format {
        ExportFormat::Shell => {
            for (name, value) in secrets {
                let value = zeroize::Zeroizing::new(shell_quote(export_text(name, value)?));
                writeln!(out, "export {name}={}", *value)?;
            }
        }
        ExportFormat::Dotenv => {
            for (name, value) in secrets {
                let value = zeroize::Zeroizing::new(dotenv_quote(export_text(name, value)?));
                writeln!(out, "{name}={}", *value)?;
            }
        }
        ExportFormat::Json => {
            let mut map = serde_json::Map::new();
            for (name, value) in secrets {
                map.insert(
                    name.clone(),
                    serde_json::Value::String(export_text(name, value)?.to_owned()),
                );
            }
            let document = serde_json::Value::Object(map);
            out.push_str(&serde_json::to_string(&document)?);
            out.push('\n');
            if let serde_json::Value::Object(map) = document {
                for (_, value) in map {
                    if let serde_json::Value::String(mut s) = value {
                        zeroize::Zeroize::zeroize(&mut s);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// `sesame export`: print the secrets of `specs` in `format`.
pub(crate) async fn cmd_export(
    layout: &Layout,
    specs: &ProfileSpecs,
    format: ExportFormat,
    prefix: Option<&str>,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let secrets = fetch_multi_profile_secrets(&client, specs, prefix).await?;
    client.shutdown().await;
    print!("{}", *render_export(&secrets, format)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(pairs: &[(&str, &[u8])]) -> SecretEnv {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), zeroize::Zeroizing::new(v.to_vec())))
            .collect()
    }

    #[test]
    fn shell_export_round_trips_through_sh() {
        let value: &[u8] = b"it's $HOME `id` !x \\n\nsecond\"line";
        let doc = render_export(&secrets(&[("K", value)]), ExportFormat::Shell).unwrap();
        let out = std::process::Command::new("sh")
            .args(["-c", "eval \"$1\"; printf '%s' \"$K\"", "_", &doc])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, value);
    }

    #[test]
    fn dotenv_escapes_quotes_backslashes_and_newlines() {
        let doc = render_export(&secrets(&[("K", b"a\"b\\c\nd")]), ExportFormat::Dotenv).unwrap();
        assert_eq!(&**doc, "K=\"a\\\"b\\\\c\\nd\"\n");
    }

    #[test]
    fn json_export_is_valid_json_in_order() {
        let doc = render_export(
            &secrets(&[("B", b"x\"\n\x01"), ("A", b"y")]),
            ExportFormat::Json,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert_eq!(parsed["B"], "x\"\n\u{1}");
        assert_eq!(parsed["A"], "y");
    }

    #[test]
    fn text_formats_refuse_unrepresentable_values() {
        for format in [
            ExportFormat::Shell,
            ExportFormat::Dotenv,
            ExportFormat::Json,
        ] {
            assert!(render_export(&secrets(&[("K", &[0xFF])]), format).is_err());
            assert!(render_export(&secrets(&[("K", b"a\0b")]), format).is_err());
        }
    }
}
