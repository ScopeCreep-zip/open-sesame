use anyhow::Context;
use zeroize::Zeroize;

use crate::cli::ExportFormat;
use crate::ipc::{connect, fetch_multi_profile_secrets, resolve_profile_specs};

/// Transform a secret key name into an environment variable name.
///
/// Rules: uppercase, hyphens and dots become underscores, strip non-alphanumeric
/// except underscores. With prefix "MYAPP": "api-key" -> "MYAPP_API_KEY".
pub(crate) fn secret_key_to_env_var(key: &str, prefix: Option<&str>) -> String {
    let var: String = key
        .chars()
        .map(|c| match c {
            '-' | '.' => '_',
            c if c.is_ascii_alphanumeric() || c == '_' => c.to_ascii_uppercase(),
            _ => '_',
        })
        .collect();

    match prefix {
        Some(p) => format!("{p}_{var}"),
        None => var,
    }
}

pub(crate) async fn cmd_env(
    profile: Option<&str>,
    prefix: Option<&str>,
    command: &[String],
) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    if command.first().is_some_and(|c| c.starts_with('-')) {
        eprintln!("hint: use '--' to separate sesame options from the command, e.g.:");
        eprintln!("  sesame env -p default -- {}", command.join(" "));
    }

    let specs = resolve_profile_specs(profile);
    let client = connect().await?;
    let env_vars = fetch_multi_profile_secrets(&client, &specs, prefix).await?;

    // Spawn child process with secrets as env vars.
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Inject SESAME_PROFILES so the child knows its context.
    let profiles_csv: String = specs
        .iter()
        .map(|s| match &s.org {
            Some(org) => format!("{org}:{}", s.vault),
            None => s.vault.clone(),
        })
        .collect::<Vec<_>>()
        .join(",");
    cmd.env("SESAME_PROFILES", &profiles_csv);

    // Inject each secret as an env var.
    for (env_name, value) in &env_vars {
        let val_str = String::from_utf8_lossy(value);
        cmd.env(env_name, val_str.as_ref());
    }

    let mut child = cmd.spawn().context("failed to spawn command")?;

    let status = child.wait().context("failed to wait for child process")?;

    for (_, mut value) in env_vars {
        value.zeroize();
    }

    std::process::exit(status.code().unwrap_or(1));
}

/// Env var names that must never be overwritten by secret export.
/// Covers dynamic linker, shell execution, path hijack, and privilege escalation vectors.
const DENIED_ENV_VARS: &[&str] = &[
    // Dynamic linker — arbitrary code execution
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_PROFILE",
    "LD_SHOW_AUXV",
    "LD_BIND_NOW",
    "LD_BIND_NOT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Core execution environment
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LOGNAME",
    "LANG",
    "TERM",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    // Shell injection vectors
    "BASH_ENV",
    "ENV",
    "BASH_FUNC_",
    "CDPATH",
    "GLOBIGNORE",
    "SHELLOPTS",
    "BASHOPTS",
    "PROMPT_COMMAND",
    "PS1",
    "PS2",
    "PS4",
    "MAIL",
    "MAILPATH",
    "MAILCHECK",
    "IFS",
    // Language runtime code execution
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYLIB",
    "RUBYOPT",
    "GOPATH",
    "GOROOT",
    "GOFLAGS",
    "JAVA_HOME",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    // Security / auth
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "KRB5_CONFIG",
    "KRB5CCNAME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "NIX_SSL_CERT_FILE",
    // Nix
    "NIX_PATH",
    "NIX_CONF_DIR",
    // Sudo / privilege
    "SUDO_ASKPASS",
    "SUDO_EDITOR",
    "VISUAL",
    "EDITOR",
    // Systemd
    "SYSTEMD_UNIT_PATH",
    "DBUS_SESSION_BUS_ADDRESS",
    // Open Sesame's own namespace
    "SESAME_PROFILE",
];

/// Returns true if `name` is a denied env var (case-insensitive prefix match for BASH_FUNC_).
pub(crate) fn is_denied_env_var(name: &str) -> bool {
    if name.starts_with("BASH_FUNC_") {
        return true;
    }
    DENIED_ENV_VARS
        .iter()
        .any(|&d| d.eq_ignore_ascii_case(name))
}

/// Shell-escape a value for safe embedding in `export K="V"`.
/// Strips null bytes (C string truncation), escapes shell metacharacters.
pub(crate) fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\0' => {} // strip null bytes — C string truncation risk
            '"' | '\\' | '$' | '`' | '!' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

/// JSON-escape a string value.
pub(crate) fn json_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\0' => String::new(),
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if c.is_control() => format!("\\u{:04x}", c as u32),
            c => c.to_string(),
        })
        .collect()
}

pub(crate) async fn cmd_export(
    profile: Option<&str>,
    format: &ExportFormat,
    prefix: Option<&str>,
) -> anyhow::Result<()> {
    let specs = resolve_profile_specs(profile);
    let client = connect().await?;
    let raw_secrets = fetch_multi_profile_secrets(&client, &specs, prefix).await?;
    if raw_secrets.is_empty() {
        return Ok(());
    }

    // Convert byte values to strings for text output formats.
    let entries: Vec<(String, String)> = raw_secrets
        .into_iter()
        .map(|(k, v)| {
            let val_str = String::from_utf8_lossy(&v).into_owned();
            (k, val_str)
        })
        .collect();

    // Output in requested format.
    match format {
        ExportFormat::Shell => {
            for (k, v) in &entries {
                println!("export {}=\"{}\"", k, shell_escape(v));
            }
        }
        ExportFormat::Dotenv => {
            for (k, v) in &entries {
                println!("{}=\"{}\"", k, shell_escape(v));
            }
        }
        ExportFormat::Json => {
            print!("{{");
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    print!(",");
                }
                print!("\"{}\":\"{}\"", json_escape(k), json_escape(v));
            }
            println!("}}");
        }
    }

    // 4. Zeroize secret copies.
    for (_, mut v) in entries {
        unsafe {
            v.as_bytes_mut().zeroize();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape_plain() {
        assert_eq!(shell_escape("hello"), "hello");
    }

    #[test]
    fn shell_escape_special_chars() {
        assert_eq!(shell_escape(r#"a"b$c`d\e!f"#), r#"a\"b\$c\`d\\e\!f"#);
    }

    #[test]
    fn shell_escape_newlines() {
        assert_eq!(shell_escape("line1\nline2\r"), "line1\\nline2\\r");
    }

    #[test]
    fn secret_name_to_env_var_basic() {
        assert_eq!(secret_key_to_env_var("api-key", None), "API_KEY");
    }

    #[test]
    fn secret_name_to_env_var_with_prefix() {
        assert_eq!(
            secret_key_to_env_var("api-key", Some("MYAPP")),
            "MYAPP_API_KEY"
        );
    }

    #[test]
    fn secret_name_to_env_var_dots_and_mixed() {
        assert_eq!(secret_key_to_env_var("db.host-name", None), "DB_HOST_NAME");
    }

    #[test]
    fn shell_escape_strips_null_bytes() {
        assert_eq!(shell_escape("before\0after"), "beforeafter");
    }

    #[test]
    fn denied_env_var_ld_preload() {
        assert!(is_denied_env_var("LD_PRELOAD"));
    }

    #[test]
    fn denied_env_var_path() {
        assert!(is_denied_env_var("PATH"));
    }

    #[test]
    fn denied_env_var_case_insensitive() {
        assert!(is_denied_env_var("ld_preload"));
        assert!(is_denied_env_var("Path"));
    }

    #[test]
    fn denied_env_var_bash_func_prefix() {
        assert!(is_denied_env_var("BASH_FUNC_evil%%"));
    }

    #[test]
    fn denied_env_var_allows_normal_names() {
        assert!(!is_denied_env_var("GITHUB_TOKEN"));
        assert!(!is_denied_env_var("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_denied_env_var("CORP_API_KEY"));
    }

    #[test]
    fn denied_env_var_sesame_profile() {
        assert!(is_denied_env_var("SESAME_PROFILE"));
    }

    #[test]
    fn json_escape_special_chars() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn json_escape_strips_null() {
        assert_eq!(json_escape("ab\0cd"), "abcd");
    }

    #[test]
    fn json_escape_control_chars() {
        assert_eq!(json_escape("\x01\x1f"), "\\u0001\\u001f");
    }
}
