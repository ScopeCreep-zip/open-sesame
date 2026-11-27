//! Secrets as environment variables: the variable a secret key becomes,
//! and the variables no secret may set. Every process that injects secrets
//! into a child environment (`sesame env`, `sesame export`, `sesame
//! workspace shell`, daemon-launcher) applies both.

/// The environment variable secret `key` becomes: ASCII letters and digits
/// uppercased, every other character `_`, after `<prefix>_` when a prefix
/// is given. `api-key` -> `API_KEY`; with prefix `MYAPP`, `MYAPP_API_KEY`.
#[must_use]
pub fn env_var_name(key: &str, prefix: Option<&str>) -> String {
    let name: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    match prefix {
        Some(prefix) => format!("{prefix}_{name}"),
        None => name,
    }
}

/// Variables no secret may set: dynamic linker, shell execution, path
/// hijack, credential, and privilege escalation vectors.
const PROTECTED: &[&str] = &[
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
    // Systemd / session bus
    "SYSTEMD_UNIT_PATH",
    "DBUS_SESSION_BUS_ADDRESS",
];

/// Prefixes no secret may set: exported bash functions, and Open Sesame's
/// own namespace (`SESAME_PROFILES`, `SESAME_PROFILE`, `SESAME_WORKSPACE`,
/// `SESAME_APP_ID`, `SESAME_SOCKET`), which the injecting process sets.
const PROTECTED_PREFIXES: &[&str] = &["BASH_FUNC_", "SESAME_"];

/// Whether no secret may set variable `name` (ASCII case-insensitive).
#[must_use]
pub fn is_protected_env_var(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    PROTECTED.contains(&upper.as_str())
        || PROTECTED_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_uppercase_with_underscores() {
        assert_eq!(env_var_name("api-key", None), "API_KEY");
        assert_eq!(env_var_name("api-key", Some("MYAPP")), "MYAPP_API_KEY");
        assert_eq!(env_var_name("db.host-name", None), "DB_HOST_NAME");
        assert_eq!(env_var_name("a b/c", None), "A_B_C");
    }

    #[test]
    fn execution_vectors_are_protected() {
        for name in ["LD_PRELOAD", "ld_preload", "Path", "BASH_FUNC_evil%%"] {
            assert!(is_protected_env_var(name), "{name}");
        }
        for name in ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "CORP_API_KEY"] {
            assert!(!is_protected_env_var(name), "{name}");
        }
    }

    #[test]
    fn sesame_namespace_is_protected() {
        for name in [
            "SESAME_PROFILES",
            "SESAME_WORKSPACE",
            "SESAME_PROFILE",
            "SESAME_SOCKET",
            "sesame_app_id",
        ] {
            assert!(is_protected_env_var(name), "{name}");
        }
    }
}
