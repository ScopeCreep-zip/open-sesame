//! Application launch command handling
//!
//! Represents commands to launch applications with environment configuration.

use crate::util::load_env_files;
use std::collections::HashMap;
use std::process::Command;

/// A command to launch an application
///
/// Represents a command to execute with environment configuration support.
/// Created from [`crate::config::LaunchConfig`] for execution.
///
/// # Examples
///
/// ```no_run
/// use open_sesame::core::LaunchCommand;
///
/// // Simple command
/// let cmd = LaunchCommand::simple("firefox");
/// cmd.execute(&[])?;
///
/// // Advanced command with args and env
/// let mut env = std::collections::HashMap::new();
/// env.insert("EDITOR".to_string(), "vim".to_string());
///
/// let cmd = LaunchCommand::advanced(
///     "ghostty",
///     vec!["--config".to_string(), "custom.toml".to_string()],
///     vec!["~/.config/ghostty/.env".to_string()],
///     env,
/// );
/// cmd.execute(&[])?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct LaunchCommand {
    /// The command/binary to execute
    pub command: String,
    /// Arguments to pass
    pub args: Vec<String>,
    /// Environment files to load (paths)
    pub env_files: Vec<String>,
    /// Explicit environment variables
    pub env: HashMap<String, String>,
}

impl LaunchCommand {
    /// Create a simple launch command with just a command name
    pub fn simple(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            env_files: Vec::new(),
            env: HashMap::new(),
        }
    }

    /// Create an advanced launch command with all options
    pub fn advanced(
        command: impl Into<String>,
        args: Vec<String>,
        env_files: Vec<String>,
        env: HashMap<String, String>,
    ) -> Self {
        Self {
            command: command.into(),
            args,
            env_files,
            env,
        }
    }

    /// Executes the launch command.
    ///
    /// Environment variable layering (later overrides earlier):
    /// 1. Inherited from current process (WAYLAND_DISPLAY, XDG_*, PATH, etc.)
    /// 2. Global env_files from settings
    /// 3. Per-app env_files
    /// 4. Explicit env vars
    pub fn execute(&self, global_env_files: &[String]) -> Result<u32, std::io::Error> {
        tracing::info!("Launching: {} {}", self.command, self.args.join(" "));

        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args);

        // Applies environment variable layering: inherited -> global files -> app files -> explicit
        let global_env = load_env_files(global_env_files);
        let app_env = load_env_files(&self.env_files);

        cmd.envs(&global_env).envs(&app_env).envs(&self.env);

        let total = global_env.len() + app_env.len() + self.env.len();
        if total > 0 {
            tracing::debug!("Set {} environment variables", total);
        }

        let child = cmd.spawn()?;
        let pid = child.id();
        tracing::debug!("Launched PID: {}", pid);

        Ok(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let cmd = LaunchCommand::simple("firefox");
        assert_eq!(cmd.command, "firefox");
        assert!(cmd.args.is_empty());
        assert!(cmd.env_files.is_empty());
        assert!(cmd.env.is_empty());
    }

    #[test]
    fn test_advanced_command() {
        let mut env = HashMap::new();
        env.insert("MY_VAR".to_string(), "value".to_string());

        let cmd = LaunchCommand::advanced(
            "firefox",
            vec!["--private-window".to_string()],
            vec!["~/.env".to_string()],
            env,
        );

        assert_eq!(cmd.command, "firefox");
        assert_eq!(cmd.args, vec!["--private-window"]);
        assert_eq!(cmd.env_files, vec!["~/.env"]);
        assert_eq!(cmd.env.get("MY_VAR"), Some(&"value".to_string()));
    }
}
