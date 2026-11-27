//! Application launch execution pipeline.
//!
//! Resolves desktop entry IDs, composes environment from launch profile tags,
//! fetches secrets via IPC, wraps in devshell if configured, and spawns via
//! systemd-run scope with zombie reaping.

use crate::scanner;
use anyhow::Context;
use core_ipc::BusClient;
use core_types::{EventKind, LaunchDenial, SecretDenialReason, SecurityLevel, TrustProfileName};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// A launched process's composed environment. Every value zeroizes on
/// drop, on every path: secret values live among the static ones.
type Env = BTreeMap<String, Zeroizing<String>>;

/// Structured launch error — carries machine-readable denial for the WM.
pub(crate) enum LaunchError {
    /// A structured denial the WM can act on (e.g. prompt for vault unlock).
    Denial(LaunchDenial),
    /// An unstructured error (spawn failure, IPC error, etc.).
    Other(anyhow::Error),
}

impl From<anyhow::Error> for LaunchError {
    fn from(e: anyhow::Error) -> Self {
        LaunchError::Other(e)
    }
}

impl From<LaunchDenial> for LaunchError {
    fn from(denial: LaunchDenial) -> Self {
        LaunchError::Denial(denial)
    }
}

/// Resolve a desktop entry ID against the cache.
///
/// An exact id match wins. Otherwise the loose candidates are every entry
/// whose full id, or last dot-separated segment, equals `entry_id`
/// case-insensitively ("firefox" matches "org.mozilla.firefox"). Exactly
/// one candidate resolves; none is `EntryNotFound`; several is
/// `EntryAmbiguous` listing them sorted, never an arbitrary pick.
pub(crate) fn resolve_entry<'a>(
    entry_id: &str,
    cache: &'a HashMap<String, scanner::CachedEntry>,
) -> Result<&'a scanner::CachedEntry, LaunchDenial> {
    if let Some(entry) = cache.get(entry_id) {
        return Ok(entry);
    }

    let lower = entry_id.to_lowercase();
    let mut candidates: Vec<&scanner::CachedEntry> = cache
        .values()
        .filter(|e| {
            e.id.to_lowercase() == lower
                || e.id
                    .rsplit('.')
                    .next()
                    .is_some_and(|seg| seg.to_lowercase() == lower)
        })
        .collect();
    candidates.sort_by(|a, b| a.id.cmp(&b.id));

    match candidates.as_slice() {
        [] => Err(LaunchDenial::EntryNotFound),
        [entry] => {
            tracing::info!(entry_id, resolved_id = %entry.id, "resolved via case-insensitive match");
            Ok(entry)
        }
        many => Err(LaunchDenial::EntryAmbiguous {
            candidates: many.iter().map(|e| e.id.clone()).collect(),
        }),
    }
}

/// Everything a spawned application receives besides its program and
/// arguments: the launch arguments, the composed environment and working
/// directory, and the `SESAME_*` identity.
struct LaunchContext<'a> {
    launch_args: &'a [String],
    composition: &'a Composition,
    profile: &'a str,
    app_id: &'a str,
    bus_socket: &'a Path,
}

impl LaunchContext<'_> {
    /// Apply the launch arguments, the composed environment, the `SESAME_*`
    /// variables (set last, so profiles cannot override them), the working
    /// directory, and the standard streams to `cmd`.
    fn configure(&self, cmd: &mut std::process::Command) {
        cmd.args(self.launch_args);
        cmd.envs(self.composition.env.iter().map(|(k, v)| (k, v.as_str())));
        cmd.env("SESAME_PROFILE", self.profile);
        cmd.env("SESAME_APP_ID", self.app_id);
        cmd.env("SESAME_SOCKET", self.bus_socket);
        if let Some(dir) = &self.composition.cwd {
            cmd.current_dir(dir);
        }
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());
    }
}

/// What every launch draws on for the daemon's lifetime: the desktop entry
/// cache (scanned before the sandbox), the live configuration, and the bus
/// endpoint children reach through `SESAME_SOCKET`.
pub(crate) struct Launcher {
    pub(crate) cache: HashMap<String, scanner::CachedEntry>,
    pub(crate) config_state: Arc<std::sync::RwLock<core_config::Config>>,
    pub(crate) bus_socket: std::path::PathBuf,
}

/// What a launch's tags compose. For every key the last tag naming it
/// wins: environment variables, secrets (by the variable they set),
/// devshell, cwd.
#[derive(Default)]
struct Composition {
    env: Env,
    /// Secret name and owning trust profile, by environment variable.
    secrets: BTreeMap<String, (String, TrustProfileName)>,
    devshell: Option<String>,
    cwd: Option<String>,
}

/// Compose the launch profiles `tags` name. A tag is `name` (in
/// `default_profile`) or `profile:name`.
fn compose(
    config: &core_config::Config,
    tags: &[String],
    default_profile: &str,
) -> Result<Composition, LaunchError> {
    let mut composition = Composition::default();
    for tag in tags {
        let (tp_name, lp_name) = parse_tag(tag, default_profile);
        let tp = config
            .profiles
            .get(tp_name)
            .ok_or_else(|| LaunchDenial::ProfileNotFound {
                profile: tp_name.to_owned(),
            })?;
        let lp =
            tp.launch_profiles
                .get(lp_name)
                .ok_or_else(|| LaunchDenial::LaunchProfileNotFound {
                    profile: tp_name.to_owned(),
                    launch_profile: lp_name.to_owned(),
                })?;
        let owner = TrustProfileName::try_from(tp_name)
            .with_context(|| format!("launch profile tag '{tag}'"))?;

        composition.env.extend(
            lp.env
                .iter()
                .map(|(k, v)| (k.clone(), Zeroizing::new(v.clone()))),
        );
        for secret in &lp.secrets {
            composition
                .secrets
                .insert(secret_env_var(secret)?, (secret.clone(), owner.clone()));
        }
        if lp.devshell.is_some() {
            composition.devshell.clone_from(&lp.devshell);
        }
        if lp.cwd.is_some() {
            composition.cwd.clone_from(&lp.cwd);
        }
    }
    Ok(composition)
}

/// Fetch every secret of `secrets` into `env`. Every denial is collected
/// before any is returned, so the WM can prompt for every locked vault at
/// once; locked vaults take precedence over missing secrets.
async fn fetch_secrets(
    client: &BusClient,
    secrets: &BTreeMap<String, (String, TrustProfileName)>,
    env: &mut Env,
) -> Result<(), LaunchError> {
    let mut locked_profiles: Vec<TrustProfileName> = Vec::new();
    let mut missing_count: u32 = 0;
    for (env_var, (secret_name, profile)) in secrets {
        let response = client
            .request(
                EventKind::SecretGet {
                    profile: profile.clone(),
                    key: secret_name.clone(),
                },
                SecurityLevel::Internal,
                std::time::Duration::from_secs(5),
            )
            .await
            .with_context(|| format!("secret '{secret_name}' fetch failed"))?;
        let EventKind::SecretGetResponse { value, denial, .. } = response.payload else {
            tracing::error!(payload = ?response.payload, "unexpected response to SecretGet");
            return Err(anyhow::anyhow!("unexpected response to SecretGet").into());
        };
        match denial {
            None => {
                let value = std::str::from_utf8(value.as_bytes())
                    .with_context(|| format!("secret '{secret_name}' is not valid UTF-8"))?;
                env.insert(env_var.clone(), Zeroizing::new(value.to_owned()));
            }
            Some(SecretDenialReason::ProfileNotActive | SecretDenialReason::Locked) => {
                tracing::error!(secret = %secret_name, %profile, "secret's vault is locked");
                if !locked_profiles.contains(profile) {
                    locked_profiles.push(profile.clone());
                }
            }
            Some(SecretDenialReason::NotFound) => {
                tracing::error!(secret = %secret_name, %profile, "secret not found");
                missing_count += 1;
            }
            Some(SecretDenialReason::RateLimited) => {
                return Err(LaunchDenial::RateLimited.into());
            }
            Some(reason) => {
                return Err(anyhow::anyhow!("secret access denied: {reason:?}").into());
            }
        }
    }
    if !locked_profiles.is_empty() {
        return Err(LaunchDenial::VaultsLocked { locked_profiles }.into());
    }
    if missing_count > 0 {
        return Err(LaunchDenial::SecretNotFound { missing_count }.into());
    }
    Ok(())
}

/// `program args`, inside `nix develop <devshell> -c` when a devshell is
/// set.
fn command(program: String, args: Vec<String>, devshell: Option<&str>) -> (String, Vec<String>) {
    match devshell {
        Some(devshell) => {
            let mut wrapped = vec![
                "develop".to_owned(),
                devshell.to_owned(),
                "-c".to_owned(),
                program,
            ];
            wrapped.extend(args);
            ("nix".to_owned(), wrapped)
        }
        None => (program, args),
    }
}

/// A launch profile cwd must name an existing absolute directory.
fn validate_cwd(cwd: Option<&str>) -> anyhow::Result<()> {
    let Some(dir) = cwd else {
        return Ok(());
    };
    let path = Path::new(dir);
    anyhow::ensure!(
        path.is_absolute(),
        "cwd must be an absolute path, got: {dir}"
    );
    anyhow::ensure!(
        path.is_dir(),
        "cwd does not exist or is not a directory: {dir}"
    );
    Ok(())
}

/// Spawn `program args` with `context` in its own transient systemd scope
/// (`systemd-run --user --scope`): its own cgroup, no inherited
/// `MemoryMax`, no mount namespace restrictions, survives launcher
/// restarts, per-app accounting in systemd-cgtop. The scope inherits the
/// systemd user manager's environment (`WAYLAND_DISPLAY`, `DISPLAY`, ...
/// the session imported with `systemctl --user import-environment`).
///
/// The scope name is unique per launch (microsecond timestamp), so a
/// relaunch never collides with an existing scope unit. The process is
/// spawned directly only when systemd-run is not installed; any other
/// systemd-run spawn error fails the launch. Returns the child and whether
/// it runs in a scope.
fn spawn(
    entry_id: &str,
    program: &str,
    args: &[String],
    context: &LaunchContext<'_>,
) -> anyhow::Result<(std::process::Child, bool)> {
    let launch_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_micros();
    let scope_name = format!(
        "app-open-sesame-{}-{launch_id}.scope",
        sanitize_unit_name(entry_id)
    );
    tracing::info!(entry_id, %program, arg_count = args.len(), %scope_name, "spawning process");

    let mut scope_cmd = std::process::Command::new("systemd-run");
    scope_cmd
        .arg("--user")
        .arg("--scope")
        .arg(format!("--unit={scope_name}"))
        .arg("--")
        .arg(program)
        .args(args);
    context.configure(&mut scope_cmd);
    match scope_cmd.spawn() {
        Ok(child) => Ok((child, true)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(error = %e, "systemd-run not installed, spawning directly");
            let mut cmd = std::process::Command::new(program);
            cmd.args(args);
            context.configure(&mut cmd);
            Ok((cmd.spawn().context("failed to spawn process")?, false))
        }
        Err(e) => Err(anyhow::Error::new(e).context("failed to spawn systemd-run")),
    }
}

/// Reap `child` (the systemd-run wrapper or the direct child) on a
/// blocking thread, so it never lingers as a zombie.
fn reap(mut child: std::process::Child, entry_id: &str, via_scope: bool) {
    let pid = child.id();
    let entry_id = entry_id.to_owned();
    tokio::task::spawn_blocking(move || match child.wait() {
        Ok(status) => {
            tracing::debug!(pid, %entry_id, %status, via_scope, "child reaped");
        }
        Err(e) => {
            tracing::warn!(pid, %entry_id, error = %e, "child wait failed");
        }
    });
}

/// Launch `entry_id` with the launch profiles `tags` compose (see
/// [`compose`]) and their secrets; returns the process id.
pub(crate) async fn launch_entry(
    launcher: &Launcher,
    client: &BusClient,
    entry_id: &str,
    profile: Option<&str>,
    tags: &[String],
    launch_args: &[String],
) -> Result<u32, LaunchError> {
    let cached = resolve_entry(entry_id, &launcher.cache)?;
    tracing::info!(entry_id, resolved_id = %cached.id, "entry resolved");
    let mut parts = scanner::tokenize_exec(&scanner::strip_field_codes(&cached.exec)).into_iter();
    let Some(exec_program) = parts.next() else {
        return Err(anyhow::anyhow!("empty Exec line for '{entry_id}'").into());
    };

    let default_profile = profile.unwrap_or(core_types::DEFAULT_PROFILE_NAME);
    let mut composition = {
        let config = launcher
            .config_state
            .read()
            .map_err(|e| anyhow::anyhow!("config state lock poisoned: {e}"))?;
        compose(&config, tags, default_profile)?
    };
    tracing::info!(
        entry_id,
        tag_count = tags.len(),
        secret_count = composition.secrets.len(),
        "launch profiles composed"
    );
    fetch_secrets(client, &composition.secrets, &mut composition.env).await?;
    validate_cwd(composition.cwd.as_deref())?;

    let (program, args) = command(
        exec_program,
        parts.collect(),
        composition.devshell.as_deref(),
    );
    let context = LaunchContext {
        launch_args,
        composition: &composition,
        profile: default_profile,
        app_id: &cached.id,
        bus_socket: &launcher.bus_socket,
    };
    let (child, via_scope) = spawn(entry_id, &program, &args, &context)?;
    let pid = child.id();
    reap(child, entry_id, via_scope);

    tracing::info!(
        entry_id,
        pid,
        %program,
        ?tags,
        devshell = ?composition.devshell,
        env_count = composition.env.len(),
        secret_count = composition.secrets.len(),
        via_scope,
        "launched"
    );
    Ok(pid)
}

/// Split a tag into its trust profile and launch profile names.
/// Unqualified: `"dev-rust"` → (`default_profile`, `"dev-rust"`).
/// Qualified: `"work:corp"` → (`"work"`, `"corp"`).
fn parse_tag<'a>(tag: &'a str, default_profile: &'a str) -> (&'a str, &'a str) {
    tag.split_once(':').unwrap_or((default_profile, tag))
}

/// The environment variable launch profile secret `name` sets
/// (`secret_env::env_var_name`). A protected variable refuses the launch:
/// the launch profile names the secret explicitly, so skipping it would
/// start the application without configuration it requires.
fn secret_env_var(name: &str) -> Result<String, LaunchDenial> {
    let variable = core_types::secret_env::env_var_name(name, None);
    if core_types::secret_env::is_protected_env_var(&variable) {
        return Err(LaunchDenial::ProtectedVariable { variable });
    }
    Ok(variable)
}

/// Sanitize a string for use as a systemd unit name component.
/// Replaces non-alphanumeric characters with dashes, collapses runs.
fn sanitize_unit_name(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            result.push('-');
            prev_dash = true;
        }
    }
    result.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, exec: &str) -> (String, scanner::CachedEntry) {
        (
            id.into(),
            scanner::CachedEntry {
                id: id.into(),
                exec: exec.into(),
            },
        )
    }

    fn test_cache() -> HashMap<String, scanner::CachedEntry> {
        [
            entry("org.mozilla.firefox", "firefox"),
            entry("com.mitchellh.ghostty", "ghostty"),
            entry("Alacritty", "alacritty"),
        ]
        .into()
    }

    fn launch_profile(env: &[(&str, &str)], secrets: &[&str]) -> core_config::LaunchProfile {
        core_config::LaunchProfile {
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            devshell: None,
            cwd: None,
        }
    }

    fn config(profiles: &[(&str, &str, core_config::LaunchProfile)]) -> core_config::Config {
        let mut config = core_config::Config::default();
        for (profile, name, launch_profile) in profiles {
            config
                .profiles
                .entry((*profile).to_owned())
                .or_default()
                .launch_profiles
                .insert((*name).to_owned(), launch_profile.clone());
        }
        config
    }

    #[test]
    fn resolve_exact_match() {
        let cache = test_cache();
        let entry = resolve_entry("org.mozilla.firefox", &cache).unwrap();
        assert_eq!(entry.id, "org.mozilla.firefox");
    }

    #[test]
    fn resolve_ambiguous_segment_lists_candidates() {
        let mut cache = test_cache();
        cache.extend([
            entry("org.gnome.Terminal", "term"),
            entry("org.kde.terminal", "term"),
        ]);
        // Every iteration order must yield the same error, never a pick.
        for _ in 0..16 {
            assert_eq!(
                resolve_entry("terminal", &cache).unwrap_err(),
                LaunchDenial::EntryAmbiguous {
                    candidates: vec!["org.gnome.Terminal".into(), "org.kde.terminal".into()],
                }
            );
        }
        // An exact id still resolves despite loose ambiguity.
        assert_eq!(
            resolve_entry("org.kde.terminal", &cache).unwrap().id,
            "org.kde.terminal"
        );
    }

    #[test]
    fn resolve_last_segment_match() {
        let cache = test_cache();
        let entry = resolve_entry("firefox", &cache).unwrap();
        assert_eq!(entry.id, "org.mozilla.firefox");
    }

    #[test]
    fn resolve_case_insensitive_match() {
        let cache = test_cache();
        let entry = resolve_entry("alacritty", &cache).unwrap();
        assert_eq!(entry.id, "Alacritty");
    }

    #[test]
    fn resolve_no_match() {
        let cache = test_cache();
        assert_eq!(
            resolve_entry("nonexistent", &cache).unwrap_err(),
            LaunchDenial::EntryNotFound
        );
    }

    #[test]
    fn the_last_tag_wins_for_environment_and_secrets() {
        let config = config(&[
            (
                "default",
                "base",
                launch_profile(&[("EDITOR", "vi"), ("PAGER", "less")], &["api-token"]),
            ),
            (
                "work",
                "corp",
                launch_profile(&[("EDITOR", "hx")], &["api-token"]),
            ),
        ]);
        let tags = ["base".to_owned(), "work:corp".to_owned()];
        let composition = compose(&config, &tags, "default").ok().unwrap();
        assert_eq!(composition.env["EDITOR"].as_str(), "hx");
        assert_eq!(composition.env["PAGER"].as_str(), "less");
        let (name, owner) = &composition.secrets["API_TOKEN"];
        assert_eq!(name, "api-token");
        assert_eq!(owner.as_ref(), "work");
    }

    #[test]
    fn unknown_profiles_and_launch_profiles_are_denied() {
        let config = config(&[("default", "base", launch_profile(&[], &[]))]);
        let denial = |tag: &str| match compose(&config, &[tag.to_owned()], "default") {
            Err(LaunchError::Denial(denial)) => denial,
            Err(LaunchError::Other(e)) => panic!("expected a denial, got {e:#}"),
            Ok(_) => panic!("expected a denial for {tag}"),
        };
        assert_eq!(
            denial("absent:base"),
            LaunchDenial::ProfileNotFound {
                profile: "absent".into()
            }
        );
        assert_eq!(
            denial("missing"),
            LaunchDenial::LaunchProfileNotFound {
                profile: "default".into(),
                launch_profile: "missing".into(),
            }
        );
    }

    #[test]
    fn devshells_wrap_the_command() {
        let args = || vec!["--flag".to_owned()];
        assert_eq!(
            command("app".to_owned(), args(), None),
            ("app".to_owned(), vec!["--flag".to_owned()])
        );
        assert_eq!(
            command("app".to_owned(), args(), Some("/p#rust")),
            (
                "nix".to_owned(),
                ["develop", "/p#rust", "-c", "app", "--flag"]
                    .map(str::to_owned)
                    .to_vec()
            )
        );
    }

    #[test]
    fn cwd_must_be_an_existing_absolute_directory() {
        assert!(validate_cwd(None).is_ok());
        assert!(validate_cwd(Some("/")).is_ok());
        assert!(validate_cwd(Some("relative")).is_err());
        assert!(validate_cwd(Some("/nonexistent-launch-dir")).is_err());
    }

    #[test]
    fn secret_variables_follow_the_shared_naming() {
        assert_eq!(secret_env_var("github-token").unwrap(), "GITHUB_TOKEN");
        assert_eq!(secret_env_var("db.host").unwrap(), "DB_HOST");
    }

    #[test]
    fn protected_secret_variables_refuse_the_launch() {
        for name in ["ld-preload", "sesame-socket", "path"] {
            assert!(
                matches!(
                    secret_env_var(name),
                    Err(LaunchDenial::ProtectedVariable { .. })
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn tags_split_into_profile_and_launch_profile() {
        assert_eq!(parse_tag("dev-rust", "default"), ("default", "dev-rust"));
        assert_eq!(parse_tag("work:corp", "default"), ("work", "corp"));
    }

    #[test]
    fn launch_context_sesame_vars_override_profile_env() {
        let composition = Composition {
            env: [
                (
                    "SESAME_PROFILE".to_owned(),
                    Zeroizing::new("spoofed".to_owned()),
                ),
                ("EDITOR".to_owned(), Zeroizing::new("hx".to_owned())),
            ]
            .into(),
            cwd: Some("/tmp".to_owned()),
            ..Composition::default()
        };
        let launch_args = ["--new-window".to_owned()];
        let context = LaunchContext {
            launch_args: &launch_args,
            composition: &composition,
            profile: "work",
            app_id: "org.mozilla.firefox",
            bus_socket: Path::new("/r/runtime/pds/bus.sock"),
        };
        let mut cmd = std::process::Command::new("firefox");
        context.configure(&mut cmd);
        let envs: HashMap<_, _> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(ToOwned::to_owned)))
            .collect();
        let get = |k: &str| envs.get(std::ffi::OsStr::new(k)).cloned().flatten();
        assert_eq!(get("SESAME_PROFILE"), Some("work".into()));
        assert_eq!(get("EDITOR"), Some("hx".into()));
        assert_eq!(get("SESAME_SOCKET"), Some("/r/runtime/pds/bus.sock".into()));
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["--new-window"]);
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/tmp")));
    }
}
