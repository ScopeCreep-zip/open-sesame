//! Application launch execution pipeline.
//!
//! Resolves desktop entry IDs, composes environment from launch profile tags,
//! fetches secrets via IPC, wraps in devshell if configured, and spawns via
//! systemd-run scope with zombie reaping.

use crate::scanner;
use anyhow::Context;
use core_ipc::BusClient;
use core_types::{EventKind, LaunchDenial, SecurityLevel, TrustProfileName};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroize;

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

/// Resolve a desktop entry ID against the cache with fallback strategies.
///
/// 1. Exact match on the full ID
/// 2. Last dot-separated segment match (e.g. "firefox" matches "org.mozilla.firefox")
/// 3. Case-insensitive full ID match
pub(crate) fn resolve_entry<'a>(
    entry_id: &str,
    cache: &'a HashMap<String, scanner::CachedEntry>,
) -> Option<&'a scanner::CachedEntry> {
    // Strategy 1: exact match
    if let Some(entry) = cache.get(entry_id) {
        return Some(entry);
    }

    // Strategy 2: last segment match (e.g., "firefox" matches "org.mozilla.firefox")
    let lower = entry_id.to_lowercase();
    if let Some(entry) = cache.values().find(|e| {
        e.id.rsplit('.')
            .next()
            .map(|seg| seg.to_lowercase() == lower)
            .unwrap_or(false)
    }) {
        tracing::info!(entry_id, resolved_id = %entry.id, "resolved via last-segment match");
        return Some(entry);
    }

    // Strategy 3: case-insensitive full ID match
    if let Some(entry) = cache.values().find(|e| e.id.to_lowercase() == lower) {
        tracing::info!(entry_id, resolved_id = %entry.id, "resolved via case-insensitive match");
        return Some(entry);
    }

    None
}

/// Launch profile `tags` are resolved to compose environment variables, secrets,
/// and optional devshell wrapping. Tags support qualified cross-profile references
/// (`"work:corp"` resolves `corp` in the `work` trust profile).
pub(crate) async fn launch_entry(
    entry_id: &str,
    profile: Option<&str>,
    tags: &[String],
    launch_args: &[String],
    cache: &HashMap<String, scanner::CachedEntry>,
    client: &BusClient,
    config_state: &Arc<std::sync::RwLock<core_config::Config>>,
) -> Result<u32, LaunchError> {
    let cached =
        resolve_entry(entry_id, cache).ok_or(LaunchError::Denial(LaunchDenial::EntryNotFound))?;
    tracing::info!(entry_id, resolved_id = %cached.id, "entry resolved");

    let exec = scanner::strip_field_codes(&cached.exec);
    let parts = scanner::tokenize_exec(&exec);
    if parts.is_empty() {
        return Err(LaunchError::Other(anyhow::anyhow!(
            "empty Exec line for '{entry_id}'"
        )));
    }

    // Resolve launch profiles from config (passed from hot-reload watcher)
    let default_profile = profile.unwrap_or(core_types::DEFAULT_PROFILE_NAME);
    let config = config_state
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let mut composed_env: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut all_secrets: Vec<(String, String)> = Vec::new(); // (secret_name, trust_profile_name)
    let mut devshell: Option<String> = None;
    let mut cwd: Option<String> = None;

    tracing::info!(
        entry_id,
        tag_count = tags.len(),
        "resolving launch profile tags"
    );
    if !tags.is_empty() {
        for tag in tags {
            let (tp_name, lp_name) = parse_tag(tag, default_profile);

            let tp = config.profiles.get(&tp_name).ok_or_else(|| {
                LaunchError::Denial(LaunchDenial::ProfileNotFound {
                    profile: tp_name.clone(),
                })
            })?;

            let lp = tp.launch_profiles.get(&lp_name).ok_or_else(|| {
                LaunchError::Denial(LaunchDenial::LaunchProfileNotFound {
                    profile: tp_name.clone(),
                    launch_profile: lp_name.clone(),
                })
            })?;

            // Merge env (later tag wins on conflict)
            for (k, v) in &lp.env {
                composed_env.insert(k.clone(), v.clone());
            }

            // Last devshell wins
            if lp.devshell.is_some() {
                devshell.clone_from(&lp.devshell);
            }

            // Last cwd wins
            if lp.cwd.is_some() {
                cwd.clone_from(&lp.cwd);
            }

            // Collect secrets with their owning trust profile
            for secret in &lp.secrets {
                if !all_secrets.iter().any(|(s, _)| s == secret) {
                    all_secrets.push((secret.clone(), tp_name.clone()));
                }
            }
        }
    }

    // Fetch secrets via IPC — collect ALL denials before aborting so the WM
    // can prompt for all required vault unlocks at once.
    let mut locked_profiles: Vec<TrustProfileName> = Vec::new();
    let mut missing_count: u32 = 0;

    tracing::info!(
        entry_id,
        secret_count = all_secrets.len(),
        "fetching secrets"
    );
    for (secret_name, tp_name) in &all_secrets {
        let tp = core_types::TrustProfileName::try_from(tp_name.as_str())
            .map_err(|e| LaunchError::Other(anyhow::anyhow!("invalid trust profile name: {e}")))?;

        let response = client
            .request(
                EventKind::SecretGet {
                    profile: tp.clone(),
                    key: secret_name.clone(),
                },
                SecurityLevel::Internal,
                std::time::Duration::from_secs(5),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "secret fetch IPC failed");
                LaunchError::Other(anyhow::anyhow!("secret fetch IPC failed"))
            })?;

        match response.payload {
            EventKind::SecretGetResponse {
                key: _,
                value,
                denial,
            } => {
                if let Some(reason) = denial {
                    tracing::error!(secret = %secret_name, ?reason, "secret fetch denied");
                    match reason {
                        core_types::SecretDenialReason::ProfileNotActive
                        | core_types::SecretDenialReason::Locked => {
                            if !locked_profiles.contains(&tp) {
                                locked_profiles.push(tp);
                            }
                        }
                        core_types::SecretDenialReason::NotFound => {
                            missing_count += 1;
                        }
                        core_types::SecretDenialReason::RateLimited => {
                            return Err(LaunchError::Denial(LaunchDenial::RateLimited));
                        }
                        _ => {
                            return Err(LaunchError::Other(anyhow::anyhow!(
                                "secret access denied: {reason:?}"
                            )));
                        }
                    }
                } else {
                    let env_var = secret_name_to_env_var(secret_name);
                    let secret_str = match String::from_utf8(value.as_bytes().to_vec()) {
                        Ok(s) => s,
                        Err(e) => {
                            let mut bad = e.into_bytes();
                            bad.zeroize();
                            return Err(LaunchError::Other(anyhow::anyhow!(
                                "secret value is not valid UTF-8"
                            )));
                        }
                    };
                    composed_env.insert(env_var, secret_str);
                }
            }
            other => {
                tracing::error!(?other, "unexpected response to SecretGet");
                return Err(LaunchError::Other(anyhow::anyhow!(
                    "unexpected response to SecretGet"
                )));
            }
        }
    }

    // Check collected denials — locked vaults take priority over missing secrets
    if !locked_profiles.is_empty() {
        return Err(LaunchError::Denial(LaunchDenial::VaultsLocked {
            locked_profiles,
        }));
    }
    if missing_count > 0 {
        return Err(LaunchError::Denial(LaunchDenial::SecretNotFound {
            missing_count,
        }));
    }

    // Build command — wrap in devshell if configured
    let (program, args) = if let Some(ref ds) = devshell {
        let mut nix_args = vec!["develop".to_string(), ds.clone(), "-c".to_string()];
        nix_args.extend(parts.iter().cloned());
        ("nix".to_string(), nix_args)
    } else {
        (parts[0].clone(), parts[1..].to_vec())
    };

    let mut cmd = std::process::Command::new(&program);
    cmd.args(&args);

    // Append launch_args from the IPC message (e.g., workspace-specific flags).
    if !launch_args.is_empty() {
        cmd.args(launch_args);
    }

    // Set working directory if configured via launch profile cwd.
    if let Some(ref dir) = cwd {
        let path = std::path::Path::new(dir);
        if !path.is_absolute() {
            return Err(LaunchError::Other(anyhow::anyhow!(
                "cwd must be an absolute path, got: {dir}"
            )));
        }
        if !path.is_dir() {
            return Err(LaunchError::Other(anyhow::anyhow!(
                "cwd does not exist or is not a directory: {dir}"
            )));
        }
        cmd.current_dir(path);
    }

    // Inject composed env vars from launch profiles
    for (k, v) in &composed_env {
        cmd.env(k, v);
    }

    // Inject default SESAME_ vars (after composed env, cannot be overridden)
    cmd.env("SESAME_PROFILE", default_profile);
    cmd.env("SESAME_APP_ID", &cached.id);
    if let Ok(sock) = core_ipc::socket_path() {
        cmd.env("SESAME_SOCKET", sock.to_string_lossy().as_ref());
    }

    // Spawn via systemd-run --user --scope. This places the child in its
    // own transient systemd scope with its own cgroup — no inherited
    // MemoryMax, no mount namespace restrictions, survives launcher
    // restarts, and proper per-app resource accounting via systemd-cgtop.
    // Falls back to direct spawn if systemd-run is unavailable.
    let scope_name = format!(
        "app-open-sesame-{}-{}.scope",
        sanitize_unit_name(entry_id),
        std::process::id()
    );
    let env_count = composed_env.len();
    let secret_count = all_secrets.len();

    tracing::info!(entry_id, %program, arg_count = args.len(), %scope_name, "spawning process");

    let mut scope_cmd = std::process::Command::new("systemd-run");
    scope_cmd
        .arg("--user")
        .arg("--scope")
        .arg(format!("--unit={scope_name}"))
        .arg("--")
        .arg(&program)
        .args(&args);

    if !launch_args.is_empty() {
        scope_cmd.args(launch_args);
    }

    scope_cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());

    // Propagate environment to systemd-run (it passes env to the child).
    for (k, v) in &composed_env {
        scope_cmd.env(k, v);
    }
    scope_cmd.env("SESAME_PROFILE", default_profile);
    scope_cmd.env("SESAME_APP_ID", &cached.id);
    if let Ok(sock) = core_ipc::socket_path() {
        scope_cmd.env("SESAME_SOCKET", sock.to_string_lossy().as_ref());
    }

    if let Some(ref dir) = cwd {
        scope_cmd.current_dir(dir);
    }

    let spawn_result = scope_cmd.spawn();
    let (mut child, via_scope) = match spawn_result {
        Ok(child) => (child, true),
        Err(e) => {
            tracing::warn!(error = %e, "systemd-run unavailable, falling back to direct spawn");
            cmd.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit());
            let child = cmd.spawn().context("failed to spawn process")?;
            (child, false)
        }
    };

    let pid = child.id();

    // Zeroize secret values after they've been copied to the child process.
    for v in composed_env.values_mut() {
        v.zeroize();
    }
    drop(composed_env);

    // Reap the systemd-run wrapper (or direct child) to prevent zombies.
    let entry_id_owned = entry_id.to_string();
    tokio::task::spawn_blocking(move || match child.wait() {
        Ok(status) => {
            tracing::debug!(pid, entry_id = %entry_id_owned, %status, via_scope, "child reaped");
        }
        Err(e) => {
            tracing::warn!(pid, entry_id = %entry_id_owned, error = %e, "child wait failed");
        }
    });

    tracing::info!(
        entry_id,
        pid,
        %program,
        ?tags,
        ?devshell,
        env_count,
        secret_count,
        via_scope,
        "launched"
    );

    Ok(pid)
}

/// Parse a tag into (profile_name, launch_profile_name).
/// Unqualified: `"dev-rust"` → (default_profile, "dev-rust").
/// Qualified: `"work:corp"` → ("work", "corp").
fn parse_tag<'a>(tag: &'a str, default_profile: &'a str) -> (String, String) {
    match tag.split_once(':') {
        Some((profile, name)) => (profile.to_string(), name.to_string()),
        None => (default_profile.to_string(), tag.to_string()),
    }
}

/// Transform a secret name to an environment variable name.
/// Uppercase, hyphens to underscores.
fn secret_name_to_env_var(name: &str) -> String {
    name.to_uppercase().replace('-', "_")
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

    fn test_cache() -> HashMap<String, scanner::CachedEntry> {
        let entries = vec![
            scanner::CachedEntry {
                id: "org.mozilla.firefox".into(),
                exec: "firefox".into(),
            },
            scanner::CachedEntry {
                id: "com.mitchellh.ghostty".into(),
                exec: "ghostty".into(),
            },
            scanner::CachedEntry {
                id: "Alacritty".into(),
                exec: "alacritty".into(),
            },
        ];
        entries.into_iter().map(|e| (e.id.clone(), e)).collect()
    }

    #[test]
    fn resolve_exact_match() {
        let cache = test_cache();
        let entry = resolve_entry("org.mozilla.firefox", &cache).unwrap();
        assert_eq!(entry.id, "org.mozilla.firefox");
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
        assert!(resolve_entry("nonexistent", &cache).is_none());
    }

    #[test]
    fn secret_name_to_env_var_basic() {
        assert_eq!(secret_name_to_env_var("github-token"), "GITHUB_TOKEN");
        assert_eq!(
            secret_name_to_env_var("anthropic-api-key"),
            "ANTHROPIC_API_KEY"
        );
        assert_eq!(secret_name_to_env_var("simple"), "SIMPLE");
        assert_eq!(secret_name_to_env_var("a-b-c"), "A_B_C");
    }

    #[test]
    fn parse_tag_unqualified() {
        let (profile, name) = parse_tag("dev-rust", "default");
        assert_eq!(profile, "default");
        assert_eq!(name, "dev-rust");
    }

    #[test]
    fn parse_tag_qualified() {
        let (profile, name) = parse_tag("work:corp", "default");
        assert_eq!(profile, "work");
        assert_eq!(name, "corp");
    }
}
