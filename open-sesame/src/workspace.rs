use anyhow::Context;
use comfy_table::{Table, presets::UTF8_FULL};
use core_types::TrustProfileName;
use owo_colors::OwoColorize;
use zeroize::Zeroize;

use crate::cli::resolve_workspace_path;
use crate::cli::{WorkspaceCmd, WorkspaceConfigCmd, WorkspaceListFormat};
use crate::ipc::{connect, fetch_multi_profile_secrets, parse_profile_specs};

/// Check if creating a path requires privilege escalation.
///
/// Walks up the directory tree to find the first existing ancestor and
/// checks if it is owned by the current user.
#[cfg(target_os = "linux")]
fn needs_privilege(path: &std::path::Path) -> bool {
    let uid = unsafe { libc::getuid() };
    let mut check = path.to_path_buf();
    loop {
        if check.exists() {
            return std::fs::metadata(&check)
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    m.uid() != uid
                })
                .unwrap_or(true);
        }
        if !check.pop() {
            return true;
        }
    }
}

/// Compare two git remote URLs, normalizing `.git` suffix and trailing slashes.
fn urls_match(a: &str, b: &str) -> bool {
    fn normalize(url: &str) -> String {
        url.trim_end_matches('/')
            .trim_end_matches(".git")
            .to_lowercase()
    }
    normalize(a) == normalize(b)
}

pub(crate) async fn cmd_workspace(cmd: WorkspaceCmd) -> anyhow::Result<()> {
    match cmd {
        WorkspaceCmd::Init { root, user } => {
            let user =
                user.unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "user".into()));

            #[cfg(target_os = "linux")]
            {
                // Confirm before privilege escalation.
                if !root.exists() && needs_privilege(&root) {
                    eprintln!(
                        "Workspace root '{}' does not exist and requires elevated privileges to create.",
                        root.display()
                    );
                    eprint!("Continue? [y/N] ");
                    use std::io::Write;
                    std::io::stderr().flush()?;
                    let mut answer = String::new();
                    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)
                        .context("failed to read confirmation")?;
                    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                use sesame_workspace::platform::WorkspacePlatform;
                let platform = sesame_workspace::platform::linux::LinuxPlatform;
                platform
                    .ensure_root(&root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }

            #[cfg(not(target_os = "linux"))]
            {
                std::fs::create_dir_all(&root).context("failed to create workspace root")?;
            }

            let user_dir = root.join(&user);
            std::fs::create_dir_all(&user_dir).context("failed to create user directory")?;

            let mut config = core_config::load_workspace_config().unwrap_or_default();
            config.settings.root = root.clone();
            config.settings.user = user.clone();
            core_config::save_workspace_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("Workspace initialized: {}", user_dir.display());
            println!(
                "Config written: {}",
                core_config::config_dir().join("workspaces.toml").display()
            );
            Ok(())
        }

        WorkspaceCmd::Clone {
            url,
            depth,
            profile,
            adopt,
        } => {
            let config = core_config::load_workspace_config().unwrap_or_default();
            let root = sesame_workspace::config::resolve_root(&config);
            let user = sesame_workspace::config::resolve_user(&config);

            let conv = sesame_workspace::convention::parse_url(&url)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let target = sesame_workspace::convention::canonical_path(&root, &user, &conv);

            // Check if the target directory already exists and can be adopted.
            let target_path = match &target {
                sesame_workspace::CloneTarget::Regular(p) => p.clone(),
                sesame_workspace::CloneTarget::WorkspaceGit(p) => p.clone(),
            };

            let adopted = if target_path.exists()
                && sesame_workspace::git::is_git_repo(&target_path)
                && adopt
            {
                // Verify the remote matches the requested URL.
                let existing_remote = sesame_workspace::git::remote_url(&target_path)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                match existing_remote {
                    Some(ref remote) if urls_match(remote, &url) => true,
                    Some(ref remote) => {
                        anyhow::bail!(
                            "directory exists with different remote:\n  existing: {remote}\n  requested: {url}\nRemove the directory or fix the remote manually."
                        );
                    }
                    None => {
                        anyhow::bail!(
                            "directory exists as a git repo but has no 'origin' remote: {}",
                            target_path.display()
                        );
                    }
                }
            } else {
                false
            };

            let result_path = if adopted {
                println!(
                    "\x1b[32mAdopted\x1b[0m existing repository: {}",
                    target_path.display()
                );
                target_path
            } else {
                let rp = sesame_workspace::git::clone_repo(&url, &target, depth)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                // Contextual output based on clone target type.
                match &target {
                    sesame_workspace::CloneTarget::WorkspaceGit(_) => {
                        println!("Cloned workspace.git to org directory: {}", rp.display());
                        println!("  Peer repos will be cloned as siblings inside this directory.");
                    }
                    sesame_workspace::CloneTarget::Regular(_) => {
                        println!("Cloned to: {}", rp.display());
                    }
                }
                rp
            };

            // Link to profile if requested.
            if let Some(ref profile_name) = profile {
                let _validated = TrustProfileName::try_from(profile_name.as_str())
                    .map_err(|e| anyhow::anyhow!("invalid profile name: {e}"))?;
                let mut ws_config = core_config::load_workspace_config().unwrap_or_default();
                sesame_workspace::config::add_link(
                    &mut ws_config,
                    &result_path.display().to_string(),
                    profile_name,
                );
                core_config::save_workspace_config(&ws_config)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("Linked -> profile \"{}\"", profile_name);
            }

            Ok(())
        }

        WorkspaceCmd::List {
            server,
            org,
            profile,
            format,
        } => {
            let config = core_config::load_workspace_config().unwrap_or_default();
            let mut workspaces = sesame_workspace::discover::discover_workspaces(&config)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            if let Some(ref s) = server {
                workspaces.retain(|w| w.convention.server == *s);
            }
            if let Some(ref o) = org {
                workspaces.retain(|w| w.convention.org == *o);
            }
            if let Some(ref p) = profile {
                workspaces.retain(|w| w.linked_profile.as_deref() == Some(p.as_str()));
            }

            match format {
                WorkspaceListFormat::Table => {
                    if workspaces.is_empty() {
                        println!("No workspaces found.");
                        return Ok(());
                    }
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL);
                    table.set_header(vec!["SERVER", "ORG", "REPO", "PROFILE", "PATH"]);
                    for ws in &workspaces {
                        let repo = ws.convention.repo.as_deref().unwrap_or("(workspace)");
                        let ws_profile = ws.linked_profile.as_deref().unwrap_or("-");
                        table.add_row(vec![
                            &ws.convention.server,
                            &ws.convention.org,
                            repo,
                            ws_profile,
                            &ws.path.display().to_string(),
                        ]);
                    }
                    println!("{table}");
                }
                WorkspaceListFormat::Json => {
                    let json: Vec<serde_json::Value> = workspaces
                        .iter()
                        .map(|ws| {
                            serde_json::json!({
                                "server": ws.convention.server,
                                "org": ws.convention.org,
                                "repo": ws.convention.repo,
                                "profile": ws.linked_profile,
                                "path": ws.path.display().to_string(),
                                "is_workspace_git": ws.is_workspace_git,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
            }
            Ok(())
        }

        WorkspaceCmd::Status { path, verbose } => {
            let path = resolve_workspace_path(path)?;
            let config = core_config::load_workspace_config().unwrap_or_default();
            let root = sesame_workspace::config::resolve_root(&config);

            let conv = sesame_workspace::convention::parse_path(&root, &path)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let remote = sesame_workspace::git::remote_url(&path)
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown".into());
            let branch =
                sesame_workspace::git::current_branch(&path).unwrap_or_else(|_| "unknown".into());
            let clean = sesame_workspace::git::is_clean(&path).unwrap_or(false);

            // Use effective config for profile resolution.
            let effective =
                sesame_workspace::config::resolve_effective_config(&config, &path, &root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            let in_ws_git = sesame_workspace::convention::is_inside_workspace_git(&path);

            println!("Workspace:  {}", path.display());
            println!("Remote:     {remote}");
            println!("Branch:     {branch}");

            // Color-coded status.
            let status_str = if clean {
                "clean".green().to_string()
            } else {
                "dirty".yellow().to_string()
            };
            println!("Status:     {status_str}");
            println!(
                "Profile:    {}",
                effective.profile.as_deref().unwrap_or("(none)")
            );
            println!(
                "Namespace:  {} ({})",
                conv.org,
                if in_ws_git {
                    "workspace.git"
                } else {
                    "no workspace.git"
                }
            );

            if verbose {
                println!(
                    "Convention: {} / {} / {} / {} / {}",
                    root.display(),
                    config.settings.user,
                    conv.server,
                    conv.org,
                    conv.repo.as_deref().unwrap_or("(workspace.git)")
                );

                // Disk usage.
                if let Ok(output) = std::process::Command::new("du")
                    .arg("-sh")
                    .arg("--")
                    .arg(&path)
                    .output()
                    && let Ok(s) = String::from_utf8(output.stdout)
                    && let Some(size) = s.split_whitespace().next()
                {
                    println!("Disk:       {size}");
                }
            }
            Ok(())
        }

        WorkspaceCmd::Link { profile, path } => {
            let _validated = TrustProfileName::try_from(profile.as_str())
                .map_err(|e| anyhow::anyhow!("invalid profile name: {e}"))?;

            let path = resolve_workspace_path(path)?;

            let mut config = core_config::load_workspace_config().unwrap_or_default();
            sesame_workspace::config::add_link(&mut config, &path.display().to_string(), &profile);
            core_config::save_workspace_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Linked {} -> profile \"{}\"", path.display(), profile);
            Ok(())
        }

        WorkspaceCmd::Unlink { path } => {
            let path = resolve_workspace_path(path)?;
            let mut config = core_config::load_workspace_config().unwrap_or_default();
            let path_str = path.display().to_string();
            if sesame_workspace::config::remove_link(&mut config, &path_str) {
                core_config::save_workspace_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("Unlinked {}", path.display());
            } else {
                println!("No link found for {}", path.display());
            }
            Ok(())
        }

        WorkspaceCmd::Shell {
            profile,
            path,
            shell,
            prefix,
            command,
        } => {
            let path = resolve_workspace_path(path)?;
            let config = core_config::load_workspace_config().unwrap_or_default();
            let root = sesame_workspace::config::resolve_root(&config);

            // Use effective config for profile resolution.
            let effective =
                sesame_workspace::config::resolve_effective_config(&config, &path, &root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Profile resolution: CLI flag > effective config > SESAME_PROFILES env > "default"
            let profile_csv = profile
                .or(effective.profile)
                .or_else(|| std::env::var("SESAME_PROFILES").ok())
                .unwrap_or_else(|| core_types::DEFAULT_PROFILE_NAME.into());

            let specs = parse_profile_specs(&profile_csv);
            let secret_prefix = prefix.or(effective.secret_prefix);

            // Connect to IPC and fetch secrets from all profiles.
            let client = connect().await?;
            let env_vars =
                fetch_multi_profile_secrets(&client, &specs, secret_prefix.as_deref()).await?;

            // Determine what to spawn.
            let (bin, args, is_interactive) = if !command.is_empty() {
                (command[0].clone(), command[1..].to_vec(), false)
            } else {
                let shell_bin = shell
                    .or_else(|| std::env::var("SHELL").ok())
                    .unwrap_or_else(|| "/bin/sh".into());
                (shell_bin, Vec::new(), true)
            };

            let mut cmd = std::process::Command::new(&bin);
            cmd.args(&args);
            cmd.current_dir(&path);
            cmd.env("SESAME_PROFILES", &profile_csv);
            cmd.env("SESAME_WORKSPACE", path.display().to_string());

            // Inject effective env vars from .sesame.toml layers.
            for (k, v) in &effective.env {
                cmd.env(k, v);
            }

            // Inject secrets.
            for (k, v) in &env_vars {
                let val_str = String::from_utf8_lossy(v);
                cmd.env(k, val_str.as_ref());
            }

            if is_interactive {
                println!(
                    "Entering workspace shell (profiles: {profile_csv}, {} secrets injected)",
                    env_vars.len()
                );
            }
            let status = cmd.status().context("failed to spawn command")?;

            // Zeroize secrets.
            for (_, mut v) in env_vars {
                v.zeroize();
            }

            std::process::exit(status.code().unwrap_or(1));
        }

        WorkspaceCmd::Config(sub) => match sub {
            WorkspaceConfigCmd::Show { path } => {
                let path = resolve_workspace_path(path)?;
                let config = core_config::load_workspace_config().unwrap_or_default();
                let root = sesame_workspace::config::resolve_root(&config);

                let effective =
                    sesame_workspace::config::resolve_effective_config(&config, &path, &root)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;

                println!("Workspace:      {}", path.display());
                println!(
                    "Profile:        {} (source: {})",
                    effective.profile.as_deref().unwrap_or("(none)"),
                    if effective.provenance.profile_source.is_empty() {
                        "default"
                    } else {
                        effective.provenance.profile_source
                    }
                );
                if let Some(ref prefix) = effective.secret_prefix {
                    println!(
                        "Secret prefix:  {prefix} (source: {})",
                        effective.provenance.secret_prefix_source
                    );
                }
                if !effective.env.is_empty() {
                    println!("Environment:");
                    for (k, v) in &effective.env {
                        println!("  {k}={v}");
                    }
                }
                if !effective.tags.is_empty() {
                    println!("Tags:           {}", effective.tags.join(", "));
                }
                Ok(())
            }
        },
    }
}
