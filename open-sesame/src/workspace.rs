use anyhow::Context;
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
            workspace_init,
            workspace_update,
            no_workspace,
            force,
            project,
            include_forks,
            include_archived,
        } => {
            let config = core_config::load_workspace_config().unwrap_or_default();
            let root = sesame_workspace::config::resolve_root(&config);
            let user = sesame_workspace::config::resolve_user(&config);

            // For --project, accept org-only URLs (e.g. https://github.com/ScopeCreep-zip)
            // by appending a placeholder repo component that parse_url requires.
            let parse_url = if project {
                let trimmed = url.trim_end_matches('/');
                // Count path segments after the scheme. org-only has 2 (server/org).
                let without_scheme = trimmed
                    .strip_prefix("https://")
                    .or_else(|| trimmed.strip_prefix("http://"))
                    .unwrap_or(trimmed);
                let segments = without_scheme.split('/').count();
                if segments == 2 {
                    format!("{trimmed}/_placeholder")
                } else {
                    url.clone()
                }
            } else {
                url.clone()
            };

            let conv = sesame_workspace::convention::parse_url(&parse_url)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            // --project: clone all repos in the org via forge API.
            if project {
                let forge =
                    sesame_workspace::forge::forge_for_server(&conv.server).ok_or_else(|| {
                        anyhow::anyhow!(
                            "forge API not supported for server: {} (supported: github.com)",
                            conv.server
                        )
                    })?;
                let opts = sesame_workspace::forge::ListOptions {
                    include_forks,
                    include_archived,
                };
                let repos = forge
                    .list_org_repos(&conv.org, &opts)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                eprintln!(
                    "Found {} repositories in {}/{}",
                    repos.len(),
                    conv.server,
                    conv.org,
                );

                // Set up workspace.git first if available (reuse auto-discovery logic).
                let org_dir = root.join(&user).join(&conv.server).join(&conv.org);
                if !org_dir.join(".git").is_dir() {
                    let ws_repo_name = &config.settings.workspace_repo;
                    let ws_url =
                        format!("https://{}/{}/{}.git", conv.server, conv.org, ws_repo_name,);
                    if sesame_workspace::git::probe_remote(&ws_url) {
                        eprintln!(
                            "Setting up org workspace from {}/{}/{}.git...",
                            conv.server, conv.org, ws_repo_name,
                        );
                        let ws_conv = sesame_workspace::convention::WorkspaceConvention {
                            server: conv.server.clone(),
                            org: conv.org.clone(),
                            repo: None,
                            is_workspace_git: true,
                        };
                        let ws_target =
                            sesame_workspace::convention::canonical_path(&root, &user, &ws_conv);
                        match sesame_workspace::git::clone_repo(&ws_url, &ws_target, None, force) {
                            Ok(p) => eprintln!("  Workspace initialized: {}", p.display()),
                            Err(e) => eprintln!("  Warning: workspace.git setup failed: {e}"),
                        }
                    }
                }

                // Filter out the workspace repo itself — it's managed separately.
                let ws_repo_name = &config.settings.workspace_repo;
                let repos: Vec<_> = repos
                    .into_iter()
                    .filter(|r| r.name != *ws_repo_name)
                    .collect();

                let mut success = 0usize;
                let mut skipped = 0usize;
                let mut failed = 0usize;

                for repo_info in &repos {
                    let repo_url = &repo_info.clone_url;
                    let repo_conv = match sesame_workspace::convention::parse_url(repo_url) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("  Skipping {}: {e}", repo_info.name);
                            failed += 1;
                            continue;
                        }
                    };
                    let repo_target =
                        sesame_workspace::convention::canonical_path(&root, &user, &repo_conv);
                    let repo_path = repo_target.path().to_path_buf();

                    if repo_path.exists() && sesame_workspace::git::is_git_repo(&repo_path) {
                        eprintln!("  {} (exists)", repo_info.name.dimmed());
                        skipped += 1;
                        continue;
                    }

                    match sesame_workspace::git::clone_repo(repo_url, &repo_target, depth, force) {
                        Ok(_) => {
                            eprintln!("  {} {}", "Cloned".green(), repo_info.name);
                            success += 1;
                        }
                        Err(e) => {
                            let hint = if e.to_string().contains("auth")
                                || e.to_string().contains("401")
                                || e.to_string().contains("403")
                            {
                                " (may be a private repo — check GITHUB_TOKEN)"
                            } else {
                                ""
                            };
                            eprintln!("  {} {}: {e}{hint}", "Failed".red(), repo_info.name,);
                            failed += 1;
                        }
                    }
                }

                eprintln!("\n{success} cloned, {skipped} skipped (exist), {failed} failed",);
                return Ok(());
            }

            let target = sesame_workspace::convention::canonical_path(&root, &user, &conv);

            // Workspace.git auto-discovery.
            //
            // Behavior is driven by config (`workspace_auto`) with CLI flag overrides:
            //   --no-workspace      → skip everything
            //   --workspace-init    → force init even if org dir exists
            //   --workspace-update  → force pull if behind
            //
            // Config modes:
            //   "auto"   → init on new org dir, inform on existing
            //   "always" → init or update without asking
            //   "never"  → no probes, no informs
            //   "prompt" → interactive confirmation (TODO: future)
            //
            // This block is best-effort — probe failures or clone failures are
            // non-fatal. The project repo clone always proceeds.
            if !conv.is_workspace_git && !no_workspace {
                let mode = if workspace_init || workspace_update {
                    "always" // CLI flags override config
                } else {
                    config.settings.workspace_auto.as_str()
                };

                if mode != "never" {
                    let org_dir = root.join(&user).join(&conv.server).join(&conv.org);
                    let ws_repo_name = &config.settings.workspace_repo;
                    let ws_url =
                        format!("https://{}/{}/{}.git", conv.server, conv.org, ws_repo_name,);

                    let has_workspace_git = org_dir.join(".git").is_dir();
                    let org_dir_exists = org_dir.exists();

                    if has_workspace_git {
                        // Workspace.git already initialized.
                        if workspace_update || mode == "always" {
                            // User or config requested update — pull.
                            eprintln!("Updating org workspace at {}...", org_dir.display());
                            match sesame_workspace::git::pull_ff_only(&org_dir) {
                                Ok(()) => eprintln!("  Workspace updated."),
                                Err(e) => eprintln!("  Warning: workspace pull failed: {e}"),
                            }
                        } else if mode == "auto" {
                            // Auto mode: show local vs remote state, don't modify.
                            let local = sesame_workspace::git::head_commit_short(&org_dir)
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| "(unborn)".into());
                            let branch = sesame_workspace::git::current_branch(&org_dir)
                                .unwrap_or_else(|_| "main".into());
                            let tracking = sesame_workspace::git::remote_tracking_commit_short(
                                &org_dir, &branch,
                            )
                            .ok()
                            .flatten();

                            if let Some(ref remote_commit) = tracking
                                && *remote_commit != local
                            {
                                eprintln!(
                                    "Note: org workspace at {} is at {local}, origin/{branch} is at {remote_commit}",
                                    org_dir.display(),
                                );
                                eprintln!(
                                    "  Update with: sesame workspace clone {} --workspace-update",
                                    url,
                                );
                            }
                        }
                    } else if !org_dir_exists {
                        // Org dir is new (doesn't exist) — safe to init assertively.
                        if sesame_workspace::git::probe_remote(&ws_url) {
                            eprintln!(
                                "Detected {}/{}/{}.git — setting up org workspace...",
                                conv.server, conv.org, ws_repo_name,
                            );
                            let ws_conv = sesame_workspace::convention::WorkspaceConvention {
                                server: conv.server.clone(),
                                org: conv.org.clone(),
                                repo: None,
                                is_workspace_git: true,
                            };
                            let ws_target = sesame_workspace::convention::canonical_path(
                                &root, &user, &ws_conv,
                            );
                            match sesame_workspace::git::clone_repo(
                                &ws_url, &ws_target, None, force,
                            ) {
                                Ok(p) => eprintln!("  Workspace initialized: {}", p.display()),
                                Err(e) => eprintln!("  Warning: workspace.git setup failed: {e}"),
                            }
                        }
                    } else if (workspace_init || mode == "always") && org_dir_exists {
                        // Org dir exists without .git — user or config wants init.
                        // This will overwrite existing files (.envrc, .gitignore, etc.)
                        // so require --force for explicit consent.
                        if !force {
                            if sesame_workspace::git::probe_remote(&ws_url) {
                                eprintln!(
                                    "Warning: --workspace-init would overwrite files in {}",
                                    org_dir.display(),
                                );
                                eprintln!(
                                    "  Add --force to proceed: sesame workspace clone {} --workspace-init --force",
                                    url,
                                );
                            }
                        } else if sesame_workspace::git::probe_remote(&ws_url) {
                            eprintln!(
                                "Initializing workspace.git around existing {}...",
                                org_dir.display(),
                            );
                            let ws_conv = sesame_workspace::convention::WorkspaceConvention {
                                server: conv.server.clone(),
                                org: conv.org.clone(),
                                repo: None,
                                is_workspace_git: true,
                            };
                            let ws_target = sesame_workspace::convention::canonical_path(
                                &root, &user, &ws_conv,
                            );
                            match sesame_workspace::git::clone_repo(
                                &ws_url, &ws_target, None, force,
                            ) {
                                Ok(p) => eprintln!("  Workspace initialized: {}", p.display()),
                                Err(e) => eprintln!("  Warning: workspace.git setup failed: {e}"),
                            }
                        }
                    } else if mode == "auto" && org_dir_exists {
                        // Org dir exists without .git, auto mode — inform only.
                        if sesame_workspace::git::probe_remote(&ws_url) {
                            eprintln!(
                                "Tip: {}/{}/{}.git is available for this org.",
                                conv.server, conv.org, ws_repo_name,
                            );
                            eprintln!(
                                "  Initialize with: sesame workspace clone {} --workspace-init",
                                url,
                            );
                            eprintln!("  Or directly: sesame workspace clone {ws_url}",);
                        }
                    }
                }
            }

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
                let rp = sesame_workspace::git::clone_repo(&url, &target, depth, force)
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

                    // Group by server/org for hierarchical display.
                    let mut groups: std::collections::BTreeMap<
                        (String, String),
                        Vec<&sesame_workspace::DiscoveredWorkspace>,
                    > = std::collections::BTreeMap::new();
                    for ws in &workspaces {
                        let key = (ws.convention.server.clone(), ws.convention.org.clone());
                        groups.entry(key).or_default().push(ws);
                    }

                    let mut total_repos = 0usize;
                    for ((srv, org_name), entries) in &groups {
                        // Section header: server/org with workspace indicator.
                        let has_ws = entries.iter().any(|e| e.is_workspace_git);
                        let ws_tag = if has_ws {
                            format!(" {}", "(workspace)".dimmed())
                        } else {
                            String::new()
                        };
                        println!("{}{ws_tag}", format!("{srv}/{org_name}").bold(),);

                        // Repo lines under this org.
                        for ws in entries {
                            if ws.is_workspace_git {
                                continue; // Don't list workspace.git as a repo row.
                            }
                            total_repos += 1;
                            let repo_name = ws.convention.repo.as_deref().unwrap_or("?");

                            let branch = sesame_workspace::git::current_branch(&ws.path)
                                .unwrap_or_else(|_| "?".into());
                            let commit = sesame_workspace::git::head_commit_short(&ws.path)
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| "?".into());
                            let clean = sesame_workspace::git::is_clean(&ws.path).unwrap_or(true);
                            let status_str = if clean {
                                "clean".green().to_string()
                            } else {
                                "dirty".yellow().to_string()
                            };

                            let profile_str = match &ws.linked_profile {
                                Some(p) => format!("  profile: {}", p.green()),
                                None => String::new(),
                            };

                            println!(
                                "  {:<20} {:<14} {}  {}{profile_str}",
                                repo_name,
                                branch,
                                commit.dimmed(),
                                status_str,
                            );
                        }
                    }

                    let org_count = groups.len();
                    let server_count = groups
                        .keys()
                        .map(|(s, _)| s.as_str())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    println!(
                        "\n{}",
                        format!(
                            "{server_count} server{}, {org_count} org{}, {total_repos} repo{}",
                            if server_count != 1 { "s" } else { "" },
                            if org_count != 1 { "s" } else { "" },
                            if total_repos != 1 { "s" } else { "" },
                        )
                        .dimmed(),
                    );
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

            // Commit info.
            let head_short = sesame_workspace::git::head_commit_short(&path)
                .ok()
                .flatten()
                .unwrap_or_else(|| "(unborn)".into());
            let head_summary = sesame_workspace::git::head_commit_summary(&path)
                .ok()
                .flatten()
                .unwrap_or_default();
            let tracking_short =
                sesame_workspace::git::remote_tracking_commit_short(&path, &branch)
                    .ok()
                    .flatten();
            print!("Commit:     {head_short}");
            if !head_summary.is_empty() {
                print!(" {head_summary}");
            }
            println!();
            if let Some(ref tracking) = tracking_short {
                if *tracking != head_short {
                    println!(
                        "Tracking:   {} (origin/{branch} — {})",
                        tracking,
                        "behind".yellow(),
                    );
                } else {
                    println!("Tracking:   {tracking} (origin/{branch} — up to date)");
                }
            }

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
