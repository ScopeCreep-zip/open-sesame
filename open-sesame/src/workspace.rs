use anyhow::Context;
use core_types::TrustProfileName;
use core_workspace_types::WorkspaceKind;
use owo_colors::OwoColorize;
use zeroize::Zeroize;

use crate::cli::resolve_workspace_path;
use crate::cli::{WorkspaceCmd, WorkspaceConfigCmd, WorkspaceListFormat};
use crate::ipc::{connect, fetch_multi_profile_secrets, parse_profile_specs};

/// Check if creating a path requires privilege escalation.
///
/// Walks up the directory tree to find the first existing ancestor
/// and checks if it is owned by the current user.
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

/// Compare two git remote URLs by semantic identity.
///
/// Parses both URLs into WorkspaceCoordinate and compares host,
/// namespace, and repository name. Transport, port, .git suffix,
/// and URL spelling differences do not affect the comparison.
/// Returns false if either URL cannot be parsed.
fn remotes_identify_same_repo(a: &str, b: &str) -> bool {
    let a_coord = sesame_workspace::convention::parse_url(a);
    let b_coord = sesame_workspace::convention::parse_url(b);
    match (a_coord, b_coord) {
        (Ok(a), Ok(b)) => {
            a.host() == b.host()
                && a.namespace() == b.namespace()
                && a.kind().repository_name() == b.kind().repository_name()
        }
        _ => false,
    }
}

/// Build an HTTPS endpoint for a workspace repository.
///
/// Workspace repository probes and clones always use HTTPS because
/// they are infrastructure operations, not user-requested clones.
fn workspace_repo_endpoint(
    server: &core_workspace_types::GitHost,
    namespace: &core_workspace_types::NamespacePath,
    repo_name: &core_workspace_types::RepositoryName,
) -> core_workspace_types::RemoteEndpoint {
    let identity = core_workspace_types::RemoteIdentity::new(
        server.clone(),
        namespace.clone(),
        repo_name.clone(),
    );
    core_workspace_types::RemoteEndpoint::https(identity)
}

pub(crate) async fn cmd_workspace(cmd: WorkspaceCmd) -> anyhow::Result<()> {
    match cmd {
        WorkspaceCmd::Init { root, user } => {
            let user =
                user.unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "user".into()));

            #[cfg(target_os = "linux")]
            {
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

            let mut config =
                core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
            config.settings.root = root.clone();
            config.settings.user = core_workspace_types::WorkspaceUser::new(&user)
                .map_err(|e| anyhow::anyhow!("invalid username: {e}"))?;
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
            let config =
                core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
            let layout = sesame_workspace::WorkspaceLayout::resolve(&config);

            let clone_input = sesame_workspace::convention::parse_clone_input(
                &url,
                &config.settings.default_server.to_string(),
                config.settings.transport,
                &config.settings.workspace_repo,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;

            let coord = &clone_input.coordinate;

            if !coord.kind().is_cloneable() && !project {
                anyhow::bail!(
                    "org-only URL requires --project to clone all repositories\n\
                     usage: sesame clone --project {url}"
                );
            }

            if project {
                let host_str = coord.host().to_string();
                let ns_str = coord.namespace().to_string();

                let forge =
                    sesame_workspace::forge::forge_for_server(&host_str).ok_or_else(|| {
                        anyhow::anyhow!(
                            "forge API not supported for server: {host_str} (supported: github.com)"
                        )
                    })?;
                let opts = sesame_workspace::forge::ListOptions {
                    include_forks,
                    include_archived,
                };
                let repos = forge
                    .list_org_repos(&ns_str, &opts)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                eprintln!("Found {} repositories in {host_str}/{ns_str}", repos.len());

                // Set up workspace.git if available.
                let org_dir = coord.canonical_path(&layout.root, &layout.user);
                if !org_dir.join(".git").is_dir() {
                    let ws_ep = workspace_repo_endpoint(
                        coord.host(),
                        coord.namespace(),
                        &config.settings.workspace_repo,
                    );
                    if sesame_workspace::git::probe_remote(&ws_ep.to_url()) {
                        eprintln!("Setting up org workspace...");
                        match sesame_workspace::git::clone_workspace_git(&ws_ep, &org_dir, force) {
                            Ok(p) => eprintln!("  Workspace initialized: {}", p.display()),
                            Err(e) => eprintln!("  Warning: workspace.git setup failed: {e}"),
                        }
                    }
                }

                let ws_repo_name = &config.settings.workspace_repo;
                let repos: Vec<_> = repos
                    .into_iter()
                    .filter(|r| r.name != ws_repo_name.as_str())
                    .collect();

                let mut success = 0usize;
                let mut skipped = 0usize;
                let mut failed = 0usize;

                for repo_info in &repos {
                    let repo_coord =
                        match sesame_workspace::convention::parse_url(&repo_info.clone_url) {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("  Skipping {}: {e}", repo_info.name);
                                failed += 1;
                                continue;
                            }
                        };
                    let repo_path = repo_coord.canonical_path(&layout.root, &layout.user);

                    if repo_path.exists() && sesame_workspace::git::is_git_repo(&repo_path) {
                        eprintln!("  {} (exists)", repo_info.name.dimmed());
                        skipped += 1;
                        continue;
                    }

                    // Forge clone URLs are always HTTPS.
                    let repo_identity = if let Some(rn) = repo_coord.kind().repository_name() {
                        core_workspace_types::RemoteIdentity::new(
                            repo_coord.host().clone(),
                            repo_coord.namespace().clone(),
                            rn.clone(),
                        )
                    } else {
                        eprintln!("  Skipping {}: no repository name", repo_info.name);
                        failed += 1;
                        continue;
                    };
                    let repo_ep = core_workspace_types::RemoteEndpoint::https(repo_identity);

                    match sesame_workspace::git::clone_to(&repo_ep, &repo_path, depth) {
                        Ok(_) => {
                            eprintln!("  {} {}", "Cloned".green(), repo_info.name);
                            success += 1;
                        }
                        Err(e) => {
                            let hint = if e.to_string().contains("auth")
                                || e.to_string().contains("401")
                                || e.to_string().contains("403")
                            {
                                " (may be a private repo, check GITHUB_TOKEN)"
                            } else {
                                ""
                            };
                            eprintln!("  {} {}: {e}{hint}", "Failed".red(), repo_info.name);
                            failed += 1;
                        }
                    }
                }

                eprintln!("\n{success} cloned, {skipped} skipped (exist), {failed} failed");
                return Ok(());
            }

            let target_path = coord.canonical_path(&layout.root, &layout.user);

            // Workspace.git auto-discovery for regular repository clones.
            if coord.kind().is_cloneable() && !no_workspace {
                let mode = if workspace_init || workspace_update {
                    core_config::WorkspaceAutoMode::Always
                } else {
                    config.settings.workspace_auto
                };

                if mode != core_config::WorkspaceAutoMode::Never {
                    let org_dir = layout
                        .root
                        .join(layout.user.as_str())
                        .join(coord.host().as_dir_name())
                        .join(coord.namespace().as_path());
                    let ws_ep = workspace_repo_endpoint(
                        coord.host(),
                        coord.namespace(),
                        &config.settings.workspace_repo,
                    );
                    let ws_url = ws_ep.to_url();

                    let has_workspace_git = org_dir.join(".git").is_dir();
                    let org_dir_exists = org_dir.exists();

                    if has_workspace_git {
                        if workspace_update || mode == core_config::WorkspaceAutoMode::Always {
                            eprintln!("Updating org workspace at {}...", org_dir.display());
                            match sesame_workspace::git::pull_ff_only(&org_dir) {
                                Ok(()) => eprintln!("  Workspace updated."),
                                Err(e) => eprintln!("  Warning: workspace pull failed: {e}"),
                            }
                        } else if mode == core_config::WorkspaceAutoMode::Auto {
                            let local = sesame_workspace::git::head_commit_short(&org_dir)
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| "(unborn)".into());
                            let branch = sesame_workspace::git::current_branch(&org_dir)
                                .unwrap_or_else(|_| "unknown".into());
                            let tracking = sesame_workspace::git::remote_tracking_commit_short(
                                &org_dir, &branch,
                            )
                            .ok()
                            .flatten();

                            if let Some(ref remote_commit) = tracking
                                && *remote_commit != local
                            {
                                eprintln!(
                                    "Note: org workspace at {} is at {local}, \
                                     origin/{branch} is at {remote_commit}",
                                    org_dir.display(),
                                );
                                eprintln!(
                                    "  Update with: sesame workspace clone \
                                     {url} --workspace-update",
                                );
                            }
                        }
                    } else if !org_dir_exists {
                        if sesame_workspace::git::probe_remote(&ws_url) {
                            eprintln!("Setting up org workspace...");
                            match sesame_workspace::git::clone_workspace_git(
                                &ws_ep, &org_dir, force,
                            ) {
                                Ok(p) => eprintln!("  Workspace initialized: {}", p.display()),
                                Err(e) => eprintln!("  Warning: workspace.git setup failed: {e}"),
                            }
                        }
                    } else if (workspace_init || mode == core_config::WorkspaceAutoMode::Always)
                        && org_dir_exists
                    {
                        if !force {
                            if sesame_workspace::git::probe_remote(&ws_url) {
                                eprintln!(
                                    "Warning: --workspace-init would overwrite files in {}",
                                    org_dir.display(),
                                );
                                eprintln!(
                                    "  Add --force to proceed: sesame workspace clone \
                                     {url} --workspace-init --force",
                                );
                            }
                        } else if sesame_workspace::git::probe_remote(&ws_url) {
                            eprintln!(
                                "Initializing workspace.git around existing {}...",
                                org_dir.display(),
                            );
                            match sesame_workspace::git::clone_workspace_git(
                                &ws_ep, &org_dir, force,
                            ) {
                                Ok(p) => eprintln!("  Workspace initialized: {}", p.display()),
                                Err(e) => eprintln!("  Warning: workspace.git setup failed: {e}"),
                            }
                        }
                    } else if mode == core_config::WorkspaceAutoMode::Auto && org_dir_exists {
                        // Network probe is a side effect — keep it inside the
                        // block body so the cost is visible when reading the
                        // else-if chain.
                        if sesame_workspace::git::probe_remote(&ws_url) {
                            eprintln!("Tip: workspace.git is available for this org.",);
                            eprintln!(
                                "  Initialize with: sesame workspace clone \
                                 {url} --workspace-init",
                            );
                            eprintln!("  Or directly: sesame workspace clone {ws_url}",);
                        }
                    }
                }
            }

            // Adoption: compare existing remote identity with requested identity.
            let adopted = if target_path.exists()
                && sesame_workspace::git::is_git_repo(&target_path)
                && adopt
            {
                let existing_remote = sesame_workspace::git::remote_url(&target_path)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                match existing_remote {
                    Some(ref remote) => {
                        if remotes_identify_same_repo(remote, &clone_input.display_url) {
                            true
                        } else {
                            anyhow::bail!(
                                "directory exists with different remote:\n\
                                 existing: {remote}\n\
                                 requested: {}\n\
                                 Remove the directory or fix the remote manually.",
                                clone_input.display_url
                            );
                        }
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
                println!("{}", target_path.display());
                eprintln!("Adopted existing repository");
                target_path
            } else {
                let rp = match coord.kind() {
                    WorkspaceKind::Repository(_) => sesame_workspace::git::clone_to(
                        &clone_input.endpoint,
                        &coord.canonical_path(&layout.root, &layout.user),
                        depth,
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                    WorkspaceKind::WorkspaceRepository(_) => {
                        sesame_workspace::git::clone_workspace_git(
                            &clone_input.endpoint,
                            &coord.canonical_path(&layout.root, &layout.user),
                            force,
                        )
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                    }
                    WorkspaceKind::Organization => {
                        anyhow::bail!("org-only URL requires --project");
                    }
                };

                match coord.kind() {
                    WorkspaceKind::WorkspaceRepository(_) => {
                        println!("{}", rp.display());
                        eprintln!("Peer repos will be cloned as siblings inside this directory.");
                    }
                    _ => {
                        println!("{}", rp.display());
                    }
                }
                rp
            };

            if let Some(ref profile_name) = profile {
                let _validated = TrustProfileName::try_from(profile_name.as_str())
                    .map_err(|e| anyhow::anyhow!("invalid profile name: {e}"))?;
                let mut ws_config =
                    core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
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
            repo,
            dirty,
            columns,
            format,
        } => {
            let config =
                core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut workspaces = sesame_workspace::discover::discover_workspaces(&config)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            if let Some(ref s) = server {
                workspaces.retain(|w| w.coordinate.host().to_string() == s.as_str());
            }
            if let Some(ref o) = org {
                workspaces.retain(|w| w.coordinate.namespace().root_segment() == o.as_str());
            }
            if let Some(ref p) = profile {
                workspaces.retain(|w| w.linked_profile.as_deref() == Some(p.as_str()));
            }
            if let Some(ref r) = repo {
                let needle = r.to_lowercase();
                workspaces.retain(|w| {
                    w.coordinate
                        .kind()
                        .repository_name()
                        .is_some_and(|name| name.as_str().to_lowercase().contains(&needle))
                });
            }

            let active_columns = match &columns {
                Some(spec) => sesame_workspace::format::parse_columns(spec)
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                None => sesame_workspace::format::DEFAULT_COLUMNS.to_vec(),
            };

            // JSON uses a full inspection request for a stable schema.
            // Table uses a column-derived request for performance.
            let insp_request = match format {
                WorkspaceListFormat::Json => sesame_workspace::InspectionRequest::all(),
                WorkspaceListFormat::Table => {
                    let mut req =
                        sesame_workspace::format::inspection_request_for_columns(&active_columns);
                    if dirty {
                        req.status = true;
                    }
                    req
                }
            };

            let mut inspections: std::collections::HashMap<
                std::path::PathBuf,
                sesame_workspace::InspectionResult,
            > = std::collections::HashMap::new();

            let needs_insp = match format {
                WorkspaceListFormat::Json => true,
                WorkspaceListFormat::Table => {
                    sesame_workspace::format::needs_inspection(&active_columns) || dirty
                }
            };

            if needs_insp {
                let insp_start = std::time::Instant::now();

                let jobs: Vec<sesame_workspace::pool::InspectJob> = workspaces
                    .iter()
                    .enumerate()
                    .filter(|(_, ws)| ws.coordinate.kind().is_cloneable())
                    .map(|(i, ws)| sesame_workspace::pool::InspectJob {
                        path: ws.path.clone(),
                        request: insp_request.clone(),
                        index: i,
                        estimated_cost: sesame_workspace::pool::estimate_cost(&ws.path),
                    })
                    .collect();

                let num_workers = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4);

                let cancel = std::sync::atomic::AtomicBool::new(false);
                let progress = sesame_workspace::progress::Progress::new();

                let results = sesame_workspace::pool::run_inspections(
                    jobs,
                    num_workers,
                    &cancel,
                    |completed, total, name, elapsed_ms| {
                        progress.update(completed, total, name, elapsed_ms);
                    },
                );

                progress.finish(results.len());

                let mut timings: Vec<(String, u64)> = Vec::new();
                for r in &results {
                    match &r.result {
                        Ok(insp) => {
                            inspections.insert(workspaces[r.index].path.clone(), insp.clone());
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %e.path.display(),
                                error = %e.message,
                                "repo inspection failed"
                            );
                        }
                    }
                    timings.push((workspaces[r.index].path.display().to_string(), r.elapsed_ms));
                }

                let total = insp_start.elapsed();
                timings.sort_by_key(|t| std::cmp::Reverse(t.1));
                tracing::info!(
                    repos = results.len(),
                    total_ms = total.as_millis() as u64,
                    workers = num_workers,
                    "workspace inspection complete"
                );
                for (path, ms) in timings.iter().take(15) {
                    tracing::info!(ms, path = path.as_str(), "slowest repo");
                }
            }

            if dirty {
                workspaces.retain(|w| {
                    if !w.coordinate.kind().is_cloneable() {
                        return false;
                    }
                    inspections
                        .get(&w.path)
                        .and_then(|i| i.status.value().copied())
                        .is_some_and(|s| s == sesame_workspace::RepoStatus::Dirty)
                });
            }

            match format {
                WorkspaceListFormat::Table => {
                    if workspaces.is_empty() {
                        println!("No workspaces found.");
                        return Ok(());
                    }

                    let mut groups: std::collections::BTreeMap<
                        (String, String),
                        Vec<&sesame_workspace::DiscoveredWorkspace>,
                    > = std::collections::BTreeMap::new();
                    for ws in &workspaces {
                        let key = (
                            ws.coordinate.host().to_string(),
                            ws.coordinate.namespace().to_string(),
                        );
                        groups.entry(key).or_default().push(ws);
                    }

                    let mut total_repos = 0usize;
                    for ((srv, ns), entries) in &groups {
                        let has_ws = entries.iter().any(|e| !e.coordinate.kind().is_cloneable());
                        let ws_tag = if has_ws {
                            format!(" {}", "(workspace)".dimmed())
                        } else {
                            String::new()
                        };
                        println!("{}{ws_tag}", format!("{srv}/{ns}").bold());

                        for ws in entries {
                            if !ws.coordinate.kind().is_cloneable() {
                                continue;
                            }
                            total_repos += 1;

                            let insp = inspections.get(&ws.path);
                            let fields: Vec<Option<String>> = active_columns
                                .iter()
                                .map(|col| sesame_workspace::format::extract_field(ws, insp, col))
                                .collect();

                            let mut display_fields: Vec<String> = Vec::with_capacity(fields.len());
                            for (i, field) in fields.iter().enumerate() {
                                let text = field.as_deref().unwrap_or("?");
                                let styled = match active_columns[i] {
                                    "status" if text == "clean" => text.green().to_string(),
                                    "status" if text == "unknown" => text.red().to_string(),
                                    "status" => text.yellow().to_string(),
                                    "commit" => text.dimmed().to_string(),
                                    "profile" if text != "?" && !text.is_empty() => {
                                        text.green().to_string()
                                    }
                                    _ => text.to_string(),
                                };
                                display_fields.push(styled);
                            }

                            let line = fields
                                .iter()
                                .zip(display_fields.iter())
                                .enumerate()
                                .map(|(i, (raw, styled))| {
                                    let col_def = sesame_workspace::format::ALL_COLUMNS
                                        .iter()
                                        .find(|c| c.name == active_columns[i]);
                                    let min_w = col_def.map(|c| c.min_width).unwrap_or(10);
                                    let raw_len = raw.as_deref().unwrap_or("?").len();
                                    let pad = min_w.saturating_sub(raw_len);
                                    format!("{styled}{:pad$}", "")
                                })
                                .collect::<Vec<_>>()
                                .join(" ");

                            println!("  {line}");
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
                            "{server_count} server{}, {org_count} org{}, \
                             {total_repos} repo{}",
                            if server_count != 1 { "s" } else { "" },
                            if org_count != 1 { "s" } else { "" },
                            if total_repos != 1 { "s" } else { "" },
                        )
                        .dimmed(),
                    );
                }
                WorkspaceListFormat::Json => {
                    let records: Vec<sesame_workspace::format::WorkspaceRecord> = workspaces
                        .iter()
                        .filter(|ws| ws.coordinate.kind().is_cloneable())
                        .map(|ws| {
                            let insp = inspections.get(&ws.path);
                            sesame_workspace::format::WorkspaceRecord::from_workspace(ws, insp)
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
            }
            Ok(())
        }

        WorkspaceCmd::Status { path, verbose } => {
            let path = resolve_workspace_path(path)?;
            let config =
                core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
            let layout = sesame_workspace::WorkspaceLayout::resolve(&config);

            let parsed = sesame_workspace::convention::parse_path(&layout.root, &path)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Use the single-open inspection API for all git metadata.
            let insp_request = sesame_workspace::InspectionRequest::all();
            let inspection = sesame_workspace::inspection::inspect(&path, &insp_request).ok();

            let effective =
                sesame_workspace::config::resolve_effective_config(&config, &path, &layout.root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            let in_ws_git = sesame_workspace::convention::is_inside_workspace_git(&path);

            println!("Workspace:  {}", path.display());

            let remote_str = inspection
                .as_ref()
                .and_then(|i| i.remote_url.value().cloned())
                .unwrap_or_else(|| "unknown".into());
            println!("Remote:     {remote_str}");

            let branch_str = inspection
                .as_ref()
                .and_then(|i| i.branch.value().cloned())
                .unwrap_or_else(|| "unknown".into());
            println!("Branch:     {branch_str}");

            let head_short = inspection
                .as_ref()
                .and_then(|i| i.head_short.value().cloned())
                .unwrap_or_else(|| "(unborn)".into());
            let head_summary = inspection
                .as_ref()
                .and_then(|i| i.head_summary.value().cloned())
                .unwrap_or_default();
            let upstream_short = inspection
                .as_ref()
                .and_then(|i| i.upstream_short.value().cloned());

            print!("Commit:     {head_short}");
            if !head_summary.is_empty() {
                print!(" {head_summary}");
            }
            println!();
            if let Some(ref tracking) = upstream_short {
                if *tracking != head_short {
                    println!(
                        "Tracking:   {} (origin/{branch_str}, {})",
                        tracking,
                        "behind".yellow(),
                    );
                } else {
                    println!("Tracking:   {tracking} (origin/{branch_str}, up to date)");
                }
            }

            let status = inspection.as_ref().and_then(|i| i.status.value().copied());
            let status_str = match status {
                Some(sesame_workspace::RepoStatus::Clean) => "clean".green().to_string(),
                Some(sesame_workspace::RepoStatus::Dirty) => "dirty".yellow().to_string(),
                None => "unknown".red().to_string(),
            };
            println!("Status:     {status_str}");
            println!(
                "Profile:    {}",
                effective.profile.as_deref().unwrap_or("(none)")
            );
            println!(
                "Namespace:  {} ({})",
                parsed.namespace,
                if in_ws_git {
                    "workspace.git"
                } else {
                    "no workspace.git"
                }
            );

            if verbose {
                let repo_display = parsed
                    .terminal
                    .as_ref()
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_else(|| "(namespace root)".into());
                println!(
                    "Convention: {} / {} / {} / {} / {}",
                    layout.root.display(),
                    layout.user,
                    parsed.host,
                    parsed.namespace,
                    repo_display,
                );

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

            let mut config =
                core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
            sesame_workspace::config::add_link(&mut config, &path.display().to_string(), &profile);
            core_config::save_workspace_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Linked {} -> profile \"{}\"", path.display(), profile);
            Ok(())
        }

        WorkspaceCmd::Unlink { path } => {
            let path = resolve_workspace_path(path)?;
            let mut config =
                core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
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
            let config =
                core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
            let layout = sesame_workspace::WorkspaceLayout::resolve(&config);

            let effective =
                sesame_workspace::config::resolve_effective_config(&config, &path, &layout.root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

            let profile_csv = profile
                .or(effective.profile)
                .or_else(|| std::env::var("SESAME_PROFILES").ok())
                .unwrap_or_else(|| core_types::DEFAULT_PROFILE_NAME.into());

            let specs = parse_profile_specs(&profile_csv);
            let secret_prefix = prefix.or(effective.secret_prefix);

            let client = connect().await?;
            let env_vars =
                fetch_multi_profile_secrets(&client, &specs, secret_prefix.as_deref()).await?;

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

            for (k, v) in &effective.env {
                cmd.env(k, v);
            }

            for (k, v) in &env_vars {
                let val_str = String::from_utf8_lossy(v);
                cmd.env(k, val_str.as_ref());
            }

            if is_interactive {
                println!(
                    "Entering workspace shell \
                     (profiles: {profile_csv}, {} secrets injected)",
                    env_vars.len()
                );
            }
            let status = cmd.status().context("failed to spawn command")?;

            for (_, mut v) in env_vars {
                v.zeroize();
            }

            std::process::exit(status.code().unwrap_or(1));
        }

        WorkspaceCmd::Config(sub) => match sub {
            WorkspaceConfigCmd::Show { path } => {
                let path = resolve_workspace_path(path)?;
                let config =
                    core_config::load_workspace_config().map_err(|e| anyhow::anyhow!("{e}"))?;
                let layout = sesame_workspace::WorkspaceLayout::resolve(&config);

                let effective = sesame_workspace::config::resolve_effective_config(
                    &config,
                    &path,
                    &layout.root,
                )
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
