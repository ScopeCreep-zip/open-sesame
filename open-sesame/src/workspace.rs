use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use core_config::{WorkspaceAutoMode, WorkspaceConfig};
use core_layout::Layout;
use core_types::TrustProfileName;
use core_workspace_types::{
    GitHost, NamespacePath, RemoteEndpoint, RemoteIdentity, WorkspaceCoordinate, WorkspaceKind,
    WorkspaceUser,
};
use owo_colors::OwoColorize;
use sesame_workspace::format::ColumnId;
use sesame_workspace::git::{CloneTarget, RemoteProbe};
use sesame_workspace::{
    CloneFailureKind, DiscoveredWorkspace, Field, InspectionResult, RemoteTarget, WorkspaceError,
    WorkspaceLayout,
};

use crate::ipc::{connect, fetch_multi_profile_secrets};
use open_sesame::cli::{ProfileSpecs, WorkspaceCmd, WorkspaceConfigCmd, WorkspaceListFormat};

pub(crate) async fn cmd_workspace(layout: &Layout, cmd: WorkspaceCmd) -> anyhow::Result<ExitCode> {
    let done = |result: anyhow::Result<()>| result.map(|()| ExitCode::SUCCESS);
    match cmd {
        WorkspaceCmd::Init { root, user } => done(init(layout, root, user)),
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
        } => done(clone(
            layout,
            &CloneRequest {
                url: &url,
                depth,
                profile: profile.as_ref(),
                adopt,
                org: OrgFlags {
                    setup: OrgSetup::from_flags(no_workspace, workspace_init || workspace_update),
                    force,
                },
                project,
                filters: sesame_workspace::forge::ListOptions {
                    include_forks,
                    include_archived,
                },
            },
        )),
        WorkspaceCmd::List {
            server,
            org,
            profile,
            repo,
            dirty,
            stale,
            columns,
            format,
        } => done(list(
            layout,
            &ListRequest {
                server: server.as_deref(),
                org: org.as_deref(),
                profile: profile.as_ref(),
                repo: repo.as_deref(),
                dirty,
                stale: stale.as_deref(),
                columns: columns.as_deref(),
                format,
            },
        )),
        WorkspaceCmd::Status { path, verbose } => done(status(layout, path, verbose)),
        WorkspaceCmd::Link { profile, path } => done(link(layout, &profile, path)),
        WorkspaceCmd::Unlink { path } => done(unlink(layout, path)),
        WorkspaceCmd::Shell {
            profile,
            inherited_profiles,
            path,
            shell,
            prefix,
            command,
        } => {
            run_shell(
                layout,
                ShellRequest {
                    profile,
                    inherited_profiles,
                    path,
                    shell,
                    prefix,
                    command,
                },
            )
            .await
        }
        WorkspaceCmd::Config(WorkspaceConfigCmd::Show { path }) => done(config_show(layout, path)),
        WorkspaceCmd::Normalize { apply } => done(normalize(layout, apply)),
    }
}

/// The workspace path argument, or the current directory. A current
/// directory that cannot be determined is an error, never `"."`.
fn resolve_workspace_path(path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match path {
        Some(p) => Ok(p),
        None => std::env::current_dir().context("failed to determine current directory"),
    }
}

/// The workspace configuration and the workspace layout it places.
fn load_layout(layout: &Layout) -> anyhow::Result<(WorkspaceConfig, WorkspaceLayout)> {
    let config = core_config::load_workspace_config(layout)?;
    let workspaces = WorkspaceLayout::from_config(layout, &config)?;
    Ok((config, workspaces))
}

/// Write a profile link for `path`, keyed by its physical path.
fn write_link(layout: &Layout, path: &Path, profile: &TrustProfileName) -> anyhow::Result<()> {
    let physical = sesame_workspace::config::physical_path(path)?;
    Ok(core_config::edit::set_workspace_link(
        layout, &physical, profile,
    )?)
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// Check if creating a path requires privilege escalation: whether the
/// nearest existing ancestor is owned by another user.
///
/// # Errors
///
/// An ancestor that exists but cannot be inspected, or a path with no
/// existing ancestor (a relative path), is an error, not a guess.
#[cfg(target_os = "linux")]
fn needs_privilege(path: &Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let uid = rustix::process::getuid().as_raw();
    for ancestor in path.ancestors() {
        match std::fs::metadata(ancestor) {
            Ok(meta) => return Ok(meta.uid() != uid),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("failed to inspect {}", ancestor.display()));
            }
        }
    }
    anyhow::bail!("{} has no existing ancestor", path.display())
}

/// The workspace user: `--user`, else the login user (`$USER`). Neither is
/// an error, not a made-up name.
fn workspace_user(layout: &Layout, flag: Option<String>) -> anyhow::Result<WorkspaceUser> {
    let name = match flag {
        Some(name) => name,
        None => layout
            .login_user()
            .ok_or_else(|| anyhow::anyhow!("$USER is not set; pass --user <name>"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("$USER is not UTF-8; pass --user <name>"))?
            .to_owned(),
    };
    WorkspaceUser::new(&name).map_err(|e| anyhow::anyhow!("invalid username '{name}': {e}"))
}

fn init(layout: &Layout, root: Option<PathBuf>, user: Option<String>) -> anyhow::Result<()> {
    let user = workspace_user(layout, user)?;
    let root = match root {
        Some(root) => root,
        None => load_layout(layout)?.1.root,
    };

    #[cfg(target_os = "linux")]
    {
        use sesame_workspace::platform::WorkspacePlatform;
        let exists = root
            .try_exists()
            .with_context(|| format!("failed to check {}", root.display()))?;
        if !exists
            && needs_privilege(&root)?
            && !crate::prompt::confirm(&format!(
                "Workspace root '{}' does not exist and requires elevated privileges to create. Continue?",
                root.display()
            ))?
        {
            println!("Cancelled.");
            return Ok(());
        }
        sesame_workspace::platform::linux::LinuxPlatform.ensure_root(&root)?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("failed to create {}", root.display()))?;
    }

    // The root exists now, so the layout holds its physical path.
    let workspaces = WorkspaceLayout::new(&root, user)?;
    let user_dir = workspaces.user_dir();
    std::fs::create_dir_all(&user_dir)
        .with_context(|| format!("failed to create {}", user_dir.display()))?;

    core_config::edit::set_workspace_settings(layout, &workspaces.root, workspaces.user.as_str())?;

    println!("Workspace initialized: {}", user_dir.display());
    println!("Config written: {}", layout.workspaces_file()?.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// clone
// ---------------------------------------------------------------------------

/// Whether org workspace setup runs for a clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrgSetup {
    /// As the configured `workspace_auto` mode decides.
    Configured,
    /// In `always` mode (`--workspace-init`, `--workspace-update`).
    Always,
    /// Not at all (`--no-workspace`, which wins over the others).
    Skip,
}

impl OrgSetup {
    fn from_flags(no_workspace: bool, raise_to_always: bool) -> Self {
        match (no_workspace, raise_to_always) {
            (true, _) => Self::Skip,
            (false, true) => Self::Always,
            (false, false) => Self::Configured,
        }
    }
}

/// The org workspace options of `sesame workspace clone`.
#[derive(Debug, Clone, Copy)]
struct OrgFlags {
    setup: OrgSetup,
    /// `--force`: initialize around an existing directory.
    force: bool,
}

struct CloneRequest<'a> {
    url: &'a str,
    depth: Option<u32>,
    profile: Option<&'a TrustProfileName>,
    adopt: bool,
    org: OrgFlags,
    project: bool,
    filters: sesame_workspace::forge::ListOptions,
}

/// What the org namespace directory holds before setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrgState {
    /// Nothing exists at the namespace directory.
    Absent,
    /// The namespace directory is a repository root (the workspace repository).
    Repository,
    /// The namespace directory exists and is not a repository root.
    Directory,
}

/// What org workspace setup does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrgAction {
    /// Nothing.
    Skip,
    /// Fast-forward the existing workspace repository.
    Update,
    /// Report when the workspace repository is behind its upstream.
    ReportDrift,
    /// Clone the workspace repository into the absent directory when the
    /// forge serves one. `required` (always mode) makes an unavailable
    /// workspace repository an error; auto mode logs it and continues.
    Clone { required: bool },
    /// Initialize the workspace repository around the existing directory;
    /// required, since only always mode with `--force` selects it.
    InitAround,
    /// The existing directory would be initialized but `--force` is
    /// missing: an error naming the command that would do it.
    RefuseInit,
    /// Report that the forge serves a workspace repository.
    Tip,
}

/// The one decision for org workspace setup, shared by single-repository
/// clones and `--project`.
///
/// `--workspace-init` and `--workspace-update` raise the configured
/// `workspace_auto` mode to `always`; `--no-workspace` disables setup.
/// An existing directory that is not a repository is initialized around
/// only with `--force`, because initialization checks out the workspace
/// repository's files into it.
fn org_action(state: OrgState, configured: WorkspaceAutoMode, flags: OrgFlags) -> OrgAction {
    let mode = match flags.setup {
        OrgSetup::Skip => return OrgAction::Skip,
        OrgSetup::Always => WorkspaceAutoMode::Always,
        OrgSetup::Configured => configured,
    };
    match (mode, state) {
        (WorkspaceAutoMode::Never, _) => OrgAction::Skip,
        (WorkspaceAutoMode::Always, OrgState::Repository) => OrgAction::Update,
        (WorkspaceAutoMode::Auto, OrgState::Repository) => OrgAction::ReportDrift,
        (WorkspaceAutoMode::Always, OrgState::Absent) => OrgAction::Clone { required: true },
        (WorkspaceAutoMode::Auto, OrgState::Absent) => OrgAction::Clone { required: false },
        (WorkspaceAutoMode::Always, OrgState::Directory) if flags.force => OrgAction::InitAround,
        (WorkspaceAutoMode::Always, OrgState::Directory) => OrgAction::RefuseInit,
        (WorkspaceAutoMode::Auto, OrgState::Directory) => OrgAction::Tip,
    }
}

/// Set up the org workspace repository of `host`/`namespace`.
///
/// The workspace repository is infrastructure, not a user-requested
/// clone: it is probed and cloned over HTTPS. In always mode (configured,
/// or via `--workspace-init`/`--workspace-update`) every setup failure
/// fails the clone, before the requested repository is cloned. In auto
/// mode a workspace repository the forge does not serve is logged and
/// skipped; local failures still fail the clone.
fn setup_org_workspace(
    layout: &WorkspaceLayout,
    config: &WorkspaceConfig,
    host: &GitHost,
    namespace: &NamespacePath,
    flags: OrgFlags,
    url: &str,
) -> anyhow::Result<()> {
    let org_dir = layout.checked_path(&WorkspaceCoordinate::from_remote_workspace_repository(
        host, namespace,
    ))?;
    let state = match std::fs::symlink_metadata(&org_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => OrgState::Absent,
        Err(e) => return Err(e.into()),
        Ok(_) if sesame_workspace::git::git_marker(&org_dir)?.is_repository_root() => {
            OrgState::Repository
        }
        Ok(_) => OrgState::Directory,
    };
    let endpoint = RemoteEndpoint::https(RemoteIdentity::new(
        host.clone(),
        namespace.clone(),
        config.settings.workspace_repo.clone(),
    ));
    let ws_url = endpoint.to_url();

    let action = org_action(state, config.settings.workspace_auto, flags);
    let required = matches!(
        action,
        OrgAction::Clone { required: true } | OrgAction::InitAround
    );
    match action {
        OrgAction::Skip => {}
        OrgAction::Update => {
            eprintln!("Updating org workspace at {}...", org_dir.display());
            sesame_workspace::git::pull_ff_only(&org_dir)
                .with_context(|| format!("org workspace pull failed for {}", org_dir.display()))?;
            eprintln!("  Workspace updated.");
        }
        OrgAction::ReportDrift => report_drift(&org_dir, url).with_context(|| {
            format!(
                "cannot compare org workspace {} with its upstream",
                org_dir.display()
            )
        })?,
        OrgAction::Clone { .. } | OrgAction::InitAround => {
            match sesame_workspace::git::probe_remote(&ws_url)? {
                RemoteProbe::Available => {
                    if state == OrgState::Directory {
                        eprintln!(
                            "Initializing workspace.git around existing {}...",
                            org_dir.display()
                        );
                    } else {
                        eprintln!("Setting up org workspace...");
                    }
                    let path = sesame_workspace::git::clone_workspace_git(
                        &endpoint,
                        &org_dir,
                        flags.force,
                    )
                    .with_context(|| format!("workspace.git setup failed for {ws_url}"))?;
                    eprintln!("  Workspace initialized: {}", path.display());
                }
                RemoteProbe::Unavailable { kind, message } if required => {
                    anyhow::bail!(
                        "workspace repository {ws_url} is unavailable: {message}{}",
                        auth_hint(kind)
                    );
                }
                RemoteProbe::Unavailable { message, .. } => {
                    tracing::info!(url = %ws_url, reason = %message, "no org workspace repository");
                }
            }
        }
        OrgAction::RefuseInit => anyhow::bail!(
            "initializing workspace.git would check its files out into the existing {}\n\
             Add --force to proceed: sesame workspace clone {url} --force",
            org_dir.display()
        ),
        OrgAction::Tip => match sesame_workspace::git::probe_remote(&ws_url)? {
            RemoteProbe::Available => {
                eprintln!("Tip: workspace.git is available for this org.");
                eprintln!("  Initialize with: sesame workspace clone {url} --workspace-init");
                eprintln!("  Or directly: sesame workspace clone {ws_url}");
            }
            RemoteProbe::Unavailable { message, .. } => {
                tracing::info!(url = %ws_url, reason = %message, "no org workspace repository");
            }
        },
    }
    Ok(())
}

/// Print a note when the workspace repository differs from its upstream
/// as the remote advertises it now.
fn report_drift(org_dir: &Path, url: &str) -> anyhow::Result<()> {
    use sesame_workspace::git::UpstreamDrift;
    match sesame_workspace::git::upstream_drift(org_dir)? {
        UpstreamDrift::UpToDate { .. } => {}
        UpstreamDrift::Differs {
            branch,
            local,
            remote,
        } => {
            eprintln!(
                "Note: org workspace at {} is at {}, origin/{branch} is at {remote}",
                org_dir.display(),
                local.as_deref().unwrap_or("(unborn)"),
            );
            eprintln!("  Update with: sesame workspace clone {url} --workspace-update");
        }
        UpstreamDrift::BranchAbsentOnRemote { branch } => eprintln!(
            "Note: org workspace at {} is on {branch}, which origin does not have",
            org_dir.display()
        ),
        UpstreamDrift::Detached => eprintln!(
            "Note: org workspace at {} has a detached HEAD; not compared with origin",
            org_dir.display()
        ),
        UpstreamDrift::NoOrigin => eprintln!(
            "Note: org workspace at {} has no origin remote",
            org_dir.display()
        ),
    }
    Ok(())
}

/// Hint appended to a remote failure of `kind`.
fn auth_hint(kind: CloneFailureKind) -> &'static str {
    match kind {
        CloneFailureKind::Authentication => {
            " (authentication required: a private or absent repository, or credentials \
             missing or refused; configure a git credential helper)"
        }
        CloneFailureKind::Other => "",
    }
}

/// Hint appended to a clone failure, from its typed cause.
fn clone_failure_hint(e: &WorkspaceError) -> &'static str {
    match e {
        WorkspaceError::CloneFailed { kind, .. } => auth_hint(*kind),
        _ => "",
    }
}

fn clone(process_layout: &Layout, req: &CloneRequest<'_>) -> anyhow::Result<()> {
    let (config, layout) = load_layout(process_layout)?;
    let clone_input = sesame_workspace::convention::parse_clone_input(
        req.url,
        &config.settings.default_server.to_string(),
        config.settings.transport,
        &config.settings.workspace_repo,
    )?;

    if req.project {
        // The URL identifies the server and org; a repository component
        // is ignored.
        let (host, namespace) = match &clone_input.target {
            RemoteTarget::Organization { host, namespace } => (host, namespace),
            RemoteTarget::Repository(endpoint) => {
                (endpoint.identity().host(), endpoint.identity().namespace())
            }
        };
        return clone_project(req, &config, &layout, host, namespace);
    }

    let RemoteTarget::Repository(endpoint) = &clone_input.target else {
        anyhow::bail!(
            "org-only URL requires --project to clone all repositories\n\
             usage: sesame workspace clone --project {}",
            req.url
        );
    };
    let target_path = layout.checked_path(&clone_input.coordinate)?;

    let result_path = match clone_input.coordinate.kind() {
        WorkspaceKind::Repository(_) => {
            // Org setup belongs to member clones; cloning the workspace
            // repository itself uses the requested endpoint below.
            setup_org_workspace(
                &layout,
                &config,
                endpoint.identity().host(),
                endpoint.identity().namespace(),
                req.org,
                req.url,
            )?;
            match sesame_workspace::git::inspect_clone_target(&target_path, endpoint.identity())? {
                CloneTarget::SameRepository if req.adopt => {
                    eprintln!("Adopted existing repository");
                    target_path
                }
                CloneTarget::SameRepository => anyhow::bail!(
                    "{} already holds {}; --adopt false requires an absent target",
                    target_path.display(),
                    clone_input.display_url
                ),
                CloneTarget::Absent => {
                    sesame_workspace::git::clone_to(endpoint, &target_path, req.depth)?
                }
            }
        }
        WorkspaceKind::WorkspaceRepository => {
            // An existing repository at the namespace directory must be
            // this workspace repository; any other existing directory is
            // initialized around by `clone_workspace_git`.
            if sesame_workspace::git::git_marker(&target_path)?.is_repository_root() {
                sesame_workspace::git::inspect_clone_target(&target_path, endpoint.identity())?;
            }
            let path =
                sesame_workspace::git::clone_workspace_git(endpoint, &target_path, req.org.force)?;
            eprintln!("Peer repos will be cloned as siblings inside this directory.");
            path
        }
        WorkspaceKind::Organization => {
            anyhow::bail!("org-only URL requires --project");
        }
    };
    println!("{}", result_path.display());

    if let Some(profile) = req.profile {
        write_link(process_layout, &result_path, profile)?;
        println!("Linked -> profile \"{profile}\"");
    }
    Ok(())
}

fn clone_project(
    req: &CloneRequest<'_>,
    config: &WorkspaceConfig,
    layout: &WorkspaceLayout,
    host: &GitHost,
    namespace: &NamespacePath,
) -> anyhow::Result<()> {
    setup_org_workspace(layout, config, host, namespace, req.org, req.url)?;

    let options = sesame_workspace::project::ProjectCloneOptions {
        depth: req.depth,
        filters: req.filters.clone(),
        workspace_repo: config.settings.workspace_repo.clone(),
    };
    let mut cloned = 0usize;
    let mut existing = 0usize;
    let mut failed = 0usize;
    let project =
        sesame_workspace::project::clone_project(layout, host, namespace, &options, |result| {
            use sesame_workspace::project::RepoOutcome;
            match &result.outcome {
                RepoOutcome::Cloned(_) => {
                    cloned += 1;
                    eprintln!("  {} {}", "Cloned".green(), result.name);
                }
                RepoOutcome::Exists(_) => {
                    existing += 1;
                    eprintln!("  {} (exists)", result.name.dimmed());
                }
                RepoOutcome::Failed(e) => {
                    failed += 1;
                    eprintln!(
                        "  {} {}: {e}{}",
                        "Failed".red(),
                        result.name,
                        clone_failure_hint(e)
                    );
                }
            }
        })?;
    eprintln!(
        "\nFound {} repositories in {host}/{namespace}, processed {} \
         (workspace repository excluded): {cloned} cloned, {existing} exist, {failed} failed",
        project.listed,
        project.results.len()
    );
    if failed > 0 {
        anyhow::bail!("{failed} repositories failed to clone");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

struct ListRequest<'a> {
    server: Option<&'a str>,
    org: Option<&'a str>,
    profile: Option<&'a TrustProfileName>,
    repo: Option<&'a str>,
    dirty: bool,
    stale: Option<&'a str>,
    columns: Option<&'a str>,
    format: WorkspaceListFormat,
}

type Inspections = HashMap<PathBuf, InspectionResult>;

/// Apply the server, org, profile, and repository filters. Filter values
/// are matched against placement, so they are lowercased.
fn filter_workspaces(workspaces: &mut Vec<DiscoveredWorkspace>, req: &ListRequest<'_>) {
    if let Some(server) = req.server {
        let needle = server.to_ascii_lowercase();
        workspaces.retain(|w| w.coordinate.host().to_string() == needle);
    }
    if let Some(org) = req.org {
        let needle = org.to_ascii_lowercase();
        workspaces.retain(|w| w.coordinate.namespace().root_segment() == needle);
    }
    if let Some(profile) = req.profile {
        workspaces.retain(|w| w.linked_profile.as_deref() == Some(profile.as_ref()));
    }
    if let Some(repo) = req.repo {
        let needle = repo.to_ascii_lowercase();
        workspaces.retain(|w| {
            w.coordinate
                .kind()
                .repository_dir()
                .is_some_and(|name| name.as_str().contains(&needle))
        });
    }
}

/// Apply the filters that need inspection: `--dirty` keeps repositories
/// with uncommitted changes, `--stale` those whose HEAD is older than the
/// threshold (seconds). An uninspected repository matches neither.
fn filter_inspected(
    workspaces: &mut Vec<DiscoveredWorkspace>,
    inspections: &Inspections,
    dirty: bool,
    stale_seconds: Option<u64>,
) -> anyhow::Result<()> {
    if dirty {
        workspaces.retain(|w| {
            inspections
                .get(&w.path)
                .and_then(|i| i.status.value().copied())
                .is_some_and(|s| s == sesame_workspace::RepoStatus::Dirty)
        });
    }
    if let Some(threshold) = stale_seconds {
        let now = unix_now()?;
        workspaces.retain(|w| {
            inspections
                .get(&w.path)
                .and_then(|i| i.head_date.value().copied())
                .is_some_and(|epoch| age_secs(now, epoch) > threshold)
        });
    }
    Ok(())
}

/// Inspect every listed repository (members and workspace repositories).
fn inspect_all(
    workspaces: &[DiscoveredWorkspace],
    request: &sesame_workspace::InspectionRequest,
) -> Inspections {
    let started = std::time::Instant::now();
    let jobs: Vec<sesame_workspace::pool::InspectJob> = workspaces
        .iter()
        .enumerate()
        .map(|(index, ws)| sesame_workspace::pool::InspectJob {
            path: ws.path.clone(),
            request: request.clone(),
            index,
            estimated_cost: sesame_workspace::pool::estimate_cost(&ws.path),
        })
        .collect();
    let workers = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let progress = sesame_workspace::progress::Progress::new();
    let results = sesame_workspace::pool::run_inspections(
        jobs,
        workers,
        &cancel,
        |completed, total, name, elapsed_ms| progress.update(completed, total, name, elapsed_ms),
    );
    progress.finish(results.len());

    let mut inspections = Inspections::new();
    let mut timings: Vec<(&Path, u64)> = Vec::with_capacity(results.len());
    for r in &results {
        let path = &workspaces[r.index].path;
        match &r.result {
            Ok(insp) => {
                inspections.insert(path.clone(), insp.clone());
            }
            Err(e) => tracing::warn!(
                path = %e.path.display(),
                error = %e.message,
                "repo inspection failed"
            ),
        }
        timings.push((path, r.elapsed_ms));
    }
    timings.sort_by_key(|t| std::cmp::Reverse(t.1));
    tracing::info!(
        repos = results.len(),
        total_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        workers,
        "workspace inspection complete"
    );
    for (path, ms) in timings.iter().take(15) {
        tracing::info!(ms, path = %path.display(), "slowest repo");
    }
    inspections
}

fn list(process_layout: &Layout, req: &ListRequest<'_>) -> anyhow::Result<()> {
    let stale_seconds = req
        .stale
        .map(sesame_workspace::parse_stale_duration)
        .transpose()
        .map_err(anyhow::Error::msg)
        .context("invalid --stale")?;
    let active_columns = match req.columns {
        Some(spec) => sesame_workspace::format::parse_columns(spec)
            .map_err(anyhow::Error::msg)
            .context("invalid --columns")?,
        None => sesame_workspace::format::DEFAULT_COLUMNS.to_vec(),
    };

    let (config, layout) = load_layout(process_layout)?;
    let discovery = sesame_workspace::discover::discover_workspaces(&layout, &config)?;
    let mut workspaces = discovery.workspaces;
    filter_workspaces(&mut workspaces, req);

    // JSON uses a full inspection request for a stable schema; the table
    // inspects what its columns and filters read.
    let request = match req.format {
        WorkspaceListFormat::Json => sesame_workspace::InspectionRequest::all(),
        WorkspaceListFormat::Table => {
            let mut request = sesame_workspace::format::inspection_request(&active_columns);
            if req.dirty {
                request.insert(Field::Status);
            }
            if stale_seconds.is_some() {
                request.insert(Field::HeadDate);
            }
            request
        }
    };
    let inspections = if request.is_empty() {
        Inspections::new()
    } else {
        inspect_all(&workspaces, &request)
    };

    filter_inspected(&mut workspaces, &inspections, req.dirty, stale_seconds)?;

    match req.format {
        WorkspaceListFormat::Table => {
            render_table(&workspaces, &inspections, &active_columns, unix_now()?);
            for issue in &discovery.issues {
                eprintln!("{} [{}] {}", "!".red(), issue.error.kind(), issue.error);
            }
            if !discovery.skipped.is_empty() {
                eprintln!(
                    "{} entries not followed (symlinks, unreadable content); \
                     --format json lists them",
                    discovery.skipped.len()
                );
            }
        }
        WorkspaceListFormat::Json => {
            use sesame_workspace::format::{
                IssueRecord, ListDocument, SkippedRecord, WorkspaceRecord,
            };
            let document = ListDocument {
                workspaces: workspaces
                    .iter()
                    .map(|ws| WorkspaceRecord::from_workspace(ws, inspections.get(&ws.path)))
                    .collect(),
                issues: discovery
                    .issues
                    .iter()
                    .map(IssueRecord::from_issue)
                    .collect(),
                skipped: discovery
                    .skipped
                    .iter()
                    .map(SkippedRecord::from_skipped)
                    .collect(),
            };
            println!("{}", serde_json::to_string_pretty(&document)?);
        }
    }

    if !discovery.issues.is_empty() {
        let hint = if discovery.issues.iter().any(|i| i.error.is_normalizable()) {
            "; run `sesame workspace normalize` to review renames"
        } else {
            ""
        };
        anyhow::bail!(
            "{} workspace entries could not be placed{hint}",
            discovery.issues.len()
        );
    }
    Ok(())
}

fn unix_now() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

/// Age in seconds of a Unix timestamp; pre-epoch timestamps count from the epoch.
fn age_secs(now: u64, epoch: i64) -> u64 {
    now.saturating_sub(u64::try_from(epoch).unwrap_or(0))
}

/// Render discovered workspaces as a table grouped by server and namespace.
///
/// A workspace repository is a row of its own namespace group, tagged
/// `(workspace)` in the group header.
fn render_table(
    workspaces: &[DiscoveredWorkspace],
    inspections: &Inspections,
    active_columns: &[ColumnId],
    now: u64,
) {
    if workspaces.is_empty() {
        println!("No workspaces found.");
        return;
    }

    let mut groups: std::collections::BTreeMap<(String, String), Vec<&DiscoveredWorkspace>> =
        std::collections::BTreeMap::new();
    for ws in workspaces {
        let key = (
            ws.coordinate.host().to_string(),
            ws.coordinate.namespace().to_string(),
        );
        groups.entry(key).or_default().push(ws);
    }

    let age_style = |text: String, epoch: Option<i64>| match epoch.map(|e| age_secs(now, e)) {
        Some(s) if s > 90 * 86400 => text.red().to_string(),
        Some(s) if s > 7 * 86400 => text.yellow().to_string(),
        Some(_) => text.green().to_string(),
        None => text.dimmed().to_string(),
    };

    let mut repo_count = 0usize;
    let mut workspace_count = 0usize;
    for ((srv, ns), entries) in &groups {
        let has_ws = entries
            .iter()
            .any(|e| *e.coordinate.kind() == WorkspaceKind::WorkspaceRepository);
        let ws_tag = if has_ws {
            format!(" {}", "(workspace)".dimmed())
        } else {
            String::new()
        };
        println!("{}{ws_tag}", format!("{srv}/{ns}").bold());

        for ws in entries {
            match ws.coordinate.kind() {
                WorkspaceKind::Repository(_) => repo_count += 1,
                WorkspaceKind::WorkspaceRepository | WorkspaceKind::Organization => {
                    workspace_count += 1;
                }
            }
            let insp = inspections.get(&ws.path);
            let line = active_columns
                .iter()
                .map(|&col| {
                    let field = sesame_workspace::format::extract_field(ws, insp, col, now);
                    let text = field.display().to_string();
                    let width = text.len();
                    let styled = match col {
                        ColumnId::Status if text == "clean" => text.green().to_string(),
                        ColumnId::Status if text == "dirty" => text.yellow().to_string(),
                        ColumnId::Commit => text.dimmed().to_string(),
                        ColumnId::LastCommit => {
                            age_style(text, insp.and_then(|i| i.head_date.value().copied()))
                        }
                        ColumnId::UpstreamDate => {
                            age_style(text, insp.and_then(|i| i.upstream_date.value().copied()))
                        }
                        ColumnId::Profile if !text.is_empty() => text.green().to_string(),
                        _ if text == "!" => text.red().to_string(),
                        _ if text == "-" => text.dimmed().to_string(),
                        _ => text,
                    };
                    let pad = col.column().min_width.saturating_sub(width);
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
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    println!(
        "\n{}",
        format!(
            "{server_count} server{}, {org_count} org{}, {repo_count} repo{}, \
             {workspace_count} workspace repo{}",
            plural(server_count),
            plural(org_count),
            plural(repo_count),
            plural(workspace_count),
        )
        .dimmed(),
    );
}

// ---------------------------------------------------------------------------
// status, link, unlink, shell, config
// ---------------------------------------------------------------------------

fn status(process_layout: &Layout, path: Option<PathBuf>, verbose: bool) -> anyhow::Result<()> {
    let path = resolve_workspace_path(path)?;
    let (config, layout) = load_layout(process_layout)?;
    let parsed = sesame_workspace::convention::parse_path(&layout.root, &path)?;

    // Use the single-open inspection API for all git metadata.
    let inspection = Some(
        sesame_workspace::inspection::inspect(&path, &sesame_workspace::InspectionRequest::all())
            .with_context(|| format!("failed to inspect {}", path.display()))?,
    );
    let effective = sesame_workspace::config::resolve_effective_config(&config, &layout, &path)?;
    let in_ws_git = sesame_workspace::convention::is_inside_workspace_git(&path)?;

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
        if *tracking == head_short {
            println!("Tracking:   {tracking} (origin/{branch_str}, up to date)");
        } else {
            println!(
                "Tracking:   {tracking} (origin/{branch_str}, {})",
                "behind".yellow()
            );
        }
    }

    let status_str = match inspection.as_ref().and_then(|i| i.status.value().copied()) {
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
            .map_or_else(|| "(namespace root)".into(), |r| r.as_str().to_string());
        println!(
            "Convention: {} / {} / {} / {} / {}",
            layout.root.display(),
            layout.user,
            parsed.host,
            parsed.namespace,
            repo_display,
        );
        if let Some(du) = inspection.as_ref().and_then(|i| i.disk_usage.value()) {
            println!(
                "Disk:       {} ({} in git)",
                sesame_workspace::format_bytes(du.total_bytes),
                sesame_workspace::format_bytes(du.git_bytes)
            );
        }
    }
    Ok(())
}

fn link(layout: &Layout, profile: &TrustProfileName, path: Option<PathBuf>) -> anyhow::Result<()> {
    let path = resolve_workspace_path(path)?;
    write_link(layout, &path, profile)?;
    println!("Linked {} -> profile \"{profile}\"", path.display());
    Ok(())
}

fn unlink(layout: &Layout, path: Option<PathBuf>) -> anyhow::Result<()> {
    let path = resolve_workspace_path(path)?;
    let physical = sesame_workspace::config::physical_path(&path)?;
    let removed = core_config::edit::remove_workspace_link(layout, &physical)?;
    if removed {
        println!("Unlinked {}", path.display());
    } else {
        println!("No link found for {}", path.display());
    }
    Ok(())
}

/// The arguments of `sesame workspace shell`.
struct ShellRequest {
    profile: Option<ProfileSpecs>,
    inherited_profiles: Option<ProfileSpecs>,
    path: Option<PathBuf>,
    shell: Option<PathBuf>,
    prefix: Option<String>,
    command: Vec<String>,
}

/// The profiles of a workspace shell: `--profile`, else the workspace's
/// linked profile, else the enclosing session's `$SESAME_PROFILES`, else
/// the default profile.
fn shell_profiles(
    flag: Option<ProfileSpecs>,
    linked: Option<&str>,
    inherited: Option<ProfileSpecs>,
) -> anyhow::Result<ProfileSpecs> {
    if let Some(specs) = flag {
        return Ok(specs);
    }
    if let Some(linked) = linked {
        return ProfileSpecs::parse(linked)
            .with_context(|| format!("invalid linked profile '{linked}'"));
    }
    match inherited {
        Some(specs) => Ok(specs),
        None => ProfileSpecs::parse(core_types::DEFAULT_PROFILE_NAME),
    }
}

async fn run_shell(process_layout: &Layout, req: ShellRequest) -> anyhow::Result<ExitCode> {
    let path = resolve_workspace_path(req.path)?;
    let (config, layout) = load_layout(process_layout)?;
    let effective = sesame_workspace::config::resolve_effective_config(&config, &layout, &path)?;

    let specs = shell_profiles(
        req.profile,
        effective.profile.as_deref(),
        req.inherited_profiles,
    )?;
    let secret_prefix = req.prefix.or(effective.secret_prefix);

    let (program, args, interactive) = match req.command.split_first() {
        None => {
            let shell = match req.shell {
                Some(shell) => shell,
                None => process_layout
                    .login_shell()
                    .ok_or_else(|| anyhow::anyhow!("$SHELL is not set; pass --shell <path>"))?
                    .to_path_buf(),
            };
            (shell.into_os_string(), Vec::new(), true)
        }
        Some((program, args)) => (program.into(), args.to_vec(), false),
    };

    let client = connect(process_layout).await?;
    let secrets = fetch_multi_profile_secrets(&client, &specs, secret_prefix.as_deref()).await?;
    client.shutdown().await;

    let mut child = std::process::Command::new(&program);
    child
        .args(&args)
        .current_dir(&path)
        .env("SESAME_PROFILES", specs.to_string())
        .env("SESAME_WORKSPACE", &path)
        .envs(&effective.env);
    if interactive {
        println!(
            "Entering workspace shell (profiles: {specs}, {} secrets injected)",
            secrets.len()
        );
    }
    crate::child::run_with_secrets(child, secrets)
}

fn config_show(process_layout: &Layout, path: Option<PathBuf>) -> anyhow::Result<()> {
    let path = resolve_workspace_path(path)?;
    let (config, layout) = load_layout(process_layout)?;
    let effective = sesame_workspace::config::resolve_effective_config(&config, &layout, &path)?;

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

// ---------------------------------------------------------------------------
// normalize
// ---------------------------------------------------------------------------

fn normalize(process_layout: &Layout, apply: bool) -> anyhow::Result<()> {
    let (_, layout) = load_layout(process_layout)?;
    let report = sesame_workspace::normalize::normalize(&layout, process_layout, apply)?;

    let verb = if apply { "Renamed" } else { "Would rename" };
    for r in &report.renames {
        println!("{verb} {} -> {}", r.from.display(), r.to.display());
    }
    let verb = if apply { "Rewrote" } else { "Would rewrite" };
    for w in &report.worktree_rewrites {
        println!(
            "{verb} {}: {} -> {}",
            w.file.display(),
            w.from.display(),
            w.to.display()
        );
    }
    for c in report
        .link_rewrites
        .iter()
        .chain(&report.launch_rewrites.writable)
    {
        println!(
            "{verb} {} {}: {} -> {}",
            c.file.display(),
            c.key,
            c.from,
            c.to
        );
    }
    for c in &report.launch_rewrites.read_only {
        eprintln!(
            "{} read-only {} {}: {} needs to become {}",
            "!".red(),
            c.file.display(),
            c.key,
            c.from,
            c.to
        );
    }
    for c in &report.collisions {
        eprintln!(
            "{} collision: {} (canonical name held by {})",
            "!".red(),
            c.path.display(),
            c.existing.display()
        );
    }
    for u in &report.unfixable {
        eprintln!("{} {}: {}", "!".red(), u.path.display(), u.reason);
    }
    if !report.skipped.is_empty() {
        eprintln!(
            "{} entries not followed (symlinks, unreadable content)",
            report.skipped.len()
        );
    }
    for failure in &report.failures {
        eprintln!("{} [{}] {failure}", "!".red(), failure.kind());
    }

    if !report.failures.is_empty() {
        anyhow::bail!(
            "normalization stopped with {} failures",
            report.failures.len()
        );
    }
    if !report.is_clean() {
        anyhow::bail!(
            "{} collisions, {} unfixable entries, and {} read-only config values \
             require manual resolution",
            report.collisions.len(),
            report.unfixable.len(),
            report.launch_rewrites.read_only.len()
        );
    }
    if !apply && !report.renames.is_empty() {
        println!(
            "\nRun with --apply to perform {} renames.",
            report.renames.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: OrgFlags = OrgFlags {
        setup: OrgSetup::Configured,
        force: false,
    };

    #[test]
    fn no_workspace_wins_over_raising_flags() {
        assert_eq!(OrgSetup::from_flags(true, true), OrgSetup::Skip);
        assert_eq!(OrgSetup::from_flags(false, true), OrgSetup::Always);
        assert_eq!(OrgSetup::from_flags(false, false), OrgSetup::Configured);
    }

    #[test]
    fn no_workspace_and_never_skip() {
        let flags = OrgFlags {
            setup: OrgSetup::Skip,
            ..NONE
        };
        for state in [OrgState::Absent, OrgState::Repository, OrgState::Directory] {
            assert_eq!(
                org_action(state, WorkspaceAutoMode::Always, flags),
                OrgAction::Skip
            );
            assert_eq!(
                org_action(state, WorkspaceAutoMode::Never, NONE),
                OrgAction::Skip
            );
        }
    }

    #[test]
    fn auto_mode_actions() {
        let mode = WorkspaceAutoMode::Auto;
        assert_eq!(
            org_action(OrgState::Absent, mode, NONE),
            OrgAction::Clone { required: false }
        );
        assert_eq!(
            org_action(OrgState::Repository, mode, NONE),
            OrgAction::ReportDrift
        );
        assert_eq!(org_action(OrgState::Directory, mode, NONE), OrgAction::Tip);
    }

    #[test]
    fn existing_directory_requires_force() {
        let init = OrgFlags {
            setup: OrgSetup::Always,
            ..NONE
        };
        assert_eq!(
            org_action(OrgState::Directory, WorkspaceAutoMode::Auto, init),
            OrgAction::RefuseInit
        );
        assert_eq!(
            org_action(
                OrgState::Directory,
                WorkspaceAutoMode::Auto,
                OrgFlags {
                    force: true,
                    ..init
                }
            ),
            OrgAction::InitAround
        );
        assert_eq!(
            org_action(OrgState::Directory, WorkspaceAutoMode::Always, NONE),
            OrgAction::RefuseInit
        );
    }

    #[test]
    fn explicit_setup_is_required() {
        let init = OrgFlags {
            setup: OrgSetup::Always,
            ..NONE
        };
        assert_eq!(
            org_action(OrgState::Absent, WorkspaceAutoMode::Auto, init),
            OrgAction::Clone { required: true }
        );
        assert_eq!(
            org_action(OrgState::Absent, WorkspaceAutoMode::Always, NONE),
            OrgAction::Clone { required: true }
        );
    }

    #[test]
    fn update_flag_updates_existing_repository() {
        let update = OrgFlags {
            setup: OrgSetup::Always,
            ..NONE
        };
        assert_eq!(
            org_action(OrgState::Repository, WorkspaceAutoMode::Auto, update),
            OrgAction::Update
        );
    }

    #[test]
    fn authentication_failure_hint_is_typed() {
        let auth = WorkspaceError::CloneFailed {
            kind: CloneFailureKind::Authentication,
            message: "x".into(),
        };
        let other = WorkspaceError::CloneFailed {
            kind: CloneFailureKind::Other,
            message: "401 auth".into(),
        };
        assert!(!clone_failure_hint(&auth).is_empty());
        assert!(clone_failure_hint(&other).is_empty());
        assert!(clone_failure_hint(&WorkspaceError::GitError("403 auth".into())).is_empty());
    }

    #[test]
    fn workspace_user_prefers_flag_then_login_user() {
        let with_user = Layout::new(core_layout::Environment {
            login_user: Some("bob".into()),
            ..core_layout::Environment::default()
        });
        assert_eq!(
            workspace_user(&with_user, Some("alice".into()))
                .unwrap()
                .as_str(),
            "alice"
        );
        assert_eq!(workspace_user(&with_user, None).unwrap().as_str(), "bob");
        assert!(workspace_user(&with_user, Some(".hidden".into())).is_err());
        let without = Layout::new(core_layout::Environment::default());
        let err = workspace_user(&without, None).unwrap_err().to_string();
        assert!(err.contains("$USER is not set"), "{err}");
    }

    #[test]
    fn shell_profiles_precedence() {
        let specs = |s: &str| ProfileSpecs::parse(s).unwrap();
        assert_eq!(
            shell_profiles(Some(specs("flag")), Some("linked"), Some(specs("env"))).unwrap(),
            specs("flag")
        );
        assert_eq!(
            shell_profiles(None, Some("linked"), Some(specs("env"))).unwrap(),
            specs("linked")
        );
        assert_eq!(
            shell_profiles(None, None, Some(specs("env"))).unwrap(),
            specs("env")
        );
        assert_eq!(
            shell_profiles(None, None, None).unwrap(),
            specs(core_types::DEFAULT_PROFILE_NAME)
        );
        assert!(shell_profiles(None, Some("../bad"), None).is_err());
    }

    #[test]
    fn age_of_pre_epoch_timestamp_counts_from_epoch() {
        assert_eq!(age_secs(100, -5), 100);
        assert_eq!(age_secs(100, 40), 60);
        assert_eq!(age_secs(10, 40), 0);
    }
}
