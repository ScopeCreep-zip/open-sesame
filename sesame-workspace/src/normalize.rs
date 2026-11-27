//! Normalize existing workspace directories to canonical (lowercase) names.
//!
//! The workspace layout is lowercase by construction, but directories
//! created before that invariant existed may not be. `normalize` renames
//! the directories of the layout walk (`crate::layout`, shared with
//! discovery): the user directory, server directories, namespace
//! directories, repository directories, and the paths inside workspace
//! repositories that lead to member repositories. Repository contents,
//! submodule checkouts, and trees that lead to no repository are never
//! touched. For every layout directory whose name is not canonical:
//! - it is renamed when no other directory holds the canonical name (on
//!   case-insensitive filesystems the canonical name aliases the same
//!   directory; that case-only rename goes through a temporary name),
//! - it is a collision when a different directory holds, or an earlier
//!   rename in this pass claims, the canonical name; both are left for
//!   the operator to merge,
//! - it is unfixable when the name cannot be made canonical (non-UTF-8,
//!   non-ASCII, undecodable server directory).
//!
//! Every rename is atomic and never replaces an existing directory
//! (`platform::rename_noreplace`).
//!
//! Stored paths are rewritten through the renames actually performed:
//! linked-worktree link files (`git::rewrite_worktree_links`), profile
//! links (`workspaces.toml` and fragments), and launch-profile
//! `cwd`/`devshell` (`config.toml` layers). Paths in the read-only system
//! policy are reported, never written.
//!
//! Dry run (`apply == false`) computes the same report without touching
//! the filesystem or configuration.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use core_config::edit::{ConfigRewrite, LaunchPathRewrites};
use core_workspace_types::{GitHost, ValidationError};

use crate::WorkspaceError;
use crate::config::WorkspaceLayout;
use crate::git::{GitMarker, WorktreeLink, WorktreeLinkRewrite};
use crate::layout::{Node, Role, Skipped, Walk};

/// A directory rename from a non-canonical to a canonical name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rename {
    pub from: PathBuf,
    pub to: PathBuf,
}

/// A non-canonical directory whose canonical name is held by another directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    pub path: PathBuf,
    pub existing: PathBuf,
}

/// A layout directory that cannot be made canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unfixable {
    pub path: PathBuf,
    pub reason: String,
}

/// The outcome of a normalization pass.
#[derive(Debug, Default)]
pub struct NormalizeReport {
    /// Renames performed (apply) or planned (dry run), in execution order.
    pub renames: Vec<Rename>,
    pub collisions: Vec<Collision>,
    pub unfixable: Vec<Unfixable>,
    /// Linked-worktree link files rewritten (apply) or planned (dry run).
    pub worktree_rewrites: Vec<WorktreeLinkRewrite>,
    /// Profile link keys rewritten (apply) or planned (dry run).
    pub link_rewrites: Vec<ConfigRewrite>,
    /// Launch-profile path values rewritten or planned; `read_only`
    /// entries live in the system policy and need an administrator.
    pub launch_rewrites: LaunchPathRewrites,
    /// Entries the layout walk did not follow.
    pub skipped: Vec<Skipped>,
    /// Failures, in order of occurrence. Everything listed above was
    /// completed before the failure that stopped the pass.
    pub failures: Vec<WorkspaceError>,
}

impl NormalizeReport {
    /// Whether the layout is fully canonical after this pass.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.collisions.is_empty()
            && self.unfixable.is_empty()
            && self.failures.is_empty()
            && self.launch_rewrites.read_only.is_empty()
    }
}

/// Normalize the workspace layout under `{root}/{user}`; stored paths are
/// rewritten in the configuration of `config` (its workspace link files,
/// its configuration layers, and its read-only system policy).
///
/// With `apply`, renames directories, then rewrites stored paths through
/// the renames completed, including when the pass stops early. Without
/// `apply`, only reports.
///
/// # Errors
///
/// Returns `WorkspaceError::Io` only when the root or a user directory
/// cannot be listed. Failures below them, and stored-path rewrite
/// failures, are reported in `NormalizeReport::failures`.
pub fn normalize(
    layout: &WorkspaceLayout,
    config: &core_layout::Layout,
    apply: bool,
) -> Result<NormalizeReport, WorkspaceError> {
    let mut report = NormalizeReport::default();
    let user = layout.user.as_str();

    // The canonical user directory first, then its case variants.
    let mut user_dirs = Vec::new();
    match std::fs::symlink_metadata(layout.user_dir()) {
        Ok(_) => user_dirs.push(user.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    for variant in crate::config::case_variants(&layout.root, user)? {
        if let Some(name) = variant.file_name().and_then(|n| n.to_str()) {
            user_dirs.push(name.to_string());
        }
    }

    // Walk every user directory and read every worktree link before any
    // rename, so link files are read at the paths they were written for.
    let mut walks = Vec::with_capacity(user_dirs.len());
    let mut links = Vec::new();
    let mut link_failures = Vec::new();
    for name in user_dirs {
        let walk = crate::layout::walk(&layout.root.join(&name))?;
        for server in &walk.servers {
            collect_links(server, &mut links, &mut link_failures);
        }
        walks.push((name, walk));
    }
    let abort = apply && !link_failures.is_empty();
    report.failures.extend(link_failures);

    if !abort {
        let mut pass = Pass {
            apply,
            claimed: HashSet::new(),
            report: &mut report,
        };
        if let Err(e) = pass.users(&layout.root, user, walks) {
            report.failures.push(e);
        }
    }

    let renames = report.renames.clone();
    let map_path = |path: &Path| rewrite_through(path, &renames);
    match crate::git::rewrite_worktree_links(&links, &map_path, apply) {
        Ok(rewrites) => report.worktree_rewrites = rewrites,
        Err(e) => report.failures.push(e),
    }
    let map = |stored: &str| {
        let rewritten = rewrite_through(Path::new(stored), &renames);
        (rewritten != Path::new(stored)).then(|| rewritten.display().to_string())
    };
    let config_result =
        core_config::edit::rewrite_workspace_links(config, &map, apply).and_then(|links| {
            report.link_rewrites = links;
            core_config::edit::rewrite_launch_paths(config, &map, apply)
        });
    match config_result {
        Ok(launch) => report.launch_rewrites = launch,
        Err(e) => report.failures.push(WorkspaceError::Config(e)),
    }
    Ok(report)
}

/// Collect the worktree links of every repository in `node`'s subtree.
fn collect_links(node: &Node, links: &mut Vec<WorktreeLink>, failures: &mut Vec<WorkspaceError>) {
    let found = match node.marker() {
        None => Ok(Vec::new()),
        Some(GitMarker::Repository) => WorktreeLink::of_repository(&node.path),
        Some(GitMarker::LinkedWorktree { admin_dir }) => {
            WorktreeLink::from_admin_dir(admin_dir).map(|link| vec![link])
        }
        Some(GitMarker::Absent | GitMarker::Submodule) => {
            unreachable!(
                "layout repositories are repository roots: {}",
                node.path.display()
            )
        }
    };
    match found {
        Ok(found) => links.extend(found),
        Err(e) => failures.push(e),
    }
    for child in &node.children {
        collect_links(child, links, failures);
    }
}

struct Pass<'a> {
    apply: bool,
    /// Canonical paths held or claimed by an earlier placement in this
    /// pass, so a dry run detects collisions between planned renames.
    claimed: HashSet<PathBuf>,
    report: &'a mut NormalizeReport,
}

/// A directory position during the pass.
///
/// `real` is where the directory is on disk now; `planned` is where it
/// is after every rename above it. They are equal under `apply`; in a
/// dry run they diverge below a planned rename, and reports use
/// `planned` so they describe the post-apply layout.
struct Position {
    real: PathBuf,
    planned: PathBuf,
}

impl Pass<'_> {
    /// Place each user directory, then its servers.
    fn users(
        &mut self,
        root: &Path,
        user: &str,
        walks: Vec<(String, Walk)>,
    ) -> Result<(), WorkspaceError> {
        for (name, walk) in walks {
            self.report.skipped.extend(walk.skipped);
            for issue in walk.issues {
                self.unfixable(issue.path, issue.error.to_string());
            }
            if let Some(position) = self.place(root, root, &name, user)? {
                self.servers(&position, &walk.servers)?;
            }
        }
        Ok(())
    }

    fn servers(&mut self, user_dir: &Position, servers: &[Node]) -> Result<(), WorkspaceError> {
        for server in servers {
            let Some(name) = self.utf8_name(server, &user_dir.planned) else {
                continue;
            };
            let canonical = match GitHost::from_dir_name(name) {
                Ok(_) => name.to_string(),
                Err(ValidationError::NonCanonicalCase { canonical, .. }) => canonical,
                Err(other) => {
                    self.unfixable(user_dir.planned.join(name), other.to_string());
                    continue;
                }
            };
            if server.role != Role::Namespace {
                self.unfixable(
                    user_dir.planned.join(name),
                    "git repository directly under the user directory".into(),
                );
                continue;
            }
            if let Some(position) =
                self.place(&user_dir.real, &user_dir.planned, name, &canonical)?
            {
                self.descend(&position, &server.children)?;
            }
        }
        Ok(())
    }

    /// Place every layout child below `parent`, then their children.
    fn descend(&mut self, parent: &Position, children: &[Node]) -> Result<(), WorkspaceError> {
        for node in children {
            let Some(name) = self.utf8_name(node, &parent.planned) else {
                continue;
            };
            if !name.is_ascii() {
                self.unfixable(
                    parent.planned.join(name),
                    format!("non-ASCII directory name: {name}"),
                );
                continue;
            }
            let canonical = name.to_ascii_lowercase();
            if let Some(position) = self.place(&parent.real, &parent.planned, name, &canonical)? {
                self.descend(&position, &node.children)?;
            }
        }
        Ok(())
    }

    /// Bring one directory to its canonical name.
    ///
    /// Returns the directory's position after this step, or `None` when
    /// it is a collision and must not be descended.
    fn place(
        &mut self,
        real_parent: &Path,
        planned_parent: &Path,
        name: &str,
        canonical: &str,
    ) -> Result<Option<Position>, WorkspaceError> {
        let real = real_parent.join(name);
        let planned_to = planned_parent.join(canonical);
        if name == canonical {
            self.claimed.insert(planned_to.clone());
            return Ok(Some(Position {
                real,
                planned: planned_to,
            }));
        }
        let planned_from = planned_parent.join(name);
        if self.claimed.contains(&planned_to) {
            self.report.collisions.push(Collision {
                path: planned_from,
                existing: planned_to,
            });
            return Ok(None);
        }
        let real_target = real_parent.join(canonical);
        let case_only_alias = match std::fs::symlink_metadata(&real_target) {
            Ok(_) => {
                if same_entry(&real, &real_target)? {
                    true
                } else {
                    self.report.collisions.push(Collision {
                        path: planned_from,
                        existing: planned_to,
                    });
                    return Ok(None);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        self.claimed.insert(planned_to.clone());
        let rename = Rename {
            from: planned_from,
            to: planned_to.clone(),
        };
        if !self.apply {
            self.report.renames.push(rename);
            return Ok(Some(Position {
                real,
                planned: planned_to,
            }));
        }
        if case_only_alias {
            let temp = real_parent.join(temp_name());
            rename_case_only(
                &crate::platform::rename_noreplace,
                &real,
                &temp,
                &real_target,
            )?;
        } else {
            crate::platform::rename_noreplace(&real, &real_target)?;
        }
        self.report.renames.push(rename);
        Ok(Some(Position {
            real: real_target,
            planned: planned_to,
        }))
    }

    /// The node's name as UTF-8, or an unfixable entry.
    fn utf8_name<'n>(&mut self, node: &'n Node, planned_parent: &Path) -> Option<&'n str> {
        let name = node.name.to_str();
        if name.is_none() {
            self.unfixable(
                planned_parent.join(&node.name),
                "non-UTF-8 directory name".into(),
            );
        }
        name
    }

    fn unfixable(&mut self, path: PathBuf, reason: String) {
        self.report.unfixable.push(Unfixable { path, reason });
    }
}

/// A temporary sibling name for a case-only rename, unique within this
/// process (pid and a per-process counter); `rename_noreplace` refuses a
/// leftover of the same name from another process instead of replacing it.
fn temp_name() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(".sesame-normalize-{}-{n}", std::process::id())
}

/// Rename `real` to `target` where both name one entry (a case-only
/// rename on a case-insensitive filesystem), through `temp`.
///
/// When the second step fails, `temp` is renamed back to `real` so no
/// directory is left under the temporary name.
fn rename_case_only(
    rename: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
    real: &Path,
    temp: &Path,
    target: &Path,
) -> std::io::Result<()> {
    rename(real, temp)?;
    if let Err(e) = rename(temp, target) {
        return match rename(temp, real) {
            Ok(()) => Err(e),
            Err(restore) => Err(std::io::Error::new(
                e.kind(),
                format!(
                    "rename {} -> {} failed ({e}), and restoring {} -> {} failed: {restore}",
                    temp.display(),
                    target.display(),
                    temp.display(),
                    real.display()
                ),
            )),
        };
    }
    Ok(())
}

/// Whether two paths name the same filesystem entry.
#[cfg(unix)]
fn same_entry(a: &Path, b: &Path) -> Result<bool, WorkspaceError> {
    use std::os::unix::fs::MetadataExt;
    let ma = std::fs::symlink_metadata(a)?;
    let mb = std::fs::symlink_metadata(b)?;
    Ok(ma.dev() == mb.dev() && ma.ino() == mb.ino())
}

/// Whether two paths name the same filesystem entry.
///
/// Without inode identity, both paths are resolved to their on-disk
/// names; case-insensitive aliases resolve to the same path.
#[cfg(not(unix))]
fn same_entry(a: &Path, b: &Path) -> Result<bool, WorkspaceError> {
    Ok(std::fs::canonicalize(a)? == std::fs::canonicalize(b)?)
}

/// Map a path through a sequence of directory renames applied in order.
fn rewrite_through(path: &Path, renames: &[Rename]) -> PathBuf {
    let mut current = path.to_path_buf();
    for rename in renames {
        if let Ok(rest) = current.strip_prefix(&rename.from) {
            // `join` of an empty path appends a trailing separator.
            current = if rest.as_os_str().is_empty() {
                rename.to.clone()
            } else {
                rename.to.join(rest)
            };
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::marker::test_repos;
    use core_workspace_types::WorkspaceUser;

    fn layout(root: &Path) -> WorkspaceLayout {
        WorkspaceLayout {
            root: root.to_path_buf(),
            user: WorkspaceUser::new("user").unwrap(),
        }
    }

    fn git_repo(root: &Path, parts: &[&str]) -> PathBuf {
        let mut path = root.join("user");
        path.extend(parts);
        test_repos::init(&path);
        path
    }

    /// Run normalize with every configuration location under `cfg`.
    fn run(root: &Path, cfg: &Path, apply: bool) -> NormalizeReport {
        normalize(&layout(root), &core_layout::Layout::under(cfg), apply).unwrap()
    }

    fn write_links(cfg: &Path, links: &[(&str, &str)]) {
        let config = core_layout::Layout::under(cfg);
        for (path, profile) in links {
            let profile = core_types::TrustProfileName::try_from(*profile).unwrap();
            core_config::edit::set_workspace_link(&config, Path::new(path), &profile).unwrap();
        }
    }

    fn links(cfg: &Path) -> std::collections::BTreeMap<String, String> {
        let path = core_layout::Layout::under(cfg).workspaces_file().unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        toml::from_str::<core_config::WorkspaceConfig>(&text)
            .unwrap()
            .links
    }

    /// The user configuration file of the layout under `cfg`.
    fn config_file(cfg: &Path) -> PathBuf {
        core_layout::Layout::under(cfg).config_file().unwrap()
    }

    #[test]
    fn dry_run_plans_without_touching() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let repo = git_repo(dir.path(), &["github.com", "NixOS", "NixPkgs"]);
        write_links(cfg.path(), &[(&repo.display().to_string(), "work")]);
        let report = run(dir.path(), cfg.path(), false);
        let server = dir.path().join("user").join("github.com");
        assert_eq!(
            report.renames,
            vec![
                Rename {
                    from: server.join("NixOS"),
                    to: server.join("nixos"),
                },
                Rename {
                    from: server.join("nixos").join("NixPkgs"),
                    to: server.join("nixos").join("nixpkgs"),
                },
            ]
        );
        assert_eq!(report.link_rewrites.len(), 1);
        assert_eq!(report.link_rewrites[0].from, repo.display().to_string());
        assert_eq!(
            report.link_rewrites[0].to,
            server.join("nixos").join("nixpkgs").display().to_string()
        );
        assert!(repo.is_dir());
        assert!(links(cfg.path()).contains_key(&repo.display().to_string()));
        assert!(report.is_clean());
    }

    #[test]
    fn apply_renames_top_down_and_rewrites_stored_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let repo = git_repo(dir.path(), &["github.com", "NixOS", "NixPkgs"]);
        std::fs::create_dir_all(repo.join("Docs")).unwrap();
        write_links(
            cfg.path(),
            &[
                (&repo.display().to_string(), "work"),
                ("/elsewhere/Project", "other"),
            ],
        );
        std::fs::write(
            config_file(cfg.path()),
            format!(
                "[profiles.work.launch_profiles.dev]\ncwd = {:?}\n",
                repo.display().to_string()
            ),
        )
        .unwrap();

        let report = run(dir.path(), cfg.path(), true);
        let canonical = dir.path().join("user/github.com/nixos/nixpkgs");
        assert!(canonical.is_dir());
        // Repository contents are not part of the layout.
        assert!(canonical.join("Docs").is_dir());
        assert_eq!(report.renames.len(), 2);
        let stored = links(cfg.path());
        assert_eq!(
            stored
                .get(&canonical.display().to_string())
                .map(String::as_str),
            Some("work")
        );
        assert_eq!(
            stored.get("/elsewhere/Project").map(String::as_str),
            Some("other")
        );
        assert_eq!(report.link_rewrites.len(), 1);
        assert_eq!(report.launch_rewrites.writable.len(), 1);
        let launch = std::fs::read_to_string(config_file(cfg.path())).unwrap();
        assert!(
            launch.contains(&format!("{:?}", canonical.display().to_string())),
            "{launch}"
        );
    }

    #[test]
    fn apply_rewrites_worktree_links() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let main = git_repo(dir.path(), &["github.com", "ScopeCreep-zip", "open-sesame"]);
        let repo = git2::Repository::open(&main).unwrap();
        test_repos::add_worktree(
            &repo,
            "fix",
            &dir.path()
                .join("user/github.com/ScopeCreep-zip/open-sesame-fix"),
        );
        drop(repo);

        let report = run(dir.path(), cfg.path(), true);
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.worktree_rewrites.len(), 3, "{report:?}");
        let org = dir.path().join("user/github.com/scopecreep-zip");
        let repo = git2::Repository::open(org.join("open-sesame")).unwrap();
        repo.find_worktree("fix").unwrap().validate().unwrap();
        git2::Repository::open(org.join("open-sesame-fix")).unwrap();
    }

    #[test]
    fn user_directory_case_variant_is_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        test_repos::init(&dir.path().join("User/github.com/org/repo"));
        let report = run(dir.path(), cfg.path(), true);
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.renames.len(), 1);
        assert!(dir.path().join("user/github.com/org/repo").is_dir());
    }

    #[test]
    fn collision_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let upper = git_repo(dir.path(), &["github.com", "ContainerCraft", "kargo"]);
        let lower = git_repo(dir.path(), &["github.com", "containercraft", "kargo"]);
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert!(upper.is_dir() && lower.is_dir());
        assert_eq!(report.collisions.len(), 1);
        assert!(!report.is_clean());
        assert!(report.renames.is_empty());
    }

    #[test]
    fn dry_run_detects_collision_between_planned_renames() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["github.com", "NixOS", "a"]);
        git_repo(dir.path(), &["github.com", "NIXOS", "b"]);
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), false);
        assert_eq!(report.renames.len(), 1, "{:?}", report.renames);
        assert_eq!(report.collisions.len(), 1);
    }

    #[test]
    fn submodule_checkout_is_never_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let app = git_repo(dir.path(), &["github.com", "org", "app"]);
        test_repos::add_submodule_checkout(&app, "Vendor", &app.join("Vendor"));
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert!(report.renames.is_empty(), "{:?}", report.renames);
        assert!(app.join("Vendor").is_dir());
    }

    #[test]
    fn plain_trees_are_never_renamed() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["github.com", "org", "repo"]);
        let notes = dir.path().join("user/github.com/org/Notes/Meeting Docs");
        let archive = dir.path().join("user/Archive/Old");
        std::fs::create_dir_all(&notes).unwrap();
        std::fs::create_dir_all(&archive).unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert!(report.renames.is_empty(), "{:?}", report.renames);
        assert!(notes.is_dir() && archive.is_dir());
    }

    #[test]
    fn workspace_root_children_are_normalized() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["github.com", "org"]);
        git_repo(dir.path(), &["github.com", "org", "RepoA"]);
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert_eq!(report.renames.len(), 1);
        assert!(dir.path().join("user/github.com/org/repoa").is_dir());
    }

    #[test]
    fn workspace_root_content_is_not_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let org = git_repo(dir.path(), &["github.com", "org"]);
        git_repo(dir.path(), &["github.com", "org", "repo-a"]);
        let content = [
            org.join("Docs").join("Guide"),
            org.join("node_modules").join("PyYAML.libs"),
            org.join("tests").join("Arbitrary"),
        ];
        for path in &content {
            std::fs::create_dir_all(path).unwrap();
        }
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert!(report.renames.is_empty(), "{:?}", report.renames);
        assert!(report.is_clean());
        for path in &content {
            assert!(path.is_dir(), "{}", path.display());
        }
    }

    #[test]
    fn workspace_root_path_to_member_is_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let org = git_repo(dir.path(), &["github.com", "org"]);
        git_repo(dir.path(), &["github.com", "org", "member"]);
        git_repo(dir.path(), &["github.com", "org", "Sub", "Proj"]);
        std::fs::create_dir_all(org.join("Sub").join("Notes")).unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert_eq!(report.renames.len(), 2, "{:?}", report.renames);
        assert!(org.join("sub").join("proj").join(".git").is_dir());
        // `Notes` does not lead to a member repository: workspace content.
        assert!(org.join("sub").join("Notes").is_dir());
    }

    #[test]
    fn nested_workspace_root_is_normalized_like_discovery_places_it() {
        let dir = tempfile::tempdir().unwrap();
        let org = git_repo(dir.path(), &["github.com", "org"]);
        git_repo(dir.path(), &["github.com", "org", "Team"]);
        git_repo(dir.path(), &["github.com", "org", "Team", "Svc"]);
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert_eq!(report.renames.len(), 2, "{:?}", report.renames);
        assert!(org.join("team").join("svc").is_dir());
        let (l, c) = (layout(dir.path()), core_config::WorkspaceConfig::default());
        let d = crate::discover::discover_workspaces(&l, &c).unwrap();
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(d.workspaces.len(), 3);
    }

    #[test]
    fn server_directory_normalized_and_junk_reported() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["GitHub.com", "org", "repo"]);
        test_repos::init(&dir.path().join("user/not:a:host/org/repo"));
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert!(dir.path().join("user/github.com/org/repo").is_dir());
        assert_eq!(report.unfixable.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_server_is_unfixable_without_aborting() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        test_repos::init(
            &dir.path()
                .join("user")
                .join(std::ffi::OsStr::from_bytes(b"gh\xff"))
                .join("org/repo"),
        );
        git_repo(dir.path(), &["github.com", "Org", "repo"]);
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.unfixable.len(), 1);
        assert!(dir.path().join("user/github.com/org/repo").is_dir());
    }

    #[test]
    fn canonical_layout_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["github.com", "org", "repo"]);
        let cfg = tempfile::tempdir().unwrap();
        let report = run(dir.path(), cfg.path(), true);
        assert!(report.renames.is_empty() && report.is_clean());
    }

    #[test]
    fn case_only_rename_goes_through_temp() {
        let calls = std::cell::RefCell::new(Vec::new());
        let rename = |from: &Path, to: &Path| {
            calls
                .borrow_mut()
                .push((from.to_path_buf(), to.to_path_buf()));
            Ok(())
        };
        rename_case_only(
            &rename,
            Path::new("/w/NixOS"),
            Path::new("/w/.tmp"),
            Path::new("/w/nixos"),
        )
        .unwrap();
        assert_eq!(
            calls.into_inner(),
            vec![
                (PathBuf::from("/w/NixOS"), PathBuf::from("/w/.tmp")),
                (PathBuf::from("/w/.tmp"), PathBuf::from("/w/nixos")),
            ]
        );
    }

    #[test]
    fn case_only_rename_restores_on_failure() {
        let calls = std::cell::RefCell::new(Vec::new());
        let rename = |from: &Path, to: &Path| {
            calls
                .borrow_mut()
                .push((from.to_path_buf(), to.to_path_buf()));
            if to == Path::new("/w/nixos") {
                Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
            } else {
                Ok(())
            }
        };
        let err = rename_case_only(
            &rename,
            Path::new("/w/NixOS"),
            Path::new("/w/.tmp"),
            Path::new("/w/nixos"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            calls.into_inner().last(),
            Some(&(PathBuf::from("/w/.tmp"), PathBuf::from("/w/NixOS")))
        );
    }
}
