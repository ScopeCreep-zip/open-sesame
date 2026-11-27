//! Discover the git repositories of the workspace layout.
//!
//! Discovery consumes the layout walk (`crate::layout`) and parses every
//! layout directory name strictly into placement types. It does not read
//! Git metadata beyond classifying `.git` entries; use the inspection
//! module for branch, commit, remote, and status.
//!
//! Every layout entry that cannot be placed (non-canonical case, non-UTF-8
//! name, undecodable server directory, unreadable layout directory, a
//! case variant of the user directory) is a `DiscoveryIssue`. Entries the
//! walk did not follow are listed in `Discovery::skipped`.

use std::path::{Path, PathBuf};

use core_config::WorkspaceConfig;
use core_workspace_types::{
    GitHost, NamespaceDir, RepoDir, ValidationError, WorkspaceCoordinate, WorkspaceKind,
};

use crate::WorkspaceError;
use crate::config::WorkspaceLayout;
use crate::layout::{Node, Role, Skipped};

/// A discovered workspace entry containing only filesystem facts.
#[derive(Debug, Clone)]
pub struct DiscoveredWorkspace {
    /// Filesystem path to the repository or workspace root.
    pub path: PathBuf,
    /// Placement parsed from the filesystem path.
    pub coordinate: WorkspaceCoordinate,
    /// Linked profile from workspace config link table, if any.
    pub linked_profile: Option<String>,
}

/// A layout entry that discovery could not place.
#[derive(Debug)]
pub struct DiscoveryIssue {
    /// The offending path.
    pub path: PathBuf,
    /// Why it could not be placed. Its message names `path` (or the
    /// `.git` entry inside it), so text output prints the error alone.
    pub error: WorkspaceError,
}

/// The result of a discovery walk.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Placed workspace entries, sorted by path.
    pub workspaces: Vec<DiscoveredWorkspace>,
    /// Layout entries that could not be placed, sorted by path.
    pub issues: Vec<DiscoveryIssue>,
    /// Entries the walk did not follow, sorted by path.
    pub skipped: Vec<Skipped>,
}

/// Discover all repositories below `{root}/{user}`.
///
/// # Errors
///
/// Returns `WorkspaceError::Io` when the root or the user directory
/// exists but cannot be listed.
pub fn discover_workspaces(
    layout: &WorkspaceLayout,
    config: &WorkspaceConfig,
) -> Result<Discovery, WorkspaceError> {
    let mut discovery = Discovery::default();

    for variant in crate::config::case_variants(&layout.root, layout.user.as_str())? {
        // `case_variants` yields UTF-8-named directory entries only.
        let value = variant
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                WorkspaceError::PathValidation(format!(
                    "{}: case variant without a UTF-8 name",
                    variant.display()
                ))
            })?
            .to_string();
        discovery.issue(
            &variant,
            WorkspaceError::NonCanonical {
                path: variant.clone(),
                source: ValidationError::NonCanonicalCase {
                    kind: "workspace user",
                    value,
                    canonical: layout.user.as_str().to_string(),
                },
            },
        );
    }

    let user_dir = layout.user_dir();
    match std::fs::symlink_metadata(&user_dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            discovery.sort();
            return Ok(discovery);
        }
        Err(e) => return Err(e.into()),
    }

    let walk = crate::layout::walk(&user_dir)?;
    discovery.skipped = walk.skipped;
    for issue in walk.issues {
        discovery.issue(&issue.path, issue.error);
    }

    for server in &walk.servers {
        let Some(name) = discovery.utf8_name(server) else {
            continue;
        };
        let host = match GitHost::from_dir_name(name) {
            Ok(host) => host,
            Err(source) => {
                discovery.issue(
                    &server.path,
                    WorkspaceError::placement(&server.path, source),
                );
                continue;
            }
        };
        if server.role != Role::Namespace {
            discovery.issue(
                &server.path,
                WorkspaceError::PathValidation(format!(
                    "{}: git repository directly under the user directory",
                    server.path.display()
                )),
            );
            continue;
        }
        let mut placer = Placer {
            host: &host,
            config,
            discovery: &mut discovery,
        };
        for child in &server.children {
            placer.place(child, &[]);
        }
    }

    discovery.sort();
    Ok(discovery)
}

impl Discovery {
    fn issue(&mut self, path: &Path, error: WorkspaceError) {
        self.issues.push(DiscoveryIssue {
            path: path.to_path_buf(),
            error,
        });
    }

    /// The node's name as UTF-8, or an issue.
    fn utf8_name<'n>(&mut self, node: &'n Node) -> Option<&'n str> {
        let name = node.name.to_str();
        if name.is_none() {
            self.issue(
                &node.path,
                WorkspaceError::PathValidation(format!(
                    "non-UTF-8 directory name: {}",
                    node.path.display()
                )),
            );
        }
        name
    }

    fn sort(&mut self) {
        self.workspaces.sort_by(|a, b| a.path.cmp(&b.path));
        self.issues.sort_by(|a, b| a.path.cmp(&b.path));
        self.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    }
}

/// Places the layout nodes below one server directory.
struct Placer<'a> {
    host: &'a GitHost,
    config: &'a WorkspaceConfig,
    discovery: &'a mut Discovery,
}

impl Placer<'_> {
    /// Place `node`, whose parent's namespace segments are `parent_ns`.
    ///
    /// A namespace directory and a workspace root extend the namespace
    /// with their own name; a repository is named by its directory.
    fn place(&mut self, node: &Node, parent_ns: &[String]) {
        let Some(name) = self.discovery.utf8_name(node) else {
            return;
        };
        match node.role {
            Role::Namespace => {
                let ns = extend(parent_ns, name);
                for child in &node.children {
                    self.place(child, &ns);
                }
            }
            Role::Repository(_) => {
                if parent_ns.is_empty() {
                    self.discovery.issue(
                        &node.path,
                        WorkspaceError::PathValidation(format!(
                            "{}: git repository directly under a server directory has no \
                             namespace",
                            node.path.display()
                        )),
                    );
                } else {
                    self.record(&node.path, parent_ns, Some(name));
                }
            }
            Role::WorkspaceRoot(_) => {
                let ns = extend(parent_ns, name);
                self.record(&node.path, &ns, None);
                for child in &node.children {
                    self.place(child, &ns);
                }
            }
        }
    }

    /// Record a placed entry: the workspace repository when `repo` is
    /// `None`, otherwise a regular repository named `repo`.
    fn record(&mut self, path: &Path, ns_segments: &[String], repo: Option<&str>) {
        let namespace = match NamespaceDir::parse(ns_segments) {
            Ok(namespace) => namespace,
            Err(source) => {
                self.discovery
                    .issue(path, WorkspaceError::placement(path, source));
                return;
            }
        };
        let kind = match repo {
            None => WorkspaceKind::WorkspaceRepository,
            Some(name) => match RepoDir::parse(name) {
                Ok(dir) => WorkspaceKind::Repository(dir),
                Err(source) => {
                    self.discovery
                        .issue(path, WorkspaceError::placement(path, source));
                    return;
                }
            },
        };
        let linked_profile = match crate::config::resolve_workspace_profile(self.config, path) {
            Ok(profile) => profile,
            Err(e) => {
                self.discovery.issue(path, e);
                return;
            }
        };
        self.discovery.workspaces.push(DiscoveredWorkspace {
            path: path.to_path_buf(),
            coordinate: WorkspaceCoordinate::new(self.host.clone(), namespace, kind),
            linked_profile,
        });
    }
}

fn extend(segments: &[String], name: &str) -> Vec<String> {
    let mut out = segments.to_vec();
    out.push(name.to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::marker::test_repos;
    use core_workspace_types::WorkspaceUser;

    fn setup(root: &Path) -> (WorkspaceLayout, WorkspaceConfig) {
        (
            WorkspaceLayout {
                root: root.to_path_buf(),
                user: WorkspaceUser::new("user").unwrap(),
            },
            WorkspaceConfig::default(),
        )
    }

    fn git_repo(root: &Path, parts: &[&str]) -> PathBuf {
        let mut path = root.join("user");
        path.extend(parts);
        test_repos::init(&path);
        path
    }

    fn discover(root: &Path) -> Discovery {
        let (layout, config) = setup(root);
        discover_workspaces(&layout, &config).unwrap()
    }

    fn repo_name(ws: &DiscoveredWorkspace) -> Option<&str> {
        ws.coordinate.kind().repository_dir().map(RepoDir::as_str)
    }

    fn paths(d: &Discovery) -> Vec<&Path> {
        d.workspaces.iter().map(|w| w.path.as_path()).collect()
    }

    #[test]
    fn discovers_flat_repo() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git_repo(dir.path(), &["github.com", "org", "repo"]);
        let d = discover(dir.path());
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(paths(&d), vec![repo.as_path()]);
        assert_eq!(d.workspaces[0].coordinate.namespace().root_segment(), "org");
        assert_eq!(repo_name(&d.workspaces[0]), Some("repo"));
        assert!(d.workspaces[0].linked_profile.is_none());
    }

    #[test]
    fn discovers_nested_namespace_repo() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["gitlab.com", "group", "subgroup", "project"]);
        let d = discover(dir.path());
        assert_eq!(d.workspaces.len(), 1);
        assert_eq!(
            d.workspaces[0].coordinate.namespace().to_string(),
            "group/subgroup"
        );
        assert_eq!(repo_name(&d.workspaces[0]), Some("project"));
    }

    #[test]
    fn discovers_workspace_root_with_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let org = git_repo(dir.path(), &["github.com", "org"]);
        git_repo(dir.path(), &["github.com", "org", "repo-a"]);
        git_repo(dir.path(), &["github.com", "org", "repo-b"]);

        let d = discover(dir.path());
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(d.workspaces.len(), 3);
        let ws_root = d.workspaces.iter().find(|w| w.path == org).unwrap();
        assert_eq!(
            ws_root.coordinate.kind(),
            &WorkspaceKind::WorkspaceRepository
        );
        for name in ["repo-a", "repo-b"] {
            let repo = d
                .workspaces
                .iter()
                .find(|w| w.path == org.join(name))
                .unwrap();
            assert_eq!(repo_name(repo), Some(name));
            assert_eq!(repo.coordinate.namespace().to_string(), "org");
        }
    }

    #[test]
    fn regular_repository_with_submodule_stays_regular() {
        let dir = tempfile::tempdir().unwrap();
        let app = git_repo(dir.path(), &["github.com", "org", "app"]);
        test_repos::add_submodule_checkout(&app, "Vendor", &app.join("Vendor"));
        let d = discover(dir.path());
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(paths(&d), vec![app.as_path()]);
        assert_eq!(repo_name(&d.workspaces[0]), Some("app"));
    }

    #[test]
    fn linked_worktree_is_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let main = git_repo(dir.path(), &["github.com", "org", "main"]);
        let repo = git2::Repository::open(&main).unwrap();
        let wt = dir.path().join("user/github.com/org/feature");
        test_repos::add_worktree(&repo, "feature", &wt);
        let d = discover(dir.path());
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(paths(&d), vec![wt.as_path(), main.as_path()]);
    }

    #[test]
    fn nested_workspace_root_is_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let org = git_repo(dir.path(), &["github.com", "org"]);
        git_repo(dir.path(), &["github.com", "org", "team"]);
        let svc = git_repo(dir.path(), &["github.com", "org", "team", "svc"]);
        let d = discover(dir.path());
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        let team = d
            .workspaces
            .iter()
            .find(|w| w.path == org.join("team"))
            .unwrap();
        assert_eq!(team.coordinate.kind(), &WorkspaceKind::WorkspaceRepository);
        assert_eq!(team.coordinate.namespace().to_string(), "org/team");
        let svc = d.workspaces.iter().find(|w| w.path == svc).unwrap();
        assert_eq!(svc.coordinate.namespace().to_string(), "org/team");
    }

    #[test]
    fn discovers_leading_dot_repo_standalone() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git_repo(dir.path(), &["github.com", "sesameos", ".github"]);
        let d = discover(dir.path());
        assert_eq!(paths(&d), vec![repo.as_path()]);
        assert_eq!(repo_name(&d.workspaces[0]), Some(".github"));
    }

    #[test]
    fn discovers_leading_dot_repo_in_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        let org = git_repo(dir.path(), &["github.com", "sesameos"]);
        git_repo(dir.path(), &["github.com", "sesameos", ".github"]);
        git_repo(dir.path(), &["github.com", "sesameos", "repo-a"]);
        let d = discover(dir.path());
        assert_eq!(d.workspaces.len(), 3);
        let dot = d
            .workspaces
            .iter()
            .find(|w| w.path == org.join(".github"))
            .unwrap();
        assert_eq!(repo_name(dot), Some(".github"));
        assert_eq!(dot.coordinate.namespace().to_string(), "sesameos");
    }

    #[test]
    fn workspace_root_content_is_not_layout() {
        let dir = tempfile::tempdir().unwrap();
        let org = git_repo(dir.path(), &["github.com", "org"]);
        git_repo(dir.path(), &["github.com", "org", "member"]);
        git_repo(dir.path(), &["github.com", "org", "Sub", "proj"]);
        std::fs::create_dir_all(org.join("node_modules").join("PyYAML.libs")).unwrap();
        // A repository vendored inside workspace content under a
        // non-canonical directory leads to a repository root, so the path
        // to it is layout and its non-canonical name is reported.
        test_repos::init(&org.join("Vendor").join("lib"));

        let d = discover(dir.path());
        assert_eq!(paths(&d), vec![org.as_path(), org.join("member").as_path()]);
        let issue_paths: Vec<PathBuf> = d.issues.iter().map(|i| i.path.clone()).collect();
        assert_eq!(
            issue_paths,
            vec![org.join("Sub").join("proj"), org.join("Vendor").join("lib")]
        );
    }

    #[test]
    fn plain_trees_are_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["github.com", "org", "repo"]);
        std::fs::create_dir_all(dir.path().join("user/github.com/org/Notes/Meeting Docs")).unwrap();
        std::fs::create_dir_all(dir.path().join("user/Archive")).unwrap();
        let d = discover(dir.path());
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(d.workspaces.len(), 1);
    }

    #[test]
    fn reports_non_canonical_directories() {
        let dir = tempfile::tempdir().unwrap();
        let bad_ns = git_repo(dir.path(), &["github.com", "NixOS", "nixpkgs"]);
        let bad_repo = git_repo(dir.path(), &["github.com", "org", "MyRepo"]);
        let good = git_repo(dir.path(), &["github.com", "org", "good"]);
        let bad_host = dir.path().join("user").join("GitHub.com");
        test_repos::init(&bad_host.join("org").join("repo"));

        let d = discover(dir.path());
        assert_eq!(paths(&d), vec![good.as_path()]);
        let issue_paths: Vec<&Path> = d.issues.iter().map(|i| i.path.as_path()).collect();
        assert_eq!(
            issue_paths,
            vec![bad_host.as_path(), bad_ns.as_path(), bad_repo.as_path()]
        );
        assert!(
            d.issues
                .iter()
                .all(|i| matches!(i.error, WorkspaceError::NonCanonical { .. }))
        );
    }

    #[test]
    fn reports_user_directory_case_variant() {
        let dir = tempfile::tempdir().unwrap();
        let variant = dir.path().join("User");
        test_repos::init(&variant.join("github.com/org/repo"));
        let d = discover(dir.path());
        assert!(d.workspaces.is_empty());
        assert_eq!(d.issues.len(), 1);
        assert_eq!(d.issues[0].path, variant);
        assert!(matches!(
            d.issues[0].error,
            WorkspaceError::NonCanonical { .. }
        ));
    }

    #[test]
    fn reports_repository_without_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let bad = git_repo(dir.path(), &["github.com", "repo"]);
        let d = discover(dir.path());
        assert!(d.workspaces.is_empty());
        assert_eq!(d.issues.len(), 1);
        assert_eq!(d.issues[0].path, bad);
    }

    #[test]
    fn reports_undecodable_server_directory_leading_to_a_repository() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("user").join("not:a:host");
        test_repos::init(&junk.join("org").join("repo"));
        let d = discover(dir.path());
        assert_eq!(d.issues.len(), 1);
        assert_eq!(d.issues[0].path, junk);
    }

    #[cfg(unix)]
    #[test]
    fn reports_non_utf8_server_without_aborting() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let bad = dir
            .path()
            .join("user")
            .join(std::ffi::OsStr::from_bytes(b"gh\xff"));
        test_repos::init(&bad.join("org/repo"));
        let good = git_repo(dir.path(), &["github.com", "org", "repo"]);
        let d = discover(dir.path());
        assert_eq!(paths(&d), vec![good.as_path()]);
        assert_eq!(d.issues.len(), 1);
        assert_eq!(d.issues[0].path, bad);
    }

    #[test]
    fn skips_non_git_dirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("user/github.com/org/not-a-repo")).unwrap();
        let d = discover(dir.path());
        assert!(d.workspaces.is_empty());
        assert!(d.issues.is_empty());
    }

    #[test]
    fn missing_user_dir_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let d = discover(dir.path());
        assert!(d.workspaces.is_empty());
        assert!(d.issues.is_empty());
    }

    #[test]
    fn deeply_nested_namespace() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["gitlab.com", "a", "b", "c", "d", "project"]);
        let d = discover(dir.path());
        assert_eq!(d.workspaces.len(), 1);
        assert_eq!(
            d.workspaces[0].coordinate.namespace().to_string(),
            "a/b/c/d"
        );
        assert_eq!(repo_name(&d.workspaces[0]), Some("project"));
    }

    #[test]
    fn ipv6_server_directory() {
        let dir = tempfile::tempdir().unwrap();
        git_repo(dir.path(), &["_ipv6_--1", "org", "repo"]);
        let d = discover(dir.path());
        assert_eq!(d.workspaces.len(), 1);
        assert!(matches!(
            d.workspaces[0].coordinate.host(),
            GitHost::Ipv6(_)
        ));
    }

    #[test]
    fn linked_profile_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git_repo(dir.path(), &["github.com", "org", "repo"]);
        let (layout, mut config) = setup(dir.path());
        config.links.insert(
            crate::config::physical_path(&repo)
                .unwrap()
                .display()
                .to_string(),
            "work".into(),
        );
        let d = discover_workspaces(&layout, &config).unwrap();
        assert_eq!(d.workspaces[0].linked_profile.as_deref(), Some("work"));
    }
}
