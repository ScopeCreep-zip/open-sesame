//! The workspace layout walk: the single traversal of `{root}/{user}`
//! that discovery and normalization both consume.
//!
//! Classification, by each directory's `.git` entry (`git::git_marker`):
//! - A repository root (main or linked worktree) whose direct children
//!   include repository roots is a workspace root. Its children are
//!   walked as workspace content.
//! - Any other repository root is a repository: a leaf, not descended.
//! - A submodule checkout is content of its superproject: never layout.
//! - A directory without `.git` is a namespace directory when, and only
//!   when, something below it is a repository root. Directories that lead
//!   to no repository are not layout at any depth.
//!
//! Every directory is visited once. Symlinks are never followed. Names
//! are kept as `OsString`; consumers decide what a non-UTF-8 name means.
//! Entries the walk does not follow at layout level (symlinks, read
//! failures inside workspace-repository content) are `Skipped`; failures
//! on layout directories are issues.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::WorkspaceError;
use crate::git::{GitMarker, git_marker};

/// A directory that belongs to the workspace layout.
#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub(crate) name: OsString,
    pub(crate) path: PathBuf,
    pub(crate) role: Role,
    /// Layout children, sorted by name. Empty for repository leaves.
    pub(crate) children: Vec<Node>,
}

/// What a layout directory is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Role {
    /// A directory without `.git` that leads to a repository.
    Namespace,
    /// A repository root without member repositories.
    Repository(GitMarker),
    /// A repository root whose direct children include repository roots.
    WorkspaceRoot(GitMarker),
}

impl Node {
    /// The repository marker of a repository or workspace root.
    pub(crate) fn marker(&self) -> Option<&GitMarker> {
        match &self.role {
            Role::Namespace => None,
            Role::Repository(marker) | Role::WorkspaceRoot(marker) => Some(marker),
        }
    }
}

/// An entry the walk did not follow.
#[derive(Debug)]
pub struct Skipped {
    /// The entry.
    pub path: PathBuf,
    /// Why it was not followed.
    pub reason: String,
}

/// A layout directory the walk could not classify or read.
#[derive(Debug)]
pub(crate) struct WalkIssue {
    pub(crate) path: PathBuf,
    pub(crate) error: WorkspaceError,
}

/// The result of walking the layout below a user directory.
#[derive(Debug, Default)]
pub(crate) struct Walk {
    /// Direct children of the user directory that lead to a repository.
    pub(crate) servers: Vec<Node>,
    pub(crate) skipped: Vec<Skipped>,
    pub(crate) issues: Vec<WalkIssue>,
}

/// Walk the layout below `user_dir`.
///
/// # Errors
///
/// Returns `WorkspaceError::Io` when `user_dir` itself cannot be listed.
/// Failures below it are reported in `Walk::issues` and `Walk::skipped`.
pub(crate) fn walk(user_dir: &Path) -> Result<Walk, WorkspaceError> {
    // The user directory is layout by definition; failing to list it is
    // the caller's error, not an issue inside the layout.
    std::fs::read_dir(user_dir)?;
    let mut walker = Walker::default();
    if let Some(children) = walker.children(user_dir, Context::Layout) {
        for (name, path) in children {
            if let Some(node) = walker.visit(path, name, Context::Layout) {
                walker.walk.servers.push(node);
            }
        }
    }
    Ok(walker.walk)
}

/// Whether a directory is reached through layout directories only, or
/// through a workspace repository's working tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    Layout,
    WorkspaceContent,
}

#[derive(Default)]
struct Walker {
    walk: Walk,
}

impl Walker {
    fn visit(&mut self, path: PathBuf, name: OsString, context: Context) -> Option<Node> {
        let marker = match git_marker(&path) {
            Ok(marker) => marker,
            Err(error) => {
                self.fail(path, error, context);
                return None;
            }
        };
        match marker {
            GitMarker::Submodule => {
                if context == Context::Layout {
                    self.skip(
                        path,
                        "submodule checkout outside its superproject's walk".into(),
                    );
                }
                None
            }
            GitMarker::Absent => {
                let children = self.children(&path, context)?;
                let nodes: Vec<Node> = children
                    .into_iter()
                    .filter_map(|(child_name, child)| self.visit(child, child_name, context))
                    .collect();
                (!nodes.is_empty()).then_some(Node {
                    name,
                    path,
                    role: Role::Namespace,
                    children: nodes,
                })
            }
            root @ (GitMarker::Repository | GitMarker::LinkedWorktree { .. }) => {
                // A repository root is layout: failing to list it is an issue.
                let Some(children) = self.children(&path, Context::Layout) else {
                    return Some(Node {
                        name,
                        path,
                        role: Role::Repository(root),
                        children: Vec::new(),
                    });
                };
                if !self.has_member(&path, &children) {
                    return Some(Node {
                        name,
                        path,
                        role: Role::Repository(root),
                        children: Vec::new(),
                    });
                }
                let nodes = children
                    .into_iter()
                    .filter_map(|(child_name, child)| {
                        self.visit(child, child_name, Context::WorkspaceContent)
                    })
                    .collect();
                Some(Node {
                    name,
                    path,
                    role: Role::WorkspaceRoot(root),
                    children: nodes,
                })
            }
        }
    }

    /// Whether any direct child of the repository at `repo` is itself a
    /// repository root. A child whose `.git` cannot be classified is
    /// content of `repo` and is recorded as skipped.
    fn has_member(&mut self, repo: &Path, children: &[(OsString, PathBuf)]) -> bool {
        let mut member = false;
        for (_, child) in children {
            match git_marker(child) {
                Ok(marker) => member |= marker.is_repository_root(),
                Err(error) => self.skip(
                    child.clone(),
                    format!("content of repository {}: {error}", repo.display()),
                ),
            }
        }
        member
    }

    /// Child directories of `dir`, excluding `.git`, sorted by name.
    /// Returns `None` when `dir` cannot be listed.
    fn children(&mut self, dir: &Path, context: Context) -> Option<Vec<(OsString, PathBuf)>> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                self.fail(dir.to_path_buf(), WorkspaceError::io_at(dir, e), context);
                return None;
            }
        };
        let mut children = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    self.fail(dir.to_path_buf(), WorkspaceError::io_at(dir, e), context);
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(e) => {
                    let path = entry.path();
                    let error = WorkspaceError::io_at(&path, e);
                    self.fail(path, error, context);
                    continue;
                }
            };
            if file_type.is_symlink() {
                if context == Context::Layout {
                    self.skip(entry.path(), "symlink not followed".into());
                }
                continue;
            }
            let name = entry.file_name();
            if file_type.is_dir() && name != gix::discover::DOT_GIT_DIR {
                children.push((name, entry.path()));
            }
        }
        children.sort();
        Some(children)
    }

    fn fail(&mut self, path: PathBuf, error: WorkspaceError, context: Context) {
        match context {
            Context::Layout => self.walk.issues.push(WalkIssue { path, error }),
            Context::WorkspaceContent => self.skip(path, error.to_string()),
        }
    }

    fn skip(&mut self, path: PathBuf, reason: String) {
        self.walk.skipped.push(Skipped { path, reason });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::marker::test_repos;

    fn names(nodes: &[Node]) -> Vec<String> {
        nodes
            .iter()
            .map(|n| n.name.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn plain_trees_are_not_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("github.com/org/Notes/Meeting Docs")).unwrap();
        std::fs::create_dir_all(dir.path().join("Archive/Old")).unwrap();
        test_repos::init(&dir.path().join("github.com/org/repo"));
        let walk = walk(dir.path()).unwrap();
        assert_eq!(names(&walk.servers), vec!["github.com"]);
        let org = &walk.servers[0].children[0];
        assert_eq!(names(&org.children), vec!["repo"]);
        assert!(walk.issues.is_empty() && walk.skipped.is_empty());
    }

    #[test]
    fn regular_repository_with_top_level_submodule_is_a_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("github.com/org/app");
        test_repos::init(&repo);
        test_repos::add_submodule_checkout(&repo, "Vendor", &repo.join("Vendor"));
        let walk = walk(dir.path()).unwrap();
        let app = &walk.servers[0].children[0].children[0];
        assert_eq!(app.role, Role::Repository(GitMarker::Repository));
        assert!(app.children.is_empty());
    }

    #[test]
    fn linked_worktree_is_a_repository_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("github.com/org/main");
        let repo = test_repos::init(&main);
        test_repos::add_worktree(&repo, "feature", &dir.path().join("github.com/org/feature"));
        let walk = walk(dir.path()).unwrap();
        let org = &walk.servers[0].children[0];
        assert_eq!(names(&org.children), vec!["feature", "main"]);
        assert!(matches!(
            org.children[0].role,
            Role::Repository(GitMarker::LinkedWorktree { .. })
        ));
    }

    #[test]
    fn workspace_root_content_leading_nowhere_is_not_layout() {
        let dir = tempfile::tempdir().unwrap();
        let org = dir.path().join("github.com/org");
        test_repos::init(&org);
        test_repos::init(&org.join("member"));
        test_repos::init(&org.join("Sub/proj"));
        std::fs::create_dir_all(org.join("node_modules/PyYAML.libs")).unwrap();
        let walk = walk(dir.path()).unwrap();
        let org_node = &walk.servers[0].children[0];
        assert!(matches!(org_node.role, Role::WorkspaceRoot(_)));
        assert_eq!(names(&org_node.children), vec!["Sub", "member"]);
    }

    #[test]
    fn nested_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        let org = dir.path().join("github.com/org");
        test_repos::init(&org);
        test_repos::init(&org.join("team"));
        test_repos::init(&org.join("team/svc"));
        let walk = walk(dir.path()).unwrap();
        let team = &walk.servers[0].children[0].children[0];
        assert!(matches!(team.role, Role::WorkspaceRoot(_)));
        assert_eq!(names(&team.children), vec!["svc"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        test_repos::init(&target.path().join("repo"));
        std::fs::create_dir_all(dir.path().join("github.com/org")).unwrap();
        std::os::unix::fs::symlink(
            target.path().join("repo"),
            dir.path().join("github.com/org/repo"),
        )
        .unwrap();
        let walk = walk(dir.path()).unwrap();
        assert!(walk.servers.is_empty());
        assert_eq!(walk.skipped.len(), 1);
        assert_eq!(walk.skipped[0].path, dir.path().join("github.com/org/repo"));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_workspace_content_is_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let org = dir.path().join("github.com/org");
        test_repos::init(&org);
        test_repos::init(&org.join("member"));
        let locked = org.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = walk(dir.path());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        let walk = result.unwrap();
        // Root bypasses permission checks; the property holds either way:
        // content never becomes an issue.
        assert!(walk.issues.is_empty(), "{:?}", walk.issues);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_names_are_kept() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let server = dir.path().join(std::ffi::OsStr::from_bytes(b"gh\xff"));
        test_repos::init(&server.join("org/repo"));
        let walk = walk(dir.path()).unwrap();
        assert_eq!(walk.servers.len(), 1);
        assert_eq!(walk.servers[0].name.as_bytes(), b"gh\xff");
    }
}
