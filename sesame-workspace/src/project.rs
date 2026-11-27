//! Project-wide clone: every repository of a forge organization.
//!
//! Repositories are enumerated through the forge API. Each repository's
//! remote identity comes from the forge's clone URL, parsed once when
//! the listing is mapped (`forge::RepoInfo`); its placement is derived
//! from that identity; its path is verified against the layout for case
//! conflicts, and an existing directory against the identity, before
//! anything is written.

use std::path::PathBuf;

use core_workspace_types::{
    GitHost, NamespacePath, RemoteEndpoint, RepoDir, RepositoryName, WorkspaceCoordinate,
};

use crate::WorkspaceError;
use crate::config::WorkspaceLayout;
use crate::forge::{ListOptions, RepoInfo, forge_for_server};
use crate::git::CloneTarget;

/// Options for a project-wide clone.
#[derive(Debug, Clone)]
pub struct ProjectCloneOptions {
    /// Shallow clone depth.
    pub depth: Option<u32>,
    /// Which repositories the forge listing includes.
    pub filters: ListOptions,
    /// The configured org-level workspace repository name; it is placed
    /// at the namespace directory and not cloned as a member.
    pub workspace_repo: RepositoryName,
}

/// The outcome for one repository of a project-wide clone.
#[derive(Debug)]
pub enum RepoOutcome {
    /// Cloned to the path.
    Cloned(PathBuf),
    /// The same repository (exact remote identity) already exists at the path.
    Exists(PathBuf),
    /// The repository could not be cloned.
    Failed(WorkspaceError),
}

/// One repository's result.
#[derive(Debug)]
pub struct RepoResult {
    /// The repository name as the forge spells it.
    pub name: String,
    pub outcome: RepoOutcome,
}

/// The result of a project-wide clone.
#[derive(Debug)]
pub struct ProjectClone {
    /// Repositories the forge listed after the fork/archive filters,
    /// including the workspace repository.
    pub listed: usize,
    /// One result per processed repository; the workspace repository is
    /// not processed as a member.
    pub results: Vec<RepoResult>,
}

/// Clone every repository of a forge organization into the layout.
///
/// `on_result` is called once per repository as it completes, in forge
/// listing order, so callers can render progress.
///
/// # Errors
///
/// Returns `WorkspaceError::PlatformNotSupported` when no forge API is
/// implemented for the host, and any error from the forge listing.
/// Per-repository failures are reported through `RepoOutcome::Failed`.
pub fn clone_project(
    layout: &WorkspaceLayout,
    host: &GitHost,
    namespace: &NamespacePath,
    options: &ProjectCloneOptions,
    mut on_result: impl FnMut(&RepoResult),
) -> Result<ProjectClone, WorkspaceError> {
    let forge = forge_for_server(&host.as_str())?.ok_or_else(|| {
        WorkspaceError::PlatformNotSupported(format!(
            "forge API not supported for server {host} (supported: github.com)"
        ))
    })?;
    let repos = forge.list_org_repos(&namespace.to_string(), &options.filters)?;
    let listed = repos.len();
    let workspace_dir = RepoDir::from_remote(&options.workspace_repo);

    let mut results = Vec::with_capacity(listed);
    for info in repos {
        if is_workspace_repository(&info, &workspace_dir) {
            continue;
        }
        let outcome = match clone_one(layout, &info, options.depth) {
            Ok(outcome) => outcome,
            Err(e) => RepoOutcome::Failed(e),
        };
        let result = RepoResult {
            name: info.identity.repository().to_string(),
            outcome,
        };
        on_result(&result);
        results.push(result);
    }
    Ok(ProjectClone { listed, results })
}

/// Whether a listed repository is the org-level workspace repository,
/// compared by placement as `convention::parse_clone_input` classifies.
fn is_workspace_repository(info: &RepoInfo, workspace_dir: &RepoDir) -> bool {
    RepoDir::from_remote(info.identity.repository()) == *workspace_dir
}

/// Clone one listed member repository.
fn clone_one(
    layout: &WorkspaceLayout,
    info: &RepoInfo,
    depth: Option<u32>,
) -> Result<RepoOutcome, WorkspaceError> {
    let path = layout.checked_path(&WorkspaceCoordinate::from_remote_repository(&info.identity))?;
    match crate::git::inspect_clone_target(&path, &info.identity)? {
        CloneTarget::SameRepository => Ok(RepoOutcome::Exists(path)),
        CloneTarget::Absent => {
            let endpoint = RemoteEndpoint::https(info.identity.clone());
            Ok(RepoOutcome::Cloned(crate::git::clone_to(
                &endpoint, &path, depth,
            )?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::marker::test_repos;

    fn info(url: &str) -> RepoInfo {
        RepoInfo {
            identity: RepoInfo::identity_from_clone_url(url).unwrap(),
            html_url: url.into(),
            default_branch: "main".into(),
            fork: false,
            archived: false,
            description: None,
        }
    }

    fn layout(root: &std::path::Path) -> WorkspaceLayout {
        WorkspaceLayout {
            root: root.to_path_buf(),
            user: core_workspace_types::WorkspaceUser::new("user").unwrap(),
        }
    }

    #[test]
    fn workspace_repository_is_not_a_member() {
        let ws = RepoDir::from_remote(&RepositoryName::new("workspace").unwrap());
        assert!(is_workspace_repository(
            &info("https://github.com/org/Workspace.git"),
            &ws
        ));
        assert!(!is_workspace_repository(
            &info("https://github.com/org/workspaces.git"),
            &ws
        ));
    }

    #[test]
    fn existing_same_repository_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("user/github.com/org/repo");
        test_repos::init(&repo)
            .remote("origin", "https://github.com/Org/Repo.git")
            .unwrap();
        let outcome = clone_one(
            &layout(dir.path()),
            &info("https://github.com/Org/Repo.git"),
            None,
        )
        .unwrap();
        assert!(matches!(outcome, RepoOutcome::Exists(p) if p == repo));
    }

    #[test]
    fn existing_case_variant_repository_is_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        test_repos::init(&dir.path().join("user/github.com/org/repo"))
            .remote("origin", "https://github.com/org/repo.git")
            .unwrap();
        assert!(matches!(
            clone_one(
                &layout(dir.path()),
                &info("https://github.com/Org/Repo.git"),
                None
            ),
            Err(WorkspaceError::PlacementConflict { .. })
        ));
    }

    #[test]
    fn existing_workspace_content_is_refused_before_git_runs() {
        let dir = tempfile::tempdir().unwrap();
        let org = dir.path().join("user/github.com/sesameos");
        test_repos::init(&org);
        std::fs::create_dir_all(org.join(".github").join("workflows")).unwrap();
        assert!(matches!(
            clone_one(
                &layout(dir.path()),
                &info("https://github.com/SesameOS/.github.git"),
                None
            ),
            Err(WorkspaceError::PathValidation(_))
        ));
    }

    #[test]
    fn case_conflict_blocks_clone() {
        let dir = tempfile::tempdir().unwrap();
        test_repos::init(&dir.path().join("user/github.com/Org/repo"));
        assert!(matches!(
            clone_one(
                &layout(dir.path()),
                &info("https://github.com/Org/repo.git"),
                None
            ),
            Err(WorkspaceError::CaseConflict { .. })
        ));
    }
}
