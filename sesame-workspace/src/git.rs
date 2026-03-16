//! Git operations via `std::process::Command`.
//!
//! **SECURITY CRITICAL:** All commands use explicit `.arg()` calls.
//! NEVER use `format!()` to build command strings.
//! NEVER use shell interpolation.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{CloneTarget, WorkspaceError};

/// Clone a repository to its canonical path.
///
/// For [`CloneTarget::WorkspaceGit`], handles the special case where the org
/// directory may already exist with sibling repos.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the git command fails.
pub fn clone_repo(
    url: &str,
    target: &CloneTarget,
    depth: Option<u32>,
) -> Result<PathBuf, WorkspaceError> {
    match target {
        CloneTarget::Regular(path) => {
            if path.exists() {
                return Err(WorkspaceError::GitError(format!(
                    "target directory already exists: {}",
                    path.display()
                )));
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            git_clone(url, path, depth)?;
            Ok(path.clone())
        }
        CloneTarget::WorkspaceGit(org_dir) => {
            clone_workspace_git(url, org_dir)?;
            Ok(org_dir.clone())
        }
    }
}

/// Get the remote URL for a git repository (origin).
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the git command fails.
pub fn remote_url(path: &Path) -> Result<Option<String>, WorkspaceError> {
    if !path.join(".git").is_dir() && !path.join(".git").is_file() {
        return Ok(None);
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("remote")
        .arg("get-url")
        .arg("origin")
        .output()
        .map_err(|e| WorkspaceError::GitError(format!("failed to run git: {e}")))?;

    if output.status.success() {
        let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if url.is_empty() {
            Ok(None)
        } else {
            Ok(Some(url))
        }
    } else {
        Ok(None)
    }
}

/// Check if a path is a git repository.
#[must_use]
pub fn is_git_repo(path: &Path) -> bool {
    path.join(".git").exists()
}

/// Get the current branch name.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the git command fails.
pub fn current_branch(path: &Path) -> Result<String, WorkspaceError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("rev-parse")
        .arg("--abbrev-ref")
        .arg("HEAD")
        .output()
        .map_err(|e| WorkspaceError::GitError(format!("failed to run git: {e}")))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(WorkspaceError::GitError(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

/// Check if the working tree is clean (no uncommitted changes).
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the git command fails.
pub fn is_clean(path: &Path) -> Result<bool, WorkspaceError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("status")
        .arg("--porcelain")
        .output()
        .map_err(|e| WorkspaceError::GitError(format!("failed to run git: {e}")))?;

    if output.status.success() {
        Ok(output.stdout.is_empty())
    } else {
        Err(WorkspaceError::GitError(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

fn git_clone(url: &str, target: &Path, depth: Option<u32>) -> Result<(), WorkspaceError> {
    let mut cmd = Command::new("git");
    cmd.arg("clone");

    if let Some(d) = depth {
        cmd.arg("--depth").arg(d.to_string());
    }

    cmd.arg("--").arg(url).arg(target);

    let output = cmd
        .output()
        .map_err(|e| WorkspaceError::GitError(format!("failed to run git clone: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(WorkspaceError::GitError(format!(
            "git clone failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn clone_workspace_git(url: &str, org_dir: &Path) -> Result<(), WorkspaceError> {
    if !org_dir.exists() {
        // Simple case: directory does not exist, clone directly.
        if let Some(parent) = org_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return git_clone(url, org_dir, None);
    }

    if org_dir.join(".git").is_dir() {
        // Already a workspace.git — pull instead.
        tracing::info!(path = %org_dir.display(), "workspace.git already exists, pulling");
        let output = Command::new("git")
            .arg("-C")
            .arg(org_dir)
            .arg("pull")
            .arg("--ff-only")
            .output()
            .map_err(|e| WorkspaceError::GitError(format!("failed to run git pull: {e}")))?;

        if output.status.success() {
            return Ok(());
        }
        return Err(WorkspaceError::GitError(format!(
            "git pull failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // Org dir exists but is not a git repo (may have sibling repos).
    // Initialize and add remote, then fetch and checkout.
    tracing::info!(
        path = %org_dir.display(),
        "org directory exists without .git, initializing workspace.git around existing content"
    );

    run_git(org_dir, &["init"])?;
    run_git(org_dir, &["remote", "add", "origin", url])?;
    run_git(org_dir, &["fetch", "origin"])?;

    // Try to checkout the default branch. If there are conflicts
    // with existing files, that is expected (sibling repos are gitignored).
    let checkout = Command::new("git")
        .arg("-C")
        .arg(org_dir)
        .arg("checkout")
        .arg("-f")
        .arg("origin/HEAD")
        .arg("-B")
        .arg("main")
        .output();
    match checkout {
        Ok(output) if !output.status.success() => {
            tracing::warn!(
                path = %org_dir.display(),
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "workspace.git checkout had errors (may be expected with sibling repos)"
            );
        }
        Err(e) => {
            tracing::warn!(path = %org_dir.display(), error = %e, "failed to run git checkout");
        }
        _ => {}
    }

    Ok(())
}

fn run_git(dir: &Path, args: &[&str]) -> Result<(), WorkspaceError> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir);
    for arg in args {
        cmd.arg(arg);
    }

    let output = cmd
        .output()
        .map_err(|e| WorkspaceError::GitError(format!("failed to run git: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(WorkspaceError::GitError(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_git_repo_false_for_plain_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_git_repo(dir.path()));
    }

    #[test]
    fn is_git_repo_true_for_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(is_git_repo(dir.path()));
    }

    #[test]
    fn remote_url_returns_none_for_non_git() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(remote_url(dir.path()).unwrap(), None);
    }
}
