//! Git operations using `gix` (pure Rust) and `git2` (bundled libgit2).
//!
//! No git CLI dependency — users install via `apt install open-sesame` with
//! zero runtime git requirement.
//!
//! ## Module layout
//!
//! - `clone`: Repository cloning (gix) and workspace.git orchestration.
//! - `inspect`: Local repository queries — branch, remote URL, clean status.
//! - `remote`: Network operations — probe, behind-check.
//! - `workspace`: git2-based operations for init-around-existing and pull.

mod clone;
mod inspect;
mod remote;
mod workspace;

pub use clone::clone_repo;
pub use inspect::{
    current_branch, head_commit_short, head_commit_summary, is_clean, is_git_repo,
    remote_tracking_commit_short, remote_url,
};
pub use remote::{is_behind_remote, probe_remote};
pub use workspace::pull_ff_only;
