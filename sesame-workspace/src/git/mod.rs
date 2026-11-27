//! Git operations using `gix` (pure Rust) and `git2` (bundled libgit2).
//!
//! No git CLI dependency — users install via `apt install open-sesame` with
//! zero runtime git requirement.
//!
//! ## Module layout
//!
//! - `clone`: Repository cloning (gix) and workspace.git orchestration.
//! - `inspect`: Local repository queries — branch, remote URL, clean status.
//! - `marker`: What a directory is by its `.git` entry; the only
//!   repository detector.
//! - `remote`: Remote probe and upstream drift; a local remote (`file://`
//!   or a path) is read in-process, since gix's local transport runs
//!   `git upload-pack`.
//! - `workspace`: git2-based operations for init-around-existing and pull.
//! - `worktree`: Linked-worktree link files and their rewrite on rename.

mod clone;
mod inspect;
pub(crate) mod marker;
mod remote;
mod workspace;
mod worktree;

pub use clone::{CloneTarget, clone_to, clone_workspace_git, inspect_clone_target};
pub use inspect::remote_url;
pub use marker::{GitMarker, git_marker};
pub use remote::{RemoteProbe, UpstreamDrift, probe_remote, upstream_drift};
pub use workspace::pull_ff_only;
pub use worktree::WorktreeLinkRewrite;
pub(crate) use worktree::{WorktreeLink, rewrite_worktree_links};
