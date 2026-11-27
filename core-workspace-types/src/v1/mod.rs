//! Version 1 workspace identity types.
//!
//! Two vocabularies:
//! - Remote (forge-facing, case-preserving): `GitHost`, `NamespacePath`,
//!   `RepositoryName`, `RemoteIdentity`, `RemoteEndpoint`.
//! - Placement (filesystem-facing, lowercase by construction):
//!   `WorkspaceUser`, `NamespaceDir`, `RepoDir`, `WorkspaceCoordinate`.

mod endpoint;
mod error;
mod host;
mod namespace;
mod placement;
mod remote;
mod repository;
mod transport;
mod user;
mod workspace;

pub use endpoint::RemoteEndpoint;
pub use error::ValidationError;
pub use host::GitHost;
pub use namespace::NamespacePath;
pub use placement::{NamespaceDir, RepoDir};
pub use remote::RemoteIdentity;
pub use repository::RepositoryName;
pub use transport::GitTransport;
pub use user::WorkspaceUser;
pub use workspace::{WorkspaceCoordinate, WorkspaceKind};
