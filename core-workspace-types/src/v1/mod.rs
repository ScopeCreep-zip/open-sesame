//! Version 1 workspace identity types.

mod endpoint;
mod error;
mod host;
mod namespace;
mod remote;
mod repository;
mod transport;
mod user;
mod workspace;

pub use endpoint::RemoteEndpoint;
pub use error::ValidationError;
pub use host::GitHost;
pub use namespace::NamespacePath;
pub use remote::RemoteIdentity;
pub use repository::RepositoryName;
pub use transport::GitTransport;
pub use user::WorkspaceUser;
pub use workspace::{WorkspaceCoordinate, WorkspaceKind};
