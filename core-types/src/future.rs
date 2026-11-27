use std::future::Future;
use std::pin::Pin;

/// The `Send` future a dyn-compatible async trait method returns: `async
/// fn` in a trait is not object-safe, so methods of traits held as `dyn`
/// (`SecretsStore`, [`CredentialStore`](crate::CredentialStore)) box it.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
