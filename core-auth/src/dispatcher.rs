//! The registry of authentication backends, one per factor.
//!
//! An unlock walks the factors daemon-secrets reports a vault still
//! requires (`crate::remaining_factors`) and looks each up here: the
//! backend's `requires_interaction()` tells the client what the factor
//! needs (nothing, a password, a touch). daemon-secrets, not the client,
//! applies the vault's policy to the factors submitted.

use crate::backend::VaultAuthBackend;
use crate::keyring::PlatformKeyringBackend;
use crate::password::PasswordBackend;
use crate::ssh::SshAgentBackend;
use core_types::{AuthFactorId, CredentialStore};
use std::sync::Arc;

/// The registered authentication backends.
pub struct AuthDispatcher {
    backends: Vec<Box<dyn VaultAuthBackend>>,
}

impl AuthDispatcher {
    /// The SSH agent and password backends, and the platform keyring
    /// backend over `credential_store` when the platform has one.
    #[must_use]
    pub fn new(credential_store: Option<Arc<dyn CredentialStore>>) -> Self {
        let mut backends: Vec<Box<dyn VaultAuthBackend>> = vec![
            Box::new(SshAgentBackend::new()),
            Box::new(PasswordBackend::new()),
        ];
        if let Some(store) = credential_store {
            backends.push(Box::new(PlatformKeyringBackend::new(store)));
        }
        Self { backends }
    }

    /// The backend that provides `factor`; `None` when no registered backend
    /// implements it.
    #[must_use]
    pub fn backend(&self, factor: AuthFactorId) -> Option<&dyn VaultAuthBackend> {
        self.backends
            .iter()
            .find(|backend| backend.factor_id() == factor)
            .map(AsRef::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::AuthInteraction;
    use core_types::{
        BoxFuture, CredentialError, CredentialId, CredentialPersistence, SensitiveBytes,
    };

    /// A store that holds nothing: the dispatcher only registers it.
    struct EmptyStore;

    impl CredentialStore for EmptyStore {
        fn vendor(&self) -> &'static str {
            "empty"
        }
        fn persistence(&self) -> CredentialPersistence {
            CredentialPersistence::UntilDelete
        }
        fn get<'a>(
            &'a self,
            _: &'a CredentialId,
        ) -> BoxFuture<'a, Result<Option<SensitiveBytes>, CredentialError>> {
            Box::pin(async { Ok(None) })
        }
        fn set<'a>(
            &'a self,
            _: &'a CredentialId,
            _: &'a str,
            _: &'a [u8],
        ) -> BoxFuture<'a, Result<(), CredentialError>> {
            Box::pin(async { Ok(()) })
        }
        fn delete<'a>(
            &'a self,
            _: &'a CredentialId,
        ) -> BoxFuture<'a, Result<bool, CredentialError>> {
            Box::pin(async { Ok(false) })
        }
    }

    #[test]
    fn each_factor_has_its_backend_and_interaction() {
        let dispatcher = AuthDispatcher::new(Some(Arc::new(EmptyStore)));
        let interaction = |factor| {
            dispatcher
                .backend(factor)
                .map(VaultAuthBackend::requires_interaction)
        };
        assert_eq!(
            interaction(AuthFactorId::SshAgent),
            Some(AuthInteraction::None)
        );
        assert_eq!(
            interaction(AuthFactorId::Password),
            Some(AuthInteraction::PasswordEntry)
        );
        assert_eq!(
            interaction(AuthFactorId::PlatformKeyring),
            Some(AuthInteraction::None)
        );
        assert_eq!(interaction(AuthFactorId::Fido2), None);
    }

    #[test]
    fn without_a_credential_store_the_keyring_factor_has_no_backend() {
        assert!(
            AuthDispatcher::new(None)
                .backend(AuthFactorId::PlatformKeyring)
                .is_none()
        );
    }
}
