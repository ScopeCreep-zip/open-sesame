//! Authentication backend dispatcher.
//!
//! Tries non-interactive backends first, falling back to password entry
//! when no automatic method is available.

use crate::backend::{AuthInteraction, VaultAuthBackend};
use crate::password::PasswordBackend;
use crate::ssh::SshAgentBackend;
use core_types::TrustProfileName;
use std::path::Path;

/// Dispatches vault unlock across registered authentication backends.
///
/// Backend priority order:
/// 1. SSH-agent (non-interactive, if enrolled and agent available)
/// 2. Password (interactive fallback, always available)
pub struct AuthDispatcher {
    backends: Vec<Box<dyn VaultAuthBackend>>,
}

impl AuthDispatcher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: vec![
                Box::new(SshAgentBackend::new()),
                Box::new(PasswordBackend::new()),
            ],
        }
    }

    /// Find the first non-interactive backend that is enrolled AND available.
    pub async fn find_auto_backend(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
    ) -> Option<&dyn VaultAuthBackend> {
        for backend in &self.backends {
            if backend.requires_interaction() == AuthInteraction::None
                && backend.is_enrolled(profile, config_dir)
                && backend.can_unlock(profile, config_dir).await
            {
                return Some(backend.as_ref());
            }
        }
        None
    }

    /// Get the password backend (always available as fallback).
    ///
    /// # Panics
    ///
    /// Panics if the password backend was not registered (this is a programming
    /// error — the constructor always registers it).
    #[must_use]
    pub fn password_backend(&self) -> &dyn VaultAuthBackend {
        self.backends
            .iter()
            .find(|b| b.backend_id() == "password")
            .map(std::convert::AsRef::as_ref)
            .expect("password backend is always registered")
    }
}

impl Default for AuthDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> TrustProfileName {
        TrustProfileName::try_from("test-profile").unwrap()
    }

    #[tokio::test]
    async fn find_auto_backend_returns_none_without_enrollment() {
        let dispatcher = AuthDispatcher::new();
        let profile = test_profile();
        let result = dispatcher
            .find_auto_backend(&profile, std::path::Path::new("/nonexistent"))
            .await;
        assert!(result.is_none());
    }

    #[test]
    fn password_backend_always_available() {
        let dispatcher = AuthDispatcher::new();
        let backend = dispatcher.password_backend();
        assert_eq!(backend.backend_id(), "password");
        assert_eq!(
            backend.requires_interaction(),
            AuthInteraction::PasswordEntry
        );
    }
}
