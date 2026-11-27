//! The Linux credential store (`core_types::CredentialStore`) over oo7: the
//! freedesktop Secret Service default collection (gnome-keyring, `KWallet`,
//! oo7-daemon, `KeePassXC`) on the host, or the Secret portal's file keyring
//! inside a Flatpak sandbox.
//!
//! Credentials are items carrying the attributes `service` and `username`
//! (`CredentialId`), the convention libsecret's `secret-tool` and
//! keyring-rs share. A locked collection is unlocked before every
//! operation, which may raise the keyring's own prompt: a locked keyring is
//! never read as an empty one.

use core_types::{
    BoxFuture, CredentialError, CredentialId, CredentialPersistence, CredentialStore,
    SensitiveBytes,
};

/// The secret service store, connected to its default collection.
pub struct SecretServiceStore {
    keyring: oo7::Keyring,
}

impl std::fmt::Debug for SecretServiceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretServiceStore").finish_non_exhaustive()
    }
}

impl SecretServiceStore {
    /// Connect to the Secret Service (or, sandboxed, the Secret portal).
    ///
    /// # Errors
    ///
    /// `CredentialError::Unavailable` when no session bus, Secret Service,
    /// or portal answers.
    pub async fn connect() -> Result<Self, CredentialError> {
        let keyring = oo7::Keyring::new()
            .await
            .map_err(|e| CredentialError::Unavailable(e.to_string()))?;
        Ok(Self { keyring })
    }

    /// Connect to the Secret Service over `connection` (a session bus, or a
    /// peer-to-peer connection to a service).
    ///
    /// # Errors
    ///
    /// `CredentialError::Unavailable` when no Secret Service answers on it.
    pub async fn with_connection(connection: &zbus::Connection) -> Result<Self, CredentialError> {
        let keyring = oo7::Keyring::host_with_connection(connection.clone())
            .await
            .map_err(|e| CredentialError::Unavailable(e.to_string()))?;
        Ok(Self { keyring })
    }

    /// Unlock the collection when it is locked.
    async fn unlocked(&self) -> Result<(), CredentialError> {
        if self.keyring.is_locked().await.map_err(classify)? {
            self.keyring.unlock().await.map_err(classify)?;
        }
        Ok(())
    }

    /// The items carrying `id`.
    async fn items(&self, id: &CredentialId) -> Result<Vec<oo7::Item>, CredentialError> {
        self.unlocked().await?;
        self.keyring
            .search_items(&attributes(id))
            .await
            .map_err(classify)
    }
}

/// The item attributes of `id`.
fn attributes(id: &CredentialId) -> [(&str, &str); 2] {
    [
        ("service", id.service.as_str()),
        ("username", id.account.as_str()),
    ]
}

/// The credential error an oo7 failure is.
fn classify(e: oo7::Error) -> CredentialError {
    match e {
        oo7::Error::DBus(oo7::dbus::Error::Dismissed) => CredentialError::Dismissed,
        oo7::Error::DBus(oo7::dbus::Error::Service(oo7::dbus::ServiceError::IsLocked(what))) => {
            CredentialError::Locked(what)
        }
        oo7::Error::File(file) if matches!(*file, oo7::file::Error::Locked) => {
            CredentialError::Locked("the portal keyring is locked".into())
        }
        other => CredentialError::Platform(other.to_string()),
    }
}

impl CredentialStore for SecretServiceStore {
    fn vendor(&self) -> &'static str {
        match self.keyring {
            oo7::Keyring::DBus(_) => "freedesktop Secret Service (oo7)",
            oo7::Keyring::File(..) => "Secret portal file keyring (oo7)",
        }
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    fn get<'a>(
        &'a self,
        id: &'a CredentialId,
    ) -> BoxFuture<'a, Result<Option<SensitiveBytes>, CredentialError>> {
        Box::pin(async move {
            let items = self.items(id).await?;
            match items.as_slice() {
                [] => Ok(None),
                [item] => {
                    // `oo7::Secret` zeroizes on drop; the copy is protected.
                    let secret = item.secret().await.map_err(classify)?;
                    Ok(Some(SensitiveBytes::from_slice(secret.as_bytes())))
                }
                many => Err(CredentialError::Ambiguous {
                    id: id.clone(),
                    count: many.len(),
                }),
            }
        })
    }

    fn set<'a>(
        &'a self,
        id: &'a CredentialId,
        label: &'a str,
        secret: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            let existing = self.items(id).await?.len();
            if existing > 1 {
                return Err(CredentialError::Ambiguous {
                    id: id.clone(),
                    count: existing,
                });
            }
            self.keyring
                .create_item(label, &attributes(id), oo7::Secret::blob(secret), true)
                .await
                .map_err(classify)
        })
    }

    fn delete<'a>(&'a self, id: &'a CredentialId) -> BoxFuture<'a, Result<bool, CredentialError>> {
        Box::pin(async move {
            let existed = !self.items(id).await?.is_empty();
            if existed {
                self.keyring
                    .delete(&attributes(id))
                    .await
                    .map_err(classify)?;
            }
            Ok(existed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_carry_the_libsecret_attributes() {
        let id = CredentialId {
            service: "open-sesame".into(),
            account: "vault-kek:work".into(),
        };
        assert_eq!(
            attributes(&id),
            [("service", "open-sesame"), ("username", "vault-kek:work")]
        );
    }

    #[test]
    fn prompts_and_locks_are_not_platform_failures() {
        assert!(matches!(
            classify(oo7::Error::DBus(oo7::dbus::Error::Dismissed)),
            CredentialError::Dismissed
        ));
        assert!(matches!(
            classify(oo7::Error::DBus(oo7::dbus::Error::Service(
                oo7::dbus::ServiceError::IsLocked("login".into())
            ))),
            CredentialError::Locked(what) if what == "login"
        ));
        assert!(matches!(
            classify(oo7::Error::File(Box::new(oo7::file::Error::Locked))),
            CredentialError::Locked(_)
        ));
        assert!(matches!(
            classify(oo7::Error::DBus(oo7::dbus::Error::Deleted)),
            CredentialError::Platform(_)
        ));
    }
}
