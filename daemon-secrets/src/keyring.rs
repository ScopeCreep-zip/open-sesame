// ============================================================================
// Platform keyring integration (ADR-SEC-001)
//
// The raw master key NEVER touches the platform keyring. Instead:
// 1. A KEK (key-encrypting-key) is derived from password+salt via BLAKE3
//    with a dedicated context string independent from Argon2id derivation.
// 2. The master key is AES-256-GCM encrypted under the KEK with a random nonce.
// 3. The wrapped blob [12-byte nonce || ciphertext || 16-byte tag] is stored.
// 4. On retrieval, the KEK is re-derived from password+salt, and the blob
//    is decrypted. GCM tag verification rejects wrong passwords.
// ============================================================================

use core_crypto::SecureBytes;
use core_types::TrustProfileName;
use std::sync::Arc;

#[cfg(target_os = "linux")]
use crate::key_locker_linux;

/// KeyLocker service constant for platform keyring.
const KEYLOCKER_SERVICE: &str = "pds";

/// Per-profile keyring account name.
pub(crate) fn keylocker_account(profile: &TrustProfileName) -> String {
    format!("vault-key-{profile}")
}

/// Wrap a profile's master key with a KEK and store in the platform keyring.
///
/// Wire format: `[12-byte random nonce][ciphertext + 16-byte GCM tag]`
#[cfg(target_os = "linux")]
pub(crate) async fn keyring_store_profile(
    master_key: &SecureBytes,
    password: &[u8],
    salt: &[u8],
    profile: &TrustProfileName,
) {
    use core_secrets::KeyLocker;

    let kek = core_crypto::derive_kek(password, salt);
    let enc_key = match core_crypto::EncryptionKey::from_bytes(
        kek.as_bytes().try_into().expect("key derivation invariant"),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, profile = %profile, "keyring: KEK construction failed");
            return;
        }
    };

    let mut nonce = [0u8; 12];
    if let Err(e) = getrandom::getrandom(&mut nonce) {
        tracing::warn!(error = %e, "keyring: nonce generation failed");
        return;
    }

    let ciphertext = match enc_key.encrypt(&nonce, master_key.as_bytes()) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::warn!(error = %e, "keyring: master key wrapping failed");
            return;
        }
    };

    let mut wrapped = Vec::with_capacity(12 + ciphertext.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend(ciphertext);

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let account = keylocker_account(profile);
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    match locker
        .store_wrapped_key(KEYLOCKER_SERVICE, &account, &wrapped)
        .await
    {
        Ok(()) => tracing::info!(profile = %profile, "KEK-wrapped vault key stored in keyring"),
        Err(e) => tracing::warn!(error = %e, profile = %profile, "keyring: store failed"),
    }
}

/// Retrieve and unwrap a profile's master key from the platform keyring.
#[cfg(target_os = "linux")]
pub(crate) async fn keyring_retrieve_profile(
    password: &[u8],
    salt: &[u8],
    profile: &TrustProfileName,
) -> Option<SecureBytes> {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::debug!(error = %e, "keyring: failed to connect to session bus");
            return None;
        }
    };
    let account = keylocker_account(profile);
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);

    match locker.has_wrapped_key(KEYLOCKER_SERVICE, &account).await {
        Ok(true) => {}
        Ok(false) => return None,
        Err(e) => {
            tracing::debug!(error = %e, "keyring: has_wrapped_key check failed");
            return None;
        }
    }

    let wrapped = match locker
        .retrieve_wrapped_key(KEYLOCKER_SERVICE, &account)
        .await
    {
        Ok(w) => w,
        Err(e) => {
            tracing::debug!(error = %e, "keyring: retrieve failed");
            return None;
        }
    };

    if wrapped.len() < 60 {
        tracing::warn!(len = wrapped.len(), "keyring: wrapped blob too short");
        return None;
    }

    let kek = core_crypto::derive_kek(password, salt);
    let enc_key = match core_crypto::EncryptionKey::from_bytes(
        kek.as_bytes().try_into().expect("key derivation invariant"),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "keyring: KEK construction failed");
            return None;
        }
    };

    let nonce: [u8; 12] = wrapped.as_bytes()[..12].try_into().ok()?;
    let ciphertext = &wrapped.as_bytes()[12..];

    match enc_key.decrypt(&nonce, ciphertext) {
        Ok(master_key) => {
            tracing::info!(profile = %profile, "vault key unwrapped from keyring (fast path)");
            Some(master_key)
        }
        Err(_) => {
            tracing::debug!(profile = %profile, "keyring: GCM tag failed (wrong password or corrupted)");
            None
        }
    }
}

/// Delete a specific profile's wrapped key from the platform keyring.
#[cfg(target_os = "linux")]
pub(crate) async fn keyring_delete_profile(profile: &TrustProfileName) {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let account = keylocker_account(profile);
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    match locker.delete_wrapped_key(KEYLOCKER_SERVICE, &account).await {
        Ok(()) => tracing::info!(profile = %profile, "wrapped vault key deleted from keyring"),
        Err(e) => tracing::debug!(error = %e, profile = %profile, "keyring: delete failed"),
    }
}

/// Delete wrapped keys for all given profiles from the platform keyring (best-effort).
#[cfg(target_os = "linux")]
pub(crate) async fn keyring_delete_all(profiles: &[TrustProfileName]) {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    for profile in profiles {
        let account = keylocker_account(profile);
        if let Err(e) = locker.delete_wrapped_key(KEYLOCKER_SERVICE, &account).await {
            tracing::debug!(error = %e, profile = %profile, "keyring: delete failed (may not exist)");
        }
    }
    tracing::info!(
        count = profiles.len(),
        "per-profile keyring entries deleted"
    );
}
