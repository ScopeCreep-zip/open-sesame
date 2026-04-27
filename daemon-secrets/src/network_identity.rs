//! Network identity keypair management for `daemon-network`.
//!
//! Generates and stores a persistent X25519 keypair in the vault under a
//! system key `_network-identity-private` in the default profile. The keypair
//! persists across daemon restarts so TOFU pins from remote peers remain valid.

use core_secrets::SecretsStore as _;
use core_types::{EventKind, SensitiveBytes, TrustProfileName};

/// System secret key name for the network identity private key.
const NETWORK_IDENTITY_KEY: &str = "_network-identity-private";

/// Handle a `NetworkIdentityRequest` from `daemon-network`.
///
/// If the default profile is unlocked and the vault contains the
/// `_network-identity-private` key, returns the keypair. If the key
/// doesn't exist, generates a new X25519 keypair, stores it, and returns it.
///
/// Returns `None` if the vault is locked or the operation fails.
pub(crate) async fn handle_network_identity_request(
    vault_state: &mut crate::vault::VaultState,
    default_profile: &TrustProfileName,
) -> Option<EventKind> {
    // Check if default profile is unlocked.
    if !vault_state.active_profiles.contains(default_profile) {
        tracing::debug!("`NetworkIdentityRequest`: default profile locked, cannot serve");
        return None;
    }

    let vault = match vault_state.vault_for(default_profile).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "`NetworkIdentityRequest`: vault access failed");
            return None;
        }
    };

    // Try to load existing keypair from vault.
    match vault.resolve(NETWORK_IDENTITY_KEY).await {
        Ok(private_bytes) => {
            let public = derive_public_from_private(private_bytes.as_bytes());
            tracing::debug!("`NetworkIdentityRequest`: returning stored keypair");
            Some(EventKind::NetworkIdentityResponse {
                private_key: SensitiveBytes::from_slice(private_bytes.as_bytes()),
                public_key: public.to_vec(),
            })
        }
        Err(_) => {
            // Key not found — generate new keypair.
            let (private, public) = match core_crypto::network::generate_x25519_keypair() {
                Ok(kp) => kp,
                Err(e) => {
                    tracing::error!(error = %e, "`NetworkIdentityRequest`: keypair generation failed");
                    return None;
                }
            };

            // Store private key in vault.
            if let Err(e) = vault.store().set(NETWORK_IDENTITY_KEY, private.as_bytes()).await {
                tracing::error!(error = %e, "`NetworkIdentityRequest`: failed to store private key");
                return None;
            }

            tracing::info!(
                pubkey = %hex::encode(&public[..16]),
                "`NetworkIdentityRequest`: generated and stored new keypair"
            );

            Some(EventKind::NetworkIdentityResponse {
                private_key: SensitiveBytes::from_slice(private.as_bytes()),
                public_key: public.to_vec(),
            })
        }
    }
}

/// Derive X25519 public key from private key bytes.
///
/// Uses BLAKE3 domain-separated derivation as a placeholder. The actual
/// X25519 scalar basepoint multiplication requires `aws-lc-rs` deterministic
/// key construction from seed (not yet exposed). When available, this will
/// use real scalar multiplication for correct ECDH.
fn derive_public_from_private(private: &[u8]) -> [u8; 32] {
    blake3::derive_key("opensesame:network-identity:pubkey:v1", private)
}
