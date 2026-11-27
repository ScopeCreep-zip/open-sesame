use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::{Error, Result};

// ============================================================================
// Multi-Factor Auth Policy Types
// ============================================================================

/// Identifies an authentication factor type.
///
/// Each variant corresponds to a pluggable `VaultAuthBackend` implementation.
/// Future backends (FIDO2, `YubiKey`, TPM, biometrics) are defined here
/// to allow forward-compatible policy configuration before their backends
/// are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthFactorId {
    /// Password-based authentication (Argon2id KDF).
    Password,
    /// SSH agent key-based authentication (deterministic signature → KEK).
    SshAgent,
    /// The operating system's credential store holds a random KEK
    /// (`CredentialStore`): the Secret Service on Linux.
    PlatformKeyring,
    /// FIDO2/WebAuthn hardware token.
    Fido2,
    /// TPM 2.0 or vTPM sealed key.
    Tpm,
    /// Fingerprint biometric sensor.
    Fingerprint,
    /// `YubiKey` OTP or challenge-response.
    Yubikey,
}

impl AuthFactorId {
    /// Parse from a string identifier used in config files.
    ///
    /// # Errors
    ///
    /// Returns `Error::Config` for unrecognized factor identifiers.
    pub fn from_config_str(s: &str) -> Result<Self> {
        match s {
            "password" => Ok(Self::Password),
            "ssh-agent" => Ok(Self::SshAgent),
            "platform-keyring" => Ok(Self::PlatformKeyring),
            "fido2" => Ok(Self::Fido2),
            "tpm" => Ok(Self::Tpm),
            "fingerprint" => Ok(Self::Fingerprint),
            "yubikey" => Ok(Self::Yubikey),
            other => Err(Error::Config(format!("unknown auth factor: {other}"))),
        }
    }

    /// Config-file string representation.
    #[must_use]
    pub fn as_config_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::SshAgent => "ssh-agent",
            Self::PlatformKeyring => "platform-keyring",
            Self::Fido2 => "fido2",
            Self::Tpm => "tpm",
            Self::Fingerprint => "fingerprint",
            Self::Yubikey => "yubikey",
        }
    }
}

impl fmt::Display for AuthFactorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_config_str())
    }
}

/// How multiple authentication factors combine to produce the master key.
///
/// Determines both the key wrapping scheme at init time and the unlock
/// policy evaluation at unlock time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthCombineMode {
    /// Master key is random; independently wrapped under each factor's KEK.
    /// ANY single enrolled factor can unlock alone.
    #[default]
    Any,
    /// Master key is derived from chaining ALL enrolled factors.
    /// Every enrolled factor must be provided at unlock time.
    All,
    /// Policy expression: some factors are always required, plus N additional
    /// from remaining enrolled factors. Key wrapping uses independent wraps
    /// (same as `Any`); policy enforcement is at the daemon level.
    Policy(AuthPolicy),
}

/// Policy expression for multi-factor unlock requirements.
///
/// Evaluated by daemon-secrets' partial unlock state machine at unlock time.
/// For `Policy` mode, the master key is independently wrapped under each
/// enrolled factor (same as `Any`), but daemon-secrets requires that ALL
/// `required` factors succeed plus `additional_required` from the remaining
/// enrolled factors before releasing the master key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicy {
    /// Factors that must ALWAYS succeed for every unlock attempt.
    pub required: Vec<AuthFactorId>,
    /// How many ADDITIONAL enrolled factors (beyond `required`) must also succeed.
    pub additional_required: u32,
}
