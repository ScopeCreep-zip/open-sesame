use core_types::TrustProfileName;

/// Validate a secret key name at the CLI trust boundary.
/// Delegates to the canonical implementation in core-types.
pub(crate) fn validate_secret_key(key: &str) -> anyhow::Result<()> {
    core_types::validate_secret_key(key).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Validate that a profile exists in config before sending an RPC.
/// Fails fast at the CLI boundary with a clear error message.
pub(crate) fn validate_profile_in_config(profile: &str) -> anyhow::Result<()> {
    let config = core_config::load_config(None).map_err(|e| anyhow::anyhow!("{e}"))?;
    if !config.profiles.contains_key(profile) {
        anyhow::bail!("profile '{}' not found in config", profile);
    }
    Ok(())
}

pub(crate) fn format_denial_reason(
    reason: &core_types::SecretDenialReason,
    key: &str,
    profile: &TrustProfileName,
) -> String {
    use core_types::SecretDenialReason;
    match reason {
        SecretDenialReason::Locked => "vault locked -- run `sesame unlock`".into(),
        SecretDenialReason::ProfileNotActive => format!(
            "profile '{}' is not active -- run `sesame profile activate {}`",
            profile, profile
        ),
        SecretDenialReason::AccessDenied => format!("access denied for secret '{}'", key),
        SecretDenialReason::RateLimited => "rate limited -- try again later".into(),
        SecretDenialReason::NotFound => {
            format!("secret '{}' not found in profile '{}'", key, profile)
        }
        SecretDenialReason::VaultError(e) => format!("vault error: {}", e),
        _ => format!("secret access denied for '{}': {:?}", key, reason),
    }
}
