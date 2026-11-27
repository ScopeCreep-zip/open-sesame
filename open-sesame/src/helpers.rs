//! Shared command plumbing: profile checks, denial messages, response
//! errors, and tables.

use core_layout::Layout;
use core_types::{EventKind, SecretDenialReason, TrustProfileName};

/// Fail fast, before any request, when `profile` is not configured.
///
/// # Errors
///
/// The `load_config` errors, and an error naming the profile when the
/// configuration does not define it.
pub(crate) fn validate_profile_in_config(
    layout: &Layout,
    profile: &TrustProfileName,
) -> anyhow::Result<()> {
    let config = core_config::load_config(layout)?;
    anyhow::ensure!(
        config.profiles.contains_key(profile.as_ref()),
        "profile '{profile}' not found in config"
    );
    Ok(())
}

/// The error for a response that does not answer the request.
pub(crate) fn unexpected(response: &EventKind) -> anyhow::Error {
    anyhow::anyhow!("unexpected response: {response:?}")
}

/// A table with the CLI's preset and `header`.
pub(crate) fn table(header: &[&str]) -> comfy_table::Table {
    let mut table = comfy_table::Table::new();
    table.load_style(comfy_table::presets::UTF8_FULL);
    table.set_header(header);
    table
}

pub(crate) fn format_denial_reason(
    reason: &SecretDenialReason,
    key: &str,
    profile: &TrustProfileName,
) -> String {
    match reason {
        SecretDenialReason::Locked => "vault locked -- run `sesame unlock`".into(),
        SecretDenialReason::ProfileNotActive => {
            format!("profile '{profile}' is not active -- run `sesame profile activate {profile}`")
        }
        SecretDenialReason::AccessDenied => format!("access denied for secret '{key}'"),
        SecretDenialReason::RateLimited => "rate limited -- try again later".into(),
        SecretDenialReason::NotFound => {
            format!("secret '{key}' not found in profile '{profile}'")
        }
        SecretDenialReason::VaultError(e) => format!("vault error: {e}"),
        _ => format!("secret access denied for '{key}': {reason:?}"),
    }
}
