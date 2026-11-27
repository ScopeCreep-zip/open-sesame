//! Factor enrollment and revocation, the one implementation every factor
//! command (`sesame ssh`, `sesame keyring`) runs.
//!
//! An enrollment is a transaction: the master key is derived from the
//! vault password, the backend enrolls, the new enrollment is proven by
//! unlocking with it and comparing the key it yields, and only then is the
//! factor recorded in the vault metadata. A failure after the backend
//! enrolled revokes what it wrote, so no half-made enrollment is left
//! behind.
//!
//! A revocation removes the factor from the metadata and the backend's
//! enrollment together, whichever of the two exists, and never leaves a
//! vault without a factor.

use anyhow::Context;
use core_auth::{VaultAuthBackend, VaultMetadata};
use core_layout::Layout;
use core_types::TrustProfileName;

/// Enroll `backend` for `profile`'s vault, with `credential` naming which
/// of its credentials, recorded under `label`.
///
/// # Errors
///
/// The vault cannot be read or its password does not open it, the backend
/// fails to enroll, the new enrollment does not yield the vault's master
/// key, or the metadata cannot be written. Every failure after the backend
/// enrolled is rolled back first.
pub(crate) async fn enroll(
    layout: &Layout,
    profile: &TrustProfileName,
    backend: &dyn VaultAuthBackend,
    credential: Option<&str>,
    label: String,
) -> anyhow::Result<()> {
    let (mut meta, keying) = VaultMetadata::load_keying(layout, profile)?;
    let factor = backend.factor_id();
    println!(
        "Enrolling {} for vault '{profile}' requires the vault password to derive its master key.",
        backend.name()
    );
    let password = crate::prompt::password(&format!("Password for vault '{profile}'"))?;
    let master = core_auth::PasswordBackend::new()
        .with_password(password)
        .unlock(profile, layout, &keying)
        .await
        .with_context(|| format!("failed to derive the master key of '{profile}'"))?;

    backend
        .enroll(profile, &master.master_key, layout, &keying, credential)
        .await
        .with_context(|| format!("{} enrollment of '{profile}' failed", backend.name()))?;

    let recorded: anyhow::Result<()> = async {
        let proof = backend
            .unlock(profile, layout, &keying)
            .await
            .context("the new enrollment does not unlock the vault")?;
        anyhow::ensure!(
            proof.master_key.as_bytes() == master.master_key.as_bytes(),
            "the new enrollment unlocks a key other than the vault's master key"
        );
        meta.add_factor(factor, label)?;
        meta.save(layout, profile)?;
        Ok(())
    }
    .await;
    if let Err(e) = recorded {
        return Err(match backend.revoke(profile, layout).await {
            Ok(()) => e.context(format!(
                "{} enrollment of '{profile}' rolled back",
                backend.name()
            )),
            Err(rollback) => e.context(format!(
                "{} enrollment of '{profile}' failed and could not be rolled back: {rollback}",
                backend.name()
            )),
        });
    }
    Ok(())
}

/// Revoke `backend`'s factor of `profile`'s vault: whether there was
/// anything to revoke (an enrollment, a metadata record, or both).
///
/// # Errors
///
/// The metadata cannot be read or written, the factor is the vault's
/// only one, or the backend fails to revoke.
pub(crate) async fn revoke(
    layout: &Layout,
    profile: &TrustProfileName,
    backend: &dyn VaultAuthBackend,
) -> anyhow::Result<bool> {
    let factor = backend.factor_id();
    let mut meta = VaultMetadata::load(layout, profile)
        .with_context(|| format!("vault metadata of '{profile}'"))?;
    let recorded = meta.has_factor(factor);
    let enrolled = backend.is_enrolled(profile, layout)?;
    if !recorded && !enrolled {
        return Ok(false);
    }
    meta.remove_factor(factor);
    anyhow::ensure!(
        !meta.enrolled_factors.is_empty(),
        "{} is the only factor of vault '{profile}'; revoking it would make the vault \
         impossible to open",
        backend.name()
    );
    backend.revoke(profile, layout).await?;
    meta.save(layout, profile)?;
    Ok(true)
}
