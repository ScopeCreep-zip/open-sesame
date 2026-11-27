//! `sesame keyring`: the platform keyring factor. Enrollment stores a
//! random KEK in the operating system's credential store (the Secret
//! Service on Linux) and wraps the vault's master key under it; status
//! reports both halves; revocation removes both.

use anyhow::Context;
use core_auth::{PlatformKeyringBackend, WrappedKey, keyring_credential};
use core_layout::{Layout, VaultFile};
use core_types::{
    AuthFactorId, CredentialError, CredentialPersistence, CredentialStore, TrustProfileName,
};
use owo_colors::OwoColorize;
use serde::Serialize;
use std::sync::Arc;

use crate::helpers::table;
use open_sesame::cli::ProfileSpecs;

/// The connected platform credential store.
///
/// # Errors
///
/// When the platform has none, or it cannot be reached.
async fn require_store() -> anyhow::Result<Arc<dyn CredentialStore>> {
    core_daemon::credential_store().await.context(
        "no platform credential store is reachable: on Linux the Secret Service \
         (gnome-keyring, KWallet, oo7-daemon, KeePassXC) must run in the session",
    )
}

pub(crate) async fn cmd_keyring_enroll(
    layout: &Layout,
    specs: &ProfileSpecs,
) -> anyhow::Result<()> {
    let store = require_store().await?;
    let vendor = store.vendor();
    let backend = PlatformKeyringBackend::new(store);
    for spec in specs {
        let profile = &spec.vault;
        let credential = keyring_credential(profile);
        crate::enrollment::enroll(
            layout,
            profile,
            &backend,
            None,
            format!("{credential} in {vendor}"),
        )
        .await?;
        println!(
            "{}",
            format!("Platform keyring enrollment created and verified for vault '{profile}'.")
                .green()
        );
        println!("  KEK: {credential} in {vendor}");
    }
    println!("Future unlocks will use the platform keyring automatically while it is unlocked.");
    Ok(())
}

pub(crate) async fn cmd_keyring_revoke(
    layout: &Layout,
    specs: &ProfileSpecs,
) -> anyhow::Result<()> {
    let backend = PlatformKeyringBackend::new(require_store().await?);
    for spec in specs {
        let profile = &spec.vault;
        if crate::enrollment::revoke(layout, profile, &backend).await? {
            println!(
                "{}",
                format!("Platform keyring enrollment revoked for vault '{profile}'.").green()
            );
        } else {
            println!(
                "{}",
                format!("No platform keyring enrollment found for vault '{profile}'.").yellow()
            );
        }
    }
    Ok(())
}

/// What the credential store holds for a vault's KEK.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum KekState {
    /// One 32-byte KEK.
    Present,
    /// No credential carries the vault's KEK id.
    Missing,
    /// A credential carries the id but holds `len` bytes, not a KEK.
    Malformed { len: usize },
    /// The store is locked and was not unlocked.
    Locked { detail: String },
    /// The user dismissed the store's prompt.
    Dismissed,
    /// `count` credentials carry the id.
    Ambiguous { count: usize },
    /// No store is reachable.
    StoreUnavailable,
    /// The store failed the query.
    Failed { detail: String },
}

impl KekState {
    fn of(result: Result<Option<core_types::SensitiveBytes>, CredentialError>) -> Self {
        match result {
            Ok(Some(kek)) if kek.len() == 32 => Self::Present,
            Ok(Some(other)) => Self::Malformed { len: other.len() },
            Ok(None) => Self::Missing,
            Err(CredentialError::Locked(detail)) => Self::Locked { detail },
            Err(CredentialError::Dismissed) => Self::Dismissed,
            Err(CredentialError::Ambiguous { count, .. }) => Self::Ambiguous { count },
            Err(CredentialError::Unavailable(_)) => Self::StoreUnavailable,
            Err(CredentialError::Platform(detail)) => Self::Failed { detail },
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Present => "present".into(),
            Self::Missing => "missing".into(),
            Self::Malformed { len } => format!("malformed ({len} bytes)"),
            Self::Locked { detail } => format!("keyring locked ({detail})"),
            Self::Dismissed => "prompt dismissed".into(),
            Self::Ambiguous { count } => format!("{count} matching items"),
            Self::StoreUnavailable => "no credential store".into(),
            Self::Failed { detail } => format!("error: {detail}"),
        }
    }
}

/// One vault's platform keyring factor: its enrollment file, its metadata
/// record (`None` with `problem` when the metadata cannot be read), and its
/// KEK. It unlocks only when all three are present.
#[derive(Debug, Serialize)]
struct VaultStatus {
    profile: String,
    enrollment_file: bool,
    recorded: Option<bool>,
    kek: KekState,
    ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<String>,
}

#[derive(Serialize)]
struct StoreStatus {
    vendor: &'static str,
    persistence: &'static str,
}

#[derive(Serialize)]
struct Report {
    store: Option<StoreStatus>,
    vaults: Vec<VaultStatus>,
}

fn persistence(p: CredentialPersistence) -> &'static str {
    match p {
        CredentialPersistence::UntilLogout => "until-logout",
        CredentialPersistence::UntilReboot => "until-reboot",
        CredentialPersistence::UntilDelete => "until-delete",
    }
}

async fn vault_status(
    layout: &Layout,
    store: Option<&dyn CredentialStore>,
    profile: &TrustProfileName,
) -> anyhow::Result<VaultStatus> {
    // An unreadable vault is reported in its row; the store and the other
    // vaults are still reported.
    let (recorded, problem) = match core_auth::VaultMetadata::load(layout, profile) {
        Ok(meta) => (Some(meta.has_factor(AuthFactorId::PlatformKeyring)), None),
        Err(e) => (None, Some(format!("vault metadata unreadable: {e}"))),
    };
    let enrollment_file = core_layout::file::exists(&WrappedKey::path(
        layout,
        profile,
        VaultFile::KeyringEnrollment,
    )?)?;
    let kek = match store {
        Some(store) => KekState::of(store.get(&keyring_credential(profile)).await),
        None => KekState::StoreUnavailable,
    };
    let ready = enrollment_file && recorded == Some(true) && kek == KekState::Present;
    Ok(VaultStatus {
        profile: profile.to_string(),
        enrollment_file,
        recorded,
        kek,
        ready,
        problem,
    })
}

pub(crate) async fn cmd_keyring_status(
    layout: &Layout,
    specs: &ProfileSpecs,
    json: bool,
) -> anyhow::Result<()> {
    let store = core_daemon::credential_store().await;
    let mut vaults = Vec::new();
    for spec in specs {
        vaults.push(vault_status(layout, store.as_deref(), &spec.vault).await?);
    }
    let report = Report {
        store: store.as_deref().map(|s| StoreStatus {
            vendor: s.vendor(),
            persistence: persistence(s.persistence()),
        }),
        vaults,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    match &report.store {
        Some(s) => println!(
            "Credential store: {} (credentials last {})",
            s.vendor, s.persistence
        ),
        None => println!("{}", "Credential store: none reachable".yellow()),
    }
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_string();
    let mut out = table(&[
        "Profile",
        "Enrollment File",
        "Recorded",
        "Keyring KEK",
        "Ready",
    ]);
    for v in &report.vaults {
        out.add_row(vec![
            v.profile.clone(),
            yes_no(v.enrollment_file),
            v.recorded.map_or_else(|| "unreadable".into(), yes_no),
            v.kek.describe(),
            yes_no(v.ready),
        ]);
    }
    println!("{out}");
    for v in &report.vaults {
        if let Some(problem) = &v.problem {
            eprintln!("{} {}: {problem}", "WARN:".yellow().bold(), v.profile);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_store_answer_is_its_own_state() {
        let kek = |len: usize| Ok(Some(core_types::SensitiveBytes::from_slice(&vec![1; len])));
        assert_eq!(KekState::of(kek(32)), KekState::Present);
        assert_eq!(KekState::of(kek(5)), KekState::Malformed { len: 5 });
        assert_eq!(KekState::of(Ok(None)), KekState::Missing);
        assert_eq!(
            KekState::of(Err(CredentialError::Locked("login".into()))),
            KekState::Locked {
                detail: "login".into()
            }
        );
        assert_eq!(
            KekState::of(Err(CredentialError::Dismissed)),
            KekState::Dismissed
        );
        assert_eq!(
            KekState::of(Err(CredentialError::Unavailable("no bus".into()))),
            KekState::StoreUnavailable
        );
    }

    #[test]
    fn states_serialize_tagged() {
        assert_eq!(
            serde_json::to_string(&KekState::Ambiguous { count: 2 }).unwrap(),
            r#"{"state":"ambiguous","count":2}"#
        );
        assert_eq!(
            serde_json::to_string(&KekState::Present).unwrap(),
            r#"{"state":"present"}"#
        );
    }

    #[tokio::test]
    async fn a_vault_is_ready_only_with_all_three_halves() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let profile = TrustProfileName::try_from("work").unwrap();
        let meta = core_auth::VaultMetadata::new(
            vec![(AuthFactorId::Password, "master password".into())],
            core_types::AuthCombineMode::Any,
            &core_types::CryptoConfig::default(),
        )
        .unwrap();
        std::fs::create_dir_all(layout.vaults_dir().unwrap()).unwrap();
        meta.save(&layout, &profile).unwrap();
        let status = vault_status(&layout, None, &profile).await.unwrap();
        assert!(!status.ready);
        assert_eq!(status.recorded, Some(false));
        assert!(!status.enrollment_file);
        assert_eq!(status.kek, KekState::StoreUnavailable);
        assert!(status.problem.is_none());
    }

    #[tokio::test]
    async fn an_unreadable_vault_is_reported_not_fatal() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let profile = TrustProfileName::try_from("work").unwrap();
        let status = vault_status(&layout, None, &profile).await.unwrap();
        assert_eq!(status.recorded, None);
        assert!(!status.ready);
        assert!(
            status
                .problem
                .as_deref()
                .is_some_and(|p| p.contains("vault metadata unreadable")),
            "{status:?}"
        );
    }
}
