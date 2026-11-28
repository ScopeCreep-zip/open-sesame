//! Installation identity file I/O (`Layout::installation_file`).

use core_layout::Layout;

use crate::loader::{path_error, read_optional, utf8};

/// The installation identity from `installation.toml`, or `None` before
/// `sesame init` has created it.
///
/// # Errors
///
/// The layout errors, and `core_types::Error::Config` naming the file when
/// it exists but cannot be read or does not parse.
pub fn load_installation(
    layout: &Layout,
) -> core_types::Result<Option<crate::schema::InstallationConfig>> {
    crate::transaction::consistent(layout, || read_installation(layout))
}

fn read_installation(
    layout: &Layout,
) -> core_types::Result<Option<crate::schema::InstallationConfig>> {
    let path = layout.installation_file()?;
    read_optional(&path)?
        .as_deref()
        .map(|bytes| parse_installation(&path, bytes))
        .transpose()
}

/// The installation identity `bytes` of `path` hold, checked to be one.
pub(crate) fn parse_installation(
    path: &std::path::Path,
    bytes: &[u8],
) -> core_types::Result<crate::InstallationConfig> {
    let installation: crate::InstallationConfig = toml::from_str(utf8(path, bytes)?)
        .map_err(|e| path_error(path, format!("cannot parse: {e}")))?;
    installation.identity().map_err(|e| path_error(path, e))?;
    Ok(installation)
}

/// The machine ID from `Layout::machine_id_file`, or `None` when the
/// platform has no such file, the file is absent, or it is empty (an
/// image whose ID is not yet established, machine-id(5)).
///
/// # Errors
///
/// `core_types::Error::Config` naming the file when it exists but cannot
/// be read.
pub fn read_machine_id(layout: &Layout) -> core_types::Result<Option<String>> {
    let Some(path) = layout.machine_id_file() else {
        return Ok(None);
    };
    let Some(bytes) = read_optional(path)? else {
        return Ok(None);
    };
    let machine_id = utf8(path, &bytes)?.trim();
    Ok((!machine_id.is_empty()).then(|| machine_id.to_owned()))
}

/// Write installation identity to `installation.toml` atomically,
/// owner-only.
///
/// # Errors
///
/// Returns an error if the config directory cannot be determined, or
/// serialization or file I/O fails.
pub fn write_installation(
    layout: &Layout,
    config: &crate::schema::InstallationConfig,
) -> core_types::Result<()> {
    let path = layout.installation_file()?;
    let contents = toml::to_string_pretty(config).map_err(|e| {
        core_types::Error::Config(format!("failed to serialize installation config: {e}"))
    })?;
    let mut transaction = crate::Transaction::for_update(layout)?;
    transaction.read(&path)?;
    transaction.write(&path, contents.as_bytes())?;
    transaction.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_config_roundtrips_through_the_layout() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let config = crate::schema::InstallationConfig::new(
            uuid::Uuid::from_u128(42),
            Some("example.invalid"),
            Some("0123abcd"),
        );
        write_installation(&layout, &config).unwrap();
        assert!(layout.installation_file().unwrap().is_file());
        let parsed = load_installation(&layout).unwrap().unwrap();
        assert_eq!(parsed.identity().unwrap(), config.identity().unwrap());
    }

    #[test]
    fn machine_id_is_trimmed_and_empty_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        assert_eq!(read_machine_id(&layout).unwrap(), None);
        let path = layout.machine_id_file().unwrap().to_path_buf();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "\n").unwrap();
        assert_eq!(read_machine_id(&layout).unwrap(), None);
        std::fs::write(&path, "0123abcd\n").unwrap();
        assert_eq!(
            read_machine_id(&layout).unwrap().as_deref(),
            Some("0123abcd")
        );
    }

    #[test]
    fn missing_installation_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            load_installation(&Layout::under(dir.path()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_installation_is_an_error_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let path = layout.installation_file().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "id = 7\n").unwrap();
        let err = load_installation(&layout).unwrap_err().to_string();
        assert!(err.contains(&path.display().to_string()), "{err}");
    }
}
