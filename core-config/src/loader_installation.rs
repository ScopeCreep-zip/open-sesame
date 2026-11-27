//! Installation identity file I/O (`Layout::installation_file`).

use core_layout::Layout;

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
    let path = layout.installation_file()?;
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(core_types::Error::Config(format!(
                "failed to read {}: {e}",
                path.display()
            )));
        }
    };
    toml::from_str(&contents)
        .map(Some)
        .map_err(|e| core_types::Error::Config(format!("failed to parse {}: {e}", path.display())))
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
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let machine_id = contents.trim();
            Ok((!machine_id.is_empty()).then(|| machine_id.to_owned()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(core_types::Error::Config(format!(
            "failed to read {}: {e}",
            path.display()
        ))),
    }
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
    core_layout::file::write(
        &path,
        contents.as_bytes(),
        core_layout::file::Mode::OwnerOnly,
    )
    .map_err(|e| core_types::Error::Config(e.to_string()))
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
