//! Workspace layout and configuration helpers.
//!
//! `WorkspaceLayout` is the single owner of root and user resolution and
//! of path construction. Every operation that turns a placement into a
//! filesystem path goes through it, and every operation that is about
//! to create or adopt a directory goes through `checked_path`, which
//! rejects case conflicts with existing directories.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use core_config::{LocalSesameConfig, WorkspaceConfig};
use core_workspace_types::{WorkspaceCoordinate, WorkspaceUser};

use crate::WorkspaceError;

/// Resolved workspace layout: root directory and username.
///
/// Constructed once from configuration and the process layout, then passed
/// to every operation that needs workspace paths.
#[derive(Debug, Clone)]
pub struct WorkspaceLayout {
    pub root: PathBuf,
    pub user: WorkspaceUser,
}

impl WorkspaceLayout {
    /// Resolve the workspace layout from configuration and the process
    /// layout.
    ///
    /// Root precedence:
    /// 1. `Layout::workspace_root_override` (`$SESAME_WORKSPACE_ROOT`)
    /// 2. `config.settings.root`
    ///
    /// # Errors
    ///
    /// The `WorkspaceLayout::new` errors.
    pub fn from_config(
        layout: &core_layout::Layout,
        config: &WorkspaceConfig,
    ) -> Result<Self, WorkspaceError> {
        let root = layout
            .workspace_root_override()
            .unwrap_or(config.settings.root.as_path());
        Self::new(root, config.settings.user.clone())
    }

    /// A layout at an explicit root.
    ///
    /// An existing root is canonicalized, so every path built from the
    /// layout (and every link key written for one) is the physical path;
    /// a symlinked root and its target produce one key form.
    ///
    /// # Errors
    ///
    /// `WorkspaceError::Io` when the root exists but cannot be resolved.
    pub fn new(root: &Path, user: WorkspaceUser) -> Result<Self, WorkspaceError> {
        Ok(Self {
            root: physical_path(root)?,
            user,
        })
    }

    /// The `{root}/{user}` directory.
    #[must_use]
    pub fn user_dir(&self) -> PathBuf {
        self.root.join(self.user.as_str())
    }

    /// The canonical path of a placement. Pure; does not touch the filesystem.
    #[must_use]
    pub fn path_of(&self, coordinate: &WorkspaceCoordinate) -> PathBuf {
        coordinate.canonical_path(&self.root, &self.user)
    }

    /// The canonical path of a placement, verified against the filesystem.
    ///
    /// Walks the layout from `{root}` down to the placement. At each
    /// level whose parent exists, an existing sibling that differs from
    /// the canonical component only in ASCII case is a conflict: the
    /// operator has a non-canonical directory that the canonical path
    /// would duplicate (case-sensitive filesystems) or alias
    /// (case-insensitive filesystems).
    ///
    /// # Errors
    ///
    /// - `WorkspaceError::CaseConflict` naming the requested and existing paths.
    /// - `WorkspaceError::Io` if a directory listing fails for a reason other
    ///   than the directory not existing.
    pub fn checked_path(
        &self,
        coordinate: &WorkspaceCoordinate,
    ) -> Result<PathBuf, WorkspaceError> {
        let mut parent = self.root.clone();
        let components =
            std::iter::once(self.user.as_str().to_string()).chain(coordinate.components());
        for component in components {
            let requested = parent.join(&component);
            if let Some(existing) = case_variants(&parent, &component)?.into_iter().next() {
                return Err(WorkspaceError::CaseConflict {
                    requested,
                    existing,
                });
            }
            parent = requested;
        }
        Ok(self.path_of(coordinate))
    }
}

/// Entries of `dir` whose name equals `name` ignoring ASCII case but not
/// exactly, sorted. Empty when `dir` does not exist.
pub(crate) fn case_variants(dir: &Path, name: &str) -> Result<Vec<PathBuf>, WorkspaceError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(WorkspaceError::io_at(dir, e)),
    };
    let mut variants = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| WorkspaceError::io_at(dir, e))?;
        // A non-UTF-8 name cannot equal the UTF-8 `name` under ASCII case
        // folding, which changes only ASCII bytes.
        let entry_name = entry.file_name();
        if let Some(entry_name) = entry_name.to_str()
            && entry_name != name
            && entry_name.eq_ignore_ascii_case(name)
        {
            variants.push(entry.path());
        }
    }
    variants.sort();
    Ok(variants)
}

/// The physical form of `path`: canonicalized when it exists, unchanged
/// when it does not.
///
/// This is the single key form for workspace paths: link keys are
/// written for it (`core_config::edit::set_workspace_link`, which drops
/// trailing separators) and queried with it (`resolve_workspace_profile`).
///
/// # Errors
///
/// `WorkspaceError::Io` when `path` exists but cannot be resolved.
pub fn physical_path(path: &Path) -> Result<PathBuf, WorkspaceError> {
    match std::fs::canonicalize(path) {
        Ok(physical) => Ok(physical),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(e) => Err(WorkspaceError::io_at(path, e)),
    }
}

/// Resolve the linked profile for a workspace path.
///
/// The query path is resolved to its physical form first. Resolution
/// order:
/// 1. Exact match in `config.links`
/// 2. Longest component-wise prefix match in `config.links`
///
/// Returns `None` if no link matches.
///
/// # Errors
///
/// The `physical_path` errors.
pub fn resolve_workspace_profile(
    config: &WorkspaceConfig,
    path: &Path,
) -> Result<Option<String>, WorkspaceError> {
    let path = physical_path(path)?;
    Ok(config
        .links
        .iter()
        .filter(|(link_path, _)| path.starts_with(Path::new(link_path.as_str())))
        .max_by_key(|(link_path, _)| Path::new(link_path.as_str()).components().count())
        .map(|(_, profile)| profile.clone()))
}

/// Load `.sesame.toml` from a directory, returning `None` if absent.
///
/// # Errors
///
/// Returns `WorkspaceError::ConfigError` if the file exists but cannot be parsed.
pub fn load_local_config(dir: &Path) -> Result<Option<LocalSesameConfig>, WorkspaceError> {
    let path = dir.join(".sesame.toml");
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(WorkspaceError::io_at(&path, e)),
    };
    let config: LocalSesameConfig = toml::from_str(&contents).map_err(|e| {
        WorkspaceError::ConfigError(format!("failed to parse {}: {e}", path.display()))
    })?;
    Ok(Some(config))
}

/// Tracks which configuration layer determined each value.
#[derive(Debug, Clone, Default)]
pub struct ConfigProvenance {
    /// Which layer set the profile value.
    pub profile_source: &'static str,
    /// Which layer set the `secret_prefix` value.
    pub secret_prefix_source: &'static str,
}

/// Resolved configuration for a workspace path, merging all layers.
#[derive(Debug, Clone, Default)]
pub struct EffectiveWorkspaceConfig {
    /// Resolved profile name.
    pub profile: Option<String>,
    /// Merged environment variables (non-secret).
    pub env: BTreeMap<String, String>,
    /// Merged tags.
    pub tags: Vec<String>,
    /// Resolved secret prefix.
    pub secret_prefix: Option<String>,
    /// Which layer determined each value.
    pub provenance: ConfigProvenance,
}

/// Resolve the effective configuration for a path by merging all layers.
///
/// Precedence (highest to lowest):
/// 1. Repo `.sesame.toml` (`{path}/.sesame.toml`)
/// 2. Workspace `.sesame.toml` (`{root}/{user}/{server}/{org}/.sesame.toml`)
/// 3. User config links (`~/.config/pds/workspaces.toml` `[links]` section)
///
/// The workspace layer applies only to paths inside the workspace
/// layout; a path outside it skips that layer. A path inside the layout
/// with a non-canonical directory is an error, not a skipped layer.
///
/// # Errors
///
/// Returns `WorkspaceError::ConfigError` if any `.sesame.toml` file is
/// malformed, and `WorkspaceError::NonCanonical` or
/// `WorkspaceError::PathValidation` for an invalid path inside the layout.
pub fn resolve_effective_config(
    user_config: &WorkspaceConfig,
    layout: &WorkspaceLayout,
    path: &Path,
) -> Result<EffectiveWorkspaceConfig, WorkspaceError> {
    let mut result = EffectiveWorkspaceConfig::default();

    // Layer 1: User config links (lowest priority of file-based layers)
    if let Some(profile) = resolve_workspace_profile(user_config, path)? {
        result.profile = Some(profile);
        result.provenance.profile_source = "user config link";
    }

    // Layer 2: Workspace .sesame.toml (org-level dir)
    let parsed = match crate::convention::parse_path(&layout.root, path) {
        Ok(parsed) => Some(parsed),
        Err(WorkspaceError::NotInWorkspace(_)) => None,
        Err(e) => return Err(e),
    };
    if let Some(parsed) = parsed {
        let workspace_dir = layout
            .user_dir()
            .join(parsed.host.as_dir_name())
            .join(parsed.namespace.as_path());
        if let Some(ws_config) = load_local_config(&workspace_dir)? {
            if let Some(ref p) = ws_config.profile {
                result.profile = Some(p.clone());
                result.provenance.profile_source = "workspace .sesame.toml";
            }
            result.env.extend(ws_config.env);
            result.tags.extend(ws_config.tags);
            if ws_config.secret_prefix.is_some() {
                result.secret_prefix = ws_config.secret_prefix;
                result.provenance.secret_prefix_source = "workspace .sesame.toml";
            }
        }
    }

    // Layer 3: Repo .sesame.toml (highest file-based priority)
    if let Some(repo_config) = load_local_config(path)? {
        if let Some(ref p) = repo_config.profile {
            result.profile = Some(p.clone());
            result.provenance.profile_source = "repo .sesame.toml";
        }
        result.env.extend(repo_config.env);
        result.tags.extend(repo_config.tags);
        if repo_config.secret_prefix.is_some() {
            result.secret_prefix = repo_config.secret_prefix;
            result.provenance.secret_prefix_source = "repo .sesame.toml";
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_workspace_types::{GitHost, NamespacePath, RemoteIdentity, RepositoryName};

    fn test_config() -> WorkspaceConfig {
        let mut config = WorkspaceConfig::default();
        config
            .links
            .insert("/workspace/user/github.com/org".into(), "personal".into());
        config
            .links
            .insert("/workspace/user/github.com/org/k9".into(), "work".into());
        config
    }

    fn layout(root: &Path) -> WorkspaceLayout {
        WorkspaceLayout {
            root: root.to_path_buf(),
            user: WorkspaceUser::new("user").unwrap(),
        }
    }

    fn coordinate(ns: &str, repo: &str) -> WorkspaceCoordinate {
        WorkspaceCoordinate::from_remote_repository(&RemoteIdentity::new(
            GitHost::new("github.com").unwrap(),
            NamespacePath::new(ns).unwrap(),
            RepositoryName::new(repo).unwrap(),
        ))
    }

    #[test]
    fn resolve_profile_exact_match() {
        let profile = resolve_workspace_profile(
            &test_config(),
            Path::new("/workspace/user/github.com/org/k9"),
        )
        .unwrap();
        assert_eq!(profile.as_deref(), Some("work"));
    }

    #[test]
    fn resolve_profile_prefix_match() {
        let profile = resolve_workspace_profile(
            &test_config(),
            Path::new("/workspace/user/github.com/org/other-repo"),
        )
        .unwrap();
        assert_eq!(profile.as_deref(), Some("personal"));
    }

    #[test]
    fn resolve_profile_longest_prefix_wins() {
        let profile = resolve_workspace_profile(
            &test_config(),
            Path::new("/workspace/user/github.com/org/k9/sub"),
        )
        .unwrap();
        assert_eq!(profile.as_deref(), Some("work"));
    }

    #[test]
    fn resolve_profile_respects_component_boundary() {
        let profile = resolve_workspace_profile(
            &test_config(),
            Path::new("/workspace/user/github.com/organic"),
        )
        .unwrap();
        assert!(profile.is_none());
    }

    #[test]
    fn resolve_profile_trailing_slash_link() {
        let mut config = WorkspaceConfig::default();
        config
            .links
            .insert("/workspace/user/github.com/org/".into(), "slash".into());
        assert_eq!(
            resolve_workspace_profile(&config, Path::new("/workspace/user/github.com/org/repo"))
                .unwrap()
                .as_deref(),
            Some("slash")
        );
    }

    #[test]
    fn resolve_profile_no_match() {
        assert!(
            resolve_workspace_profile(&test_config(), Path::new("/home/user/project"))
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_root_has_one_link_key_form() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let repo = real.join("user/github.com/org/repo");
        std::fs::create_dir_all(&repo).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let via_alias = alias.join("user/github.com/org/repo/");

        let key_of = |path: &Path| core_config::edit::link_key(&physical_path(path).unwrap());
        let key = key_of(&via_alias).unwrap();
        assert_eq!(key, key_of(&repo).unwrap());
        assert!(!key.ends_with('/'), "{key}");

        let mut config = WorkspaceConfig::default();
        config.links.insert(key, "work".into());
        for query in [&repo, &via_alias] {
            assert_eq!(
                resolve_workspace_profile(&config, query)
                    .unwrap()
                    .as_deref(),
                Some("work"),
                "{}",
                query.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn layout_root_is_physical() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let layout = WorkspaceLayout::new(&alias, WorkspaceUser::new("user").unwrap()).unwrap();
        assert_eq!(layout.root, std::fs::canonicalize(&real).unwrap());
    }

    #[test]
    fn root_override_takes_precedence_over_configured_root() {
        let configured = tempfile::tempdir().unwrap();
        let overridden = tempfile::tempdir().unwrap();
        let mut config = WorkspaceConfig::default();
        config.settings.root = configured.path().to_path_buf();
        config.settings.user = WorkspaceUser::new("user").unwrap();

        let plain = core_layout::Layout::under(configured.path());
        assert_eq!(
            WorkspaceLayout::from_config(&plain, &config).unwrap().root,
            physical_path(configured.path()).unwrap()
        );
        let with_override = core_layout::Layout::new(core_layout::Environment {
            workspace_root: Some(overridden.path().to_path_buf()),
            ..core_layout::Environment::default()
        });
        assert_eq!(
            WorkspaceLayout::from_config(&with_override, &config)
                .unwrap()
                .root,
            physical_path(overridden.path()).unwrap()
        );
    }

    #[test]
    fn path_of_is_canonical() {
        assert_eq!(
            layout(Path::new("/w")).path_of(&coordinate("NixOS", "NixPkgs")),
            PathBuf::from("/w/user/github.com/nixos/nixpkgs")
        );
    }

    #[test]
    fn checked_path_accepts_absent_and_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path());
        let coord = coordinate("nixos", "nixpkgs");
        assert_eq!(l.checked_path(&coord).unwrap(), l.path_of(&coord));
        std::fs::create_dir_all(l.path_of(&coord)).unwrap();
        assert_eq!(l.checked_path(&coord).unwrap(), l.path_of(&coord));
    }

    #[test]
    fn checked_path_rejects_case_variant_at_any_level() {
        for existing in [
            &["user", "github.com", "NixOS"][..],
            &["user", "github.com", "nixos", "NixPkgs"][..],
            &["user", "GitHub.com"][..],
            &["User"][..],
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut on_disk = dir.path().to_path_buf();
            on_disk.extend(existing);
            std::fs::create_dir_all(&on_disk).unwrap();
            let err = layout(dir.path())
                .checked_path(&coordinate("NixOS", "NixPkgs"))
                .unwrap_err();
            assert!(
                matches!(&err, WorkspaceError::CaseConflict { existing: e, .. } if *e == on_disk),
                "{existing:?}: {err}"
            );
        }
    }

    #[test]
    fn load_local_config_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_local_config(dir.path()).unwrap().is_none());
    }

    #[test]
    fn load_local_config_present() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
            profile = "work"
            secret_prefix = "MYAPP"
            [env]
            RUST_LOG = "debug"
        "#;
        std::fs::write(dir.path().join(".sesame.toml"), content).unwrap();
        let cfg = load_local_config(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.profile.as_deref(), Some("work"));
        assert_eq!(cfg.secret_prefix.as_deref(), Some("MYAPP"));
        assert_eq!(cfg.env["RUST_LOG"], "debug");
    }

    #[test]
    fn effective_config_repo_overrides_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let org_dir = root.join("user").join("github.com").join("org");
        let repo_dir = org_dir.join("repo");
        std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

        std::fs::write(
            org_dir.join(".sesame.toml"),
            "profile = \"workspace-profile\"\n[env]\nSHARED = \"from-workspace\"\nONLY_WS = \"ws\"\n",
        )
        .unwrap();
        std::fs::write(
            repo_dir.join(".sesame.toml"),
            "profile = \"repo-profile\"\n[env]\nSHARED = \"from-repo\"\nONLY_REPO = \"repo\"\n",
        )
        .unwrap();

        let mut user_config = WorkspaceConfig::default();
        user_config.links.insert(
            physical_path(&repo_dir).unwrap().display().to_string(),
            "user-link-profile".into(),
        );

        let eff = resolve_effective_config(&user_config, &layout(root), &repo_dir).unwrap();
        assert_eq!(eff.profile.as_deref(), Some("repo-profile"));
        assert_eq!(eff.provenance.profile_source, "repo .sesame.toml");
        assert_eq!(eff.env["SHARED"], "from-repo");
        assert_eq!(eff.env["ONLY_WS"], "ws");
        assert_eq!(eff.env["ONLY_REPO"], "repo");
    }

    #[test]
    fn effective_config_user_link_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo_dir = root
            .join("user")
            .join("github.com")
            .join("org")
            .join("repo");
        std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

        let mut user_config = WorkspaceConfig::default();
        user_config.links.insert(
            physical_path(&repo_dir).unwrap().display().to_string(),
            "linked-profile".into(),
        );

        let eff = resolve_effective_config(&user_config, &layout(root), &repo_dir).unwrap();
        assert_eq!(eff.profile.as_deref(), Some("linked-profile"));
        assert_eq!(eff.provenance.profile_source, "user config link");
    }

    #[test]
    fn effective_config_outside_layout_skips_workspace_layer() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let eff = resolve_effective_config(
            &WorkspaceConfig::default(),
            &layout(root.path()),
            elsewhere.path(),
        )
        .unwrap();
        assert!(eff.profile.is_none());
    }

    #[test]
    fn effective_config_non_canonical_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo_dir = root
            .join("user")
            .join("github.com")
            .join("Org")
            .join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        assert!(matches!(
            resolve_effective_config(&WorkspaceConfig::default(), &layout(root), &repo_dir),
            Err(WorkspaceError::NonCanonical { .. })
        ));
    }
}
