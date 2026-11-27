//! In-place edits of configuration files.
//!
//! Configuration is layered: `workspaces.toml` plus `workspaces.d/*.toml`
//! fragments, and `config.toml` plus `config.d/*.toml` drop-ins and
//! `profiles/*/config.toml` overrides above the read-only system policy.
//! Loading merges the layers; writing must not. Every edit targets the
//! single file that defines the key, parsed and rewritten with
//! `toml_edit` so comments, ordering, and formatting survive. This module
//! is the only configuration write path.
//!
//! Every failure is `core_types::Error::Config` naming the file or path.

use std::path::{Path, PathBuf};

use core_layout::Layout;
use core_types::Error;
use toml_edit::{DocumentMut, Item, Value};

use crate::loader::{system_policy_file, toml_files_in};
use crate::loader_workspace::workspace_config_files;

/// One key whose value (or, for links, whose name) changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRewrite {
    /// The file that defines the key.
    pub file: PathBuf,
    /// Dotted key path (`links."/workspace/..."`, `profiles.work.launch_profiles.dev.cwd`).
    pub key: String,
    pub from: String,
    pub to: String,
}

/// The result of a launch-path rewrite pass.
#[derive(Debug, Default)]
pub struct LaunchPathRewrites {
    /// Rewrites in user-owned files (applied when requested).
    pub writable: Vec<ConfigRewrite>,
    /// Rewrites needed in the system policy, which this process must not edit.
    pub read_only: Vec<ConfigRewrite>,
}

/// Parse a file into an editable document; a missing file is empty.
fn read_document(path: &Path) -> core_types::Result<DocumentMut> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(Error::Config(format!(
                "failed to read {}: {e}",
                path.display()
            )));
        }
    };
    contents
        .parse()
        .map_err(|e| Error::Config(format!("failed to parse {}: {e}", path.display())))
}

fn write_document(path: &Path, doc: &DocumentMut) -> core_types::Result<()> {
    core_layout::file::write(
        path,
        doc.to_string().as_bytes(),
        core_layout::file::Mode::OwnerOnly,
    )
    .map_err(|e| Error::Config(e.to_string()))
}

/// The table `key` of `doc`, created when absent.
fn table_mut<'d>(
    doc: &'d mut DocumentMut,
    key: &str,
    file: &Path,
) -> core_types::Result<&'d mut dyn toml_edit::TableLike> {
    doc.entry(key)
        .or_insert_with(toml_edit::table)
        .as_table_like_mut()
        .ok_or_else(|| Error::Config(format!("{}: `{key}` is not a table", file.display())))
}

/// The file among `files` whose `links` table defines `key`; the last
/// one wins, because fragments load after the base and override it.
fn link_owner(files: &[PathBuf], key: &str) -> core_types::Result<Option<PathBuf>> {
    let mut owner = None;
    for file in files {
        let doc = read_document(file)?;
        if doc
            .get("links")
            .and_then(Item::as_table_like)
            .is_some_and(|links| links.contains_key(key))
        {
            owner = Some(file.clone());
        }
    }
    Ok(owner)
}

/// The `links` key for `path`: the path rebuilt from its components,
/// which drops trailing separators and `.` components, so `/a/b` and
/// `/a/b/` are one key. Resolving symlinks is the caller's concern:
/// callers pass the physical path (`sesame_workspace::config::physical_path`).
///
/// # Errors
///
/// `Error::Config` for a non-UTF-8 path, which a TOML key cannot hold.
pub fn link_key(path: &Path) -> core_types::Result<String> {
    let normalized: PathBuf = path.components().collect();
    normalized
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| Error::Config(format!("link path is not UTF-8: {}", normalized.display())))
}

/// Set a workspace-to-profile link in the file that defines it, or in
/// `workspaces.toml` when no file does.
///
/// # Errors
///
/// When the path is not UTF-8, or a file cannot be listed, read, parsed,
/// or written.
pub fn set_workspace_link(
    layout: &Layout,
    path: &Path,
    profile: &core_types::TrustProfileName,
) -> core_types::Result<()> {
    let key = link_key(path)?;
    let files = workspace_config_files(layout)?;
    let target = match link_owner(&files, &key)? {
        Some(owner) => owner,
        None => layout.workspaces_file()?,
    };
    let mut doc = read_document(&target)?;
    table_mut(&mut doc, "links", &target)?.insert(&key, toml_edit::value(profile.as_ref()));
    write_document(&target, &doc)
}

/// Remove a workspace-to-profile link from every file that defines it.
/// Returns whether any file defined it.
///
/// # Errors
///
/// When the path is not UTF-8, or a file cannot be listed, read, parsed,
/// or written.
pub fn remove_workspace_link(layout: &Layout, path: &Path) -> core_types::Result<bool> {
    let key = link_key(path)?;
    let mut removed = false;
    for file in workspace_config_files(layout)? {
        let mut doc = read_document(&file)?;
        let changed = doc
            .get_mut("links")
            .and_then(Item::as_table_like_mut)
            .and_then(|links| links.remove(&key))
            .is_some();
        if changed {
            write_document(&file, &doc)?;
            removed = true;
        }
    }
    Ok(removed)
}

/// Set `settings.root` and `settings.user` in `workspaces.toml`.
///
/// # Errors
///
/// When the root is not UTF-8 or the file cannot be read, parsed, or
/// written.
pub fn set_workspace_settings(layout: &Layout, root: &Path, user: &str) -> core_types::Result<()> {
    let path = layout.workspaces_file()?;
    let root = root
        .to_str()
        .ok_or_else(|| Error::Config(format!("workspace root is not UTF-8: {}", root.display())))?;
    let mut doc = read_document(&path)?;
    let settings = table_mut(&mut doc, "settings", &path)?;
    settings.insert("root", toml_edit::value(root));
    settings.insert("user", toml_edit::value(user));
    write_document(&path, &doc)
}

/// Rename link keys across `workspaces.toml` and its fragments.
///
/// `map` returns the new key for a key that must change. With `apply`,
/// each owning file is rewritten; otherwise only the plan is returned.
///
/// # Errors
///
/// When a file cannot be listed, read, parsed, or written, or a renamed
/// key would collide with an existing key in the same file.
pub fn rewrite_workspace_links(
    layout: &Layout,
    map: &dyn Fn(&str) -> Option<String>,
    apply: bool,
) -> core_types::Result<Vec<ConfigRewrite>> {
    let mut rewrites = Vec::new();
    for file in workspace_config_files(layout)? {
        let mut doc = read_document(&file)?;
        let Some(links) = doc.get_mut("links").and_then(Item::as_table_like_mut) else {
            continue;
        };
        let renames: Vec<(String, String)> = links
            .iter()
            .filter_map(|(key, _)| map(key).map(|to| (key.to_string(), to)))
            .collect();
        for (from, to) in &renames {
            if links.contains_key(to) {
                return Err(Error::Config(format!(
                    "{}: cannot rename link {from} to {to}: {to} is already linked",
                    file.display()
                )));
            }
            if let Some(item) = links.remove(from) {
                links.insert(to, item);
            }
            rewrites.push(ConfigRewrite {
                file: file.clone(),
                key: format!("links.{from:?}"),
                from: from.clone(),
                to: to.clone(),
            });
        }
        if apply && !renames.is_empty() {
            write_document(&file, &doc)?;
        }
    }
    Ok(rewrites)
}

/// Every `config.toml` layer, each with whether this process may write
/// it: the system policy (read-only), the user config, its drop-ins, and
/// every profile override (all profiles, not only an active one).
///
/// A directory under `profiles` whose name is not a valid profile name is
/// an error: no profile can own it, so its contents are not configuration.
fn config_layers(layout: &Layout) -> core_types::Result<Vec<(PathBuf, bool)>> {
    let mut layers: Vec<(PathBuf, bool)> = system_policy_file(layout)?
        .map(|p| (p, false))
        .into_iter()
        .collect();
    layers.push((layout.config_file()?, true));
    layers.extend(
        toml_files_in(&layout.config_drop_in_dir()?)?
            .into_iter()
            .map(|p| (p, true)),
    );
    let profiles = layout.profiles_dir()?;
    let list_failed =
        |e: std::io::Error| Error::Config(format!("failed to list {}: {e}", profiles.display()));
    let mut overrides = Vec::new();
    match std::fs::read_dir(&profiles) {
        Ok(entries) => {
            for entry in entries {
                let name = entry.map_err(list_failed)?.file_name();
                let profile = name
                    .to_str()
                    .and_then(|name| core_types::TrustProfileName::try_from(name).ok())
                    .ok_or_else(|| {
                        Error::Config(format!(
                            "{}: not a valid profile name",
                            profiles.join(&name).display()
                        ))
                    })?;
                overrides.push(layout.profile_config_file(&profile)?);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(list_failed(e)),
    }
    overrides.sort();
    layers.extend(overrides.into_iter().map(|p| (p, true)));
    Ok(layers)
}

/// Map the path portion of a launch-profile value. `devshell` values may
/// carry a `#attr` flake fragment, which is preserved.
fn map_launch_value(
    field: &str,
    value: &str,
    map: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    if field == "devshell"
        && let Some((path, attr)) = value.split_once('#')
    {
        return map(path).map(|p| format!("{p}#{attr}"));
    }
    map(value)
}

/// Rewrite `cwd` and `devshell` paths in every launch profile.
///
/// Scans `profiles.*.launch_profiles.*.{cwd,devshell}` in each layer.
/// Values in user-owned files are rewritten with `apply`; values in the
/// system policy are reported as read-only and never written.
///
/// # Errors
///
/// When a file cannot be listed, read, parsed, or written.
pub fn rewrite_launch_paths(
    layout: &Layout,
    map: &dyn Fn(&str) -> Option<String>,
    apply: bool,
) -> core_types::Result<LaunchPathRewrites> {
    let mut result = LaunchPathRewrites::default();
    for (file, writable) in config_layers(layout)? {
        if !crate::loader::exists(&file)? {
            continue;
        }
        let mut doc = read_document(&file)?;
        let mut found = Vec::new();
        if let Some(profiles) = doc.get_mut("profiles").and_then(Item::as_table_like_mut) {
            for (profile, item) in profiles.iter_mut() {
                let Some(launch) = item
                    .as_table_like_mut()
                    .and_then(|p| p.get_mut("launch_profiles"))
                    .and_then(Item::as_table_like_mut)
                else {
                    continue;
                };
                for (name, lp) in launch.iter_mut() {
                    let Some(lp) = lp.as_table_like_mut() else {
                        continue;
                    };
                    for field in ["cwd", "devshell"] {
                        let Some(value) = lp.get_mut(field).and_then(Item::as_value_mut) else {
                            continue;
                        };
                        let Some(current) = value.as_str().map(str::to_string) else {
                            continue;
                        };
                        let Some(to) = map_launch_value(field, &current, map) else {
                            continue;
                        };
                        if writable && apply {
                            let decor = value.decor().clone();
                            *value = Value::from(to.as_str());
                            *value.decor_mut() = decor;
                        }
                        found.push(ConfigRewrite {
                            file: file.clone(),
                            key: format!("profiles.{profile}.launch_profiles.{name}.{field}"),
                            from: current,
                            to,
                        });
                    }
                }
            }
        }
        if found.is_empty() {
            continue;
        }
        if writable {
            if apply {
                write_document(&file, &doc)?;
            }
            result.writable.extend(found);
        } else {
            result.read_only.extend(found);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// A layout under a fresh temporary root, with the root kept alive.
    fn layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        (dir, layout)
    }

    fn fragment(layout: &Layout, name: &str) -> PathBuf {
        layout.workspaces_drop_in_dir().unwrap().join(name)
    }

    fn profile(name: &str) -> core_types::TrustProfileName {
        core_types::TrustProfileName::try_from(name).unwrap()
    }

    #[test]
    fn set_link_writes_base_and_preserves_comments() {
        let (_root, layout) = layout();
        let base = layout.workspaces_file().unwrap();
        write(&base, "# keep me\n[settings]\nroot = \"/w\"\n");
        set_workspace_link(&layout, Path::new("/w/u/github.com/org"), &profile("work")).unwrap();
        let text = read(&base);
        assert!(text.contains("# keep me"), "{text}");
        assert!(
            text.contains("\"/w/u/github.com/org\" = \"work\""),
            "{text}"
        );
    }

    #[test]
    fn set_link_never_copies_fragment_links_into_base() {
        let (_root, layout) = layout();
        let base = layout.workspaces_file().unwrap();
        let frag = fragment(&layout, "10-team.toml");
        write(&base, "[links]\n\"/a\" = \"base\"\n");
        write(&frag, "[links]\n\"/b\" = \"team\"\n");
        set_workspace_link(&layout, Path::new("/c"), &profile("new")).unwrap();
        set_workspace_link(&layout, Path::new("/b"), &profile("other")).unwrap();
        assert!(read(&frag).contains("\"/b\" = \"other\""));
        let base_text = read(&base);
        assert!(!base_text.contains("/b"), "{base_text}");
        assert!(base_text.contains("\"/c\" = \"new\""), "{base_text}");
    }

    #[test]
    fn remove_link_from_fragment() {
        let (_root, layout) = layout();
        let frag = fragment(&layout, "10-team.toml");
        write(&frag, "[links]\n\"/b\" = \"team\"\n\"/c\" = \"x\"\n");
        assert!(remove_workspace_link(&layout, Path::new("/b/")).unwrap());
        assert!(!read(&frag).contains("/b"));
        assert!(!remove_workspace_link(&layout, Path::new("/missing")).unwrap());
    }

    #[test]
    fn link_keys_drop_trailing_separators() {
        let (_root, layout) = layout();
        set_workspace_link(&layout, Path::new("/w/u/org/"), &profile("a")).unwrap();
        set_workspace_link(&layout, Path::new("/w/u/org"), &profile("b")).unwrap();
        let text = read(&layout.workspaces_file().unwrap());
        assert!(text.contains("\"/w/u/org\" = \"b\""), "{text}");
        assert!(!text.contains("/org/"), "{text}");
    }

    #[test]
    fn non_table_links_is_an_error_naming_the_file() {
        let (_root, layout) = layout();
        let base = layout.workspaces_file().unwrap();
        write(&base, "links = 3\n");
        let err = set_workspace_link(&layout, Path::new("/w"), &profile("a")).unwrap_err();
        assert!(
            matches!(&err, Error::Config(m) if m.contains("`links` is not a table")),
            "{err}"
        );
    }

    #[test]
    fn rewrite_links_per_file_and_dry_run() {
        let (_root, layout) = layout();
        let base = layout.workspaces_file().unwrap();
        let frag = fragment(&layout, "10-team.toml");
        write(&base, "[links]\n\"/w/u/github.com/Org\" = \"work\"\n");
        write(&frag, "[links]\n\"/w/u/github.com/Org/Repo\" = \"team\"\n");
        let map = |key: &str| key.contains("Org").then(|| key.to_ascii_lowercase());

        let plan = rewrite_workspace_links(&layout, &map, false).unwrap();
        assert_eq!(plan.len(), 2);
        assert!(read(&base).contains("/Org\""));

        rewrite_workspace_links(&layout, &map, true).unwrap();
        assert!(read(&base).contains("\"/w/u/github.com/org\" = \"work\""));
        assert!(read(&frag).contains("\"/w/u/github.com/org/repo\" = \"team\""));
    }

    #[test]
    fn rewrite_links_refuses_collision() {
        let (_root, layout) = layout();
        let base = layout.workspaces_file().unwrap();
        write(&base, "[links]\n\"/Org\" = \"a\"\n\"/org\" = \"b\"\n");
        let map = |key: &str| (key == "/Org").then(|| "/org".to_string());
        assert!(rewrite_workspace_links(&layout, &map, true).is_err());
        assert!(read(&base).contains("\"/Org\" = \"a\""));
    }

    #[test]
    fn invalid_profile_directory_is_an_error() {
        let (_root, layout) = layout();
        let bogus = layout.profiles_dir().unwrap().join(".hidden");
        write(&bogus.join("config.toml"), "");
        let err = rewrite_launch_paths(&layout, &|_| None, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid profile name"), "{err}");
    }

    #[test]
    fn rewrite_launch_paths_preserves_decor_and_reports_policy() {
        let (_root, layout) = layout();
        let user = layout.config_file().unwrap();
        let profile = layout.profile_config_file(&profile("work")).unwrap();
        let policy = layout.system_policy_file().unwrap().to_path_buf();
        write(
            &user,
            "[profiles.work.launch_profiles.dev]\ncwd = \"/w/u/github.com/Org/repo\" # here\ndevshell = \"/w/u/github.com/Org/repo#rust\"\n",
        );
        write(
            &profile,
            "[profiles.work.launch_profiles.ops]\ncwd = \"/w/u/github.com/Org/ops\"\n",
        );
        write(
            &policy,
            "[profiles.work.launch_profiles.corp]\ncwd = \"/w/u/github.com/Org\"\n",
        );
        let map = |p: &str| p.contains("/Org").then(|| p.replace("/Org", "/org"));
        let result = rewrite_launch_paths(&layout, &map, true).unwrap();
        assert_eq!(result.writable.len(), 3);
        assert_eq!(result.read_only.len(), 1);
        let text = read(&user);
        assert!(
            text.contains("cwd = \"/w/u/github.com/org/repo\" # here"),
            "{text}"
        );
        assert!(
            text.contains("devshell = \"/w/u/github.com/org/repo#rust\""),
            "{text}"
        );
        assert!(read(&profile).contains("/org/ops"));
        assert!(read(&policy).contains("/Org"));
    }

    #[test]
    fn set_settings_preserves_other_keys() {
        let (_root, layout) = layout();
        let base = layout.workspaces_file().unwrap();
        write(&base, "[settings]\ntransport = \"ssh\"\n");
        set_workspace_settings(&layout, Path::new("/w"), "alice").unwrap();
        let text = read(&base);
        assert!(text.contains("transport = \"ssh\""));
        assert!(text.contains("root = \"/w\"") && text.contains("user = \"alice\""));
    }
}
