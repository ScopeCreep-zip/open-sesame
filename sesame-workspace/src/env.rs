//! The crate's reader of process environment variables that are not
//! locations: proxy settings (`net::ProxyPolicy`) and the forge
//! credential (`forge::github`). Locations, including the workspace root
//! override, come from `core_layout::Layout`.

use crate::WorkspaceError;

/// The value of the first of `names` that is set, in order. An empty
/// value counts as unset (the curl/git convention for proxy variables).
///
/// # Errors
///
/// `WorkspaceError::ConfigError` naming the variable when one is set to a
/// value that is not UTF-8: ignoring it would silently drop the setting
/// (bypass a proxy, or connect unauthenticated).
#[expect(
    clippy::disallowed_methods,
    reason = "the single reader of non-location environment variables in this crate"
)]
pub(crate) fn first_set(names: &[&str]) -> Result<Option<String>, WorkspaceError> {
    first_set_with(names, |name| std::env::var(name))
}

/// [`first_set`] over an injectable variable lookup.
fn first_set_with(
    names: &[&str],
    lookup: impl Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<Option<String>, WorkspaceError> {
    for &name in names {
        match lookup(name) {
            Ok(value) if !value.is_empty() => return Ok(Some(value)),
            Ok(_) | Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(WorkspaceError::ConfigError(format!(
                    "{name} is set to a value that is not UTF-8"
                )));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_utf8_variable_is_an_error_not_unset() {
        let result = first_set_with(&["HTTPS_PROXY", "https_proxy"], |name| match name {
            "HTTPS_PROXY" => Err(std::env::VarError::NotUnicode("p\u{fffd}".into())),
            _ => Ok("http://fallback:1".into()),
        });
        assert!(matches!(result, Err(WorkspaceError::ConfigError(e)) if e.contains("HTTPS_PROXY")));
    }

    #[test]
    fn first_set_wins_and_empty_counts_as_unset() {
        let both = first_set_with(&["A", "a"], |name| Ok(format!("v-{name}"))).unwrap();
        assert_eq!(both.as_deref(), Some("v-A"));
        let second_only = first_set_with(&["A", "a"], |name| match name {
            "A" => Ok(String::new()),
            _ => Ok("low".into()),
        })
        .unwrap();
        assert_eq!(second_only.as_deref(), Some("low"));
        let none = first_set_with(&["A", "a"], |_| Err(std::env::VarError::NotPresent)).unwrap();
        assert!(none.is_none());
    }
}
