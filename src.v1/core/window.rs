//! Window domain types
//!
//! NewTypes for window-related identifiers to provide type safety.

use std::fmt;

/// Unique identifier for a window (from Wayland protocol)
///
/// Wraps a string identifier obtained from the window manager.
/// On Wayland/COSMIC, this is typically a handle from the toplevel manager protocol.
///
/// # Examples
///
/// ```
/// use open_sesame::WindowId;
///
/// let id = WindowId::new("cosmic-toplevel-123");
/// assert_eq!(id.as_str(), "cosmic-toplevel-123");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowId(String);

impl WindowId {
    /// Create a new WindowId from a string identifier
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the underlying string identifier
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WindowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for WindowId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for WindowId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// Application identifier (e.g., "firefox", "com.mitchellh.ghostty")
///
/// Represents an application's unique identifier, typically following
/// reverse-DNS notation on Linux/Wayland systems.
///
/// # Examples
///
/// ```
/// use open_sesame::AppId;
///
/// let app_id = AppId::new("com.mitchellh.ghostty");
/// assert_eq!(app_id.as_str(), "com.mitchellh.ghostty");
/// assert_eq!(app_id.last_segment(), "ghostty");
///
/// let simple = AppId::new("firefox");
/// assert_eq!(simple.last_segment(), "firefox");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppId(String);

impl AppId {
    /// Create a new AppId
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the underlying string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the last segment of a dotted app ID.
    ///
    /// For example, "com.mitchellh.ghostty" returns "ghostty".
    pub fn last_segment(&self) -> &str {
        self.0.split('.').next_back().unwrap_or(&self.0)
    }

    /// Returns a lowercase version for case-insensitive comparison.
    pub fn to_lowercase(&self) -> String {
        self.0.to_lowercase()
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for AppId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for AppId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// A window on the desktop
///
/// Represents a toplevel window obtained from the window manager.
///
/// # Examples
///
/// ```
/// use open_sesame::Window;
///
/// let window = Window::new(
///     "toplevel-1",
///     "firefox",
///     "GitHub - Mozilla Firefox"
/// );
///
/// assert_eq!(window.app_id.as_str(), "firefox");
/// assert_eq!(window.title, "GitHub - Mozilla Firefox");
/// assert!(!window.is_focused);
///
/// let focused = Window::with_focus(
///     "toplevel-2",
///     "ghostty",
///     "Terminal",
///     true
/// );
/// assert!(focused.is_focused);
/// ```
#[derive(Debug, Clone)]
pub struct Window {
    /// Unique identifier for activation
    pub id: WindowId,
    /// Application identifier
    pub app_id: AppId,
    /// Window title
    pub title: String,
    /// Whether this window currently has focus
    pub is_focused: bool,
}

impl Window {
    /// Create a new window
    pub fn new(
        id: impl Into<WindowId>,
        app_id: impl Into<AppId>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            app_id: app_id.into(),
            title: title.into(),
            is_focused: false,
        }
    }

    /// Create a new window with focus state
    pub fn with_focus(
        id: impl Into<WindowId>,
        app_id: impl Into<AppId>,
        title: impl Into<String>,
        is_focused: bool,
    ) -> Self {
        Self {
            id: id.into(),
            app_id: app_id.into(),
            title: title.into(),
            is_focused,
        }
    }

    /// Create a mock window for testing
    #[cfg(test)]
    pub fn mock(app_id: &str, title: &str) -> Self {
        Self::new(format!("mock-{}-{}", app_id, title.len()), app_id, title)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_id() {
        let id = WindowId::new("test-123");
        assert_eq!(id.as_str(), "test-123");
        assert_eq!(format!("{}", id), "test-123");
    }

    #[test]
    fn test_app_id_last_segment() {
        let app = AppId::new("com.mitchellh.ghostty");
        assert_eq!(app.last_segment(), "ghostty");

        let simple = AppId::new("firefox");
        assert_eq!(simple.last_segment(), "firefox");
    }

    #[test]
    fn test_window_creation() {
        let window = Window::new("id-1", "firefox", "GitHub - Mozilla Firefox");
        assert_eq!(window.id.as_str(), "id-1");
        assert_eq!(window.app_id.as_str(), "firefox");
        assert_eq!(window.title, "GitHub - Mozilla Firefox");
    }
}
