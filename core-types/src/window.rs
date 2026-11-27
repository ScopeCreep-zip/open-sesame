use serde::{Deserialize, Serialize};

use crate::ids::{AppId, CompositorWorkspaceId, MonitorId, ProfileId, WindowId};

/// A toplevel window as the compositor reports it. A field the reporting
/// source does not observe is `None`, never a placeholder value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    pub id: WindowId,
    pub app_id: AppId,
    pub title: String,
    pub workspace_id: Option<CompositorWorkspaceId>,
    pub monitor_id: Option<MonitorId>,
    pub geometry: Option<Geometry>,
    pub is_focused: bool,
    pub is_minimized: Option<bool>,
    pub is_fullscreen: Option<bool>,
    pub profile_id: Option<ProfileId>,
}

impl Window {
    /// The window `id` of `app_id`, titled `title`, focused or not; every
    /// other field unobserved.
    #[must_use]
    pub fn new(id: WindowId, app_id: AppId, title: String, is_focused: bool) -> Self {
        Self {
            id,
            app_id,
            title,
            workspace_id: None,
            monitor_id: None,
            geometry: None,
            is_focused,
            is_minimized: None,
            is_fullscreen: None,
            profile_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Padding {
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
    pub left: u32,
}
