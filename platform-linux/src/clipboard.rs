//! Wayland clipboard access via data-control protocols.
//!
//! Abstracts clipboard read/write over:
//! - `ext-data-control-v1` (preferred, standardized)
//! - `wlr-data-control-v1` (fallback for older compositors)
//!
//! COSMIC note: requires `COSMIC_DATA_CONTROL_ENABLED=1` environment variable.
//!
//! Phase 1: trait definition only. Implementation in Phase 5 (Clipboard).

use std::future::Future;
use std::pin::Pin;

/// Clipboard content with MIME type metadata.
#[derive(Debug, Clone)]
pub struct ClipboardContent {
    pub mime_type: String,
    pub data: Vec<u8>,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction over Wayland data-control clipboard protocols.
pub trait DataControl: Send + Sync {
    /// Read the current clipboard selection.
    fn read_selection(&self) -> BoxFuture<'_, core_types::Result<Option<ClipboardContent>>>;

    /// Write content to the clipboard.
    fn write_selection(&self, content: &ClipboardContent) -> BoxFuture<'_, core_types::Result<()>>;

    /// Subscribe to clipboard change notifications.
    /// Returns a receiver that yields each time the clipboard changes.
    fn subscribe(
        &self,
    ) -> BoxFuture<'_, core_types::Result<tokio::sync::mpsc::Receiver<ClipboardContent>>>;

    /// Protocol name for diagnostics.
    fn protocol_name(&self) -> &str;
}

/// Detect and instantiate the appropriate data-control backend.
///
/// Phase 1: returns an error (no implementations yet).
pub fn connect_data_control() -> core_types::Result<Box<dyn DataControl>> {
    Err(core_types::Error::Platform(
        "data-control connection not yet implemented (Phase 5)".into(),
    ))
}
