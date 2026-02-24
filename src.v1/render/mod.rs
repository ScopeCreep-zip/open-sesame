//! Rendering pipeline
//!
//! Provides composable render passes for the overlay UI.

pub mod context;
pub mod pipeline;
pub mod primitives;
pub mod text;

pub use context::RenderContext;
pub use pipeline::{RenderPass, RenderPipeline};
pub use primitives::{Color, rounded_rect};
pub use text::{FontWeight, TextRenderer};
