//! Core domain types for Open Sesame
//!
//! Contains pure domain logic with no I/O dependencies.
//! All types here are testable without Wayland.

pub mod hint;
pub mod launcher;
pub mod matcher;
pub mod window;

pub use hint::{HintAssignment, HintSequence, WindowHint};
pub use launcher::LaunchCommand;
pub use matcher::{HintMatcher, MatchResult};
pub use window::{AppId, Window, WindowId};
