//! Input processing module
//!
//! Handles keyboard input and converts to actions.

mod buffer;
mod processor;

pub use buffer::InputBuffer;
pub use processor::{InputAction, InputProcessor, SelectionDirection};
