//! Validated workspace identity types for Open Sesame.
//!
//! This crate provides the foundational types that core-config and
//! sesame-workspace both consume. It has no platform dependencies and
//! no Git library dependencies. All types validate on construction and
//! are safe to use in filesystem paths, URL construction, and
//! serialization without further checking.
#![forbid(unsafe_code)]

pub mod v1;
pub use v1::*;
