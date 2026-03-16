//! Fuzzy matching, frecency scoring, and index management for PDS.
//!
//! Uses nucleo for interactive fuzzy matching and SQLite for frecency
//! persistence. Frecency uses Mozilla double-exponential decay.
//!
//! This crate is consumed by daemon-launcher and provides:
//! - `FuzzyMatcher`: nucleo-backed parallel fuzzy matcher
//! - `FrecencyDb`: SQLite-backed per-profile frecency index
//! - `SearchEngine`: combines fuzzy + frecency for ranked results
#![forbid(unsafe_code)]

mod frecency;
mod matcher;
mod search;

pub use frecency::FrecencyDb;
pub use matcher::{FuzzyMatcher, MatchItem, inject_items};
pub use search::{SearchEngine, SearchResult};
