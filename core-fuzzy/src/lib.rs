//! Fuzzy matching, frecency scoring, and index management for PDS.
//!
//! Uses nucleo for interactive fuzzy matching and SQLite FTS5 for
//! structured datasets. Frecency uses Mozilla double-exponential decay.
#![forbid(unsafe_code)]
