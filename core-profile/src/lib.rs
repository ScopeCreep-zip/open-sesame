//! Profile schema, context-driven activation, isolation contracts, and atomic switching.
//!
//! Implements the multi-persona profile system: ContextEngine evaluates activation
//! rules, SwitchOperation executes atomic profile transitions, and IsolationContract
//! enforces cross-profile data boundary policy.
#![forbid(unsafe_code)]
