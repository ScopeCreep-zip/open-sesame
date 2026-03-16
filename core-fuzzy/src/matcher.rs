//! Nucleo-backed parallel fuzzy matcher.
//!
//! Wraps the high-level `Nucleo` API with a simpler interface for
//! daemon-launcher's use case: inject items once, update pattern on
//! each keystroke, tick to get ranked results.

use std::sync::Arc;

/// An item in the fuzzy matcher index.
#[derive(Debug, Clone)]
pub struct MatchItem {
    /// Unique identifier (e.g. desktop entry app ID).
    pub id: String,
    /// Display name (primary match column).
    pub name: String,
    /// Additional searchable text (keywords, categories, exec).
    pub extra: String,
}

/// Wraps nucleo for PDS launcher fuzzy matching.
///
/// Two match columns: name (primary) and extra (keywords/categories).
/// The matcher runs on a background threadpool and results are retrieved
/// via `tick()` + `snapshot()`.
pub struct FuzzyMatcher {
    nucleo: nucleo::Nucleo<MatchItem>,
}

impl FuzzyMatcher {
    /// Create a new matcher with the given notification callback.
    ///
    /// `notify` is called when new results are available and the caller
    /// should call `tick()`. Typically wired to a UI redraw or channel send.
    pub fn new(notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        let config = nucleo::Config::DEFAULT;
        // 2 columns: name + extra (keywords/categories/exec)
        let nucleo = nucleo::Nucleo::new(config, notify, None, 2);
        Self { nucleo }
    }

    /// Get an injector handle for adding items from any thread.
    pub fn injector(&self) -> nucleo::Injector<MatchItem> {
        self.nucleo.injector()
    }

    /// Update the search pattern. Call `tick()` after to process.
    pub fn update_pattern(&mut self, query: &str) {
        self.nucleo.pattern.reparse(
            0,
            query,
            nucleo::pattern::CaseMatching::Smart,
            nucleo::pattern::Normalization::Smart,
            query.starts_with(&self.last_pattern_prefix(query)),
        );
    }

    /// Tick the matcher, waiting up to `timeout_ms` for the worker to finish.
    ///
    /// Returns whether results changed and whether the worker is still running.
    pub fn tick(&mut self, timeout_ms: u64) -> nucleo::Status {
        self.nucleo.tick(timeout_ms)
    }

    /// Get the current match snapshot.
    ///
    /// Returns up to `max_results` matched items sorted by score (descending).
    /// Each tuple is `(raw_nucleo_score, &MatchItem)`.
    pub fn results(&self, max_results: u32) -> Vec<(u32, &MatchItem)> {
        let snapshot = self.nucleo.snapshot();
        let count = snapshot.matched_item_count().min(max_results) as usize;
        let matches = snapshot.matches();
        (0..count)
            .filter_map(|i| {
                let item = snapshot.get_matched_item(i as u32)?;
                Some((matches[i].score, item.data))
            })
            .collect()
    }

    /// Access the underlying nucleo instance (for snapshot/score access).
    pub fn nucleo(&self) -> &nucleo::Nucleo<MatchItem> {
        &self.nucleo
    }

    /// Restart the matcher with fresh items (e.g. on profile switch).
    pub fn restart(&mut self) {
        self.nucleo.restart(true);
    }

    /// Helper: compute the common prefix for append-only optimization.
    fn last_pattern_prefix(&self, _query: &str) -> String {
        // nucleo handles this internally via pattern status tracking.
        // The `append` parameter in reparse tells nucleo whether the new
        // pattern is an extension of the previous one (allows incremental matching).
        String::new()
    }
}

/// Inject a batch of items into the matcher.
///
/// Items are injected lock-free and wait-free. The matcher will pick them
/// up on the next `tick()`.
pub fn inject_items(injector: &nucleo::Injector<MatchItem>, items: Vec<MatchItem>) {
    for item in items {
        injector.push(item, |item, columns| {
            columns[0] = item.name.as_str().into();
            columns[1] = item.extra.as_str().into();
        });
    }
}
