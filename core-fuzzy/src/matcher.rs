//! Nucleo-backed parallel fuzzy matcher.
//!
//! Wraps the high-level `Nucleo` API for daemon-launcher's use case:
//! inject items once, update the pattern on each query, settle the
//! matcher, and read the ranked results.

use std::sync::Arc;

/// How long one wait for the matcher worker lasts (nucleo recommends 10 ms).
const TICK_MS: u64 = 10;

/// An item in the fuzzy matcher index.
#[derive(Debug, Clone)]
pub struct MatchItem {
    /// Unique identifier (e.g. desktop entry app ID).
    pub id: String,
    /// Display name (primary match column).
    pub name: String,
    /// Additional searchable text (keywords, categories, exec).
    pub extra: String,
    /// Icon name or absolute path (not searched).
    pub icon: Option<String>,
}

/// Wraps nucleo for PDS launcher fuzzy matching.
///
/// Two match columns: name (primary) and extra (keywords/categories).
/// The matcher runs on a background threadpool; [`settle`](Self::settle)
/// waits for it and [`results`](Self::results) reads its snapshot.
pub struct FuzzyMatcher {
    nucleo: nucleo::Nucleo<MatchItem>,
    /// The query of the last `update_pattern`: nucleo narrows the previous
    /// matches only when the new query extends it.
    last_query: String,
}

impl FuzzyMatcher {
    /// Create a new matcher with the given notification callback.
    ///
    /// `notify` is called when new results are available.
    #[must_use]
    pub fn new(notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        // 2 columns: name + extra (keywords/categories/exec)
        let nucleo = nucleo::Nucleo::new(nucleo::Config::DEFAULT, notify, None, 2);
        Self {
            nucleo,
            last_query: String::new(),
        }
    }

    /// An injector handle for adding items from any thread.
    #[must_use]
    pub fn injector(&self) -> nucleo::Injector<MatchItem> {
        self.nucleo.injector()
    }

    /// Update the search pattern; [`settle`](Self::settle) applies it.
    ///
    /// A query that extends the previous one (typing) re-filters the
    /// previous matches; any other edit (backspace, replacement) rescores
    /// every item. Claiming an extension that is not one loses matches
    /// (`nucleo::pattern::MultiPattern::reparse`).
    pub fn update_pattern(&mut self, query: &str) {
        let append = query.starts_with(self.last_query.as_str());
        self.nucleo.pattern.reparse(
            0,
            query,
            nucleo::pattern::CaseMatching::Smart,
            nucleo::pattern::Normalization::Smart,
            append,
        );
        query.clone_into(&mut self.last_query);
    }

    /// Wait until the worker has matched every injected item against the
    /// current pattern, so the snapshot is complete.
    pub fn settle(&mut self) {
        while self.nucleo.tick(TICK_MS).running {}
    }

    /// Up to `max_results` matched items, highest nucleo score first, each
    /// with its raw score.
    #[must_use]
    pub fn results(&self, max_results: u32) -> Vec<(u32, &MatchItem)> {
        let snapshot = self.nucleo.snapshot();
        let count = snapshot.matched_item_count().min(max_results);
        snapshot
            .matches()
            .iter()
            .zip(snapshot.matched_items(..count))
            .map(|(m, item)| (m.score, item.data))
            .collect()
    }
}

/// Inject a batch of items into the matcher.
///
/// One lock-free batch append and one `notify` call for the whole batch;
/// the matcher picks the items up on the next [`FuzzyMatcher::settle`].
pub fn inject_items(injector: &nucleo::Injector<MatchItem>, items: Vec<MatchItem>) {
    injector.extend(items.into_iter(), |item, columns| {
        columns[0] = item.name.as_str().into();
        columns[1] = item.extra.as_str().into();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn item(name: &str) -> MatchItem {
        MatchItem {
            id: name.into(),
            name: name.into(),
            extra: String::new(),
            icon: None,
        }
    }

    fn names(matcher: &FuzzyMatcher) -> Vec<String> {
        let mut names: Vec<String> = matcher
            .results(u32::MAX)
            .into_iter()
            .map(|(_, item)| item.name.clone())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn removing_characters_widens_the_matches_again() {
        let mut matcher = FuzzyMatcher::new(Arc::new(|| {}));
        inject_items(&matcher.injector(), vec![item("firefox"), item("files")]);
        matcher.update_pattern("fir");
        matcher.settle();
        assert_eq!(names(&matcher), ["firefox"]);
        matcher.update_pattern("fi");
        matcher.settle();
        assert_eq!(names(&matcher), ["files", "firefox"]);
    }

    #[test]
    fn typing_narrows_the_matches() {
        let mut matcher = FuzzyMatcher::new(Arc::new(|| {}));
        inject_items(&matcher.injector(), vec![item("firefox"), item("files")]);
        matcher.update_pattern("fi");
        matcher.settle();
        assert_eq!(names(&matcher), ["files", "firefox"]);
        matcher.update_pattern("fil");
        matcher.settle();
        assert_eq!(names(&matcher), ["files"]);
    }

    #[test]
    fn results_are_capped_and_ranked() {
        let mut matcher = FuzzyMatcher::new(Arc::new(|| {}));
        inject_items(
            &matcher.injector(),
            (0..50).map(|i| item(&format!("app-{i}"))).collect(),
        );
        matcher.update_pattern("app");
        matcher.settle();
        let results = matcher.results(5);
        assert_eq!(results.len(), 5);
        assert!(results.windows(2).all(|pair| pair[0].0 >= pair[1].0));
    }

    #[test]
    fn a_batch_notifies_once() {
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&notified);
        let matcher = FuzzyMatcher::new(Arc::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        }));
        inject_items(
            &matcher.injector(),
            (0..100).map(|i| item(&format!("app-{i}"))).collect(),
        );
        assert_eq!(notified.load(Ordering::Relaxed), 1);
    }
}
