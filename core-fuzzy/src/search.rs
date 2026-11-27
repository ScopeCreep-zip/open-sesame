//! Combined search engine: fuzzy matching + frecency ranking.
//!
//! Blends nucleo fuzzy scores with frecency boosts using a 70/30 weighting
//! (ADR-LNC-004). The fuzzy score provides relevance to the query while
//! frecency biases toward frequently/recently used items.

use std::collections::HashMap;

use crate::frecency::FrecencyDb;
use crate::matcher::FuzzyMatcher;
use core_types::{LaunchResult, TrustProfileName};

/// Combines `FuzzyMatcher` and the active profile's `FrecencyDb` for
/// ranked launcher results.
pub struct SearchEngine {
    matcher: FuzzyMatcher,
    /// The active profile and its frecency database.
    profile: TrustProfileName,
    frecency: FrecencyDb,
    /// The active profile's frecency scores, refreshed on every change.
    frecency_cache: HashMap<String, f64>,
    /// The highest cached frecency score, at least 1.0 (normalization).
    frecency_max: f64,
}

/// Weight for fuzzy score component (0.0 - 1.0).
const FUZZY_WEIGHT: f64 = 0.7;
/// Weight for frecency score component (0.0 - 1.0).
const FRECENCY_WEIGHT: f64 = 0.3;

impl SearchEngine {
    /// A search engine over `matcher`, ranking by `profile`'s `frecency`.
    ///
    /// # Errors
    ///
    /// The [`FrecencyDb::scores`] errors.
    pub fn new(
        matcher: FuzzyMatcher,
        profile: TrustProfileName,
        frecency: FrecencyDb,
    ) -> core_types::Result<Self> {
        let mut engine = Self {
            matcher,
            profile,
            frecency,
            frecency_cache: HashMap::new(),
            frecency_max: 1.0,
        };
        engine.refresh_frecency()?;
        Ok(engine)
    }

    /// Reload the cached frecency scores from the database.
    fn refresh_frecency(&mut self) -> core_types::Result<()> {
        let scores = self.frecency.scores()?;
        self.frecency_max = scores.first().map_or(1.0, |(_, s)| *s).max(1.0);
        self.frecency_cache = scores.into_iter().collect();
        Ok(())
    }

    /// Rank by `profile`'s `frecency` from now on.
    ///
    /// # Errors
    ///
    /// The [`FrecencyDb::scores`] errors; the engine then keeps its
    /// previous profile.
    pub fn switch_profile(
        &mut self,
        profile: TrustProfileName,
        frecency: FrecencyDb,
    ) -> core_types::Result<()> {
        let previous = std::mem::replace(&mut self.frecency, frecency);
        if let Err(e) = self.refresh_frecency() {
            self.frecency = previous;
            return Err(e);
        }
        self.profile = profile;
        Ok(())
    }

    /// The up to `max_results` best matches of `query`, by combined score:
    /// `fuzzy * 0.7 + frecency * 0.3`, each normalized to 0.0–1.0.
    pub fn query(&mut self, query: &str, max_results: u32) -> Vec<LaunchResult> {
        self.matcher.update_pattern(query);
        self.matcher.settle();

        let matches = self.matcher.results(max_results);
        let max_score = f64::from(matches.first().map_or(0, |(score, _)| *score).max(1));
        let mut results: Vec<LaunchResult> = matches
            .into_iter()
            .map(|(score, item)| LaunchResult {
                entry_id: item.id.clone(),
                name: item.name.clone(),
                icon: item.icon.clone(),
                score: f64::from(score) / max_score * FUZZY_WEIGHT
                    + self.frecency_for(&item.id) * FRECENCY_WEIGHT,
            })
            .collect();

        // Re-sort by combined score (nucleo sorts by fuzzy only).
        results.sort_by(|a, b| b.score.total_cmp(&a.score));
        results
    }

    /// Record a launch of `entry_id` and re-rank by it.
    ///
    /// # Errors
    ///
    /// The [`FrecencyDb::record_launch`] and [`FrecencyDb::scores`] errors.
    pub fn record_launch(&mut self, entry_id: &str) -> core_types::Result<()> {
        self.frecency.record_launch(entry_id)?;
        self.refresh_frecency()
    }

    /// The active profile.
    #[must_use]
    pub fn profile(&self) -> &TrustProfileName {
        &self.profile
    }

    /// Normalized frecency score for an entry (0.0 - 1.0).
    fn frecency_for(&self, entry_id: &str) -> f64 {
        self.frecency_cache
            .get(entry_id)
            .map_or(0.0, |score| score / self.frecency_max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{MatchItem, inject_items};
    use std::sync::Arc;

    fn engine(dir: &std::path::Path, names: &[&str]) -> SearchEngine {
        let matcher = FuzzyMatcher::new(Arc::new(|| {}));
        inject_items(
            &matcher.injector(),
            names
                .iter()
                .map(|name| MatchItem {
                    id: format!("{name}.desktop"),
                    name: (*name).into(),
                    extra: String::new(),
                    icon: None,
                })
                .collect(),
        );
        let frecency = FrecencyDb::open(&dir.join("work.db")).unwrap();
        SearchEngine::new(
            matcher,
            TrustProfileName::try_from("work").unwrap(),
            frecency,
        )
        .unwrap()
    }

    #[test]
    fn launches_rerank_equally_fuzzy_matches_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path(), &["alpha", "alphb"]);
        let before = engine.query("alp", 10);
        assert_eq!(before.len(), 2);
        let last = before[1].entry_id.clone();
        engine.record_launch(&last).unwrap();
        assert_eq!(engine.query("alp", 10)[0].entry_id, last);
    }

    #[test]
    fn switching_profiles_ranks_by_the_new_database() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path(), &["alpha", "alphb"]);
        let home = FrecencyDb::open(&dir.path().join("home.db")).unwrap();
        home.record_launch("alphb.desktop").unwrap();
        engine
            .switch_profile(TrustProfileName::try_from("home").unwrap(), home)
            .unwrap();
        assert_eq!(engine.profile().as_ref(), "home");
        assert_eq!(engine.query("alp", 10)[0].entry_id, "alphb.desktop");
    }

    #[test]
    fn queries_return_every_match_up_to_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..200).map(|i| format!("app-{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut engine = engine(dir.path(), &refs);
        assert_eq!(engine.query("app", 500).len(), 200);
        assert_eq!(engine.query("app", 7).len(), 7);
    }
}
