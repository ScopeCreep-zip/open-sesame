//! Combined search engine: fuzzy matching + frecency ranking.
//!
//! Blends nucleo fuzzy scores with frecency boosts using a 70/30 weighting
//! (ADR-LNC-004). The fuzzy score provides relevance to the query while
//! frecency biases toward frequently/recently used items.

use std::collections::HashMap;

use crate::frecency::FrecencyDb;
use crate::matcher::FuzzyMatcher;
use core_types::TrustProfileName;

/// A ranked search result combining fuzzy match score and frecency boost.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Entry identifier (desktop entry app ID).
    pub entry_id: String,
    /// Display name.
    pub name: String,
    /// Icon name (if available).
    pub icon: Option<String>,
    /// Combined score (fuzzy * 0.7 + frecency_normalized * 0.3).
    pub score: f64,
}

/// Combines `FuzzyMatcher` and `FrecencyDb` for ranked launcher results.
pub struct SearchEngine {
    matcher: FuzzyMatcher,
    frecency: FrecencyDb,
    /// Cached frecency scores for the active profile, refreshed on query.
    frecency_cache: HashMap<String, f64>,
    /// Maximum frecency score in cache (for normalization).
    frecency_max: f64,
    /// Active trust profile for frecency lookups.
    profile_id: TrustProfileName,
}

/// Weight for fuzzy score component (0.0 - 1.0).
const FUZZY_WEIGHT: f64 = 0.7;
/// Weight for frecency score component (0.0 - 1.0).
const FRECENCY_WEIGHT: f64 = 0.3;

impl SearchEngine {
    /// Create a new search engine for the given profile.
    pub fn new(matcher: FuzzyMatcher, frecency: FrecencyDb, profile_id: TrustProfileName) -> Self {
        Self {
            matcher,
            frecency,
            frecency_cache: HashMap::new(),
            frecency_max: 0.0,
            profile_id,
        }
    }

    /// Refresh frecency cache from the database.
    ///
    /// Call this periodically or when the profile changes.
    pub fn refresh_frecency(&mut self) -> core_types::Result<()> {
        let scores = self.frecency.scores(&self.profile_id)?;
        self.frecency_max = scores.first().map(|(_, s)| *s).unwrap_or(1.0).max(1.0); // avoid division by zero
        self.frecency_cache = scores.into_iter().collect();
        Ok(())
    }

    /// Switch the active profile for frecency lookups.
    ///
    /// Atomically swaps the profile ID and refreshes the frecency cache.
    pub fn switch_profile(&mut self, profile_id: TrustProfileName) -> core_types::Result<()> {
        self.profile_id = profile_id;
        self.refresh_frecency()
    }

    /// Update the search pattern and tick the matcher.
    ///
    /// Returns ranked results combining fuzzy and frecency scores.
    pub fn query(&mut self, query: &str, max_results: u32) -> Vec<SearchResult> {
        self.matcher.update_pattern(query);
        self.matcher.tick(10); // 10ms timeout per ADR

        let snapshot = self.matcher.nucleo().snapshot();
        let count = snapshot.matched_item_count().min(max_results) as usize;

        // snapshot.matches() is sorted by score descending (same order as
        // matched_items). The first entry has the highest score.
        let matches = snapshot.matches();
        let max_score = matches.first().map_or(0, |m| m.score).max(1);

        let mut results: Vec<SearchResult> = (0..count)
            .filter_map(|i| {
                let m = &matches[i];
                let item = snapshot.get_matched_item(i as u32)?;
                let data = item.data;

                let fuzzy_score = m.score as f64 / max_score as f64;
                let frecency_score = self.frecency_for(&data.id);
                let combined = fuzzy_score * FUZZY_WEIGHT + frecency_score * FRECENCY_WEIGHT;

                Some(SearchResult {
                    entry_id: data.id.clone(),
                    name: data.name.clone(),
                    icon: None, // filled by caller from desktop entry data
                    score: combined,
                })
            })
            .collect();

        // Re-sort by combined score (nucleo sorts by fuzzy only).
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Record a launch for frecency tracking.
    pub fn record_launch(&self, entry_id: &str) -> core_types::Result<()> {
        self.frecency.record_launch(entry_id, &self.profile_id)
    }

    /// Get the underlying matcher for item injection.
    pub fn matcher(&self) -> &FuzzyMatcher {
        &self.matcher
    }

    /// Get a mutable reference to the underlying matcher.
    pub fn matcher_mut(&mut self) -> &mut FuzzyMatcher {
        &mut self.matcher
    }

    /// Get the frecency DB reference.
    pub fn frecency(&self) -> &FrecencyDb {
        &self.frecency
    }

    /// Get the current trust profile.
    pub fn profile_id(&self) -> &TrustProfileName {
        &self.profile_id
    }

    /// Normalized frecency score for an entry (0.0 - 1.0).
    fn frecency_for(&self, entry_id: &str) -> f64 {
        self.frecency_cache
            .get(entry_id)
            .map(|score| score / self.frecency_max)
            .unwrap_or(0.0)
    }
}
