//! Keystroke latency of `FuzzyMatcher` over a 500K-item index: one
//! `update_pattern` plus `settle` (the worker has matched every item).
//! The launcher budget is one 60 Hz frame (16 ms) per keystroke.

use core_fuzzy::{FuzzyMatcher, MatchItem, inject_items};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

const ITEMS: u32 = 500_000;

fn index() -> Vec<MatchItem> {
    (0..ITEMS)
        .map(|i| MatchItem {
            id: format!("org.example.app{i}"),
            name: format!("Application {i}"),
            extra: format!("category-{} keyword-{}", i % 97, i % 1009),
            icon: None,
        })
        .collect()
}

fn fuzzy_search_benchmark(c: &mut Criterion) {
    let mut matcher = FuzzyMatcher::new(Arc::new(|| {}));
    inject_items(&matcher.injector(), index());
    matcher.settle();

    let mut group = c.benchmark_group("fuzzy_500k");
    // Clearing the query then entering `query`: both are full rescores
    // of the index.
    for query in ["app", "Application 4999", "zzzz"] {
        group.bench_function(format!("rescore/{query}"), |b| {
            b.iter(|| {
                matcher.update_pattern("");
                matcher.settle();
                matcher.update_pattern(query);
                matcher.settle();
                black_box(matcher.results(10).len())
            });
        });
    }
    // A backspace (rescore) then a typed character (narrowing re-filter).
    group.bench_function("backspace-then-type/Application", |b| {
        b.iter(|| {
            matcher.update_pattern("Applicatio");
            matcher.settle();
            matcher.update_pattern("Application");
            matcher.settle();
            black_box(matcher.results(10).len())
        });
    });
    group.finish();
}

criterion_group!(benches, fuzzy_search_benchmark);
criterion_main!(benches);
