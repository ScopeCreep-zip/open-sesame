use criterion::{Criterion, criterion_group, criterion_main};

fn fuzzy_search_benchmark(c: &mut Criterion) {
    use core_fuzzy::{FuzzyMatcher, MatchItem, inject_items};
    use std::sync::Arc;

    // Generate 500K synthetic items.
    let items: Vec<MatchItem> = (0..500_000)
        .map(|i| MatchItem {
            id: format!("item-{i:06}"),
            name: format!(
                "item-{i:06}-{}",
                if i % 3 == 0 {
                    "alpha"
                } else if i % 3 == 1 {
                    "bravo"
                } else {
                    "charlie"
                }
            ),
            extra: String::new(),
        })
        .collect();

    let mut matcher = FuzzyMatcher::new(Arc::new(|| {}));
    inject_items(&matcher.injector(), items);
    matcher.update_pattern("alpha");
    matcher.tick(100); // Initial processing.

    c.bench_function("fuzzy_search_500k", |b| {
        b.iter(|| {
            matcher.update_pattern("alpha");
            matcher.tick(10);
            let _results = matcher.results(10);
        });
    });
}

criterion_group!(benches, fuzzy_search_benchmark);
criterion_main!(benches);
