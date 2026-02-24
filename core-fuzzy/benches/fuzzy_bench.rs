use criterion::{criterion_group, criterion_main, Criterion};

fn fuzzy_search_benchmark(_c: &mut Criterion) {
    // TODO: benchmark fuzzy search over 500K items (target: < 16ms)
}

criterion_group!(benches, fuzzy_search_benchmark);
criterion_main!(benches);
