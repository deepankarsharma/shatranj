#![feature(stdarch_x86_avx512)]

use criterion::{criterion_group, criterion_main, Criterion};
use lib::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let path = get_filename();
    c.bench_function("count_newlines_standard_non_appending", |b| b.iter(|| count_newlines_standard_non_appending(path.as_str())));
}

criterion_group!(
    name=profiled;
    config=Criterion::default().sample_size(10);
    targets=criterion_benchmark
);

criterion_main!(profiled);