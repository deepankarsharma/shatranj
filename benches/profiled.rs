#![feature(stdarch_x86_avx512)]

use criterion::{criterion_group, criterion_main, Criterion};
use lib::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let path = get_filename();
    unsafe {
        c.bench_function("count_newlines_memmap_avx2_running_sum", |b| b.iter(|| count_newlines_memmap_avx2_running_sum(path.as_str())));
    }
}

criterion_group!(
    name=profiled;
    config=Criterion::default().sample_size(10);
    targets=criterion_benchmark
);

criterion_main!(profiled);