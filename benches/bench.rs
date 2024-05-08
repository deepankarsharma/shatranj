#![feature(stdarch_x86_avx512)]

use criterion::{criterion_group, criterion_main, Criterion};
use lib::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let path = get_filename();
    c.bench_function("count_newlines_direct_io", |b| b.iter(|| count_newlines_direct_io(path.as_str())));
    c.bench_function("count_newlines_standard", |b| b.iter(|| count_newlines_standard(path.as_str())));
    c.bench_function("count_newlines_standard_non_appending", |b| b.iter(|| count_newlines_standard_non_appending(path.as_str())));
    c.bench_function("count_newlines_memmap", |b| b.iter(|| count_newlines_memmap(path.as_str())));
    unsafe {
        c.bench_function("count_newlines_memmap_avx2", |b| b.iter(|| count_newlines_memmap_avx2(path.as_str())));
        c.bench_function("count_newlines_memmap_avx512", |b| b.iter(|| count_newlines_memmap_avx512(path.as_str())));
    }

    c.bench_function("count_newlines_vectored_io", |b| b.iter(|| count_newlines_vectored_io(path.as_str())));
    c.bench_function("count_lines_io_uring", |b| b.iter(|| count_lines_io_uring(path.as_str())));
    c.bench_function("count_lines_io_uring_vectored", |b| b.iter(|| count_lines_io_uring_vectored(path.as_str())));
}

criterion_group!(
    name=benches;
    config=Criterion::default().sample_size(10);
    targets=criterion_benchmark
);

criterion_main!(benches);