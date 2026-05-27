// Benchmark: Shannon entropy calculation performance
//
// Run with: cargo bench --bench entropy

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn compute_entropy_scalar(data: &[u8]) -> f32 {
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn bench_entropy_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_by_size");

    for size in &[64_usize, 256, 1024, 4096, 65536, 1024 * 1024] {
        let data: Vec<u8> = (0..*size)
            .map(|i| (i * 7 + 13) as u8)
            .collect();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            format!("scalar_{}", size),
            &data,
            |b, data| {
                b.iter(|| compute_entropy_scalar(black_box(data)))
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_entropy_sizes);
criterion_main!(benches);
