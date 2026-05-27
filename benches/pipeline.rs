// Benchmark: full 4-stage pipeline throughput
//
// Run with: cargo bench --bench pipeline

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use bytes::Bytes;

fn bench_entropy_scalar(c: &mut Criterion) {
    // Create test input: 1MB of realistic mixed content
    let content: Vec<u8> = (0..1024 * 1024)
        .map(|i| match i % 10 {
            0..=6 => (b'a' + (i % 26) as u8),
            7 => b'=',
            8 => b'"',
            _ => (b'0' + (i % 10) as u8),
        })
        .collect();
    let bytes = Bytes::from(content);

    let mut group = c.benchmark_group("entropy");
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    group.bench_function("scalar_1mb", |b| {
        b.iter(|| {
            // Simple entropy calculation as baseline
            let data = black_box(&bytes);
            let mut freq = [0u32; 256];
            for &byte in data.iter() {
                freq[byte as usize] += 1;
            }
            let len = data.len() as f32;
            let entropy: f32 = freq.iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = c as f32 / len;
                    -p * p.log2()
                })
                .sum();
            black_box(entropy)
        })
    });

    group.finish();
}

fn bench_aho_corasick_patterns(c: &mut Criterion) {
    use aho_corasick::AhoCorasick;

    let patterns = vec![
        "AKIA", "ghp_", "gho_", "ghs_", "glpat-", "xox",
        "sk_live_", "sk_test_", "sk-", "sk-ant-", "hf_",
        "SG.", "eyJ", "Bearer ", "-----BEGIN",
        "password", "secret", "token", "api_key", "apikey",
    ];

    let ac = AhoCorasick::new(&patterns).unwrap();
    let haystack: Vec<u8> = (0..1024 * 1024)
        .map(|i| b'a' + ((i * 7 + 3) % 26) as u8)
        .collect();

    let mut group = c.benchmark_group("pattern_matching");
    group.throughput(Throughput::Bytes(haystack.len() as u64));

    group.bench_function("aho_corasick_20_patterns_1mb", |b| {
        b.iter(|| {
            let count = ac.find_iter(black_box(&haystack)).count();
            black_box(count)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_entropy_scalar, bench_aho_corasick_patterns);
criterion_main!(benches);
