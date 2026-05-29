/// Criterion benchmark: Shannon entropy gate throughput.
///
/// Tests the entropy stage in isolation against various payload sizes
/// to measure raw throughput and compare against the >800 MB/s target.
///
/// Run with:
///   cargo bench --bench entropy
///   cargo bench --bench entropy -- --save-baseline main
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use bytes::Bytes;
use secret_squirrel::config::PipelineConfig;
use secret_squirrel::stages::entropy::{shannon_entropy, EntropyGate};

// ── Raw shannon_entropy benchmarks ──────────────────────────────────────────

fn bench_shannon_entropy(c: &mut Criterion) {
    let sizes = [64usize, 256, 1024, 4096, 65536, 1_048_576];

    let mut group = c.benchmark_group("shannon_entropy");
    for size in sizes {
        // High-entropy payload: cycling 0..=255
        let data: Vec<u8> = (0u8..=255).cycle().take(size).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("high_entropy", size), &data, |b, d| {
            b.iter(|| shannon_entropy(black_box(d)));
        });

        // Low-entropy payload: all zeros
        let zeros = vec![0u8; size];
        group.bench_with_input(BenchmarkId::new("low_entropy", size), &zeros, |b, d| {
            b.iter(|| shannon_entropy(black_box(d)));
        });
    }
    group.finish();
}

// ── EntropyGate::filter benchmarks ──────────────────────────────────────────

fn bench_entropy_gate(c: &mut Criterion) {
    let config = PipelineConfig::default();
    let gate = EntropyGate::new(&config);

    let mut group = c.benchmark_group("entropy_gate");

    // Simulate a small source file (~10 KB)
    let small: Vec<u8> = (0u8..=255).cycle().take(10_240).collect();
    let small_bytes = Bytes::from(small);
    group.throughput(Throughput::Bytes(small_bytes.len() as u64));
    group.bench_function("10kb_high_entropy", |b| {
        b.iter(|| gate.filter(black_box(&small_bytes)));
    });

    // Simulate a larger file (~1 MB)
    let large: Vec<u8> = (0u8..=255).cycle().take(1_048_576).collect();
    let large_bytes = Bytes::from(large);
    group.throughput(Throughput::Bytes(large_bytes.len() as u64));
    group.bench_function("1mb_high_entropy", |b| {
        b.iter(|| gate.filter(black_box(&large_bytes)));
    });

    // All-zero payload (fast rejection path)
    let zeros = Bytes::from(vec![0u8; 1_048_576]);
    group.throughput(Throughput::Bytes(zeros.len() as u64));
    group.bench_function("1mb_zeros_rejected", |b| {
        b.iter(|| gate.filter(black_box(&zeros)));
    });

    // Mixed payload: 10% high-entropy, 90% prose-like low-entropy
    let mut mixed: Vec<u8> = Vec::with_capacity(655360);
    for chunk_idx in 0..160 {
        if chunk_idx % 10 == 0 {
            mixed.extend((0u8..=255).cycle().take(4096));
        } else {
            let text = b"the quick brown fox jumps over the lazy dog near the river bend ";
            mixed.extend(text.iter().cycle().take(4096));
        }
    }
    let mixed_bytes = Bytes::from(mixed);
    group.throughput(Throughput::Bytes(mixed_bytes.len() as u64));
    group.bench_function("mixed_10pct_secrets", |b| {
        b.iter(|| gate.filter(black_box(&mixed_bytes)));
    });

    group.finish();
}

// ── Tokenizer benchmark ──────────────────────────────────────────────────────

fn bench_tokenizer(c: &mut Criterion) {
    use secret_squirrel::scoring::cnn::tokenize;

    let secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",
        "sk_live_abcdefghijklmnopqrstuvwxyz123456",
    ];

    let mut group = c.benchmark_group("tokenizer");
    for secret in &secrets {
        group.bench_with_input(
            BenchmarkId::new("tokenize_256", &secret[..secret.len().min(20)]),
            secret,
            |b, s| {
                b.iter(|| tokenize(black_box(s), 256));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_shannon_entropy,
    bench_entropy_gate,
    bench_tokenizer
);
criterion_main!(benches);
