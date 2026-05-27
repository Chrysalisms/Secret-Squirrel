/// Criterion benchmark: full pipeline stages throughput.
///
/// Tests the complete 4-stage pipeline (entropy → proximity → tristream → pattern)
/// with realistic content, measuring combined stage overhead and throughput.
///
/// Run with:
///   cargo bench --bench pipeline
///   cargo bench --bench pipeline -- --save-baseline main
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use bytes::Bytes;

// ── Aho-Corasick pattern matching ────────────────────────────────────────────

fn bench_aho_corasick(c: &mut Criterion) {
    use aho_corasick::AhoCorasick;

    // Realistic set of secret prefixes (Stage 4 patterns)
    let patterns = vec![
        "AKIA", "ghp_", "gho_", "ghs_", "glpat-", "xoxb-", "xoxp-",
        "sk_live_", "sk_test_", "sk-", "sk-ant-", "hf_",
        "SG.", "eyJ", "Bearer ", "-----BEGIN",
        "password", "secret", "token", "api_key", "apikey", "access_key",
    ];

    let ac = AhoCorasick::new(&patterns).unwrap();

    let sizes = [10_240usize, 102_400, 1_048_576];
    let mut group = c.benchmark_group("aho_corasick");

    for size in sizes {
        // Realistic mixed content (mostly prose, occasional keyword)
        let haystack: Vec<u8> = (0..size)
            .map(|i| {
                if i % 500 == 0 { b'S' } // occasional 'S' for 'SG.' match
                else { b'a' + ((i * 7 + 3) % 26) as u8 }
            })
            .collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("pattern_scan", size),
            &haystack,
            |b, h| {
                b.iter(|| {
                    let count = ac.find_iter(black_box(h)).count();
                    black_box(count)
                })
            },
        );
    }
    group.finish();
}

// ── EntropyGate + ProximityDetector ─────────────────────────────────────────

fn bench_entropy_plus_proximity(c: &mut Criterion) {
    use secret_squirrel::stages::entropy::EntropyGate;
    use secret_squirrel::stages::proximity::ProximityDetector;
    use secret_squirrel::config::PipelineConfig;

    let config = PipelineConfig::default();
    let gate = EntropyGate::new(&config);
    let detector = ProximityDetector::new(&config);

    // 1 MB of realistic source content: mix of prose and secret-shaped lines
    let mut payload = Vec::with_capacity(1_048_576);
    let secret_line = b"AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n";
    let prose_line  = b"// this function computes the hash of the input data using sha256\n";
    for i in 0..15_000 {
        if i % 100 == 0 {
            payload.extend_from_slice(secret_line);
        } else {
            payload.extend_from_slice(prose_line);
        }
        if payload.len() >= 1_048_576 {
            break;
        }
    }
    let content = Bytes::from(payload);

    let mut group = c.benchmark_group("entropy_plus_proximity");
    group.throughput(Throughput::Bytes(content.len() as u64));

    group.bench_function("stage1_entropy_only", |b| {
        b.iter(|| gate.filter(black_box(&content)));
    });

    group.bench_function("stage1+2_entropy_proximity", |b| {
        b.iter(|| {
            let candidates = gate.filter(black_box(&content));
            let matches = detector.filter(candidates, black_box(&content));
            black_box(matches)
        });
    });

    group.finish();
}

// ── Markov scorer ────────────────────────────────────────────────────────────

fn bench_markov_scorer(c: &mut Criterion) {
    use secret_squirrel::scoring::markov::MarkovScorer;

    let scorer = MarkovScorer::default();

    let secrets = [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",
        "sk_live_abcdefghijklmnopqrstuvwxyz123456",
        "the quick brown fox jumps over the lazy dog",
        "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMIK7MDENG",
    ];

    let mut group = c.benchmark_group("markov_scorer");
    for secret in &secrets {
        let label = &secret[..secret.len().min(24)];
        group.bench_with_input(
            BenchmarkId::new("score", label),
            secret,
            |b, s| b.iter(|| scorer.score(black_box(s))),
        );
    }

    // Bulk throughput: score 10,000 strings
    group.bench_function("score_10k_strings", |b| {
        b.iter(|| {
            let mut sum = 0.0f32;
            for i in 0..10_000 {
                let s: String = (0..40).map(|j| ((b'a' + ((i * 7 + j * 3) % 26) as u8) as char)).collect();
                sum += scorer.score(black_box(&s));
            }
            black_box(sum)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_aho_corasick, bench_entropy_plus_proximity, bench_markov_scorer);
criterion_main!(benches);
