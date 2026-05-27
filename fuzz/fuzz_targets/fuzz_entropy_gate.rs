#![no_main]
// Fuzz target: Shannon entropy gate
//
// The entropy gate processes arbitrary byte slices with sliding windows.
// Invariants:
//   1. Never panics on any input
//   2. Entropy output is always in [0.0, 8.0]
//   3. All-same-byte input always produces 0.0 entropy
//   4. Result count is bounded by input length

use libfuzzer_sys::fuzz_target;
use bytes::Bytes;
use secret_squirrel::stages::entropy::EntropyGate;
use secret_squirrel::config::PipelineConfig;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use the first byte to vary the threshold between 2.0 and 6.0
    let threshold = 2.0 + (data[0] as f32 / 255.0) * 4.0;
    let content = Bytes::copy_from_slice(&data[1..]);

    let config = PipelineConfig {
        entropy_threshold: threshold,
        chunk_size: 64,
        min_secret_length: 8,
        ..Default::default()
    };

    let gate = EntropyGate::new(&config);
    let candidates = gate.filter(&content);

    // Invariant: entropy of each candidate is in valid range
    for candidate in &candidates {
        assert!(
            candidate.entropy >= 0.0 && candidate.entropy <= 8.01, // small float tolerance
            "entropy {} out of [0, 8] range",
            candidate.entropy
        );
        // Invariant: candidate offset + length must be within the original content
        assert!(
            candidate.offset + candidate.length <= content.len(),
            "candidate range [{}, {}) exceeds input length {}",
            candidate.offset,
            candidate.offset + candidate.length,
            content.len()
        );
    }
});
