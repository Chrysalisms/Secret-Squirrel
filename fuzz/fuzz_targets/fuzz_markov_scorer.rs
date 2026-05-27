#![no_main]
// Fuzz target: Markov scorer
//
// The Markov scorer converts arbitrary strings to randomness scores.
// Invariants:
//   1. Never panics on any UTF-8 or non-UTF-8 input
//   2. Output is always in [0.0, 1.0]
//   3. Empty strings score 0.0 (no trigrams to score)
//   4. Single/double char strings score 0.0 (minimum 3 chars for a trigram)

use libfuzzer_sys::fuzz_target;
use secret_squirrel::scoring::MarkovScorer;

fuzz_target!(|data: &[u8]| {
    let scorer = MarkovScorer::new();

    // Test with raw bytes interpreted as lossy UTF-8
    let s = String::from_utf8_lossy(data);
    let score = scorer.score(&s);

    assert!(
        score >= 0.0 && score <= 1.0,
        "Markov score {score} out of [0.0, 1.0] for input (len={})",
        s.len()
    );

    // Short string invariant
    if s.len() < 3 {
        assert_eq!(
            score, 0.0,
            "strings shorter than 3 chars must score 0.0, got {score}"
        );
    }
});
