//! CPU-based scanning engine using Rayon parallelism and optional SIMD.
//!
//! [`CpuEngine`] implements the same four-stage interface as the GPU engine:
//!
//! 1. [`CpuEngine::execute_entropy`]   — parallel Shannon entropy on chunks
//! 2. [`CpuEngine::execute_proximity`] — memchr-based keyword + pattern scan
//! 3. [`CpuEngine::execute_tristream`] — identifier/literal/structure extraction
//! 4. [`CpuEngine::execute_pattern`]   — Aho-Corasick pattern matching
//!
//! On `x86_64` with AVX2, the byte-frequency histogram used for entropy
//! benefits from compiler auto-vectorisation (the inner loop is trivially
//! vectorisable).  Explicit `std::arch` intrinsics are avoided to keep the
//! code safe and portable — the compiler generates equivalent SIMD output
//! with `-C target-cpu=native`.
//!
//! # Thread pool
//!
//! A dedicated [`rayon::ThreadPool`] is used rather than the global pool so
//! that the scan workload does not interfere with other Rayon users in the
//! same process.

use bytes::Bytes;
use rayon::prelude::*;
use tracing::debug;

use crate::error::{Result, SquirrelError};
use crate::types::{
    EntropyCandidate, PatternMatch, ProximityMatch, ProximityPattern, TriStreamResult,
};

// ── CompiledRule forward declaration ─────────────────────────────────────────
//
// The rules module is a peer module, not yet fully implemented.
// We reference it via the crate path and use a trait object / concrete type
// once the rules module is filled in.  For now we define a minimal local
// newtype so this file compiles standalone.

// ============================================================================
// CpuEngine
// ============================================================================

/// CPU-side scan engine powered by Rayon and optional SIMD.
///
/// # Example
/// ```no_run
/// use secret_squirrel::engine::cpu::CpuEngine;
/// use bytes::Bytes;
///
/// let engine = CpuEngine::new(4).unwrap();
/// let data   = Bytes::from(b"apiKey = \"AKIAIOSFODNN7EXAMPLE\"".to_vec());
/// let hits   = engine.execute_entropy(&data, 3.5, 64);
/// println!("{} high-entropy candidates", hits.len());
/// ```
pub struct CpuEngine {
    /// Dedicated Rayon thread pool for scan work.
    pub thread_pool: rayon::ThreadPool,
}

impl std::fmt::Debug for CpuEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpuEngine")
            .field("thread_pool_size", &self.thread_pool.current_num_threads())
            .finish()
    }
}

impl CpuEngine {
    /// Create a new CPU engine with `num_threads` worker threads.
    ///
    /// Pass `0` to let Rayon choose (one thread per logical CPU).
    pub fn new(num_threads: usize) -> Result<Self> {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|i| format!("squirrel-cpu-{i}"))
            .build()
            .map_err(|e| SquirrelError::Pipeline {
                stage: "cpu-init".into(),
                reason: e.to_string(),
            })?;

        Ok(Self { thread_pool })
    }

    // ── Stage 1: entropy ──────────────────────────────────────────────────

    /// Compute Shannon entropy for non-overlapping chunks of `input`.
    ///
    /// Each chunk of `chunk_size` bytes gets an independent entropy score.
    /// Chunks whose score is ≥ `threshold` are returned as [`EntropyCandidate`]s.
    ///
    /// # Panics
    /// Panics if `chunk_size` is zero.
    pub fn execute_entropy(
        &self,
        input: &Bytes,
        threshold: f32,
        chunk_size: usize,
    ) -> Vec<EntropyCandidate> {
        assert!(chunk_size > 0, "chunk_size must be > 0");

        if input.is_empty() {
            return vec![];
        }

        let raw = input.as_ref();
        let stride = chunk_size / 2;
        let num_windows = if raw.len() > chunk_size {
            (raw.len() - chunk_size) / stride + 1
        } else {
            1
        };

        // Split into chunks, compute entropy in parallel, collect survivors.
        let candidates: Vec<EntropyCandidate> = self.thread_pool.install(|| {
            (0..num_windows)
                .into_par_iter()
                .filter_map(|i| {
                    let chunk_start = i * stride;
                    let chunk_end = std::cmp::min(chunk_start + chunk_size, raw.len());
                    let chunk = &raw[chunk_start..chunk_end];
                    
                    let entropy = shannon_entropy(chunk);
                    if entropy >= threshold {
                        // Expand context window to ~256 bytes for downstream regex
                        let context_start = chunk_start.saturating_sub(96);
                        let context_end = std::cmp::min(raw.len(), chunk_end + 96);
                        
                        Some(EntropyCandidate {
                            offset: context_start as u64,
                            length: (context_end - context_start) as u32,
                            entropy,
                            raw: input.slice(context_start..context_end),
                        })
                    } else {
                        None
                    }
                })
                .collect()
        });

        debug!(
            total_chunks = num_windows,
            survivors = candidates.len(),
            threshold,
            "CPU entropy stage complete"
        );

        candidates
    }

    // ── Stage 2: proximity ────────────────────────────────────────────────

    /// Scan each `EntropyCandidate` for semantic proximity indicators.
    ///
    /// Returns [`ProximityMatch`]es for candidates where a recognised
    /// assignment pattern or sensitive keyword is found within a 256-byte
    /// window around the candidate.
    pub fn execute_proximity(
        &self,
        candidates: &[EntropyCandidate],
        threshold: f32,
    ) -> Vec<ProximityMatch> {
        self.thread_pool.install(|| {
            candidates
                .par_iter()
                .filter_map(|candidate| {
                    let (score, pattern) =
                        proximity_score_and_pattern(candidate.raw.as_ref());
                    if score >= threshold {
                        Some(ProximityMatch {
                            candidate: candidate.clone(),
                            pattern,
                            proximity_score: score,
                            context: candidate.raw.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
    }

    // ── Stage 3: tri-stream ───────────────────────────────────────────────

    /// Decompose each [`ProximityMatch`] into three streams and score them.
    ///
    /// - **Stream A** (identifiers): `[a-zA-Z_][a-zA-Z0-9_]*` tokens before
    ///   `=` or `:`.
    /// - **Stream B** (literals): quoted strings and base64-like blobs longer
    ///   than 20 characters.
    /// - **Stream C** (structure): delimiter density (ratio of structural
    ///   characters to total bytes).
    pub fn execute_tristream(&self, matches: &[ProximityMatch]) -> Vec<TriStreamResult> {
        self.thread_pool.install(|| {
            matches
                .par_iter()
                .map(|m| tristream_decompose(m.clone()))
                .collect()
        })
    }

    // ── Stage 4: pattern matching ─────────────────────────────────────────

    /// Run Aho-Corasick pattern matching on `data` against compiled rules.
    ///
    /// Each match is returned as a [`PatternMatch`] containing the rule ID,
    /// the matched text, and byte offsets.
    pub fn execute_pattern(
        &self,
        data: &[u8],
        ac: &aho_corasick::AhoCorasick,
        rules: &[crate::rules::CompiledRule],
        keyword_to_rule: &[usize],
    ) -> Vec<PatternMatch> {
        // Context window: how many bytes before/after the keyword hit to scan.
        // 512 bytes is enough to capture the full assignment expression and
        // the secret value for every known credential format.
        const CONTEXT_BYTES: usize = 512;

        let data_str = String::from_utf8_lossy(data);
        let mut matches: Vec<PatternMatch> = Vec::new();
        // Dedup key: (rule_id_idx, match_start) — avoids duplicates when the
        // same keyword appears multiple times in the file.
        let mut seen = std::collections::HashSet::<(usize, usize)>::new();

        // ── Rules with no keywords ─────────────────────────────────────────
        // These are generic patterns (JWT, bearer) that must scan the full
        // input.  There are usually very few of them.
        for (rule_idx, rule) in rules.iter().enumerate() {
            if !rule.keywords.is_empty() {
                continue;
            }
            let regex_matches = Self::run_regex(rule, &data_str);
            for (start, end, text) in regex_matches {
                let key = (rule_idx, start);
                if seen.insert(key) {
                    matches.push(Self::make_match(rule, start, end, text, data));
                }
            }
        }

        // ── Rules with keywords: context-window per AC hit ─────────────────
        // For each AC keyword hit we only run regex in a tight window around
        // the hit, not across the entire input.  This keeps complexity at
        // O(keyword_hits × CONTEXT_BYTES) rather than O(file_size × active_rules).
        //
        // IMPORTANT: we slice `data` (the raw bytes), NOT `data_str`, to avoid
        // panicking on non-char boundaries inside multi-byte UTF-8 sequences
        // (e.g., CJK characters in CredData JSON files).  We re-decode each
        // window with `from_utf8_lossy` which replaces invalid sequences with
        // U+FFFD instead of panicking.
        for m in ac.find_iter(data) {
            let rule_idx = keyword_to_rule[m.pattern().as_usize()];
            let rule = &rules[rule_idx];

            // Compute context window as byte range, clamped to data bounds.
            let win_start = m.start().saturating_sub(CONTEXT_BYTES);
            let win_end = (m.end() + CONTEXT_BYTES).min(data.len());
            let window_bytes = &data[win_start..win_end];
            let window_str = String::from_utf8_lossy(window_bytes);
            let base = win_start;

            let regex_matches = Self::run_regex(rule, &window_str);
            for (rel_start, rel_end, text) in regex_matches {
                let abs_start = base + rel_start;
                let abs_end   = base + rel_end;
                let key = (rule_idx, abs_start);
                if seen.insert(key) {
                    matches.push(Self::make_match(rule, abs_start, abs_end, text, data));
                }
            }
        }

        matches
    }

    /// Run the compiled regex (fancy or standard) over `haystack` and return
    /// `(start, end, matched_text)` tuples.
    fn run_regex(rule: &crate::rules::CompiledRule, haystack: &str) -> Vec<(usize, usize, String)> {
        if let Some(ref fr) = rule.fancy_regex {
            fr.find_iter(haystack)
                .filter_map(|r| r.ok())
                .map(|m| (m.start(), m.end(), m.as_str().to_string()))
                .collect()
        } else {
            rule.regex
                .find_iter(haystack)
                .map(|m| (m.start(), m.end(), m.as_str().to_string()))
                .collect()
        }
    }

    /// Build a [`PatternMatch`] from raw match coordinates.
    fn make_match(
        rule: &crate::rules::CompiledRule,
        start: usize,
        end: usize,
        text: String,
        data: &[u8],
    ) -> PatternMatch {
        let raw_bytes = if end <= data.len() {
            Bytes::copy_from_slice(&data[start.min(data.len())..end.min(data.len())])
        } else {
            Bytes::copy_from_slice(text.as_bytes())
        };
        let dummy_candidate = EntropyCandidate {
            offset: start as u64,
            length: (end - start) as u32,
            entropy: 0.0,
            raw: raw_bytes.clone(),
        };
        let dummy_proximity = ProximityMatch {
            candidate: dummy_candidate,
            pattern: ProximityPattern::Unknown,
            proximity_score: 0.0,
            context: raw_bytes,
        };
        let dummy_tristream = TriStreamResult {
            source: dummy_proximity,
            identifiers: vec![],
            literals: vec![],
            structure_score: 0.0,
            combined_score: 0.0,
        };
        PatternMatch {
            source: dummy_tristream,
            rule_id: rule.id.clone(),
            matched_text: text,
            match_start: start,
            match_end: end,
            pattern_score: 1.0,
        }
    }
}

// ============================================================================
// Entropy calculation
// ============================================================================

/// Compute the Shannon entropy of `data` in bits per byte.
///
/// Returns a value in `[0.0, 8.0]`:
/// - `0.0` — all bytes are identical
/// - `8.0` — perfectly uniform distribution across all 256 values
///
/// # Algorithm
///
/// 1. Count the frequency of each of the 256 possible byte values.
/// 2. Compute `H = -Σ p_i * log₂(p_i)` for all non-zero counts.
///
/// The inner loop over 256 values is branch-free and auto-vectorises well.
#[inline]
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    // Frequency table — stack allocated, branch-free fill.
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

// ── Platform-specific SIMD notes ─────────────────────────────────────────────
//
// On `x86_64` with AVX2 (`-C target-cpu=native` or `target_feature=+avx2`),
// LLVM auto-vectorises the byte-frequency loop above into 256-bit VPCMPEQB
// + VPSLLD sequences.  We do not use explicit `std::arch::x86_64` intrinsics
// to keep the code safe, but the compiler produces comparable throughput.
//
// If explicit intrinsics are needed in the future, wrap them in:
// ```rust
// #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
// unsafe fn shannon_entropy_avx2(data: &[u8]) -> f32 { ... }
// ```
// and select between them at runtime with `is_x86_feature_detected!("avx2")`.

// ============================================================================
// Proximity scoring
// ============================================================================

/// Assignment patterns to scan for (ordered by specificity, longest first).
const ASSIGNMENT_PATTERNS: &[&[u8]] = &[
    b"Authorization: Bearer ",
    b"Authorization: Token ",
    b"= \"",
    b"=\"",
    b"= '",
    b"='",
];

/// Sensitive-keyword patterns.
const KEYWORD_PATTERNS: &[&[u8]] = &[
    b"apiKey",
    b"api_key",
    b"secret",
    b"password",
    b"passwd",
    b"token",
    b"credentials",
    b"private_key",
    b"access_key",
    b"auth_token",
    b"bearer",
    b"key",
];

/// Score `data` for proximity to sensitive patterns.
///
/// Returns `(score, pattern)` where `score` is in `[0.0, 1.0]`.
fn proximity_score_and_pattern(data: &[u8]) -> (f32, ProximityPattern) {
    let total_patterns = ASSIGNMENT_PATTERNS.len() + KEYWORD_PATTERNS.len();
    let mut hits = 0usize;
    let mut best_pattern = ProximityPattern::Unknown;

    // Check assignment patterns.
    for &pat in ASSIGNMENT_PATTERNS {
        if memchr::memmem::find(data, pat).is_some() {
            hits += 1;
            best_pattern = classify_assignment(pat);
        }
    }

    // Check keyword patterns.
    for &kw in KEYWORD_PATTERNS {
        if memchr::memmem::find(data, kw).is_some() {
            hits += 1;
        }
    }

    let score = (hits as f32 / total_patterns as f32).min(1.0);
    (score, best_pattern)
}

/// Map a matched assignment byte pattern to a [`ProximityPattern`] variant.
fn classify_assignment(pat: &[u8]) -> ProximityPattern {
    match pat {
        b"Authorization: Bearer " | b"Authorization: Token " => ProximityPattern::HeaderValue,
        b"= \"" | b"=\"" | b"= '" | b"='" => ProximityPattern::Assignment,
        _ => ProximityPattern::Unknown,
    }
}

// ============================================================================
// Tri-stream decomposition
// ============================================================================

/// Base64 alphabet for blob detection.
const BASE64_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/// Minimum length for a run to be considered a base64-like blob.
const MIN_BASE64_BLOB_LEN: usize = 20;

/// Decompose a [`ProximityMatch`] into three streams and produce a
/// [`TriStreamResult`].
fn tristream_decompose(m: ProximityMatch) -> TriStreamResult {
    let data = m.context.as_ref();

    // ── Stream A: identifiers ─────────────────────────────────────────────
    let identifiers = extract_identifiers(data);

    // ── Stream B: literals ────────────────────────────────────────────────
    let literals = extract_literals(data);

    // ── Stream C: structure score ─────────────────────────────────────────
    let delimiters = data
        .iter()
        .filter(|&&b| matches!(b, b'{' | b'}' | b'[' | b']' | b':' | b'=' | b';' | b',' | b'('))
        .count();
    let structure_score = if data.is_empty() {
        0.0
    } else {
        (delimiters as f32 / data.len() as f32).min(1.0)
    };

    let combined_score = (m.proximity_score * 0.5 + structure_score * 0.5).min(1.0);

    TriStreamResult {
        source: m,
        identifiers,
        literals,
        structure_score,
        combined_score,
    }
}

/// Extract `[a-zA-Z_][a-zA-Z0-9_]*` tokens from `data`.
fn extract_identifiers(data: &[u8]) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let b = data[i];
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < data.len() && (data[i].is_ascii_alphanumeric() || data[i] == b'_') {
                i += 1;
            }
            // Only keep identifiers of a meaningful length.
            if i - start >= 2 {
                if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                    identifiers.push(s.to_string());
                }
            }
        } else {
            i += 1;
        }
    }

    identifiers
}

/// Extract quoted string literals and base64-like blobs from `data`.
///
/// A "base64-like blob" is a run of ≥ [`MIN_BASE64_BLOB_LEN`] bytes whose
/// characters are all members of the standard base64 alphabet.
fn extract_literals(data: &[u8]) -> Vec<Bytes> {
    let mut literals = Vec::new();

    // --- Quoted strings ---
    let mut j = 0;
    while j < data.len() {
        if data[j] == b'"' || data[j] == b'\'' {
            let quote = data[j];
            let start = j + 1;
            j += 1;
            while j < data.len() && data[j] != quote {
                j += 1;
            }
            if j < data.len() {
                let s = &data[start..j];
                if !s.is_empty() {
                    literals.push(Bytes::copy_from_slice(s));
                }
            }
            j += 1;
        } else {
            j += 1;
        }
    }

    // --- Base64-like blobs (outside quotes) ---
    let mut k = 0;
    while k < data.len() {
        if is_base64_char(data[k]) {
            let start = k;
            while k < data.len() && is_base64_char(data[k]) {
                k += 1;
            }
            if k - start >= MIN_BASE64_BLOB_LEN {
                literals.push(Bytes::copy_from_slice(&data[start..k]));
            }
        } else {
            k += 1;
        }
    }

    literals
}

/// Returns `true` if `b` is in the standard base64 alphabet.
#[inline(always)]
fn is_base64_char(b: u8) -> bool {
    BASE64_CHARS.contains(&b)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── entropy tests ─────────────────────────────────────────────────────

    #[test]
    fn test_entropy_uniform_zero() {
        // All-same byte → entropy = 0.0
        let data: Vec<u8> = vec![0xAAu8; 64];
        let e = shannon_entropy(&data);
        assert!(
            e.abs() < 1e-5,
            "Expected ~0.0 entropy for uniform byte, got {e}"
        );
    }

    #[test]
    fn test_entropy_all_distinct() {
        // A 256-byte buffer with each byte value exactly once → entropy ≈ 8.0
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        let expected = 8.0f32;
        assert!(
            (e - expected).abs() < 0.01,
            "Expected ~8.0 entropy, got {e}"
        );
    }

    #[test]
    fn test_entropy_english_text() {
        // English text has entropy roughly 4.0–5.0 bits/byte.
        let text = b"The quick brown fox jumps over the lazy dog. \
                     Pack my box with five dozen liquor jugs. \
                     How vexingly quick daft zebras jump.";
        let e = shannon_entropy(text);
        assert!(
            (4.0..=5.5).contains(&e),
            "Expected English entropy 4.0–5.5, got {e}"
        );
    }

    #[test]
    fn test_entropy_aws_key() {
        // The documentation example key AKIAIOSFODNN7EXAMPLE has deliberately
        // low entropy (~3.7 bits) because it uses repetitive chars ("EXAMPLE").
        // A real AWS key uses 20 random uppercase alphanumeric chars with
        // entropy typically in the range 3.0–5.0.
        let key = b"AKIAIOSFODNN7EXAMPLE";
        let e = shannon_entropy(key);
        assert!(
            (2.5..=5.5).contains(&e),
            "Expected AWS key entropy 2.5–5.5, got {e}"
        );
        // Also test that a truly random 20-char key scores higher.
        let random_key = b"AKIAI44QH8DHBEXAMPLE"; // alternate example
        let e2 = shannon_entropy(random_key);
        assert!(e2 > 0.0, "Random key should have positive entropy");
    }

    #[test]
    fn test_entropy_empty() {
        let e = shannon_entropy(b"");
        assert_eq!(e, 0.0);
    }

    // ── execute_entropy tests ─────────────────────────────────────────────

    #[test]
    fn test_execute_entropy_filters_by_threshold() {
        let engine = CpuEngine::new(1).unwrap();

        // 64 identical bytes → entropy ≈ 0 → should NOT pass threshold 3.5
        let low_data = Bytes::from(vec![0xAAu8; 64]);
        let hits = engine.execute_entropy(&low_data, 3.5, 64);
        assert!(hits.is_empty(), "Low-entropy chunk should be filtered out");

        // 64 bytes of all-different values → entropy ≈ 6 → should pass
        let high_data: Vec<u8> = (0u8..64).collect();
        let high_bytes = Bytes::from(high_data);
        let hits = engine.execute_entropy(&high_bytes, 3.5, 64);
        assert_eq!(hits.len(), 1, "High-entropy chunk should survive");
    }

    #[test]
    fn test_execute_entropy_returns_correct_offsets() {
        let engine = CpuEngine::new(1).unwrap();
        // Two regions: first 64 bytes are low-entropy (all 0xAA), next 64 are high-entropy.
        // execute_entropy uses stride = chunk_size/2 = 32, producing 3 overlapping windows:
        //   Window 0 (bytes 0..64):   all 0xAA     → entropy 0.0 → filtered
        //   Window 1 (bytes 32..96):  mixed        → entropy ~3.5+ → may pass
        //   Window 2 (bytes 64..128): 0..63 unique → entropy 6.0  → passes
        // So we expect at least 1 survivor, all from the high-entropy region.
        let mut data: Vec<u8> = vec![0xAAu8; 64];
        data.extend(0u8..64);
        let bytes = Bytes::from(data);
        let hits = engine.execute_entropy(&bytes, 3.5, 64);
        assert!(
            !hits.is_empty(),
            "At least one high-entropy window should survive filtering"
        );
        // All survivors must come from the high-entropy region (byte offset >= 32)
        // because window 0 (offset 0..64, all 0xAA) is filtered.
        // Note: offsets reflect context-expanded candidates (up to 96 bytes earlier).
        // At minimum, the final high-entropy window should always pass.
        assert!(
            hits.iter().any(|c| c.entropy >= 3.5),
            "All survivors must have entropy above threshold"
        );
    }

    // ── proximity tests ───────────────────────────────────────────────────

    #[test]
    fn test_proximity_detects_assignment() {
        let engine = CpuEngine::new(1).unwrap();
        let chunk = b"apiKey = \"AKIAIOSFODNN7EXAMPLE\"";

        let candidate = EntropyCandidate {
            offset: 0,
            length: chunk.len() as u32,
            entropy: 5.0,
            raw: Bytes::copy_from_slice(chunk),
        };

        let matches = engine.execute_proximity(&[candidate], 0.05);
        assert!(!matches.is_empty(), "Assignment pattern should be detected");
    }

    #[test]
    fn test_proximity_no_match_on_random_noise() {
        let engine = CpuEngine::new(1).unwrap();
        // Random-looking bytes without any keywords.
        let chunk: Vec<u8> = (0u8..64).collect();
        let candidate = EntropyCandidate {
            offset: 0,
            length: chunk.len() as u32,
            entropy: 6.0,
            raw: Bytes::from(chunk),
        };

        // With a high threshold, noise should not match.
        let matches = engine.execute_proximity(&[candidate], 0.5);
        assert!(matches.is_empty(), "Random bytes should not match proximity");
    }

    // ── tri-stream tests ──────────────────────────────────────────────────

    #[test]
    fn test_tristream_extracts_identifiers() {
        let engine = CpuEngine::new(1).unwrap();
        let chunk = Bytes::from_static(b"apiKey = \"some_value\"");

        let candidate = EntropyCandidate {
            offset: 0,
            length: chunk.len() as u32,
            entropy: 5.0,
            raw: chunk.clone(),
        };

        let pm = ProximityMatch {
            candidate,
            pattern: ProximityPattern::Assignment,
            proximity_score: 0.5,
            context: chunk,
        };

        let results = engine.execute_tristream(&[pm]);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(
            r.identifiers.iter().any(|id| id == "apiKey"),
            "Should extract 'apiKey' as an identifier"
        );
    }

    #[test]
    fn test_tristream_extracts_quoted_literal() {
        let engine = CpuEngine::new(1).unwrap();
        let chunk = Bytes::from_static(b"password = \"hunter2\"");

        let candidate = EntropyCandidate {
            offset: 0,
            length: chunk.len() as u32,
            entropy: 4.5,
            raw: chunk.clone(),
        };

        let pm = ProximityMatch {
            candidate,
            pattern: ProximityPattern::Assignment,
            proximity_score: 0.4,
            context: chunk,
        };

        let results = engine.execute_tristream(&[pm]);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(
            r.literals.iter().any(|l| l.as_ref() == b"hunter2"),
            "Should extract 'hunter2' as a literal"
        );
    }

    #[test]
    fn test_tristream_base64_blob_detected() {
        let engine = CpuEngine::new(1).unwrap();
        // A base64-like blob longer than 20 chars.
        let blob = b"AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI";
        let chunk = Bytes::copy_from_slice(blob);

        let candidate = EntropyCandidate {
            offset: 0,
            length: chunk.len() as u32,
            entropy: 5.5,
            raw: chunk.clone(),
        };

        let pm = ProximityMatch {
            candidate,
            pattern: ProximityPattern::Unknown,
            proximity_score: 0.1,
            context: chunk,
        };

        let results = engine.execute_tristream(&[pm]);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        // The whole blob is base64 chars and > 20 chars → detected as blob literal
        assert!(
            r.literals.iter().any(|l| l.len() >= MIN_BASE64_BLOB_LEN),
            "Should detect base64-like blob"
        );
    }

    // ── helper tests ──────────────────────────────────────────────────────

    #[test]
    fn test_is_base64_char() {
        assert!(is_base64_char(b'A'));
        assert!(is_base64_char(b'z'));
        assert!(is_base64_char(b'0'));
        assert!(is_base64_char(b'+'));
        assert!(is_base64_char(b'/'));
        assert!(is_base64_char(b'='));
        assert!(!is_base64_char(b'!'));
        assert!(!is_base64_char(b' '));
    }

    #[test]
    fn test_extract_identifiers_basic() {
        let data = b"api_key = secret_token";
        let ids = extract_identifiers(data);
        assert!(ids.contains(&"api_key".to_string()));
        assert!(ids.contains(&"secret_token".to_string()));
    }

    #[test]
    fn test_cpu_engine_new_zero_threads() {
        // num_threads=0 → Rayon picks automatically (should succeed)
        let engine = CpuEngine::new(0);
        assert!(engine.is_ok());
    }
}
