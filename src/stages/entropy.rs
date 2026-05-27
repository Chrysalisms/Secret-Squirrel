//! Stage 1 — Shannon Entropy Gate.
//!
//! Scans raw byte content using overlapping windows and computes Shannon entropy
//! for each window. Windows whose entropy exceeds the configured threshold AND
//! whose length meets the minimum are emitted as [`EntropyCandidate`]s for
//! downstream stages.
//!
//! # Complexity
//!
//! O(n) time with O(256) extra space per window (byte frequency table).
//! The sliding-window approach avoids re-scanning bytes redundantly.

use bytes::Bytes;

use crate::config::PipelineConfig;
use crate::types::EntropyCandidate;

/// Stage 1: Shannon entropy filter.
///
/// Splits content into overlapping windows (stride = chunk_size / 2) and
/// emits candidates whose entropy exceeds `threshold` and whose length is
/// at least `min_length`.
#[derive(Debug, Clone)]
pub struct EntropyGate {
    /// Minimum Shannon entropy (bits per byte) to pass a window.
    pub threshold: f32,
    /// Size of each analysis window in bytes.
    pub chunk_size: usize,
    /// Minimum byte length of a candidate to be emitted.
    pub min_length: usize,
}

impl EntropyGate {
    /// Create a new [`EntropyGate`] from pipeline configuration.
    pub fn new(config: &PipelineConfig) -> Self {
        Self {
            threshold: config.entropy_threshold,
            chunk_size: config.entropy_chunk_size,
            min_length: config.min_candidate_length,
        }
    }

    /// Filter `content`, returning all high-entropy byte windows as candidates.
    ///
    /// Windows overlap by 50% of `chunk_size` so secrets that straddle a
    /// window boundary are still detected.
    ///
    /// # Arguments
    ///
    /// * `content` — The raw bytes to scan. Cloned cheaply from a `Bytes` arc.
    pub fn filter(&self, content: &Bytes) -> Vec<EntropyCandidate> {
        if content.is_empty() {
            return Vec::new();
        }

        let stride = (self.chunk_size / 2).max(1);
        let mut candidates = Vec::new();

        let mut offset = 0usize;
        while offset < content.len() {
            let end = (offset + self.chunk_size).min(content.len());
            let window = &content[offset..end];

            // Only emit candidates that meet the minimum length requirement.
            if window.len() >= self.min_length {
                let entropy = shannon_entropy(window);
                if entropy > self.threshold {
                    candidates.push(EntropyCandidate {
                        offset: offset as u64,
                        length: window.len() as u32,
                        entropy,
                        raw: content.slice(offset..end),
                    });
                }
            }

            // Advance by stride; stop when we have consumed the last byte.
            if end == content.len() {
                break;
            }
            offset += stride;
        }

        candidates
    }
}

/// Compute the Shannon entropy of a byte slice.
///
/// H = -Σ p_i · log₂(p_i) over all byte values 0..=255 that appear.
///
/// Returns a value in [0.0, 8.0] (bits per symbol).
/// - 0.0 → all identical bytes (zero entropy)
/// - 8.0 → all 256 byte values appear with equal frequency
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    // Build a frequency table using a stack-allocated array (no heap alloc).
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for count in freq.iter() {
        if *count == 0 {
            continue;
        }
        let p = *count as f32 / len;
        // Use the identity: -p * log2(p) = p * log2(1/p)
        entropy -= p * p.log2();
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PipelineConfig;

    fn gate() -> EntropyGate {
        EntropyGate::new(&PipelineConfig::default())
    }

    // ---- shannon_entropy unit tests ----

    #[test]
    fn test_entropy_all_zeros() {
        let data = vec![0u8; 64];
        let h = shannon_entropy(&data);
        assert_eq!(h, 0.0, "All-identical bytes → zero entropy");
    }

    #[test]
    fn test_entropy_all_unique() {
        // 256 distinct bytes → maximum entropy = 8.0
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&data);
        // Due to floating-point arithmetic we check near 8.0
        assert!(
            (h - 8.0).abs() < 0.001,
            "All 256 byte values → entropy ≈ 8.0, got {h}"
        );
    }

    #[test]
    fn test_entropy_password_string() {
        // "password" has 8 chars but only 7 unique ('s' repeats twice):
        // p,a,s,s,w,o,r,d → freq: p=1,a=1,s=2,w=1,o=1,r=1,d=1
        // Expected ≈ 2.75 bits (low, mostly distinct but short)
        let data = b"password";
        let h = shannon_entropy(data);
        // The exact value is ~2.906 for "password"; we assert it's in a
        // reasonable "low-entropy" range (< 3.5) consistent with the spec.
        assert!(
            h < 3.5,
            "\"password\" should have low entropy (< 3.5), got {h}"
        );
        assert!(h > 1.0, "\"password\" entropy should be > 1.0, got {h}");
    }

    #[test]
    fn test_entropy_base64_string() {
        // A 32-char base64 string should have entropy > 4.5
        let data = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE";
        let h = shannon_entropy(data);
        assert!(
            h > 4.5,
            "Base64 string should have entropy > 4.5, got {h}"
        );
    }

    #[test]
    fn test_entropy_empty_slice() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    // ---- EntropyGate::filter unit tests ----

    #[test]
    fn test_filter_high_entropy_detected() {
        let gate = gate();
        // 64 bytes of base64-like content → high entropy
        let content = Bytes::from(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE+Zq9vK8sX23pLY5tNmR1uW4Q=".to_vec());
        let candidates = gate.filter(&content);
        assert!(
            !candidates.is_empty(),
            "High-entropy content should produce at least one candidate"
        );
    }

    #[test]
    fn test_filter_low_entropy_rejected() {
        let gate = gate();
        // 64 bytes of repeated 'a' → entropy = 0
        let content = Bytes::from(vec![b'a'; 128]);
        let candidates = gate.filter(&content);
        assert!(
            candidates.is_empty(),
            "Low-entropy content (all 'a') should produce no candidates"
        );
    }

    #[test]
    fn test_filter_empty_content() {
        let gate = gate();
        let candidates = gate.filter(&Bytes::new());
        assert!(candidates.is_empty(), "Empty content → no candidates");
    }

    #[test]
    fn test_filter_candidate_fields() {
        let gate = gate();
        // High-entropy 64-byte window
        let raw: Vec<u8> = (0u8..=63).collect();
        let content = Bytes::from(raw);
        let candidates = gate.filter(&content);
        assert!(!candidates.is_empty());
        let c = &candidates[0];
        assert!(c.entropy > gate.threshold);
        assert!(c.length as usize >= gate.min_length);
        assert_eq!(c.offset, 0);
    }

    #[test]
    fn test_filter_short_content_below_min_length() {
        let mut cfg = PipelineConfig::default();
        cfg.min_candidate_length = 32;
        let gate = EntropyGate::new(&cfg);
        // Only 4 bytes — below min_length even if entropy is high
        let content = Bytes::from(b"\xDE\xAD\xBE\xEF".to_vec());
        let candidates = gate.filter(&content);
        assert!(
            candidates.is_empty(),
            "Content shorter than min_length should be filtered out"
        );
    }
}
