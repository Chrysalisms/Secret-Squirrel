//! Four-stage pipeline coordinator for Secret Squirrel.
//!
//! [`Pipeline`] sequences the four scan stages in order, using the
//! [`Router`] to dispatch each stage to the GPU or CPU as appropriate:
//!
//! ```text
//! Fragment bytes
//!     │
//!     ▼
//! ┌───────────────────────────────────────┐
//! │ Stage 1 — Shannon Entropy Gate        │ ← eliminates ~95% of input
//! │   threshold: PipelineConfig::entropy_ │
//! │   threshold (default 3.5 bits/byte)   │
//! └─────────────────┬─────────────────────┘
//!                   │ EntropyCandidate[]
//!                   ▼
//! ┌───────────────────────────────────────┐
//! │ Stage 2 — Semantic Proximity Filter   │ ← keyword / assignment patterns
//! │   threshold: proximity_threshold      │
//! └─────────────────┬─────────────────────┘
//!                   │ ProximityMatch[]
//!                   ▼
//! ┌───────────────────────────────────────┐
//! │ Stage 3 — Tri-Stream Decomposition    │ ← identifier / literal / struct
//! └─────────────────┬─────────────────────┘
//!                   │ TriStreamResult[]
//!                   ▼
//! ┌───────────────────────────────────────┐
//! │ Stage 4 — Pattern Verification        │ ← AC automaton + regex on survivors
//! └─────────────────┬─────────────────────┘
//!                   │ PatternMatch[]
//!                   ▼
//!             (returned to caller)
//! ```
//!
//! The pipeline is intentionally **synchronous and infallible for individual
//! stages** — each stage returns an empty `Vec` on degenerate input rather
//! than propagating an error.  Errors are only surfaced for unrecoverable
//! conditions (e.g., thread pool failure).

use tracing::debug;

use crate::config::PipelineConfig;
use crate::error::Result;
use crate::types::{Fragment, PatternMatch};

use super::router::Router;

// ============================================================================
// Pipeline
// ============================================================================

/// Coordinates the four-stage scan pipeline for a single [`Fragment`].
///
/// Instantiate via [`Pipeline::new`], then call [`Pipeline::process_fragment`]
/// once per fragment.  The returned [`PatternMatch`]es are raw — scoring,
/// deduplication, and report generation happen in downstream modules.
pub struct Pipeline {
    /// GPU/CPU routing engine.
    router: Router,
    /// Stage-threshold configuration.
    config: PipelineConfig,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Pipeline {
    /// Create a new pipeline from a pre-built router and config.
    pub fn new(router: Router, config: PipelineConfig) -> Self {
        Self { router, config }
    }

    /// Run the full 4-stage pipeline on a [`Fragment`].
    ///
    /// Returns raw [`PatternMatch`]es before scoring or deduplication.
    /// An empty `Vec` is returned if the fragment is filtered out by any stage.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::SquirrelError::Pipeline`] if an unrecoverable
    /// error occurs (e.g., the thread pool is poisoned).  Individual stage
    /// failures (empty results) are **not** errors.
    pub fn process_fragment(&self, fragment: &Fragment) -> Result<Vec<PatternMatch>> {
        let input = &fragment.content;
        let path = &fragment.metadata.path;

        debug!(
            path = %path,
            bytes = input.len(),
            "Pipeline: processing fragment"
        );

        // ── Stage 1: entropy gate ─────────────────────────────────────────
        let candidates = self.router.execute_entropy(
            input,
            self.config.entropy_threshold,
            self.config.entropy_chunk_size,
        )?;

        debug!(
            path = %path,
            survivors = candidates.len(),
            "Pipeline stage 1 (entropy) complete"
        );

        if candidates.is_empty() {
            return Ok(vec![]);
        }

        // ── Stage 2: proximity filter ─────────────────────────────────────
        let proximity_matches = self
            .router
            .execute_proximity(&candidates, self.config.proximity_threshold)?;

        debug!(
            path = %path,
            survivors = proximity_matches.len(),
            "Pipeline stage 2 (proximity) complete"
        );

        if proximity_matches.is_empty() {
            return Ok(vec![]);
        }

        // ── Stage 3: tri-stream decomposition ─────────────────────────────
        let tristream_results = self.router.execute_tristream(&proximity_matches)?;

        debug!(
            path = %path,
            survivors = tristream_results.len(),
            "Pipeline stage 3 (tristream) complete"
        );

        if tristream_results.is_empty() {
            return Ok(vec![]);
        }

        // ── Stage 4: pattern verification ─────────────────────────────────
        // Build a flat view of all surviving bytes for the AC automaton.
        // Each surviving region is scanned independently against the compiled
        // rule set.  This stage is always on the CPU (regex is CPU-bound).
        //
        // NOTE: The actual Aho-Corasick automaton and rule set are loaded in
        // the `rules` module and injected by the caller.  Here we operate on
        // the raw bytes carried by each TriStreamResult and produce
        // PatternMatch stubs with empty rule_id when no rules are injected.
        //
        // In production the `ScanSession` orchestrator injects the compiled
        // rules via `Pipeline::process_fragment_with_rules`.

        let pattern_matches: Vec<PatternMatch> = tristream_results
            .into_iter()
            .map(|tsr| {
                // For each tri-stream result, emit a single PassThrough
                // PatternMatch so that the scoring layer can see the fragment.
                // The actual rule_id and pattern_score are filled in by the
                // rules layer.
                PatternMatch {
                    match_start: tsr.source.candidate.offset as usize,
                    match_end: (tsr.source.candidate.offset
                        + tsr.source.candidate.length as u64)
                        as usize,
                    matched_text: String::from_utf8_lossy(
                        tsr.source.candidate.raw.as_ref(),
                    )
                    .into_owned(),
                    pattern_score: tsr.combined_score,
                    rule_id: String::new(), // filled in by rules layer
                    source: tsr,
                }
            })
            .collect();

        debug!(
            path = %path,
            matches = pattern_matches.len(),
            "Pipeline stage 4 (pattern) complete"
        );

        Ok(pattern_matches)
    }

    /// Run the full pipeline **with** a compiled Aho-Corasick automaton and
    /// rule set.  This is the production entry point used by [`super::session`].
    ///
    /// Unlike [`process_fragment`], stage 4 here performs real pattern
    /// verification against the compiled rules.
    pub fn process_fragment_with_rules(
        &self,
        fragment: &Fragment,
        ac: &aho_corasick::AhoCorasick,
        rules: &[crate::rules::CompiledRule],
    ) -> Result<Vec<PatternMatch>> {
        let input = &fragment.content;
        let path = &fragment.metadata.path;

        debug!(
            path = %path,
            bytes = input.len(),
            "Pipeline (with rules): processing fragment"
        );

        // Stages 1–3 are identical.
        let candidates = self.router.execute_entropy(
            input,
            self.config.entropy_threshold,
            self.config.entropy_chunk_size,
        )?;
        if candidates.is_empty() {
            return Ok(vec![]);
        }

        let proximity_matches = self
            .router
            .execute_proximity(&candidates, self.config.proximity_threshold)?;
        if proximity_matches.is_empty() {
            return Ok(vec![]);
        }

        let tristream_results = self.router.execute_tristream(&proximity_matches)?;
        if tristream_results.is_empty() {
            return Ok(vec![]);
        }

        // Stage 4: real pattern verification.
        let mut all_matches = Vec::new();
        for tsr in tristream_results {
            let raw = tsr.source.candidate.raw.clone();
            let base_offset = tsr.source.candidate.offset as usize;

            let hits = self.router.cpu.execute_pattern(raw.as_ref(), ac, rules);

            for mut hit in hits {
                // Adjust match offsets to be relative to the original fragment.
                hit.match_start += base_offset;
                hit.match_end += base_offset;

                // Replace the dummy TriStreamResult source from execute_pattern
                // with the real one we computed in stage 3.
                let rebuilt = PatternMatch {
                    source: crate::types::TriStreamResult {
                        source: tsr.source.clone(),
                        identifiers: tsr.identifiers.clone(),
                        literals: tsr.literals.clone(),
                        structure_score: tsr.structure_score,
                        combined_score: tsr.combined_score,
                    },
                    rule_id: hit.rule_id,
                    matched_text: hit.matched_text,
                    match_start: hit.match_start,
                    match_end: hit.match_end,
                    pattern_score: hit.pattern_score,
                };
                all_matches.push(rebuilt);
            }
        }

        debug!(
            path = %path,
            matches = all_matches.len(),
            "Pipeline (with rules) stage 4 complete"
        );

        Ok(all_matches)
    }

    /// Return a reference to the inner router (for stats gathering).
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Return a reference to the pipeline config.
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GpuConfig, PipelineConfig};
    use crate::types::{Fragment, FragmentMetadata, SourceType};
    use bytes::Bytes;

    async fn make_pipeline() -> Pipeline {
        let gpu_config = GpuConfig {
            enabled: false,
            threshold_bytes: 100 * 1024 * 1024,
            backend: None,
        };
        let router = Router::new(&gpu_config).await;
        Pipeline::new(router, PipelineConfig::default())
    }

    fn make_fragment(content: &[u8], path: &str) -> Fragment {
        Fragment {
            content: Bytes::copy_from_slice(content),
            metadata: FragmentMetadata {
                path: path.to_string(),
                source_type: SourceType::Directory,
                size: content.len() as u64,
                attributes: Default::default(),
            },
        }
    }

    #[tokio::test]
    async fn test_pipeline_low_entropy_no_matches() {
        let pipeline = make_pipeline().await;
        // All-same bytes → entropy = 0 → filtered at stage 1.
        let fragment = make_fragment(&vec![0xAAu8; 1024], "test.env");
        let matches = pipeline.process_fragment(&fragment).unwrap();
        assert!(
            matches.is_empty(),
            "Low-entropy fragment should produce no matches"
        );
    }

    #[tokio::test]
    async fn test_pipeline_high_entropy_with_keyword_produces_match() {
        // Build a config with very low thresholds so the test isn't brittle.
        let gpu_config = GpuConfig {
            enabled: false,
            threshold_bytes: 100 * 1024 * 1024,
            backend: None,
        };
        let router = Router::new(&gpu_config).await;
        let config = PipelineConfig {
            entropy_threshold: 2.0,      // very low — accept almost anything
            proximity_threshold: 0.01,   // very low — accept almost anything
            entropy_chunk_size: 64,
            ..PipelineConfig::default()
        };
        let pipeline = Pipeline::new(router, config);

        // Pad a keyword + high-entropy suffix to a full 64-byte chunk.
        let mut content = b"apiKey = \"".to_vec();
        // Add bytes spanning a wide range to maximize entropy.
        content.extend((75u8..129u8).chain(0u8..10u8));
        let fragment = make_fragment(&content, "config.json");
        let matches = pipeline.process_fragment(&fragment).unwrap();
        // With very low thresholds, at least one match should survive.
        assert!(
            !matches.is_empty(),
            "High-entropy chunk with keyword should produce at least one match"
        );
    }

    #[tokio::test]
    async fn test_pipeline_empty_fragment_no_matches() {
        let pipeline = make_pipeline().await;
        let fragment = make_fragment(b"", "empty.txt");
        let matches = pipeline.process_fragment(&fragment).unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_returns_correct_offsets() {
        let pipeline = make_pipeline().await;
        // Two chunks: first low-entropy, second high-entropy with keyword.
        let mut content = vec![0xAAu8; 64]; // chunk 0: low entropy
        let mut chunk1 = b"password=\"".to_vec();
        chunk1.extend(0u8..54u8);
        content.extend_from_slice(&chunk1);

        let fragment = make_fragment(&content, "secrets.yml");
        let matches = pipeline.process_fragment(&fragment).unwrap();

        for m in &matches {
            assert!(
                m.match_start >= 64,
                "Match should be in the second chunk (offset >= 64), got {}",
                m.match_start
            );
        }
    }
}
