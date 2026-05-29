//! Score fusion engine.
//!
//! Combines the scores from all four pipeline stages, the Markov randomness
//! scorer, and optionally the CNN classifier and AST semantic adjuster into a
//! single [`FusedScore`].
//!
//! # Weighting
//!
//! Weights are loaded from [`ScoringConfig`] and should sum to 1.0:
//!
//! | Source      | Default weight |
//! |-------------|---------------|
//! | Entropy     | 0.15          |
//! | Proximity   | 0.15          |
//! | Tri-stream  | 0.20          |
//! | Markov      | 0.25          |
//! | Pattern     | 0.25          |
//!
//! CNN and AST scores, when present, blend in by reducing the other weights
//! proportionally (their sum replaces up to 0.20 of the total weight).

use crate::config::ScoringConfig;
use crate::scoring::confidence::ConfidenceAdjuster;
use crate::types::{FragmentMetadata, FusedScore, PatternMatch};

/// Fusion engine — weighted combination of all scoring signals.
#[derive(Debug, Clone)]
pub struct FusionEngine {
    /// Weight for the Shannon entropy stage score.
    pub entropy_weight: f64,
    /// Weight for the semantic proximity stage score.
    pub proximity_weight: f64,
    /// Weight for the tri-stream decomposition score.
    pub tristream_weight: f64,
    /// Weight for the Markov randomness score.
    pub markov_weight: f64,
    /// Weight for the pattern match stage score.
    pub pattern_weight: f64,
}

impl FusionEngine {
    /// Create a [`FusionEngine`] from scoring configuration.
    pub fn new(config: &ScoringConfig) -> Self {
        Self {
            entropy_weight: config.entropy_weight,
            proximity_weight: config.proximity_weight,
            tristream_weight: config.tristream_weight,
            markov_weight: config.markov_weight,
            pattern_weight: config.pattern_weight,
        }
    }

    /// Compute the fused confidence score for a [`PatternMatch`].
    ///
    /// # Arguments
    ///
    /// * `pm`       — The pattern match output from Stage 4.
    /// * `markov`   — Markov randomness score (0.0–1.0).
    /// * `cnn`      — Optional CNN classifier score (0.0–1.0).
    /// * `ast`      — Optional AST-based context adjustment (±delta, applied
    ///                after normalization).
    /// * `metadata` — Fragment provenance for confidence adjustment.
    ///
    /// # Returns
    ///
    /// A [`FusedScore`] with the overall confidence and all sub-scores.
    pub fn compute(
        &self,
        pm: &PatternMatch,
        markov: f32,
        cnn: Option<f32>,
        ast: Option<f32>,
        metadata: &FragmentMetadata,
    ) -> FusedScore {
        // Extract per-stage scores from the pattern match provenance chain.
        let entropy_score = pm.source.source.candidate.entropy as f64 / 8.0; // Normalize [0,8] → [0,1]
        let proximity_score = pm.source.source.proximity_score as f64;
        let tristream_score = pm.source.combined_score as f64;
        let pattern_score = pm.pattern_score as f64;
        let markov_score = markov as f64;

        // Compute weighted sum.
        let raw = self.entropy_weight * entropy_score
            + self.proximity_weight * proximity_score
            + self.tristream_weight * tristream_score
            + self.markov_weight * markov_score
            + self.pattern_weight * pattern_score;

        // Blend in CNN if available (replaces 0.15 of total weight, redistributed).
        let (raw, cnn_score_opt) = if let Some(cnn_val) = cnn {
            let cnn_blend = 0.15;
            let scale = 1.0 - cnn_blend;
            let blended = raw * scale + cnn_blend * cnn_val as f64;
            (blended, Some(cnn_val as f64))
        } else {
            (raw, None)
        };

        // Normalize to [0.0, 1.0] — the weighted sum is already within range
        // if weights sum to 1.0, but we clamp for safety.
        let normalized = raw.clamp(0.0, 1.0);

        // Apply provenance-aware confidence adjustment.
        let identifiers: Vec<String> = pm.source.identifiers.clone();
        let adjusted =
            ConfidenceAdjuster::adjust_with_identifiers(normalized, metadata, &identifiers);

        // Apply optional AST adjustment (additive delta, clamped).
        let ast_adjustment_opt = ast.map(|a| a as f64);
        let final_confidence = if let Some(delta) = ast_adjustment_opt {
            (adjusted + delta).clamp(0.0, 1.0)
        } else {
            adjusted
        };

        FusedScore {
            confidence: final_confidence,
            entropy: entropy_score,
            proximity: proximity_score,
            tristream: tristream_score,
            pattern: pattern_score,
            markov: markov_score,
            cnn_score: cnn_score_opt,
            ast_adjustment: ast_adjustment_opt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PipelineConfig, ScoringConfig};
    use crate::stages::entropy::shannon_entropy;
    use crate::types::{
        EntropyCandidate, FragmentMetadata, ProximityMatch, ProximityPattern, SourceType,
        TriStreamResult,
    };
    use bytes::Bytes;
    use std::collections::HashMap;

    fn default_engine() -> FusionEngine {
        FusionEngine::new(&ScoringConfig::default())
    }

    fn meta(path: &str) -> FragmentMetadata {
        FragmentMetadata {
            path: path.to_string(),
            source_type: SourceType::Directory,
            size: 100,
            attributes: HashMap::new(),
        }
    }

    fn make_pattern_match(
        context: &str,
        secret: &str,
        entropy: f32,
        proximity: f32,
        tristream: f32,
        pattern_score: f32,
    ) -> PatternMatch {
        let secret_bytes = secret.as_bytes();
        let offset = context
            .as_bytes()
            .windows(secret_bytes.len())
            .position(|w| w == secret_bytes)
            .unwrap_or(0);

        let pm = ProximityMatch {
            candidate: EntropyCandidate {
                offset: offset as u64,
                length: secret_bytes.len() as u32,
                entropy,
                raw: Bytes::copy_from_slice(secret_bytes),
            },
            pattern: ProximityPattern::Assignment,
            proximity_score: proximity,
            context: Bytes::copy_from_slice(context.as_bytes()),
        };

        let tri = TriStreamResult {
            source: pm,
            identifiers: vec!["API_SECRET".to_string()],
            literals: vec![Bytes::copy_from_slice(secret_bytes)],
            structure_score: 0.5,
            combined_score: tristream,
        };

        PatternMatch {
            source: tri,
            rule_id: "test-rule".to_string(),
            matched_text: secret.to_string(),
            match_start: offset,
            match_end: offset + secret_bytes.len(),
            pattern_score,
            encoding_chain: None,
        }
    }

    #[test]
    fn test_fused_score_fields_populated() {
        let engine = default_engine();
        let pm = make_pattern_match(
            "API_SECRET = \"AKIAIOSFODNN7EXAMPLE\"",
            "AKIAIOSFODNN7EXAMPLE",
            5.0,  // entropy
            0.8,  // proximity
            0.75, // tristream
            0.90, // pattern_score
        );
        let score = engine.compute(&pm, 0.7, None, None, &meta("config.env"));
        assert!(
            (0.0..=1.0).contains(&score.confidence),
            "Confidence out of range: {}",
            score.confidence
        );
        assert!(score.entropy > 0.0);
        assert!(score.proximity > 0.0);
        assert!(score.tristream > 0.0);
        assert!(score.pattern > 0.0);
        assert!(score.markov > 0.0);
        assert!(score.cnn_score.is_none());
        assert!(score.ast_adjustment.is_none());
    }

    #[test]
    fn test_cnn_score_blended_in() {
        let engine = default_engine();
        let pm = make_pattern_match("x = \"abc\"", "abc", 3.0, 0.5, 0.5, 0.5);
        let without_cnn = engine.compute(&pm, 0.5, None, None, &meta("x.txt"));
        let with_cnn = engine.compute(&pm, 0.5, Some(1.0), None, &meta("x.txt"));

        // CNN = 1.0 should push the score up.
        assert!(
            with_cnn.confidence >= without_cnn.confidence,
            "CNN=1.0 should not decrease confidence"
        );
        assert!(with_cnn.cnn_score.is_some());
    }

    #[test]
    fn test_ast_adjustment_applied() {
        let engine = default_engine();
        let pm = make_pattern_match("x = \"abc\"", "abc", 3.0, 0.5, 0.5, 0.5);
        let without_ast = engine.compute(&pm, 0.5, None, None, &meta("x.py"));
        let with_ast = engine.compute(&pm, 0.5, None, Some(0.2), &meta("x.py"));

        assert!(
            with_ast.confidence >= without_ast.confidence,
            "Positive AST delta should increase confidence"
        );
        assert!(with_ast.ast_adjustment.is_some());
    }

    #[test]
    fn test_dotenv_provenance_increases_confidence() {
        let engine = default_engine();
        let pm = make_pattern_match("x = \"abc\"", "abc", 3.0, 0.5, 0.5, 0.5);
        let normal = engine.compute(&pm, 0.5, None, None, &meta("app.py"));
        let dotenv = engine.compute(&pm, 0.5, None, None, &meta(".env"));

        assert!(
            dotenv.confidence > normal.confidence,
            ".env provenance should boost confidence: {:.3} vs {:.3}",
            dotenv.confidence,
            normal.confidence
        );
    }

    #[test]
    fn test_weights_sum_to_one() {
        let config = ScoringConfig::default();
        let total = config.entropy_weight
            + config.proximity_weight
            + config.tristream_weight
            + config.markov_weight
            + config.pattern_weight;
        assert!(
            (total - 1.0).abs() < 1e-9,
            "Default weights should sum to 1.0, got {total}"
        );
    }
}
