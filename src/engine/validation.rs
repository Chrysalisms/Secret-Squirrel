use bytes::Bytes;

use crate::engine::cpu::CpuEngine;
use crate::engine::routing::RuleBucketIndexes;
use crate::rules::CompiledRule;
use crate::types::{
    EntropyCandidate, MatchEvidence, MatchKind, PatternMatch, ProximityMatch, ProximityPattern,
    RoutedCandidate, TriStreamResult,
};

#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    pub validator_runs: usize,
    pub regex_matches: usize,
    pub decoded_matches: usize,
}

pub fn validate_routed_candidates(
    _cpu: &CpuEngine,
    candidates: &[RoutedCandidate],
    path: &str,
    rules: &[CompiledRule],
    buckets: &RuleBucketIndexes,
) -> (Vec<PatternMatch>, ValidationStats) {
    let mut out = Vec::new();
    let mut stats = ValidationStats::default();

    for candidate in candidates {
        let bucket = buckets.for_candidate(candidate, path);
        if bucket.is_empty() {
            continue;
        }
        for &rule_idx in bucket {
            stats.validator_runs += 1;
            let rule = &rules[rule_idx];
            for hit in CpuEngine::run_routed_regex(rule, &candidate.candidate.snippet) {
                if hit.3.is_some() {
                    stats.decoded_matches += 1;
                }
                stats.regex_matches += 1;
                out.push(make_routed_match(rule, candidate, hit.0, hit.1, hit.2, hit.3));
            }
        }
    }

    (out, stats)
}

fn make_routed_match(
    rule: &CompiledRule,
    candidate: &RoutedCandidate,
    rel_start: usize,
    rel_end: usize,
    text: String,
    encoding_chain: Option<Vec<String>>,
) -> PatternMatch {
    let start = candidate.candidate.base_offset + rel_start;
    let end = candidate.candidate.base_offset + rel_end;
    let value_bytes = Bytes::copy_from_slice(candidate.candidate.value.as_bytes());
    let tristream = TriStreamResult {
        source: ProximityMatch {
            candidate: EntropyCandidate {
                offset: start as u64,
                length: candidate.candidate.value.len() as u32,
                entropy: candidate.candidate.entropy_score,
                raw: value_bytes.clone(),
            },
            pattern: candidate.candidate.evidence.proximity_pattern,
            proximity_score: candidate.candidate.proximity_score,
            context: candidate.candidate.context.clone(),
        },
        identifiers: candidate.candidate.identifier.clone().into_iter().collect(),
        literals: vec![value_bytes],
        structure_score: candidate.candidate.structure_score,
        combined_score: ((candidate.candidate.proximity_score + candidate.candidate.structure_score)
            / 2.0)
            .min(1.0),
    };

    PatternMatch {
        source: tristream,
        rule_id: rule.id.clone(),
        matched_text: text,
        match_start: start,
        match_end: end,
        pattern_score: rule.confidence_weight as f32,
        evidence: merge_evidence(&candidate.candidate.evidence, rule),
        encoding_chain,
    }
}

fn merge_evidence(base: &MatchEvidence, rule: &CompiledRule) -> MatchEvidence {
    let mut evidence = base.clone();
    let lower_rule = rule.id.to_lowercase();
    if lower_rule.contains("catchall") {
        evidence.generic_catchall = true;
    }
    if lower_rule.contains("jwt") {
        evidence.kind = MatchKind::Jwt;
    } else if lower_rule.contains("bearer") {
        evidence.kind = MatchKind::BearerAuth;
    } else if lower_rule.contains("private-key") || lower_rule.contains("pem") {
        evidence.kind = MatchKind::PrivateKey;
        evidence.private_key_like = true;
    } else if lower_rule.contains("url") && lower_rule.contains("credential") {
        evidence.kind = MatchKind::UrlCredentials;
    } else if lower_rule.contains("api-key") {
        evidence.kind = MatchKind::ApiKeyAssignment;
    } else if lower_rule.contains("password") {
        evidence.kind = MatchKind::PasswordAssignment;
    } else if lower_rule.contains("token") {
        evidence.kind = MatchKind::TokenAssignment;
    }

    if matches!(evidence.proximity_pattern, ProximityPattern::Unknown) {
        evidence.proximity_pattern = base.proximity_pattern;
    }
    evidence
}
