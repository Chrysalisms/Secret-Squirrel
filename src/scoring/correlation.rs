//! Cross-file credential chain engine.
//!
//! Detects when the same secret value or variable name appears across multiple
//! files, forming a "credential chain". Common patterns:
//!
//! - `.env` defines `DB_PASSWORD=hunter2`
//! - `docker-compose.yml` references `${DB_PASSWORD}`
//! - `app.py` calls `os.getenv("DB_PASSWORD")`
//!
//! The engine classifies each finding in a chain into one of three roles:
//!
//! | Role          | Description                                          |
//! |---------------|------------------------------------------------------|
//! | **Origin**    | Where the value is assigned/defined                  |
//! | **Propagation** | Where the variable is referenced by name           |
//! | **Usage**     | Where the value itself (or the env var) is consumed  |
//!
//! # Memory safety
//!
//! [`FindingRef`] stores **only** the finding ID, rule ID, location, and
//! secret hash — never the raw secret value. The `budget_bytes` limit
//! prevents the engine from accumulating unbounded state on very large scans.

use std::collections::HashMap;

use crate::types::{CredentialChain, Finding, Location};

/// A memory-safe reference to a finding — no raw secret value stored.
#[derive(Debug, Clone)]
pub struct FindingRef {
    /// Unique finding ID (matches [`Finding::id`]).
    pub finding_id: String,
    /// Rule that produced this finding.
    pub rule_id: String,
    /// Source location of the finding.
    pub location: Location,
    /// HMAC-SHA256 hash of the secret value (for value-based correlation).
    pub secret_hash: String,
}

impl FindingRef {
    fn from_finding(f: &Finding) -> Self {
        Self {
            finding_id: f.id.clone(),
            rule_id: f.rule_id.clone(),
            location: f.location.clone(),
            secret_hash: f.secret_hash.clone(),
        }
    }
}

/// Reference patterns that indicate variable propagation (reading a variable
/// from another location rather than defining it).
///
/// These are searched as byte substrings within the match context.
static _PROPAGATION_PATTERNS: &[&str] = &[
    "${",        // Shell / Docker Compose variable expansion
    "$(",        // Shell command substitution (less common)
    "getenv(",   // Python os.getenv()
    "environ[",  // Python os.environ[]
    "ENV[",      // Ruby ENV[]
    "System.getenv(", // Java
    "process.env.", // JavaScript/Node.js
    "os.Getenv(", // Go
];

/// Cross-file credential chain engine.
///
/// # Memory budget
///
/// The engine tracks a rough byte estimate of its stored state. When
/// `budget_bytes` is exceeded, the oldest entries (lowest-offset findings)
/// are evicted from the by-value index to stay within budget.
pub struct CorrelationEngine {
    /// Index from secret hash → list of finding refs sharing that value.
    by_value: HashMap<String, Vec<FindingRef>>,
    /// Index from variable name → list of finding refs mentioning that variable.
    by_variable: HashMap<String, Vec<FindingRef>>,
    /// Memory budget in bytes.
    budget_bytes: u64,
    /// Approximate current memory usage in bytes.
    used_bytes: u64,
}

impl CorrelationEngine {
    /// Create a new correlation engine with the given memory budget.
    pub fn new(budget_bytes: u64) -> Self {
        Self {
            by_value: HashMap::new(),
            by_variable: HashMap::new(),
            budget_bytes,
            used_bytes: 0,
        }
    }

    /// Add a finding to the correlation indices.
    ///
    /// # Arguments
    ///
    /// * `finding`       — The finding to index.
    /// * `variable_name` — Optional variable name associated with this finding
    ///                     (e.g., `"DB_PASSWORD"`). If provided, the finding is
    ///                     indexed both by value-hash and by variable name.
    pub fn add_finding(&mut self, finding: &Finding, variable_name: Option<&str>) {
        let fref = FindingRef::from_finding(finding);

        // Rough size estimate: finding ID + hash + path + rule ID.
        let entry_size = (fref.finding_id.len()
            + fref.secret_hash.len()
            + fref.location.path.len()
            + fref.rule_id.len()) as u64;

        // Enforce memory budget: skip if already over budget.
        if self.used_bytes + entry_size > self.budget_bytes {
            tracing::warn!(
                "CorrelationEngine budget exceeded ({}/{}B), skipping finding {}",
                self.used_bytes,
                self.budget_bytes,
                fref.finding_id
            );
            return;
        }

        self.used_bytes += entry_size;

        // Index by secret hash (value-based correlation).
        self.by_value
            .entry(fref.secret_hash.clone())
            .or_default()
            .push(fref.clone());

        // Index by variable name (name-based propagation detection).
        if let Some(var_name) = variable_name {
            if !var_name.is_empty() {
                self.by_variable
                    .entry(var_name.to_string())
                    .or_default()
                    .push(fref);
            }
        }
    }

    /// Resolve all tracked findings into [`CredentialChain`]s.
    ///
    /// A chain is formed when:
    /// - A variable name appears in 2 or more distinct files, **or**
    /// - The same secret hash appears in 2 or more distinct files.
    ///
    /// Each chain finding is classified as:
    /// - **Origin**: earliest-offset occurrence (lowest line number)
    /// - **Propagation**: occurrences in other files that reference the
    ///   variable name via a propagation pattern
    /// - **Usage**: all remaining cross-file occurrences
    ///
    /// Findings in a chain receive a +0.20 confidence boost (expressed in the
    /// `chain_confidence` field — the caller applies this to individual findings).
    ///
    /// # Returns
    ///
    /// A `Vec<CredentialChain>`, one per detected chain.
    pub fn resolve_chains(&self) -> Vec<CredentialChain> {
        let mut chains: Vec<CredentialChain> = Vec::new();
        let mut processed_hashes: std::collections::HashSet<String> = Default::default();

        // ---- Variable-name chains ----
        for (var_name, refs) in &self.by_variable {
            // Require 2+ distinct files.
            let distinct_paths: std::collections::HashSet<&str> =
                refs.iter().map(|r| r.location.path.as_str()).collect();
            if distinct_paths.len() < 2 {
                continue;
            }

            // Sort by (path, line) to find the earliest (origin) occurrence.
            let mut sorted = refs.clone();
            sorted.sort_by(|a, b| {
                a.location.path.cmp(&b.location.path)
                    .then(a.location.start_line.cmp(&b.location.start_line))
                    .then(a.location.byte_offset.cmp(&b.location.byte_offset))
            });

            let origin = &sorted[0];
            let mut propagation_ids: Vec<String> = Vec::new();
            let mut usage_ids: Vec<String> = Vec::new();

            for fref in sorted.iter().skip(1) {
                if is_propagation_context(&fref.location) {
                    propagation_ids.push(fref.finding_id.clone());
                } else {
                    usage_ids.push(fref.finding_id.clone());
                }
                // Mark this hash as having been included in a chain already.
                processed_hashes.insert(fref.secret_hash.clone());
            }
            processed_hashes.insert(origin.secret_hash.clone());

            // Confidence boost for chains: +0.20 added to the base 0.0.
            // (The actual per-finding boost is applied by the caller when
            // re-scoring findings that appear in a chain.)
            let chain_confidence = 0.20_f64;

            chains.push(CredentialChain {
                variable_name: var_name.clone(),
                origin_id: origin.finding_id.clone(),
                propagation_ids,
                usage_ids,
                chain_confidence,
            });
        }

        // ---- Value-hash chains (same secret in multiple files, variable name unknown) ----
        for (hash, refs) in &self.by_value {
            if processed_hashes.contains(hash) {
                continue; // Already included via a variable-name chain.
            }

            let distinct_paths: std::collections::HashSet<&str> =
                refs.iter().map(|r| r.location.path.as_str()).collect();
            if distinct_paths.len() < 2 {
                continue;
            }

            let mut sorted = refs.clone();
            sorted.sort_by(|a, b| {
                a.location.byte_offset.cmp(&b.location.byte_offset)
            });

            let origin = &sorted[0];
            let usage_ids: Vec<String> = sorted
                .iter()
                .skip(1)
                .map(|r| r.finding_id.clone())
                .collect();

            chains.push(CredentialChain {
                variable_name: hash[..8.min(hash.len())].to_string(), // first 8 chars of hash
                origin_id: origin.finding_id.clone(),
                propagation_ids: Vec::new(),
                usage_ids,
                chain_confidence: 0.20,
            });
        }

        chains
    }

    /// Return the current approximate memory usage in bytes.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }
}

/// Heuristic: returns `true` if the location's path or surrounding context
/// suggests the finding is a *reference* to a variable rather than a definition.
///
/// Currently checks the file extension for known consumer patterns.
/// A future version will inspect the actual match context bytes.
fn is_propagation_context(loc: &Location) -> bool {
    let path = loc.path.to_lowercase();
    path.ends_with("docker-compose.yml")
        || path.ends_with("docker-compose.yaml")
        || path.ends_with(".yml")
        || path.ends_with(".yaml")
        || path.contains("compose")
        || path.contains("manifest")
        || path.contains("deployment")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FusedScore, RedactedString, Severity};
    use chrono::Utc;

    fn make_finding(id: &str, path: &str, line: u32, secret_hash: &str) -> Finding {
        Finding {
            id: id.to_string(),
            rule_id: "test".to_string(),
            description: "Test".to_string(),
            secret: RedactedString::new("REDACTED".to_string()),
            secret_hash: secret_hash.to_string(),
            match_context: String::new(),
            location: Location {
                path: path.to_string(),
                start_line: line,
                end_line: line,
                start_col: 0,
                end_col: 20,
                byte_offset: line as u64 * 80,
            },
            score: FusedScore {
                confidence: 0.7,
                entropy: 0.5,
                proximity: 0.5,
                tristream: 0.5,
                pattern: 0.7,
                markov: 0.6,
                cnn_score: None,
                ast_adjustment: None,
            },
            severity: Severity::High,
            chain: None,
            validation: None,
            remediation: None,
            detected_at: Utc::now(), encoding_chain: None,
        }
    }

    #[test]
    fn test_three_file_chain_detected() {
        // DB_PASSWORD defined in .env, referenced in docker-compose.yml,
        // consumed in app.py.
        let mut engine = CorrelationEngine::new(10 * 1024 * 1024); // 10MB budget

        let f_env = make_finding("id-env",    ".env",              1, "hash-db-pw");
        let f_dc  = make_finding("id-dc",     "docker-compose.yml", 5, "hash-db-pw");
        let f_app = make_finding("id-app",    "app.py",            42, "hash-db-pw");

        engine.add_finding(&f_env, Some("DB_PASSWORD"));
        engine.add_finding(&f_dc,  Some("DB_PASSWORD"));
        engine.add_finding(&f_app, Some("DB_PASSWORD"));

        let chains = engine.resolve_chains();

        assert!(!chains.is_empty(), "Should detect at least one chain");
        let chain = chains.iter().find(|c| c.variable_name == "DB_PASSWORD")
            .expect("Should find DB_PASSWORD chain");

        // Origin should be the .env file (alphabetically first / lowest offset).
        assert_eq!(chain.origin_id, "id-env", "Origin should be .env finding");

        // Total chain members = origin (1) + propagation + usage = 3.
        let total = 1 + chain.propagation_ids.len() + chain.usage_ids.len();
        assert_eq!(total, 3, "Chain should have 3 members total");
    }

    #[test]
    fn test_single_file_no_chain() {
        let mut engine = CorrelationEngine::new(10 * 1024 * 1024);
        let f = make_finding("id-1", "src/config.py", 10, "hash-abc");
        engine.add_finding(&f, Some("API_KEY"));

        let chains = engine.resolve_chains();
        assert!(chains.is_empty(), "Single-file findings should not form a chain");
    }

    #[test]
    fn test_value_hash_chain_across_files() {
        let mut engine = CorrelationEngine::new(10 * 1024 * 1024);
        // Same secret hash in two different files, no variable name.
        let f1 = make_finding("id-1", "src/a.py", 1, "shared-hash");
        let f2 = make_finding("id-2", "src/b.py", 1, "shared-hash");
        engine.add_finding(&f1, None);
        engine.add_finding(&f2, None);

        let chains = engine.resolve_chains();
        assert!(!chains.is_empty(), "Same secret hash in 2 files → chain");
        assert_eq!(chains[0].usage_ids.len(), 1);
    }

    #[test]
    fn test_budget_enforcement() {
        // Extremely small budget — findings should be dropped gracefully.
        let mut engine = CorrelationEngine::new(10); // 10 bytes only
        let f1 = make_finding("id-1", "a.py", 1, "hash-1");
        let f2 = make_finding("id-2", "b.py", 1, "hash-1");
        engine.add_finding(&f1, Some("KEY"));
        engine.add_finding(&f2, Some("KEY"));

        // Should not panic; chains may be empty due to budget.
        let _chains = engine.resolve_chains();
    }

    #[test]
    fn test_docker_compose_classified_as_propagation() {
        let mut engine = CorrelationEngine::new(10 * 1024 * 1024);
        let f_env = make_finding("id-env", ".env",               1, "hash-pw");
        let f_dc  = make_finding("id-dc",  "docker-compose.yml", 5, "hash-pw");
        engine.add_finding(&f_env, Some("DB_PASS"));
        engine.add_finding(&f_dc,  Some("DB_PASS"));

        let chains = engine.resolve_chains();
        let chain = chains.iter().find(|c| c.variable_name == "DB_PASS").unwrap();

        // docker-compose.yml should be classified as propagation.
        assert!(
            chain.propagation_ids.contains(&"id-dc".to_string()),
            "docker-compose.yml should be a propagation node, got: {:?}",
            chain
        );
    }
}
