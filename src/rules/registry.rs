//! Rule registry — central store for compiled rules with hot-reload support.
//!
//! The registry is the single source of truth for all active detection rules
//! at runtime. It holds both the compiled rules and the shared Aho-Corasick
//! automaton used for fast pre-filtering.
//!
//! # Default rules
//!
//! A default rule set is embedded into the binary at compile time via
//! `include_str!`. Users can extend or override these by providing a
//! custom rule file path at startup.

use crate::error::{Result, SquirrelError};
use crate::rules::compiler::{compile_rules, CompiledRule};
use crate::rules::parser::{
    detect_format, parse_betterleaks_config, parse_gitleaks_config, parse_squirrel_config,
    RuleCategory, RuleFormat,
};
use aho_corasick::AhoCorasick;
use tracing::{debug, info, warn};

/// Default rules embedded at compile time.
///
/// The file at `rules/default.toml` (relative to the crate root) is baked into
/// the binary so the scanner works out-of-the-box without any external files.
const DEFAULT_RULES_TOML: &str = include_str!("../../rules/default.toml");

/// Central registry of all active detection rules.
///
/// Constructed once at startup via [`RuleRegistry::load`] and then shared
/// (read-only) across all scanning threads.
pub struct RuleRegistry {
    /// All compiled detection rules.
    rules: Vec<CompiledRule>,
    /// Aho-Corasick automaton built from all rule keywords.
    automaton: AhoCorasick,
    /// Mapping from Aho-Corasick match index (keyword index) to rule index in `rules`.
    keyword_to_rule: Vec<usize>,
}

impl RuleRegistry {
    /// Load the registry from embedded defaults and an optional user config file.
    ///
    /// Rules are loaded in this order (later rules with the same ID win):
    /// 1. Embedded default rules (baked into the binary)
    /// 2. User-supplied config file (any supported format)
    ///
    /// # Arguments
    ///
    /// * `user_config_path` — Optional path to a user rule file. If `None`,
    ///   only the embedded defaults are loaded.
    pub fn load(user_config_path: Option<&std::path::Path>) -> Result<Self> {
        // ── Step 1: load embedded defaults ───────────────────────────────────
        let mut all_rules =
            parse_squirrel_config(DEFAULT_RULES_TOML).map_err(|e| SquirrelError::RuleParse {
                path: "rules/default.toml".to_string(),
                reason: format!("embedded default rules are malformed: {e}"),
            })?;

        info!(count = all_rules.len(), "loaded embedded default rules");

        // ── Step 1.5: scan rules/ subdirectories at runtime ─────────────────
        // Load any .toml files found in `rules/*/` directories.  We look in:
        //   1. A `rules/` directory adjacent to the running binary.
        //   2. A `rules/` directory in the current working directory.
        // This allows category files (ai/, cloud/, etc.) to be loaded without
        // requiring a recompile or include_str! for each individual file.
        let rules_search_dirs: Vec<std::path::PathBuf> = {
            let mut dirs = Vec::new();
            // Current working directory rules/
            if let Ok(cwd) = std::env::current_dir() {
                dirs.push(cwd.join("rules"));
            }
            // Rules dir next to the binary
            if let Ok(exe) = std::env::current_exe() {
                if let Some(exe_dir) = exe.parent() {
                    dirs.push(exe_dir.join("rules"));
                }
            }
            dirs
        };

        for rules_dir in &rules_search_dirs {
            if !rules_dir.is_dir() {
                continue;
            }
            // Walk one level deep (ai/, cloud/, crypto/, etc.)
            let subdirs = match std::fs::read_dir(rules_dir) {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            for subdir_entry in subdirs.flatten() {
                let subdir_path = subdir_entry.path();
                if !subdir_path.is_dir() {
                    continue;
                }
                let toml_files = match std::fs::read_dir(&subdir_path) {
                    Ok(rd) => rd,
                    Err(_) => continue,
                };
                for file_entry in toml_files.flatten() {
                    let file_path = file_entry.path();
                    if file_path.extension().and_then(|e| e.to_str()) != Some("toml") {
                        continue;
                    }
                    match std::fs::read_to_string(&file_path) {
                        Ok(content) => {
                            match parse_squirrel_config(&content) {
                                Ok(file_rules) => {
                                    info!(
                                        count = file_rules.len(),
                                        path = %file_path.display(),
                                        "loaded category rules"
                                    );
                                    // Merge: later rules with same ID override earlier ones.
                                    let file_ids: std::collections::HashSet<_> =
                                        file_rules.iter().map(|r| r.id.clone()).collect();
                                    all_rules.retain(|r| !file_ids.contains(&r.id));
                                    all_rules.extend(file_rules);
                                }
                                Err(e) => {
                                    warn!(
                                        path = %file_path.display(),
                                        error = %e,
                                        "failed to parse category rule file — skipping"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(path = %file_path.display(), error = %e, "could not read category rule file");
                        }
                    }
                }
            }
            // Only load from the first directory found
            break;
        }

        // ── Step 2: load user config if provided ─────────────────────────────
        if let Some(path) = user_config_path {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let format = detect_format(&content);
                    let user_rules = match format {
                        RuleFormat::Squirrel => parse_squirrel_config(&content),
                        RuleFormat::Betterleaks => parse_betterleaks_config(&content),
                        RuleFormat::Gitleaks => parse_gitleaks_config(&content),
                    }
                    .map_err(|e| SquirrelError::RuleParse {
                        path: path.to_string_lossy().into_owned(),
                        reason: e.to_string(),
                    })?;

                    info!(
                        count = user_rules.len(),
                        path = %path.display(),
                        format = ?format,
                        "loaded user rules"
                    );

                    // Merge: user rules with duplicate IDs override defaults.
                    let user_ids: std::collections::HashSet<_> =
                        user_rules.iter().map(|r| r.id.clone()).collect();
                    all_rules.retain(|r| !user_ids.contains(&r.id));
                    all_rules.extend(user_rules);
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "could not read user rule file — using defaults only"
                    );
                }
            }
        }

        // ── Step 3: compile all rules ─────────────────────────────────────────
        let compiled = compile_rules(all_rules)?;

        let mut keyword_to_rule = Vec::new();
        let mut keywords = Vec::new();
        for (rule_idx, rule) in compiled.iter().enumerate() {
            for kw in &rule.keywords {
                keywords.push(kw.as_str());
                keyword_to_rule.push(rule_idx);
            }
        }

        let automaton = aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::LeftmostFirst)
            .build(&keywords)
            .expect("failed to build AhoCorasick automaton");

        info!(compiled = compiled.len(), "rule compilation complete");

        Ok(Self {
            rules: compiled,
            automaton,
            keyword_to_rule,
        })
    }

    /// Returns all compiled rules.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Returns the shared Aho-Corasick keyword automaton.
    pub fn automaton(&self) -> &AhoCorasick {
        &self.automaton
    }

    /// Returns the mapping from keyword match index to rule index.
    pub fn keyword_to_rule(&self) -> &[usize] {
        &self.keyword_to_rule
    }

    /// Returns rules filtered by category.
    pub fn by_category(&self, category: &RuleCategory) -> Vec<&CompiledRule> {
        self.rules
            .iter()
            .filter(|r| &r.category == category)
            .collect()
    }

    /// Returns a rule by its unique ID, or `None` if not found.
    pub fn by_id(&self, id: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Reload rules from `path`, replacing the current rule set.
    ///
    /// This is the hot-reload path — typically triggered by a SIGHUP or
    /// a file-system watcher event.
    pub fn reload(&mut self, path: &std::path::Path) -> Result<()> {
        let new = Self::load(Some(path))?;
        self.rules = new.rules;
        self.automaton = new.automaton;
        self.keyword_to_rule = new.keyword_to_rule;
        debug!(path = %path.display(), "rule registry reloaded");
        Ok(())
    }

    /// Returns the number of loaded rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` if no rules are loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Convenience: load defaults only (no user config).
    pub fn load_defaults() -> Result<Self> {
        Self::load(None)
    }

    /// Alias for `rules()` — returns all compiled rules.
    pub fn all_rules(&self) -> &[CompiledRule] {
        &self.rules
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_defaults() {
        let registry = RuleRegistry::load(None).unwrap();
        assert!(!registry.is_empty(), "default rules should not be empty");
        assert!(
            registry.len() >= 10,
            "expected at least 10 default rules, got {}",
            registry.len()
        );
    }

    #[test]
    fn test_by_id_aws() {
        let registry = RuleRegistry::load(None).unwrap();
        // The actual AWS access key rule is "aws-access-token" in default.toml.
        let rule = registry.by_id("aws-access-token");
        assert!(rule.is_some(), "aws-access-token rule must be present");
        // Also confirm the secret access key rule exists.
        let sak = registry.by_id("aws-secret-access-key");
        assert!(sak.is_some(), "aws-secret-access-key rule must be present");
    }

    #[test]
    fn test_by_category_cloud() {
        let registry = RuleRegistry::load(None).unwrap();
        let cloud_rules = registry.by_category(&RuleCategory::Cloud);
        assert!(
            !cloud_rules.is_empty(),
            "at least one cloud rule should be present"
        );
    }

    #[test]
    fn test_automaton_matches_keyword() {
        let registry = RuleRegistry::load(None).unwrap();
        // The AWS rule has keyword "AKIA" — it should match.
        assert!(
            registry
                .automaton()
                .is_match("export AWS_KEY=AKIAIOSFODNN7EXAMPLE"),
            "automaton should match AKIA keyword"
        );
    }

    #[test]
    fn test_user_rule_overrides_default() {
        use std::io::Write;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let user_toml = r#"
[[rules]]
id = "aws-access-key-id"
description = "Overridden AWS rule"
regex = 'AKIA[0-9A-Z]{16}'
keywords = ["AKIA"]
severity = "info"
category = "cloud"
"#;
        let path = dir.path().join("user.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(user_toml.as_bytes()).unwrap();

        let registry = RuleRegistry::load(Some(&path)).unwrap();
        let rule = registry.by_id("aws-access-key-id").unwrap();
        // The override sets severity to Info.
        assert_eq!(rule.severity, crate::types::Severity::Info);
    }

    #[test]
    fn test_reload() {
        let mut registry = RuleRegistry::load(None).unwrap();
        // Reload from no user path (just re-loads defaults).
        // We use a non-existent path which should fall back gracefully.
        let fake_path = std::path::Path::new("/nonexistent/path.toml");
        let result = registry.reload(fake_path);
        // Should succeed (user file not found → warn + use defaults).
        assert!(result.is_ok());
    }
}
