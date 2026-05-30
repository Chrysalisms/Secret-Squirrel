use crate::error::{Result, SquirrelError};
use crate::types::Severity;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Master configuration for a Secret Squirrel scan session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct SquirrelConfig {
    /// General scan settings
    pub scan: ScanConfig,

    /// GPU routing settings
    pub gpu: GpuConfig,

    /// Pipeline thresholds
    pub pipeline: PipelineConfig,

    /// Output settings
    pub output: OutputConfig,

    /// Validation settings
    pub validation: ValidationConfig,

    /// Source-specific settings
    pub sources: SourcesConfig,

    /// Scoring weights
    pub scoring: ScoringConfig,
}

impl SquirrelConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        toml::from_str(&contents).map_err(|e| SquirrelError::Config(e.to_string()))
    }

    /// Load configuration with cascading: defaults → config file → env vars.
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let mut config = Self::default();

        // Load from file if provided
        if let Some(path) = config_path {
            if path.exists() {
                let file_config = Self::from_file(path)?;
                config.merge(file_config);
            }
        } else {
            // Try default config locations
            for default_path in default_config_paths() {
                if default_path.exists() {
                    let file_config = Self::from_file(&default_path)?;
                    config.merge(file_config);
                    break;
                }
            }
        }

        Ok(config)
    }

    /// Merge another config into this one (other wins on non-default values).
    fn merge(&mut self, _other: Self) {
        // Simple replacement — more sophisticated merge logic can be added later
        // For now, the loaded file config wins
        *self = _other;
    }
}

/// Default paths to search for configuration files.
fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from(".squirrel.toml"),
        PathBuf::from(".betterleaks.toml"), // backward compat
        PathBuf::from(".gitleaks.toml"),    // backward compat
    ];

    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".config").join("squirrel").join("config.toml"));
        paths.push(home.join(".squirrel.toml"));
    }

    paths
}

/// General scan settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Minimum severity to report
    pub severity_threshold: Severity,
    /// Minimum confidence score to report (0.0–1.0)
    pub confidence_threshold: f64,
    /// Enable cross-file correlation
    pub correlate: bool,
    /// Enable semantic analysis (tree-sitter)
    pub semantic: bool,
    /// Enable credential validation
    pub validate: bool,
    /// Only report new findings compared to last scan (baseline mode)
    pub baseline: bool,
    /// Maximum file size to scan (bytes). Default: 50MB
    pub max_file_size: u64,
    /// Git history depth (commits). 0 = full history
    pub git_depth: usize,
    /// Allow showing raw secret values (also requires SQUIRREL_ALLOW_SHOW_SECRETS=1 env var)
    pub show_secrets: bool,
    /// Model tier to use for CNN inference
    pub model_tier: ModelTier,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            severity_threshold: Severity::Low,
            confidence_threshold: 0.5,
            correlate: false,
            semantic: false,
            validate: false,
            baseline: false,
            max_file_size: 50 * 1024 * 1024, // 50MB
            git_depth: 0,
            show_secrets: false,
            model_tier: ModelTier::Default,
        }
    }
}

/// GPU acceleration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GpuConfig {
    /// Enable GPU acceleration (requires `gpu` feature)
    pub enabled: bool,
    /// Minimum input size to route to GPU (bytes). Default: 100MB
    pub threshold_bytes: u64,
    /// Prefer specific GPU backend (auto-detected if not set)
    pub backend: Option<String>,
}

impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_bytes: 100 * 1024 * 1024, // 100MB
            backend: None,
        }
    }
}

/// Pipeline stage thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PipelineConfig {
    /// Stage 1: Minimum entropy to pass (Shannon entropy, bits per byte)
    pub entropy_threshold: f32,
    /// Stage 1: Minimum candidate length (chars)
    pub min_candidate_length: usize,
    /// Stage 1: Chunk size for entropy calculation (bytes)
    pub entropy_chunk_size: usize,
    /// Stage 2: Minimum proximity score to pass
    pub proximity_threshold: f32,
    /// Channel buffer capacity between stages
    pub channel_capacity: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.5,
            min_candidate_length: 8,
            entropy_chunk_size: 64,
            proximity_threshold: 0.15,
            channel_capacity: 256,
        }
    }
}

/// Output and reporting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Output file path (stdout if None)
    pub output_path: Option<PathBuf>,
    /// Log format for structured logging
    pub log_format: LogFormat,
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            output_path: None,
            log_format: LogFormat::Text,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Sarif,
    Table,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

/// Validation engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidationConfig {
    /// Default rate limit (requests per second) for unknown providers
    pub default_rate_limit: f64,
    /// Timeout per validation call (seconds)
    pub timeout_secs: u64,
    /// Circuit breaker: failures before opening
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker: cooldown period (seconds)
    pub circuit_breaker_cooldown_secs: u64,
    /// Memory budget for correlation engine (bytes). Default: 256MB
    pub correlation_budget_bytes: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            default_rate_limit: 10.0,
            timeout_secs: 5,
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown_secs: 60,
            correlation_budget_bytes: 256 * 1024 * 1024, // 256MB
        }
    }
}

/// Source-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SourcesConfig {
    /// File patterns to ignore (in addition to .gitignore)
    pub ignore_patterns: Vec<String>,
    /// Maximum archive decompression ratio before zip bomb protection triggers
    pub max_decompression_ratio: u64,
    /// GitHub API token (override with GITHUB_TOKEN env var)
    pub github_token: Option<String>,
    /// GitLab API token (override with GITLAB_TOKEN env var)
    pub gitlab_token: Option<String>,
}

impl Default for SourcesConfig {
    fn default() -> Self {
        Self {
            ignore_patterns: vec![
                "*.min.js".to_string(),
                "*.map".to_string(),
                "vendor/**".to_string(),
                "node_modules/**".to_string(),
            ],
            max_decompression_ratio: 100,
            github_token: None,
            gitlab_token: None,
        }
    }
}

/// Scoring weight configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScoringConfig {
    pub entropy_weight: f64,
    pub proximity_weight: f64,
    pub tristream_weight: f64,
    pub markov_weight: f64,
    pub pattern_weight: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            entropy_weight: 0.15,
            proximity_weight: 0.15,
            tristream_weight: 0.20,
            markov_weight: 0.25,
            pattern_weight: 0.25,
        }
    }
}

/// ML model tier selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ModelTier {
    /// Tier 1: Markov chain only (embedded, no download required)
    Default,
    /// Tier 2: Tiny CNN (500K params, ~2MB ONNX, for GitHub Actions)
    Tiny,
    /// Tier 3: Large CNN (1M params, ~4MB ONNX, for self-hosted CPU)
    Large,
    /// Tier 4: TinyBERT (14M params, ~55MB, for self-hosted GPU)
    Enhanced,
    /// Tier 5: DistilBERT (66M params, ~130MB, maximum accuracy)
    Maximum,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SquirrelConfig::default();
        assert_eq!(config.pipeline.entropy_threshold, 3.5);
        assert_eq!(config.gpu.threshold_bytes, 100 * 1024 * 1024);
        assert!(!config.scan.validate); // validation is opt-in
        assert!(!config.scan.show_secrets); // never show secrets by default
    }

    #[test]
    fn test_config_serialization() {
        let config = SquirrelConfig::default();
        let toml = toml::to_string(&config).unwrap();
        let _deserialized: SquirrelConfig = toml::from_str(&toml).unwrap();
    }
}
