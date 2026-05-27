use thiserror::Error;

/// Unified error type for Secret Squirrel operations.
#[derive(Debug, Error)]
pub enum SquirrelError {
    #[error("GPU initialization failed: {0}")]
    GpuInit(String),

    #[error("GPU dispatch error: {0}")]
    GpuDispatch(String),

    #[error("Rule parsing error in '{path}': {reason}")]
    RuleParse { path: String, reason: String },

    #[error("Source error ({src_name}): {reason}")]
    Source { src_name: String, reason: String },

    #[error("Validation error for provider '{provider}': {reason}")]
    Validation { provider: String, reason: String },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Pipeline error in stage '{stage}': {reason}")]
    Pipeline { stage: String, reason: String },

    #[error("Archive error: {0}")]
    Archive(String),

    #[error("MCP error: {0}")]
    Mcp(String),

    #[error("CNN inference error: {0}")]
    Cnn(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Rate limit exceeded for provider '{provider}'. Retry after {retry_after_secs}s")]
    RateLimit {
        provider: String,
        retry_after_secs: u64,
    },

    #[error("Circuit breaker open for provider '{provider}'")]
    CircuitBreakerOpen { provider: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("Git error: {0}")]
    Git(#[from] git2::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Path traversal attempt blocked: {path}")]
    PathTraversal { path: String },

    #[error("Decompression ratio exceeded safe limit (ratio: {ratio}:1)")]
    CompressionBomb { ratio: u64 },
}

/// Convenience Result alias using SquirrelError.
pub type Result<T> = std::result::Result<T, SquirrelError>;

impl SquirrelError {
    /// Returns true if this error is recoverable — the scan can continue.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            SquirrelError::Source { .. }
                | SquirrelError::Archive(_)
                | SquirrelError::RateLimit { .. }
                | SquirrelError::Io(_)
                | SquirrelError::Git(_)
        )
    }

    /// Returns the severity level of the error for logging purposes.
    pub fn severity(&self) -> &'static str {
        match self {
            SquirrelError::GpuInit(_) | SquirrelError::GpuDispatch(_) => "warn",
            SquirrelError::PathTraversal { .. } | SquirrelError::CompressionBomb { .. } => "error",
            SquirrelError::RateLimit { .. } | SquirrelError::CircuitBreakerOpen { .. } => "warn",
            _ => "error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recoverable_errors() {
        let io_err = SquirrelError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.is_recoverable());

        let gpu_err = SquirrelError::GpuInit("no adapter found".to_string());
        assert!(!gpu_err.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = SquirrelError::RuleParse {
            path: "rules/aws.toml".to_string(),
            reason: "invalid regex".to_string(),
        };
        assert!(err.to_string().contains("rules/aws.toml"));
        assert!(err.to_string().contains("invalid regex"));
    }
}
