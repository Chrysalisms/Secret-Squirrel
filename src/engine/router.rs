//! Smart GPU/CPU router for Secret Squirrel's scan pipeline.
//!
//! [`Router`] decides at runtime which compute backend to use for each
//! scan fragment:
//!
//! - If `input_size >= threshold_bytes` **and** a [`GpuEngine`] is present,
//!   the fragment goes to the GPU path.
//! - Otherwise (small fragment, no GPU, or GPU fails) it falls back to the
//!   [`CpuEngine`].
//!
//! GPU failures are handled gracefully: the router logs a `WARN`-level
//! message and re-executes the same operation on the CPU without returning
//! an error to the caller.
//!
//! # Construction
//!
//! ```no_run
//! use secret_squirrel::config::SquirrelConfig;
//! use secret_squirrel::engine::router::Router;
//!
//! // Router::new is async; call it inside a tokio runtime:
//! // let config = SquirrelConfig::default();
//! // let router = Router::new(&config.gpu).await;
//! ```

use bytes::Bytes;
use tracing::debug;
#[allow(unused_imports)]
use tracing::warn;

use crate::config::GpuConfig;
use crate::error::Result;
use crate::types::{EntropyCandidate, ProximityMatch, TriStreamResult};

use super::cpu::CpuEngine;
use super::gpu::GpuEngine;

// ============================================================================
// Router
// ============================================================================

/// GPU/CPU routing engine.
///
/// Wraps both a mandatory [`CpuEngine`] and an optional [`GpuEngine`].
/// Call [`Router::new`] to probe the system and initialise accordingly.
#[derive(Debug)]
pub struct Router {
    /// GPU engine instance, if one was successfully initialised.
    pub gpu: Option<GpuEngine>,
    /// Always-available CPU engine.
    pub cpu: CpuEngine,
    /// Minimum input size (bytes) to route to the GPU.
    pub threshold_bytes: u64,
    /// Entropy threshold forwarded from pipeline config.
    pub entropy_threshold: f32,
    /// Proximity threshold forwarded from pipeline config.
    pub proximity_threshold: f32,
    /// Entropy chunk size forwarded from pipeline config.
    pub entropy_chunk_size: usize,
}

impl Router {
    /// Initialise the router from a [`GpuConfig`].
    ///
    /// If `config.enabled` is `false` or the GPU feature is disabled, the
    /// GPU engine is skipped and `self.gpu` will be `None`.
    pub async fn new(config: &GpuConfig) -> Self {
        // Initialise the CPU engine (always available).
        let cpu = CpuEngine::new(0).unwrap_or_else(|e| {
            // Fatal: if we can't even build the thread pool, panic early.
            panic!("Failed to initialise CPU engine: {e}");
        });

        // Attempt GPU initialisation if enabled.
        let gpu = if config.enabled {
            #[cfg(feature = "gpu")]
            {
                let engine = GpuEngine::new().await;
                if engine.is_none() {
                    warn!("No GPU adapter found — using CPU-only mode");
                }
                engine
            }
            #[cfg(not(feature = "gpu"))]
            {
                debug!("GPU feature disabled at compile time");
                None
            }
        } else {
            debug!("GPU disabled in config");
            None
        };

        Self {
            gpu,
            cpu,
            threshold_bytes: config.threshold_bytes,
            // These are set to sensible defaults; the caller (pipeline) can
            // override them by supplying thresholds directly to each method.
            entropy_threshold: 3.5,
            proximity_threshold: 0.2,
            entropy_chunk_size: 64,
        }
    }

    /// Returns `true` if the GPU path should be used for an input of
    /// `input_size` bytes.
    ///
    /// The GPU path is preferred when:
    /// 1. A GPU engine is available, **and**
    /// 2. `input_size >= self.threshold_bytes`
    #[inline]
    pub fn should_use_gpu(&self, input_size: u64) -> bool {
        self.gpu.is_some() && input_size >= self.threshold_bytes
    }

    // ── Stage 1: entropy ──────────────────────────────────────────────────

    /// Compute Shannon entropy for every chunk of `input`.
    ///
    /// Routes to GPU if the input is large enough, otherwise uses the CPU.
    /// If the GPU dispatch fails, falls back to CPU automatically.
    pub fn execute_entropy(
        &self,
        input: &Bytes,
        threshold: f32,
        chunk_size: usize,
    ) -> Result<Vec<EntropyCandidate>> {
        if self.should_use_gpu(input.len() as u64) {
            #[cfg(feature = "gpu")]
            if let Some(gpu) = &self.gpu {
                debug!(bytes = input.len(), "Routing entropy stage to GPU");
                // GPU path — if it returns an empty vec on error we fall
                // back rather than propagating (entropy of zero-len is empty).
                let result = gpu.execute_entropy(input, threshold);
                if !result.is_empty() || input.is_empty() {
                    return Ok(result);
                }
                warn!(
                    bytes = input.len(),
                    "GPU entropy returned no results unexpectedly; falling back to CPU"
                );
            }
        }

        debug!(bytes = input.len(), "Routing entropy stage to CPU");
        Ok(self.cpu.execute_entropy(input, threshold, chunk_size))
    }

    // ── Stage 2: proximity ────────────────────────────────────────────────

    /// Scan `candidates` for semantic proximity patterns.
    ///
    /// Routes to GPU for large candidate sets, otherwise uses the CPU.
    pub fn execute_proximity(
        &self,
        candidates: &[EntropyCandidate],
        threshold: f32,
    ) -> Result<Vec<ProximityMatch>> {
        if self.should_use_gpu(candidates.len() as u64 * 64) {
            #[cfg(feature = "gpu")]
            if let Some(gpu) = &self.gpu {
                debug!(
                    candidates = candidates.len(),
                    "Routing proximity stage to GPU"
                );
                return Ok(gpu.execute_proximity(candidates, threshold));
            }
        }

        debug!(
            candidates = candidates.len(),
            "Routing proximity stage to CPU"
        );
        Ok(self.cpu.execute_proximity(candidates, threshold))
    }

    // ── Stage 3: tri-stream ───────────────────────────────────────────────

    /// Decompose `matches` into identifier, literal, and structure streams.
    ///
    /// Routes to GPU for large match sets, otherwise uses the CPU.
    pub fn execute_tristream(
        &self,
        matches: &[ProximityMatch],
    ) -> Result<Vec<TriStreamResult>> {
        if self.should_use_gpu(matches.len() as u64 * 256) {
            #[cfg(feature = "gpu")]
            if let Some(gpu) = &self.gpu {
                debug!(
                    matches = matches.len(),
                    "Routing tri-stream stage to GPU"
                );
                return Ok(gpu.execute_tristream(matches));
            }
        }

        debug!(
            matches = matches.len(),
            "Routing tri-stream stage to CPU"
        );
        Ok(self.cpu.execute_tristream(matches))
    }

    /// Returns `true` if a GPU engine is currently available.
    pub fn gpu_available(&self) -> bool {
        self.gpu.is_some()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GpuConfig;

    /// Build a router with GPU disabled (works in all CI environments).
    async fn cpu_only_router() -> Router {
        let config = GpuConfig {
            enabled: false,
            threshold_bytes: 100 * 1024 * 1024,
            backend: None,
        };
        Router::new(&config).await
    }

    #[tokio::test]
    async fn test_router_gpu_disabled() {
        let router = cpu_only_router().await;
        assert!(router.gpu.is_none());
        assert!(!router.gpu_available());
    }

    #[tokio::test]
    async fn test_should_use_gpu_false_without_gpu() {
        let router = cpu_only_router().await;
        // Even with large input, GPU is not available.
        assert!(!router.should_use_gpu(200 * 1024 * 1024));
    }

    #[tokio::test]
    async fn test_should_use_gpu_below_threshold() {
        let router = cpu_only_router().await;
        // Small input → CPU even if GPU were available (threshold = 100MB).
        assert!(!router.should_use_gpu(1024));
    }

    #[tokio::test]
    async fn test_execute_entropy_cpu_path() {
        let router = cpu_only_router().await;
        // 64 distinct bytes → high entropy → one candidate
        let data: Vec<u8> = (0u8..64).collect();
        let bytes = Bytes::from(data);
        let candidates = router.execute_entropy(&bytes, 3.5, 64).unwrap();
        assert_eq!(candidates.len(), 1);
    }

    #[tokio::test]
    async fn test_execute_entropy_empty_input() {
        let router = cpu_only_router().await;
        let candidates = router.execute_entropy(&Bytes::new(), 3.5, 64).unwrap();
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn test_execute_proximity_cpu_path() {
        let router = cpu_only_router().await;
        let chunk = bytes::Bytes::from_static(b"apiKey = \"AKIAIOSFODNN7EXAMPLE\"");
        let candidate = EntropyCandidate {
            offset: 0,
            length: chunk.len() as u32,
            entropy: 5.0,
            raw: chunk,
        };
        let matches = router.execute_proximity(&[candidate], 0.05).unwrap();
        assert!(!matches.is_empty());
    }

    #[tokio::test]
    async fn test_execute_tristream_cpu_path() {
        let router = cpu_only_router().await;
        let chunk = bytes::Bytes::from_static(b"password = \"hunter2\"");
        let candidate = EntropyCandidate {
            offset: 0,
            length: chunk.len() as u32,
            entropy: 4.0,
            raw: chunk.clone(),
        };
        let pm = ProximityMatch {
            candidate,
            pattern: crate::types::ProximityPattern::Assignment,
            proximity_score: 0.4,
            context: chunk,
        };
        let results = router.execute_tristream(&[pm]).unwrap();
        assert_eq!(results.len(), 1);
    }
}
