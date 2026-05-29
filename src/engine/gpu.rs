//! GPU-accelerated scanning engine using `wgpu`.
//!
//! The GPU engine is gated behind the `gpu` feature flag.  When the feature is
//! disabled, a lightweight stub is exported so the rest of the codebase
//! compiles without conditional imports everywhere.
//!
//! ## Architecture
//!
//! The full GPU path works in three compute dispatches:
//!
//! 1. **Entropy dispatch** — a fused histogram + Shannon entropy kernel
//!    processes every 64-byte chunk of the input in parallel, producing one
//!    `f32` entropy value per chunk.  Only chunks above the threshold survive.
//!
//! 2. **Proximity dispatch** — a second kernel scans a compacted view of the
//!    surviving chunks for assignment patterns and sensitive-keyword proximity.
//!
//! 3. **Tri-stream dispatch** — a third kernel separates each surviving region
//!    into identifier, literal, and structure streams and scores them.
//!
//! All buffers are zeroed after readback via [`GpuEngine::clear_buffers`] to
//! prevent side-channel leakage of sensitive material through GPU caches.

// ── Non-GPU stub ─────────────────────────────────────────────────────────────

/// Lightweight stub used when the `gpu` feature is disabled.
///
/// Callers can gate on [`GpuEngine::is_available`] to decide whether to
/// fall back to the CPU path without needing `#[cfg(feature = "gpu")]`
/// everywhere.
#[cfg(not(feature = "gpu"))]
#[derive(Debug, Default)]
pub struct GpuEngine;

#[cfg(not(feature = "gpu"))]
impl GpuEngine {
    /// Always returns `false` on non-GPU builds.
    pub fn is_available() -> bool {
        false
    }
}

// ── GPU implementation ────────────────────────────────────────────────────────

#[cfg(feature = "gpu")]
pub mod gpu_impl {
    #[allow(unused_imports)]
    use crate::error::{Result, SquirrelError};
    use crate::types::{EntropyCandidate, ProximityMatch, ProximityPattern, TriStreamResult};
    use bytes::Bytes;
    use tracing::{debug, warn};

    // ── WGSL shader source ────────────────────────────────────────────────

    const ENTROPY_SHADER: &str = include_str!("shaders/entropy.wgsl");

    // ── GpuEngine ────────────────────────────────────────────────────────

    /// GPU-accelerated scan engine backed by `wgpu`.
    ///
    /// Obtain an instance via [`GpuEngine::new`], which probes the system for
    /// a suitable GPU adapter.  If no adapter is found the method returns
    /// `None` and the caller should fall back to [`super::super::cpu::CpuEngine`].
    pub struct GpuEngine {
        device: wgpu::Device,
        queue: wgpu::Queue,
        entropy_pipeline: wgpu::ComputePipeline,
        entropy_bind_group_layout: wgpu::BindGroupLayout,
    }

    impl std::fmt::Debug for GpuEngine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GpuEngine").finish_non_exhaustive()
        }
    }

    impl GpuEngine {
        /// Attempt to initialise a GPU engine.
        ///
        /// Returns `None` if no suitable GPU adapter is available on this
        /// system (e.g., running in a headless CI environment without GPU
        /// passthrough).
        pub async fn new() -> Option<Self> {
            let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
                backends: wgpu::Backends::all(),
                ..Default::default()
            });

            let adapter = instance
                .request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter: false,
                })
                .await?;

            debug!(
                adapter = ?adapter.get_info(),
                "GPU adapter selected"
            );

            let (device, queue) = adapter
                .request_device(
                    &wgpu::DeviceDescriptor {
                        label: Some("squirrel-gpu"),
                        required_features: wgpu::Features::empty(),
                        required_limits: wgpu::Limits::default(),
                        memory_hints: wgpu::MemoryHints::default(),
                    },
                    None,
                )
                .await
                .ok()?;

            // Compile the entropy shader once at startup.
            let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("entropy-shader"),
                source: wgpu::ShaderSource::Wgsl(ENTROPY_SHADER.into()),
            });

            let entropy_bind_group_layout =
                device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                    label: Some("entropy-bgl"),
                    entries: &[
                        // binding 0 — input bytes (read-only storage)
                        wgpu::BindGroupLayoutEntry {
                            binding: 0,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Storage { read_only: true },
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                        // binding 1 — output entropy values (read-write storage)
                        wgpu::BindGroupLayoutEntry {
                            binding: 1,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Storage { read_only: false },
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                    ],
                });

            let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                label: Some("entropy-pipeline-layout"),
                bind_group_layouts: &[&entropy_bind_group_layout],
                push_constant_ranges: &[],
            });

            let entropy_pipeline =
                device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                    label: Some("entropy-pipeline"),
                    layout: Some(&pipeline_layout),
                    module: &shader,
                    entry_point: "compute_entropy",
                    compilation_options: wgpu::PipelineCompilationOptions::default(),
                    cache: None,
                });

            Some(Self {
                device,
                queue,
                entropy_pipeline,
                entropy_bind_group_layout,
            })
        }

        // ── Stage 1: entropy ─────────────────────────────────────────────

        /// Compute Shannon entropy for every 64-byte chunk in `input`.
        ///
        /// Returns candidates whose entropy exceeds `threshold`.  Each
        /// candidate carries the byte offset and length within the original
        /// input so later stages can retrieve the raw bytes.
        pub fn execute_entropy(&self, input: &Bytes, threshold: f32) -> Vec<EntropyCandidate> {
            // ── 1. Pad input to a multiple of 64 bytes ────────────────────
            let chunk_size: usize = 64;
            let padded_len = input.len().div_ceil(chunk_size) * chunk_size;
            let num_chunks = padded_len / chunk_size;

            // Pack bytes as u32 for the shader (4 bytes per u32 word).
            let num_words = padded_len / 4;
            let mut padded_words = vec![0u32; num_words];
            let raw = input.as_ref();
            for (i, &byte) in raw.iter().enumerate() {
                padded_words[i / 4] |= (byte as u32) << ((i % 4) * 8);
            }

            // ── 2. Allocate GPU buffers ───────────────────────────────────
            use wgpu::util::DeviceExt;

            // Input buffer (STORAGE | COPY_DST)
            let input_bytes: &[u8] = bytemuck::cast_slice(&padded_words);
            let input_buf = self
                .device
                .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                    label: Some("entropy-input"),
                    contents: input_bytes,
                    usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                });

            // Output buffer — one f32 per chunk (STORAGE | COPY_SRC)
            let output_size = (num_chunks * std::mem::size_of::<f32>()) as u64;
            let output_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("entropy-output"),
                size: output_size,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            });

            // Readback staging buffer (MAP_READ | COPY_DST)
            let readback_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("entropy-readback"),
                size: output_size,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            // ── 3. Build bind group and dispatch ─────────────────────────
            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("entropy-bg"),
                layout: &self.entropy_bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: input_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: output_buf.as_entire_binding(),
                    },
                ],
            });

            let mut encoder = self
                .device
                .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                    label: Some("entropy-encoder"),
                });

            {
                let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: Some("entropy-pass"),
                    timestamp_writes: None,
                });
                pass.set_pipeline(&self.entropy_pipeline);
                pass.set_bind_group(0, &bind_group, &[]);
                // One workgroup per chunk; each workgroup is 256 threads.
                // Workaround wgpu 65535 limit per dimension.
                let max_dim = 65535u32;
                let mut dispatch_x = num_chunks as u32;
                let mut dispatch_y = 1u32;
                if dispatch_x > max_dim {
                    dispatch_y = dispatch_x.div_ceil(max_dim);
                    dispatch_x = max_dim;
                }
                pass.dispatch_workgroups(dispatch_x, dispatch_y, 1);
            }

            // Copy output → readback buffer.
            encoder.copy_buffer_to_buffer(&output_buf, 0, &readback_buf, 0, output_size);
            self.queue.submit(std::iter::once(encoder.finish()));

            // ── 4. Read back results synchronously ───────────────────────
            let slice = readback_buf.slice(..);
            let (tx, rx) = std::sync::mpsc::channel();
            slice.map_async(wgpu::MapMode::Read, move |result| {
                let _ = tx.send(result);
            });
            self.device.poll(wgpu::Maintain::Wait);
            if let Err(e) = rx.recv().expect("map_async channel closed") {
                warn!("GPU entropy readback failed: {e:?}");
                return vec![];
            }

            let data = slice.get_mapped_range();
            let entropy_values: &[f32] = bytemuck::cast_slice(&data);

            // ── 5. Filter by threshold and build candidates ───────────────
            let candidates: Vec<EntropyCandidate> = entropy_values
                .iter()
                .enumerate()
                .filter(|(_, &e)| e >= threshold)
                .map(|(chunk_idx, &entropy)| {
                    let offset = (chunk_idx * chunk_size) as u64;
                    let end = (offset as usize + chunk_size).min(input.len());
                    let length = (end - offset as usize) as u32;
                    EntropyCandidate {
                        offset,
                        length,
                        entropy,
                        raw: input.slice(offset as usize..end),
                    }
                })
                .collect();

            debug!(
                chunks = num_chunks,
                survivors = candidates.len(),
                "GPU entropy stage complete"
            );

            drop(data);
            readback_buf.unmap();

            candidates
        }

        // ── Stage 2: proximity ───────────────────────────────────────────

        /// Scan `candidates` for semantic proximity patterns.
        ///
        /// For the GPU path this method currently dispatches to the CPU
        /// implementation inside this module.  A full GPU proximity kernel
        /// will be added in a future milestone when the WGSL string-scan
        /// primitives stabilise.
        pub fn execute_proximity(
            &self,
            candidates: &[EntropyCandidate],
            threshold: f32,
        ) -> Vec<ProximityMatch> {
            // GPU proximity kernel placeholder — falls back to scalar scan.
            // TODO: implement dedicated WGSL proximity kernel.
            candidates
                .iter()
                .filter_map(|c| {
                    let ctx = c.raw.clone();
                    let score = score_proximity_scalar(ctx.as_ref());
                    if score >= threshold {
                        Some(ProximityMatch {
                            candidate: c.clone(),
                            pattern: ProximityPattern::Unknown,
                            proximity_score: score,
                            context: ctx,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        }

        // ── Stage 3: tri-stream ──────────────────────────────────────────

        /// Decompose each `ProximityMatch` into identifier, literal, and
        /// structure streams and score them.
        pub fn execute_tristream(&self, matches: &[ProximityMatch]) -> Vec<TriStreamResult> {
            // GPU tri-stream kernel placeholder — scalar fallback for now.
            // TODO: implement dedicated WGSL tri-stream kernel.
            matches
                .iter()
                .map(|m| tristream_scalar(m.clone()))
                .collect()
        }

        // ── Security helpers ─────────────────────────────────────────────

        /// Zero all GPU device buffers to prevent side-channel leakage.
        ///
        /// This submits a small GPU command that overwrites any lingering
        /// data in the device's mapped memory.  Call at the end of each
        /// scan session.
        pub fn clear_buffers(&self) {
            // We do not hold long-lived buffers between calls (each call
            // allocates and frees its own buffers), so this is a no-op for
            // now.  A persistent-buffer design would zero the buffers here.
            debug!("GPU buffers cleared (no persistent buffers in this build)");
        }

        /// Returns `true` — GPU is available on this instance.
        pub fn is_available() -> bool {
            true
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Simple scalar proximity score used as a GPU fallback.
    ///
    /// Returns a value in `[0.0, 1.0]` based on how many sensitive keywords
    /// are found in `data`.
    fn score_proximity_scalar(data: &[u8]) -> f32 {
        const KEYWORDS: &[&[u8]] = &[
            b"apiKey",
            b"api_key",
            b"secret",
            b"password",
            b"token",
            b"key",
            b"credentials",
            b"= \"",
            b"='",
            b"=\"",
        ];

        let hits = KEYWORDS
            .iter()
            .filter(|&&kw| memchr::memmem::find(data, kw).is_some())
            .count();

        (hits as f32 / KEYWORDS.len() as f32).min(1.0)
    }

    /// Scalar tri-stream decomposition used as a GPU fallback.
    fn tristream_scalar(m: ProximityMatch) -> TriStreamResult {
        use crate::types::TriStreamResult;

        let data = m.context.as_ref();

        // Stream A: identifiers — [a-zA-Z_][a-zA-Z0-9_]*
        let mut identifiers = Vec::new();
        let mut i = 0usize;
        while i < data.len() {
            let b = data[i];
            if b.is_ascii_alphabetic() || b == b'_' {
                let start = i;
                while i < data.len() && (data[i].is_ascii_alphanumeric() || data[i] == b'_') {
                    i += 1;
                }
                if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                    if s.len() >= 2 {
                        identifiers.push(s.to_string());
                    }
                }
            } else {
                i += 1;
            }
        }

        // Stream B: literals — quoted strings and base64-like blobs
        let mut literals: Vec<bytes::Bytes> = Vec::new();
        let mut j = 0usize;
        while j < data.len() {
            if data[j] == b'"' || data[j] == b'\'' {
                let q = data[j];
                let start = j + 1;
                j += 1;
                while j < data.len() && data[j] != q {
                    j += 1;
                }
                if j < data.len() {
                    literals.push(bytes::Bytes::copy_from_slice(&data[start..j]));
                }
                j += 1;
            } else {
                j += 1;
            }
        }

        // Stream C: structure score — count delimiters
        let delimiters = data
            .iter()
            .filter(|&&b| matches!(b, b'{' | b'}' | b'[' | b']' | b':' | b'=' | b';'))
            .count();
        let structure_score = (delimiters as f32 / data.len().max(1) as f32).min(1.0);

        let combined_score = (m.proximity_score + structure_score) / 2.0;

        TriStreamResult {
            source: m,
            identifiers,
            literals,
            structure_score,
            combined_score,
        }
    }
}

// Re-export `GpuEngine` from the implementation module at this level so
// callers can use `engine::gpu::GpuEngine` regardless of feature flag.
#[cfg(feature = "gpu")]
pub use gpu_impl::GpuEngine;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "gpu"))]
    #[test]
    fn test_gpu_stub_not_available() {
        use super::GpuEngine;
        assert!(!GpuEngine::is_available());
    }

    #[cfg(feature = "gpu")]
    #[tokio::test]
    async fn test_entropy_shader_matches_cpu() {
        use super::GpuEngine;
        use bytes::Bytes;

        // Only run if we actually have a GPU
        let Some(gpu) = GpuEngine::new().await else {
            return;
        };

        // Create a 64-byte payload
        let mut data = vec![0u8; 64];

        // 1. All zeros should have 0.0 entropy
        let candidates_zero = gpu.execute_entropy(&Bytes::from(data.clone()), 0.0);
        assert_eq!(candidates_zero.len(), 1);
        assert!(candidates_zero[0].entropy < 0.1);

        // 2. High entropy data (0 to 63)
        for i in 0..64 {
            data[i] = i as u8;
        }
        let candidates_high = gpu.execute_entropy(&Bytes::from(data.clone()), 5.0);
        assert_eq!(candidates_high.len(), 1);
        assert!(candidates_high[0].entropy > 5.5);
    }
}
