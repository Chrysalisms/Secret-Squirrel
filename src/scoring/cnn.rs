//! CNN/ONNX-based credential classifier.
//!
//! This module is split into two sections:
//!
//! 1. **Always compiled** — [`char_to_idx`], [`tokenize`], and [`ModelTier`] are
//!    available regardless of whether the `cnn` feature is enabled. This allows
//!    the CLI, config, and model-manager to reference model metadata without
//!    pulling in ONNX Runtime.
//!
//! 2. **`cnn`-feature-gated** — [`classifier::CnnClassifier`] wraps an
//!    `ort::Session` and exposes a single [`classify`][classifier::CnnClassifier::classify]
//!    method that returns a probability in `[0.0, 1.0]`.
//!
//! # Alphabet
//!
//! Input strings are tokenised to a 100-symbol alphabet (indices 0–99).
//! Index 99 (`UNK_IDX`) is the catch-all for any byte that does not map to a
//! known character class.  Sequences are padded with zeros and truncated to
//! `max_seq_len` before being fed to the model.

// ============================================================
// SECTION 1 — Always compiled (no `#[cfg(feature = "cnn")]`)
// ============================================================

/// Size of the character-level embedding alphabet.
pub const ALPHABET_SIZE: usize = 100;

/// Embedding index used for unknown/unmapped bytes.
pub const UNK_IDX: i64 = 99;

/// Map a single ASCII byte to its embedding index.
///
/// | Range         | Indices | Description             |
/// |---------------|---------|-------------------------|
/// | `a`–`z`       | 0–25    | Lowercase letters        |
/// | `A`–`Z`       | 26–51   | Uppercase letters        |
/// | `0`–`9`       | 52–61   | Decimal digits           |
/// | `!`–`/`       | 62–76   | Punctuation (33–47)     |
/// | `:`–`@`       | 77–83   | Punctuation (58–64)     |
/// | `[`–`` ` ``   | 84–89   | Punctuation (91–96)     |
/// | `{`–`~`       | 90–93   | Punctuation (123–126)   |
/// | ` ` (space)   | 86      | Space character          |
/// | everything else | 99    | `UNK_IDX`               |
///
/// Note: space (0x20 = 32) does not fall into the `33..=47` range, so it is
/// handled explicitly as index 86.
#[inline]
pub fn char_to_idx(c: u8) -> i64 {
    match c {
        b'a'..=b'z' => (c - b'a') as i64,          // 0–25
        b'A'..=b'Z' => (c - b'A' + 26) as i64,     // 26–51
        b'0'..=b'9' => (c - b'0' + 52) as i64,     // 52–61
        b' ' => 86,                                  // space
        33..=47 => (c - 33 + 62) as i64,            // 62–76
        58..=64 => (c - 58 + 77) as i64,            // 77–83
        91..=96 => (c - 91 + 84) as i64,            // 84–89
        123..=126 => (c - 123 + 90) as i64,         // 90–93
        _ => UNK_IDX,
    }
}

/// Tokenise a string to a fixed-length sequence of character indices.
///
/// * If `input` is shorter than `max_len`, the tail is zero-padded.
/// * If `input` is longer than `max_len`, it is truncated to `max_len` bytes.
///   Truncation is byte-based; multi-byte UTF-8 sequences that happen to fall
///   at the boundary will be mapped to `UNK_IDX` by `char_to_idx`.
#[must_use]
pub fn tokenize(input: &str, max_len: usize) -> Vec<i64> {
    let mut tokens: Vec<i64> = input
        .bytes()
        .take(max_len)
        .map(char_to_idx)
        .collect();
    tokens.resize(max_len, 0);
    tokens
}

/// Selects the ONNX model variant to use for CNN inference.
///
/// Each tier trades off model size, accuracy, and hardware requirements:
///
/// | Tier      | Params  | Size  | Accuracy | Target                 |
/// |-----------|---------|-------|----------|------------------------|
/// | None      | —       | 0 MB  | N/A      | Markov-only mode       |
/// | Tiny      | ~500 K  | ~2 MB | 96–97 %  | GitHub Actions         |
/// | Large     | ~1 M    | ~4 MB | 98–99 %  | Self-hosted CPU runner |
/// | Enhanced  | ~14.5 M | ~55 MB| ~99 %    | GPU workstation        |
/// | Maximum   | ~66 M   | ~260 MB| ~99.5 % | GPU (max accuracy)     |
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelTier {
    /// Disable CNN — use Markov chain scoring only.
    None,
    /// Tiny CNN (~500 K params, ~2 MB, 96–97 %). Best for GitHub Actions.
    Tiny,
    /// Large CNN (~1 M params, ~4 MB, 98–99 %). Self-hosted CPU runner.
    Large,
    /// TinyBERT (~14.5 M params, ~55 MB, ~99 %). GPU workstation.
    Enhanced,
    /// DistilBERT (~66 M params, ~260 MB, ~99.5 %). GPU — maximum accuracy.
    Maximum,
}

impl ModelTier {
    /// Returns the ONNX model filename for this tier.
    ///
    /// Returns an empty string for [`ModelTier::None`].
    #[must_use]
    pub fn filename(&self) -> &'static str {
        match self {
            ModelTier::None     => "",
            ModelTier::Tiny     => "squirrel-tiny-fp32.onnx",
            ModelTier::Large    => "squirrel-large-fp32.onnx",
            ModelTier::Enhanced => "squirrel-tinybert-fp32.onnx",
            ModelTier::Maximum  => "squirrel-distilbert-fp32.onnx",
        }
    }

    /// Maximum sequence length (in characters) this tier's model accepts.
    #[must_use]
    pub fn max_seq_len(&self) -> usize {
        match self {
            ModelTier::None | ModelTier::Tiny => 256,
            _ => 512,
        }
    }

    /// Approximate size of the model file on disk, in bytes.
    #[must_use]
    pub fn approx_size_bytes(&self) -> u64 {
        match self {
            ModelTier::None     => 0,
            ModelTier::Tiny     => 2_000_000,
            ModelTier::Large    => 4_000_000,
            ModelTier::Enhanced => 55_000_000,
            ModelTier::Maximum  => 260_000_000,
        }
    }

    /// Human-readable expected accuracy string.
    #[must_use]
    pub fn expected_accuracy(&self) -> &'static str {
        match self {
            ModelTier::None     => "N/A (Markov chain)",
            ModelTier::Tiny     => "96-97%",
            ModelTier::Large    => "98-99%",
            ModelTier::Enhanced => "~99%",
            ModelTier::Maximum  => "~99.5%",
        }
    }

    /// Build the GitHub Release download URL for this model.
    ///
    /// # Example
    /// ```
    /// # use secret_squirrel::scoring::cnn::ModelTier;
    /// let url = ModelTier::Tiny.download_url("0.1.0");
    /// assert!(url.starts_with("https://"));
    /// assert!(url.contains("0.1.0"));
    /// ```
    #[must_use]
    pub fn download_url(&self, version: &str) -> String {
        format!(
            "https://github.com/Chrysalisms/Secret-Squirrel/releases/download/v{version}/{}",
            self.filename()
        )
    }
}

// ============================================================
// SECTION 2 — `cnn` feature-gated: actual ONNX inference
// ============================================================

/// Inner module containing [`CnnClassifier`], gated on the `cnn` feature.
///
/// When built without `--features cnn` the struct is simply not available, but
/// all tokenisation helpers above remain usable for testing and benchmarking.
#[cfg(feature = "cnn")]
pub mod classifier {
    use std::path::Path;

    use ort::{
        session::Session,
        value::Tensor,
        execution_providers::{CPUExecutionProvider, ExecutionProviderDispatch},
    };

    use crate::error::{Result, SquirrelError};
    use super::{tokenize, ModelTier};

    /// ONNX-Runtime-backed CNN classifier for credential detection.
    ///
    /// # Loading
    ///
    /// ```no_run
    /// # use std::path::Path;
    /// # use secret_squirrel::scoring::cnn::{ModelTier, classifier::CnnClassifier};
    /// let clf = CnnClassifier::from_tier(ModelTier::Tiny, Path::new("/home/user/.squirrel/models")).unwrap();
    /// let score = clf.classify("AKIAIOSFODNN7EXAMPLE").unwrap();
    /// ```
    ///
    /// # Model contract
    ///
    /// The ONNX model must accept a single input named `"input_ids"` with
    /// shape `[1, max_seq_len]` and dtype `int64`, and produce a single output
    /// with shape `[1, 2]` (logits for `[benign, secret]`), or `[1, 1]`
    /// (a raw sigmoid probability).  The classifier handles both layouts.
    pub struct CnnClassifier {
        /// Loaded ONNX Runtime session.
        session: Session,
        /// Which model file / tier is loaded.
        tier: ModelTier,
        /// Sequence length the model expects.
        max_seq_len: usize,
    }

    impl CnnClassifier {
        /// Load a [`CnnClassifier`] from an ONNX file on disk.
        ///
        /// Uses the ort 2.0.0-rc.12 API:
        /// `Session::builder()?.commit_from_file(path)?`
        ///
        /// # Errors
        ///
        /// Returns [`SquirrelError::Cnn`] if ONNX Runtime fails to load the model.
        pub fn load(path: &Path, tier: ModelTier) -> Result<Self> {
            let max_seq_len = tier.max_seq_len();

            // Constrain ORT thread pool via environment before initializing the session.
            // This prevents ORT 1.20.x from hanging in environments without GPU hardware
            // (e.g., WSL, CI runners without CUDA). These vars are read during ORT init.
            // We only set them if not already set by the caller.
            if std::env::var("OMP_NUM_THREADS").is_err() {
                // SAFETY: single-threaded at this point; no concurrent env mutations.
                unsafe { std::env::set_var("OMP_NUM_THREADS", "2"); }
            }
            if std::env::var("ORT_NUM_INTRA_THREADS").is_err() {
                unsafe { std::env::set_var("ORT_NUM_INTRA_THREADS", "2"); }
            }
            if std::env::var("ORT_NUM_INTER_THREADS").is_err() {
                unsafe { std::env::set_var("ORT_NUM_INTER_THREADS", "1"); }
            }

            // Build a CPU-only execution provider list.
            // `with_execution_providers` takes `impl AsRef<[ExecutionProviderDispatch]>`,
            // so we convert first and store in a Vec (which implements AsRef<[T]>).
            let cpu_eps: Vec<ExecutionProviderDispatch> = vec![
                CPUExecutionProvider::default().into(),
            ];

            let mut builder = Session::builder()
                .map_err(|e| SquirrelError::Cnn(format!("ort SessionBuilder::new failed: {e}")))?;

            // Apply CPU-only EP. If this fails (e.g., ORT version mismatch), recover the
            // builder and proceed — CPU is always available in the standard ORT release.
            builder = builder
                .with_execution_providers(cpu_eps)
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        "ORT execution provider setup failed ({}), using ORT defaults",
                        e
                    );
                    e.recover()
                });

            let session = builder
                .commit_from_file(path)
                .map_err(|e| SquirrelError::Cnn(format!(
                    "ort failed to load model {:?}: {e}", path
                )))?;

            Ok(Self { session, tier, max_seq_len })
        }

        /// Resolve a [`ModelTier`] to a filename inside `model_dir` and load it.
        ///
        /// # Errors
        ///
        /// Returns [`SquirrelError::Cnn`] if the model file does not exist or
        /// ONNX Runtime fails to initialise.
        pub fn from_tier(tier: ModelTier, model_dir: &Path) -> Result<Self> {
            if tier == ModelTier::None {
                return Err(SquirrelError::Cnn(
                    "ModelTier::None has no associated model file".to_string(),
                ));
            }
            let path = model_dir.join(tier.filename());
            if !path.exists() {
                return Err(SquirrelError::Cnn(format!(
                    "Model not found: {:?}. Run `squirrel model pull {:?}` to download.",
                    path, tier
                )));
            }
            Self::load(&path, tier)
        }

        /// Run the model on `input` and return a probability in `[0.0, 1.0]`.
        ///
        /// `0.0` means the model is confident the input is **benign**;
        /// `1.0` means it is confident the input is a **secret/credential**.
        ///
        /// # Implementation notes
        ///
        /// Uses the ort 2.0.0-rc.12 ndarray API:
        ///
        /// ```text
        /// Tensor::<i64>::from_array(([1usize, max_seq_len], token_vec))?
        /// session.run(ort::inputs!["input_ids" => tensor])?
        /// outputs[0].try_extract_tensor::<f32>()  →  ArrayViewD<f32>
        /// ```
        ///
        /// # Errors
        ///
        /// Returns [`SquirrelError::Cnn`] if tensor construction or ONNX Runtime
        /// inference fails.
        pub fn classify(&mut self, input: &str) -> Result<f64> {
            // 1. Tokenise to a flat Vec<i64> of length max_seq_len.
            let tokens: Vec<i64> = tokenize(input, self.max_seq_len);

            // 2. Build an owned i64 tensor with shape [1, max_seq_len].
            //
            // ort 2.0 tuple API: `Tensor::from_array((shape, data_vec))`
            // shape elements can be usize or i64.
            let tensor = Tensor::<i64>::from_array(
                ([1_usize, self.max_seq_len], tokens)
            )
            .map_err(|e| SquirrelError::Cnn(format!("Tensor::<i64>::from_array failed: {e}")))?;

            // 3. Run inference.
            //
            // `ort::inputs!["name" => value]` produces a
            // `Vec<(Cow<str>, SessionInputValue)>` directly — it is NOT a
            // `Result`, so no `.map_err()` is needed around the macro call.
            let outputs = self
                .session
                .run(ort::inputs!["input_ids" => tensor])
                .map_err(|e| SquirrelError::Cnn(format!("ORT inference error: {e}")))?;

            // 4. Extract the f32 tensor from the first output.
            //
            // `try_extract_tensor::<f32>()` returns `Result<(&Shape, &[f32])>`.
            // `Shape` derefs to `&[i64]` containing the dimension sizes.
            let (raw_shape, data) = outputs[0]
                .try_extract_tensor::<f32>()
                .map_err(|e| SquirrelError::Cnn(format!("output extraction failed: {e}")))?;
            // Convert the Shape dims into a plain Vec<i64> for pattern matching.
            let shape: Vec<i64> = raw_shape.iter().copied().collect();

            // Shape is a Vec<i64> (e.g. [1, 2] for two-class or [1, 1] for sigmoid).
            let dims: &[i64] = &shape[..];

            let probability = match dims {
                [1, 2] => {
                    // Two-class logits [benign, secret]: numerically stable softmax.
                    let logit_b = data[0];
                    let logit_s = data[1];
                    let max = logit_b.max(logit_s);
                    let exp_b = (logit_b - max).exp();
                    let exp_s = (logit_s - max).exp();
                    (exp_s / (exp_b + exp_s)) as f64
                }
                [1, n] if *n >= 1 => {
                    // Single-value sigmoid output — treat as P(secret) directly.
                    data[0] as f64
                }
                other => {
                    return Err(SquirrelError::Cnn(format!(
                        "Unexpected model output shape: {other:?}. Expected [1,2] or [1,1]."
                    )));
                }
            };

            Ok(probability.clamp(0.0, 1.0))
        }

        /// Returns the [`ModelTier`] that was loaded.
        #[must_use]
        pub fn tier(&self) -> &ModelTier {
            &self.tier
        }

        /// Returns the sequence length the model was configured for.
        #[must_use]
        pub fn max_seq_len(&self) -> usize {
            self.max_seq_len
        }
    }
}

#[cfg(feature = "cnn")]
pub use classifier::CnnClassifier;

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- char_to_idx ---

    #[test]
    fn test_char_to_idx_lowercase() {
        assert_eq!(char_to_idx(b'a'), 0);
        assert_eq!(char_to_idx(b'z'), 25);
    }

    #[test]
    fn test_char_to_idx_uppercase() {
        assert_eq!(char_to_idx(b'A'), 26);
        assert_eq!(char_to_idx(b'Z'), 51);
    }

    #[test]
    fn test_char_to_idx_digits() {
        assert_eq!(char_to_idx(b'0'), 52);
        assert_eq!(char_to_idx(b'9'), 61);
    }

    #[test]
    fn test_char_to_idx_space() {
        assert_eq!(char_to_idx(b' '), 86);
    }

    #[test]
    fn test_char_to_idx_punctuation_low() {
        // '!' = 33  → index 62
        assert_eq!(char_to_idx(b'!'), 62);
        // '/' = 47  → 47 - 33 + 62 = 76
        assert_eq!(char_to_idx(b'/'), 76);
    }

    #[test]
    fn test_char_to_idx_punctuation_mid() {
        // ':' = 58  → index 77
        assert_eq!(char_to_idx(b':'), 77);
        // '@' = 64  → 64 - 58 + 77 = 83
        assert_eq!(char_to_idx(b'@'), 83);
    }

    #[test]
    fn test_char_to_idx_unknown() {
        // DEL (0x7F = 127) is not in any range
        assert_eq!(char_to_idx(0x7F), UNK_IDX);
        // High byte
        assert_eq!(char_to_idx(0xFF), UNK_IDX);
    }

    #[test]
    fn test_char_to_idx_all_indices_in_range() {
        for byte in 0u8..=127 {
            let idx = char_to_idx(byte);
            assert!(
                (0..ALPHABET_SIZE as i64).contains(&idx),
                "char_to_idx({byte}) = {idx} is out of alphabet range"
            );
        }
    }

    // --- tokenize ---

    #[test]
    fn test_tokenize_pads_to_max_len() {
        let tokens = tokenize("abc", 10);
        assert_eq!(tokens.len(), 10);
        assert_eq!(tokens[0], char_to_idx(b'a'));
        assert_eq!(tokens[1], char_to_idx(b'b'));
        assert_eq!(tokens[2], char_to_idx(b'c'));
        // Padding must be 0
        for &t in &tokens[3..] {
            assert_eq!(t, 0, "padding should be 0");
        }
    }

    #[test]
    fn test_tokenize_exact_length() {
        let tokens = tokenize("hello", 5);
        assert_eq!(tokens.len(), 5);
        assert_eq!(tokens[4], char_to_idx(b'o'));
    }

    #[test]
    fn test_tokenize_truncates_long_input() {
        let long = "a".repeat(300);
        let tokens = tokenize(&long, 256);
        assert_eq!(tokens.len(), 256);
    }

    #[test]
    fn test_tokenize_empty_string() {
        let tokens = tokenize("", 8);
        assert_eq!(tokens, vec![0i64; 8]);
    }

    #[test]
    fn test_tokenize_max_len_zero() {
        let tokens = tokenize("hello", 0);
        assert!(tokens.is_empty());
    }

    // --- ModelTier ---

    #[test]
    fn test_model_tier_filename_ends_with_onnx() {
        assert!(ModelTier::Tiny.filename().ends_with(".onnx"));
        assert!(ModelTier::Large.filename().ends_with(".onnx"));
        assert!(ModelTier::Enhanced.filename().ends_with(".onnx"));
        assert!(ModelTier::Maximum.filename().ends_with(".onnx"));
    }

    #[test]
    fn test_model_tier_none_filename_empty() {
        assert_eq!(ModelTier::None.filename(), "");
    }

    #[test]
    fn test_model_tier_none_has_zero_size() {
        assert_eq!(ModelTier::None.approx_size_bytes(), 0);
    }

    #[test]
    fn test_model_tier_size_ordering() {
        assert!(ModelTier::Tiny.approx_size_bytes() < ModelTier::Large.approx_size_bytes());
        assert!(ModelTier::Large.approx_size_bytes() < ModelTier::Enhanced.approx_size_bytes());
        assert!(ModelTier::Enhanced.approx_size_bytes() < ModelTier::Maximum.approx_size_bytes());
    }

    #[test]
    fn test_model_tier_seq_len_none_tiny() {
        assert_eq!(ModelTier::None.max_seq_len(), 256);
        assert_eq!(ModelTier::Tiny.max_seq_len(), 256);
    }

    #[test]
    fn test_model_tier_seq_len_larger() {
        assert_eq!(ModelTier::Large.max_seq_len(), 512);
        assert_eq!(ModelTier::Enhanced.max_seq_len(), 512);
        assert_eq!(ModelTier::Maximum.max_seq_len(), 512);
    }

    #[test]
    fn test_model_tier_download_url() {
        let url = ModelTier::Tiny.download_url("0.1.0");
        assert!(url.starts_with("https://"));
        assert!(url.contains("0.1.0"));
        assert!(url.contains(".onnx"));
        assert!(url.contains("Chrysalisms/Secret-Squirrel"));
    }

    #[test]
    fn test_model_tier_download_url_none_is_empty_path() {
        // None maps to empty filename, so URL ends with "/"
        let url = ModelTier::None.download_url("1.0.0");
        assert!(url.starts_with("https://"));
    }

    #[test]
    fn test_model_tier_serde_roundtrip() {
        let tier = ModelTier::Enhanced;
        let json = serde_json::to_string(&tier).expect("serialize");
        let back: ModelTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tier, back);
    }

    #[test]
    fn test_model_tier_serde_lowercase() {
        // serde(rename_all = "lowercase") means "enhanced" not "Enhanced"
        let json = serde_json::to_string(&ModelTier::Enhanced).unwrap();
        assert_eq!(json, r#""enhanced""#);
    }
}
