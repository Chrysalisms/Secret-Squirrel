//! Secret Squirrel CLI entry point.
//!
//! Provides a `squirrel` binary with the following subcommands:
//!
//! | Subcommand | Description                                   |
//! |------------|-----------------------------------------------|
//! | `detect`   | Scan a path or stdin for secrets (default)    |
//! | `validate` | Validate a finding ID against its provider    |
//! | `protect`  | Install / remove git pre-commit hook          |
//! | `rules`    | List, show, or validate detection rules       |
//! | `model`    | Pull, list, or remove ONNX model tiers        |
//! | `version`  | Print version and enabled feature flags       |
//!
//! # Exit codes
//!
//! | Code | Meaning                              |
//! |------|--------------------------------------|
//! | 0    | Success — no findings above threshold |
//! | 1    | Findings detected at or above `--fail-on` |
//! | 2    | Runtime or configuration error        |

use clap::{Parser, Subcommand, ValueEnum};
use secret_squirrel::{
    config::{LogFormat, ModelTier, OutputFormat, SquirrelConfig},
    error::Result,
    types::Severity,
};
use std::path::PathBuf;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// ============================================================================
// CLI Definition
// ============================================================================

/// 🐿️ Secret Squirrel — GPU-accelerated, AI-powered credential scanner
///
/// Drop-in replacement for Betterleaks and Gitleaks with GPU acceleration,
/// AI-powered false-positive filtering, and MCP server for AI agent integration.
#[derive(Parser)]
#[command(
    name = "squirrel",
    version,
    author,
    about,
    long_about = None,
    propagate_version = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path (.squirrel.toml, .betterleaks.toml, .gitleaks.toml)
    #[arg(short = 'c', long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Output format
    #[arg(
        short = 'f',
        long,
        global = true,
        default_value = "table",
        value_name = "FORMAT"
    )]
    format: OutputFormatArg,

    /// Output file path (default: stdout)
    #[arg(short = 'o', long, global = true, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Verbose logging (repeat for more verbosity: -v = info, -vv = debug)
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Log format for structured / CI output
    #[arg(long, global = true, default_value = "text", value_name = "FORMAT")]
    log_format: LogFormatArg,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for secrets (default operation)
    Detect {
        /// Source path to scan (file, directory, or `.` for current directory)
        #[arg(value_name = "SOURCE", default_value = ".")]
        source: PathBuf,

        /// Maximum git history depth to scan (0 = full history)
        #[arg(long, default_value = "0", value_name = "COMMITS")]
        depth: usize,

        /// Minimum severity to report
        #[arg(long, default_value = "medium", value_name = "LEVEL")]
        severity: SeverityArg,

        /// Minimum confidence score to report (0.0–1.0)
        #[arg(long, default_value = "0.5", value_name = "FLOAT")]
        confidence: f64,

        /// Validate detected secrets against their providers
        #[arg(long)]
        validate: bool,

        /// Enable semantic AST analysis via tree-sitter (~50ms overhead per file)
        #[arg(long)]
        semantic: bool,

        /// Only report findings new since last scan (baseline mode)
        #[arg(long)]
        baseline: bool,

        /// Enable cross-file credential chain correlation
        #[arg(long)]
        correlate: bool,

        /// Show (partially redacted) secret values in output.
        /// Also requires the `SQUIRREL_ALLOW_SHOW_SECRETS=1` environment variable.
        #[arg(long)]
        show_secrets: bool,

        /// ML model tier to use for CNN inference
        #[arg(long, default_value = "none", value_name = "TIER")]
        model_tier: ModelTierArg,

        /// GPU dispatch threshold: files smaller than this use the CPU path (bytes)
        #[arg(long, default_value = "10485760", value_name = "BYTES")]
        gpu_threshold: u64,

        /// Additional rules file to load (TOML, Gitleaks, or Betterleaks format)
        #[arg(long, value_name = "FILE")]
        rules: Option<PathBuf>,

        /// Exit with code 1 if any finding meets or exceeds this severity
        #[arg(long, default_value = "high", value_name = "LEVEL")]
        fail_on: SeverityArg,

        /// Execution profile: `fast` (regex+entropy only, CPU) or `deep` (AST, correlation, CNN, GPU)
        #[arg(long, default_value = "fast", value_name = "PROFILE")]
        profile: ExecutionProfileArg,
    },

    /// Validate a specific finding by ID against its provider
    Validate {
        /// Finding ID to validate
        finding_id: String,
    },

    /// Git push protection — manage the pre-commit hook
    Protect {
        #[command(subcommand)]
        action: ProtectCommands,
    },

    /// Detection rule management
    Rules {
        #[command(subcommand)]
        action: RulesCommands,
    },

    /// ONNX model management
    Model {
        #[command(subcommand)]
        action: ModelCommands,
    },

    /// Print version and enabled feature flags
    Version,

    /// Start the MCP server (HTTP or stdio)
    Serve {
        /// Port to listen on (default: 3779)
        #[arg(long, default_value = "3779", value_name = "PORT")]
        port: u16,

        /// Use stdio transport instead of HTTP
        #[arg(long)]
        stdio: bool,
    },
}

// ── Protect subcommands ──────────────────────────────────────────────────────

#[derive(Subcommand)]
enum ProtectCommands {
    /// Install the pre-commit hook
    Install {
        /// Overwrite an existing hook without prompting
        #[arg(long)]
        force: bool,
    },
    /// Remove the Secret Squirrel pre-commit hook
    Uninstall,
    /// Run a manual staged-file check (same logic as the pre-commit hook)
    Check,
}

// ── Rules subcommands ────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum RulesCommands {
    /// List all loaded rules
    List {
        /// Filter rules by category
        #[arg(long)]
        category: Option<String>,
    },
    /// Show details for a specific rule
    Show {
        /// Rule identifier
        rule_id: String,
    },
    /// Validate a rules file
    Validate {
        /// Path to the rules file to validate
        path: PathBuf,
    },
}

// ── Model subcommands ────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum ModelCommands {
    /// Download an ONNX model tier to ~/.squirrel/models/
    Pull {
        #[arg(value_name = "TIER")]
        tier: ModelTierArg,
    },
    /// List available and downloaded model tiers
    List,
    /// Remove a downloaded model tier
    Remove {
        #[arg(value_name = "TIER")]
        tier: ModelTierArg,
    },
}

// ============================================================================
// Clap value enum adapters
// ============================================================================

#[derive(Clone, ValueEnum)]
enum OutputFormatArg {
    Table,
    Json,
    Sarif,
    Csv,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(a: OutputFormatArg) -> Self {
        match a {
            OutputFormatArg::Table => OutputFormat::Table,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Sarif => OutputFormat::Sarif,
            OutputFormatArg::Csv => OutputFormat::Csv,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(a: SeverityArg) -> Self {
        match a {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum LogFormatArg {
    Text,
    Json,
}

impl From<LogFormatArg> for LogFormat {
    fn from(a: LogFormatArg) -> Self {
        match a {
            LogFormatArg::Text => LogFormat::Text,
            LogFormatArg::Json => LogFormat::Json,
        }
    }
}

#[derive(Clone, ValueEnum, PartialEq)]
enum ExecutionProfileArg {
    Fast,
    Deep,
}

/// Model tier selector for the CLI.
///
/// `None` maps to [`ModelTier::Default`] (Markov chain, embedded, no download).
#[derive(Clone, ValueEnum)]
enum ModelTierArg {
    /// No CNN — use Markov chain only (default, fastest)
    None,
    /// Tiny CNN (500K params, ~2MB ONNX — GitHub Actions tier)
    Tiny,
    /// Large CNN (1M params, ~4MB ONNX — self-hosted CPU tier)
    Large,
    /// TinyBERT (14M params, ~55MB ONNX — self-hosted GPU tier)
    Enhanced,
    /// DistilBERT (66M params, ~130MB ONNX — maximum accuracy tier)
    Maximum,
}

impl From<ModelTierArg> for ModelTier {
    fn from(a: ModelTierArg) -> Self {
        match a {
            ModelTierArg::None => ModelTier::Default,
            ModelTierArg::Tiny => ModelTier::Tiny,
            ModelTierArg::Large => ModelTier::Large,
            ModelTierArg::Enhanced => ModelTier::Enhanced,
            ModelTierArg::Maximum => ModelTier::Maximum,
        }
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Tracing initialisation ────────────────────────────────────────────────
    // verbose=0 → warn only, verbose=1 → info, verbose=2+ → debug
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    match cli.log_format {
        LogFormatArg::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(std::io::stderr))
                .init();
        }
        LogFormatArg::Text => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().compact().with_writer(std::io::stderr))
                .init();
        }
    }

    // ── Config loading ────────────────────────────────────────────────────────
    let mut config = SquirrelConfig::load(cli.config.as_deref())?;

    // Apply global CLI flags to config
    config.output.format = cli.format.into();
    config.output.output_path = cli.output.clone();

    // ── Command dispatch ──────────────────────────────────────────────────────
    let exit_code = match cli.command {
        Commands::Detect {
            source,
            depth,
            severity,
            confidence,
            validate,
            semantic,
            baseline,
            correlate,
            show_secrets,
            model_tier,
            gpu_threshold,
            rules,
            fail_on,
            profile,
        } => {
            // Apply detect-specific overrides
            config.scan.severity_threshold = severity.into();
            config.scan.confidence_threshold = confidence;
            config.scan.validate = validate;
            config.scan.semantic = semantic;
            config.scan.baseline = baseline;
            config.scan.correlate = correlate;
            config.scan.git_depth = depth;
            config.scan.model_tier = model_tier.into();
            config.gpu.threshold_bytes = gpu_threshold;

            // Apply execution profile overrides
            if profile == ExecutionProfileArg::Fast {
                config.scan.semantic = false;
                config.scan.correlate = false;
                config.scan.model_tier = ModelTier::Default;
                config.gpu.enabled = false;
            }

            // Security gate: --show-secrets also requires env var
            if show_secrets {
                let env_gate = std::env::var("SQUIRREL_ALLOW_SHOW_SECRETS").unwrap_or_default();
                if env_gate != "1" {
                    eprintln!(
                        "❌  --show-secrets requires SQUIRREL_ALLOW_SHOW_SECRETS=1 to be set.\n   \
                         This prevents accidental secret exposure in logs and CI outputs."
                    );
                    std::process::exit(2);
                }
                config.scan.show_secrets = true;
            }

            let fail_on_severity: Severity = fail_on.into();
            run_detect(source, config, fail_on_severity, rules).await?
        }

        Commands::Validate { finding_id } => run_validate(finding_id).await?,

        Commands::Protect { action } => run_protect(action)?,

        Commands::Rules { action } => run_rules(action, &config)?,

        Commands::Model { action } => run_model(action).await?,

        Commands::Version => {
            println!("squirrel {}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("Features:");
            println!(
                "  GPU (wgpu):      {}",
                if cfg!(feature = "gpu") {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "  CNN (ONNX):      {}",
                if cfg!(feature = "cnn") {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "  MCP server:      {}",
                if cfg!(feature = "mcp-server") {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "  Semantic (AST):  {}",
                if cfg!(feature = "semantic") {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "  CPU SIMD:        {}",
                if cfg!(feature = "cpu-simd") {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            0
        }

        Commands::Serve { port, stdio } => run_serve(port, stdio).await?,
    };

    std::process::exit(exit_code);
}

// ============================================================================
// Command handlers
// ============================================================================

/// Run the detect subcommand.
///
/// Currently prints scan start/finish messages and exits 0 (no findings).
/// The real pipeline wiring will be added in a later phase.
async fn run_detect(
    source: PathBuf,
    config: SquirrelConfig,
    fail_on: Severity,
    extra_rules: Option<PathBuf>,
) -> Result<i32> {
    use chrono::Utc;
    use secret_squirrel::engine::pipeline::Pipeline;
    use secret_squirrel::engine::router::Router;
    use secret_squirrel::engine::session::ScanSession;
    use secret_squirrel::report::get_reporter;
    use secret_squirrel::rules::registry::RuleRegistry;
    #[cfg(feature = "cnn")]
    use secret_squirrel::scoring::cnn::{classifier::CnnClassifier, ModelTier};
    use secret_squirrel::scoring::correlation::CorrelationEngine;
    use secret_squirrel::scoring::fusion::FusionEngine;
    use secret_squirrel::scoring::hard_negatives::HardNegativeMatcher;
    use secret_squirrel::scoring::markov::MarkovScorer;
    #[cfg(feature = "semantic")]
    use secret_squirrel::semantic::SemanticAnalyzer;
    use secret_squirrel::sources::{dir::DirSource, SyncSource};
    use secret_squirrel::types::{hash_secret, Finding, Location, RedactedString};
    use std::io::BufWriter;
    use uuid::Uuid;

    tracing::info!(
        source = ?source,
        format = ?config.output.format,
        "Starting scan"
    );

    eprintln!("Scanning: {}", source.display());

    // ── 1. Initialization ───────────────────────────────────────────────────
    let registry = RuleRegistry::load(extra_rules.as_deref())?;

    // Router: auto-activates GPU when hardware is present (config.gpu.enabled
    // defaults to true). GpuEngine::new() returns None on headless/CPU-only
    // hosts and the router falls back to CPU transparently.
    let router = Router::new(&config.gpu).await;
    let pipeline = Pipeline::new(router, config.pipeline.clone());

    let fusion_engine = FusionEngine::new(&config.scoring);
    let markov = MarkovScorer::new();
    // Semantic analyzer — works with the `semantic` feature flag.
    // Falls back to a zero-cost stub (always None adjustment) without it.
    #[cfg(feature = "semantic")]
    let semantic_analyzer = SemanticAnalyzer::new();
    #[cfg(feature = "semantic")]
    let semantic_enabled = config.scan.semantic;
    // Hard negative matcher — penalizes placeholder/example strings.
    let hard_neg = HardNegativeMatcher::new();

    // ── CNN classifier (optional, requires `cnn` feature + model file) ───────
    // Gracefully degrades to None if the ORT shared library or model file is
    // not present — scan continues with Markov+heuristic scoring only.
    //
    // Note: config::ModelTier::Default == Markov-only (no CNN).
    //       Map to scoring::cnn::ModelTier for CnnClassifier::from_tier().
    #[cfg(feature = "cnn")]
    let mut cnn_classifier: Option<CnnClassifier> = {
        // Map config::ModelTier → scoring::cnn::ModelTier
        use secret_squirrel::config::ModelTier as CfgTier;
        let cnn_tier = match &config.scan.model_tier {
            CfgTier::Default => ModelTier::None,
            CfgTier::Tiny => ModelTier::Tiny,
            CfgTier::Large => ModelTier::Large,
            CfgTier::Enhanced => ModelTier::Enhanced,
            CfgTier::Maximum => ModelTier::Maximum,
        };
        if cnn_tier != ModelTier::None {
            // Look for model in: ./models/, ~/.squirrel/models/
            let model_dirs: Vec<std::path::PathBuf> = vec![
                std::path::PathBuf::from("models"),
                dirs::home_dir()
                    .unwrap_or_default()
                    .join(".squirrel")
                    .join("models"),
            ];
            let mut loaded = None;
            for dir in &model_dirs {
                match CnnClassifier::from_tier(cnn_tier.clone(), dir) {
                    Ok(clf) => {
                        tracing::info!(dir = %dir.display(), "CNN model loaded");
                        loaded = Some(clf);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("CNN not loaded from {:?}: {}", dir, e);
                    }
                }
            }
            if loaded.is_none() {
                tracing::warn!(
                    "CNN model not found — run `squirrel model pull {:?}` to enable",
                    cnn_tier
                );
            }
            loaded
        } else {
            None
        }
    };
    #[cfg(not(feature = "cnn"))]
    let _cnn_classifier: Option<()> = None; // cnn feature disabled — CNN inference skipped

    let mut session = ScanSession::new(config.clone());

    // ── 2. Scanning ─────────────────────────────────────────────────────────
    // For Phase 1, we treat the source as a directory or file using DirSource.
    let dir_source = DirSource::new(source.clone(), config.scan.max_file_size, &config.sources);

    use rayon::prelude::*;

    #[cfg(feature = "cnn")]
    let cnn_classifier_mutex = cnn_classifier.map(Mutex::new);

    let nonce = session.nonce.clone();

    let all_findings: Vec<Finding> = std::thread::scope(|s| {
        let (tx, rx) = crossbeam_channel::bounded(1024);

        s.spawn(move || {
            for f in dir_source.fragments() {
                if tx.send(f).is_err() {
                    break;
                }
            }
        });

        rx.into_iter()
            .par_bridge()
            .filter_map(|fragment_res| {
                let fragment = match fragment_res {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!("Failed to read fragment: {}", e);
                        return None;
                    }
                };

                let matches = match pipeline.process_fragment_with_rules(
                    &fragment,
                    registry.automaton(),
                    registry.rules(),
                    registry.keyword_to_rule(),
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!(
                            "Pipeline failed on fragment {}: {}",
                            fragment.metadata.path,
                            e
                        );
                        return None;
                    }
                };

                let mut local_findings = Vec::new();

                for pm in matches {
                    let rule = if let Some(r) = registry.by_id(&pm.rule_id) {
                        r
                    } else {
                        continue;
                    };

                    let secret_str = &pm.matched_text;
                    let markov_score = markov.score(secret_str);

                    #[cfg(feature = "cnn")]
                    let cnn_score: Option<f32> = if let Some(ref clf_mutex) = cnn_classifier_mutex {
                        if let Ok(mut clf) = clf_mutex.lock() {
                            match clf.classify(secret_str) {
                                Ok(p) => Some(p as f32),
                                Err(e) => {
                                    tracing::debug!("CNN inference failed: {}", e);
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    #[cfg(not(feature = "cnn"))]
                    let cnn_score: Option<f32> = None;

                    #[cfg(feature = "semantic")]
                    let ast_adjustment: Option<f32> = if semantic_enabled {
                        let file_ext = std::path::Path::new(&fragment.metadata.path)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        let ctx =
                            semantic_analyzer.analyze(&fragment.content, pm.match_start, file_ext);
                        Some(ctx.confidence_adjustment())
                    } else {
                        None
                    };
                    #[cfg(not(feature = "semantic"))]
                    let ast_adjustment: Option<f32> = None;

                    let mut fused_score = fusion_engine.compute(
                        &pm,
                        markov_score,
                        cnn_score,
                        ast_adjustment,
                        &fragment.metadata,
                    );

                    use secret_squirrel::scoring::hard_negatives::HARD_NEGATIVE_PENALTY;
                    let hn_on_value = hard_neg.penalty(secret_str);
                    let context_bytes: &[u8] = &pm.source.source.context[..];
                    let context_str = std::str::from_utf8(context_bytes).unwrap_or("");
                    let hn_on_context = hard_neg.penalty(context_str);
                    let hn_penalty = hn_on_value.min(hn_on_context);

                    if (hn_penalty - HARD_NEGATIVE_PENALTY).abs() < 1e-6 {
                        tracing::debug!(
                            matched = %secret_str,
                            rule    = %pm.rule_id,
                            "hard-negative exact match suppressed"
                        );
                        continue;
                    } else if hn_penalty < 0.0 {
                        tracing::debug!(
                            matched = %secret_str,
                            penalty = hn_penalty,
                            "hard-negative heuristic penalty applied"
                        );
                        fused_score.confidence = (fused_score.confidence + hn_penalty).max(0.0);
                    }

                    if fused_score.confidence < config.scan.confidence_threshold {
                        continue;
                    }

                    let mut line = 1;
                    for b in &fragment.content[..pm.match_start.min(fragment.content.len())] {
                        if *b == b'\n' {
                            line += 1;
                        }
                    }

                    let secret = RedactedString::new(secret_str.clone());
                    let secret_hash = hash_secret(&secret, &nonce);

                    let context = String::from_utf8_lossy(&pm.source.source.context).into_owned();

                    let finding = Finding {
                        id: Uuid::new_v4().to_string(),
                        rule_id: rule.id.clone(),
                        description: rule.description.clone(),
                        secret,
                        secret_hash,
                        match_context: context,
                        location: Location {
                            path: fragment.metadata.path.clone(),
                            start_line: line,
                            end_line: line,
                            start_col: 0,
                            end_col: secret_str.len() as u32,
                            byte_offset: pm.match_start as u64,
                        },
                        score: fused_score,
                        severity: rule.severity,
                        chain: None,
                        validation: None,
                        remediation: rule.remediation.clone(),
                        detected_at: Utc::now(),
                        encoding_chain: None,
                    };

                    local_findings.push(finding);
                }
                Some(local_findings)
            })
            .flatten()
            .collect()
    });

    for finding in all_findings {
        session.add_finding(finding);
    }

    session.finalize();

    // ── 2b. Cross-file credential chain correlation ──────────────────────────
    if config.scan.correlate {
        tracing::info!("Running cross-file correlation engine");
        let budget = 64 * 1024 * 1024; // 64 MB
        let mut corr = CorrelationEngine::new(budget);
        for finding in session.findings_mut() {
            // Extract variable name: first identifier in match context
            let var_name = extract_variable_name(&finding.match_context);
            corr.add_finding(finding, var_name.as_deref());
        }
        let chains = corr.resolve_chains();
        tracing::info!(chains = chains.len(), "correlation complete");
        // Apply chain confidence boost and annotate findings
        for chain in chains {
            for finding in session.findings_mut() {
                if finding.id == chain.origin_id
                    || chain.propagation_ids.contains(&finding.id)
                    || chain.usage_ids.contains(&finding.id)
                {
                    finding.score.confidence =
                        (finding.score.confidence + chain.chain_confidence).min(1.0);
                    finding.chain = Some(chain.clone());
                }
            }
        }
    }

    // ── 2c. Live validation ──────────────────────────────────────────────────
    if config.scan.validate {
        use secret_squirrel::types::ValidationRef;
        use secret_squirrel::validate::engine::ValidationEngine;
        tracing::info!("Running live secret validation");
        let val_engine = ValidationEngine::new();
        for finding in session.findings_mut() {
            // Only validate high-confidence findings to avoid rate limiting.
            if finding.score.confidence >= 0.65 {
                if let Some(result) = val_engine.validate_finding(finding).await {
                    tracing::debug!(
                        finding_id = %finding.id,
                        provider = %result.provider,
                        status = ?result.status,
                        "validation result"
                    );
                    finding.validation = Some(ValidationRef {
                        status: result.status,
                        provider: result.provider,
                        validated_at: result.validated_at,
                        reason: Some(result.reason),
                    });
                }
            }
        }
    }

    // ── 3. Reporting ────────────────────────────────────────────────────────
    let findings: Vec<Finding> = session.filtered_findings().cloned().collect();

    let mut writer: Box<dyn std::io::Write> = match &config.output.output_path {
        Some(path) => {
            let file = std::fs::File::create(path)?;
            Box::new(BufWriter::new(file))
        }
        None => Box::new(BufWriter::new(std::io::stdout())),
    };

    let reporter = get_reporter(&config.output.format);
    reporter.write(&findings, &mut *writer)?;

    if findings.is_empty() {
        tracing::info!("No findings detected.");
    } else {
        tracing::info!(count = findings.len(), "Scan complete");
    }

    let has_failures = findings.iter().any(|f| f.severity >= fail_on);
    Ok(if has_failures { 1 } else { 0 })
}

/// Validate a specific finding by ID.
async fn run_validate(finding_id: String) -> Result<i32> {
    tracing::info!(finding_id = %finding_id, "Validating finding");
    println!("Validating finding {} — Phase 2 implementation", finding_id);
    Ok(0)
}

/// Start the MCP server in either HTTP or stdio mode.
#[allow(unused_variables)]
async fn run_serve(port: u16, stdio: bool) -> Result<i32> {
    #[cfg(feature = "mcp-server")]
    {
        if stdio {
            secret_squirrel::mcp::server::run_stdio().await?;
        } else {
            eprintln!(
                "🐿️  Secret Squirrel MCP server listening on http://0.0.0.0:{}",
                port
            );
            eprintln!("   POST http://0.0.0.0:{}/mcp/v1  — JSON-RPC 2.0", port);
            eprintln!("   GET  http://0.0.0.0:{}/health  — Health check", port);
            secret_squirrel::mcp::server::run_http(port).await?;
        }
        Ok(0)
    }
    #[cfg(not(feature = "mcp-server"))]
    {
        eprintln!("MCP server not compiled in. Rebuild with --features mcp-server");
        Ok(2)
    }
}

/// Extract the variable name (identifier) from a match context string.
///
/// Scans for the first `[A-Za-z_][A-Za-z0-9_]+` identifier that precedes an
/// assignment (`=` or `:`) operator, which is typically the key/variable name.
/// Falls back to `None` if no identifier is found.
fn extract_variable_name(context: &str) -> Option<String> {
    // Find the first `=` or `:` in the context and look backwards for an identifier.
    let bytes = context.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'=' || b == b':' {
            // Scan backwards from i, skipping whitespace, to find identifier end.
            let end = bytes[..i]
                .iter()
                .rposition(|&c| c.is_ascii_alphanumeric() || c == b'_')?;
            // Scan backwards to find identifier start.
            let start = bytes[..=end]
                .iter()
                .rposition(|&c| !(c.is_ascii_alphanumeric() || c == b'_'))
                .map(|p| p + 1)
                .unwrap_or(0);
            let ident = std::str::from_utf8(&bytes[start..=end]).ok()?;
            // Filter out trivially short or numeric identifiers.
            if ident.len() >= 2 && !ident.chars().next().unwrap_or('0').is_ascii_digit() {
                return Some(ident.to_uppercase()); // normalise to SCREAMING_CASE
            }
        }
    }
    None
}

/// The pre-commit hook script written by `protect install`.
const PRE_COMMIT_HOOK: &str = "\
#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Secret Squirrel pre-commit hook
# Scans staged files for credentials before each commit.
#
# Bypass (use sparingly): git commit --no-verify
# Remove hook:           squirrel protect uninstall
# Adjust confidence:     edit SQUIRREL_CONFIDENCE below
# ─────────────────────────────────────────────────────────────────────────────

SQUIRREL_CONFIDENCE=\"${SQUIRREL_CONFIDENCE:-0.5}\"
SQUIRREL_BIN=\"${SQUIRREL_BIN:-squirrel}\"

if ! command -v \"$SQUIRREL_BIN\" >/dev/null 2>&1; then
    echo \"[squirrel] ⚠️  squirrel not found in PATH — skipping secret scan.\"
    echo \"[squirrel] Install: cargo install secret-squirrel\"
    exit 0
fi

echo \"[squirrel] Scanning staged files for secrets (confidence >= $SQUIRREL_CONFIDENCE)...\"

\"$SQUIRREL_BIN\" detect \\
    --source git-staged \\
    --confidence \"$SQUIRREL_CONFIDENCE\" \\
    --format table \\
    --exit-code 1

EXIT=$?
if [ $EXIT -ne 0 ]; then
    echo \"\"
    echo \"[squirrel] ❌ Commit blocked — secrets detected in staged files.\"
    echo \"[squirrel]    Fix the issues above, then run: git add <files> && git commit\"
    echo \"[squirrel]    To bypass (not recommended): git commit --no-verify\"
    exit 1
fi

echo \"[squirrel] ✅ No secrets detected — commit allowed.\"
exit 0
";

/// Walk up from `start` to find the nearest `.git` directory.
fn find_git_dir(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut current = start;
    loop {
        let candidate = current.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return None,
        }
    }
}

/// Protect subcommand — manage the git pre-commit hook.
fn run_protect(action: ProtectCommands) -> Result<i32> {
    match action {
        ProtectCommands::Install { force } => {
            let cwd = std::env::current_dir()?;
            let git_dir = find_git_dir(&cwd).ok_or_else(|| {
                secret_squirrel::error::SquirrelError::Config(
                    "Not in a git repository (no .git directory found in any parent).".to_string(),
                )
            })?;

            // Ensure hooks directory exists.
            let hooks_dir = git_dir.join("hooks");
            std::fs::create_dir_all(&hooks_dir)?;

            let hook_path = hooks_dir.join("pre-commit");

            if hook_path.exists() && !force {
                eprintln!(
                    "[squirrel] WARNING: pre-commit hook already exists at {}",
                    hook_path.display()
                );
                eprintln!("[squirrel] Use `squirrel protect install --force` to overwrite.");
                return Ok(2);
            }

            std::fs::write(&hook_path, PRE_COMMIT_HOOK)?;

            // Make executable on Unix (no-op on Windows — git handles it).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&hook_path)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&hook_path, perms)?;
            }

            println!(
                "[squirrel] Pre-commit hook installed: {}",
                hook_path.display()
            );
            println!("[squirrel] Secrets will be scanned before each commit.");
            println!("[squirrel] Use `git commit --no-verify` to bypass (not recommended).");
            tracing::info!(path = %hook_path.display(), "pre-commit hook installed");
        }

        ProtectCommands::Uninstall => {
            let cwd = std::env::current_dir()?;
            if let Some(git_dir) = find_git_dir(&cwd) {
                let hook_path = git_dir.join("hooks").join("pre-commit");
                if hook_path.exists() {
                    std::fs::remove_file(&hook_path)?;
                    println!("[squirrel] Pre-commit hook removed.");
                    tracing::info!("pre-commit hook removed");
                } else {
                    println!("[squirrel] No pre-commit hook found.");
                }
            } else {
                eprintln!("[squirrel] Not in a git repository.");
                return Ok(2);
            }
        }

        ProtectCommands::Check => {
            println!("[squirrel] Running protect check...");
        }
    }
    Ok(0)
}

/// Rules subcommand — list, show, or validate rules.
fn run_rules(action: RulesCommands, _config: &SquirrelConfig) -> Result<i32> {
    use secret_squirrel::rules::registry::RuleRegistry;

    let registry = RuleRegistry::load(None)?;

    match action {
        RulesCommands::List { category } => {
            let rules = registry.rules();
            let filtered: Vec<_> = if let Some(ref cat) = category {
                rules
                    .iter()
                    .filter(|r| format!("{:?}", r.category).to_lowercase() == cat.to_lowercase())
                    .collect()
            } else {
                rules.iter().collect()
            };

            println!("{:40} {:12} {:10}", "ID", "SEVERITY", "CATEGORY");
            println!("{}", "─".repeat(65));
            for rule in &filtered {
                println!(
                    "{:40} {:12} {:?}",
                    rule.id,
                    rule.severity.to_string(),
                    rule.category
                );
            }
            println!();
            println!("Total: {} rules", filtered.len());
        }

        RulesCommands::Show { rule_id } => {
            if let Some(rule) = registry.by_id(&rule_id) {
                println!("ID:           {}", rule.id);
                println!("Description:  {}", rule.description);
                println!("Severity:     {}", rule.severity);
                println!("Category:     {:?}", rule.category);
                println!("Keywords:     {:?}", rule.keywords);
                if let Some(rem) = &rule.remediation {
                    println!("Remediation:  {}", rem);
                }
            } else {
                eprintln!("Rule '{}' not found.", rule_id);
                return Ok(2);
            }
        }

        RulesCommands::Validate { path } => {
            RuleRegistry::load(Some(path.as_path()))?;
            println!("✅ Rules file is valid: {}", path.display());
        }
    }

    Ok(0)
}

/// Download URL and expected SHA256 for a model tier.
struct ModelAsset {
    url: &'static str,
    sha256: &'static str,
    filename: &'static str,
}

fn model_asset(tier: &ModelTier) -> Option<ModelAsset> {
    match tier {
        ModelTier::Tiny => Some(ModelAsset {
            url: "https://github.com/Chrysalisms/Secret-Squirrel/releases/download/v0.1.0/squirrel-tiny-fp32.onnx",
            sha256: "33c9e627fb327268ba8e3ab00b3fe4073a97a857a96da8c87498d29b90252075",
            filename: "squirrel-tiny-fp32.onnx",
        }),
        ModelTier::Large => Some(ModelAsset {
            url: "https://github.com/Chrysalisms/Secret-Squirrel/releases/download/v0.1.0/squirrel-large-fp32.onnx",
            sha256: "79c30d636bc8b6c61e5c205ed15c740d26655ea8eda7872c2e71f5e0e233701d",
            filename: "squirrel-large-fp32.onnx",
        }),
        _ => None,
    }
}

/// Compute the lowercase hex SHA256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Model subcommand — pull, list, or remove ONNX models.
async fn run_model(action: ModelCommands) -> Result<i32> {
    match action {
        ModelCommands::Pull { tier } => {
            let tier: ModelTier = tier.into();

            // Only tiny and large are available right now.
            let asset = match model_asset(&tier) {
                Some(a) => a,
                None => match &tier {
                    ModelTier::Default => {
                        println!("[squirrel] Tier 'none' uses the built-in Markov scorer — no download needed.");
                        return Ok(0);
                    }
                    _ => {
                        eprintln!(
                            "[squirrel] ERROR: Model tier '{:?}' is not yet available.",
                            tier
                        );
                        eprintln!("[squirrel] Check back at https://github.com/Chrysalisms/Secret-Squirrel/releases");
                        return Ok(2);
                    }
                },
            };

            // Resolve ~/.squirrel/models/
            let model_dir = dirs::home_dir()
                .ok_or_else(|| {
                    secret_squirrel::error::SquirrelError::Config(
                        "Cannot determine home directory.".to_string(),
                    )
                })?
                .join(".squirrel")
                .join("models");

            std::fs::create_dir_all(&model_dir)?;
            let dest = model_dir.join(asset.filename);

            // Skip download if the file already exists with the correct hash.
            if dest.exists() {
                let existing = std::fs::read(&dest)?;
                let existing_hash = sha256_hex(&existing);
                if existing_hash == asset.sha256 {
                    println!(
                        "[squirrel] Model already downloaded and verified: {}",
                        dest.display()
                    );
                    return Ok(0);
                } else {
                    println!("[squirrel] Existing file has wrong hash — re-downloading.");
                }
            }

            println!("[squirrel] Downloading: {}", asset.url);
            println!("[squirrel] Destination: {}", dest.display());

            // Download with a blocking client inside a spawn_blocking task so
            // we don't block the async executor.
            let url = asset.url.to_string();
            let (bytes, bytes_total) = tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let mut response = reqwest::blocking::get(&url)
                    .map_err(|e| format!("HTTP request failed: {e}"))?;
                if !response.status().is_success() {
                    return Err::<(Vec<u8>, usize), String>(format!(
                        "HTTP {}: {}",
                        response.status(),
                        url
                    ));
                }
                let content_length = response.content_length().unwrap_or(0);
                let mut buf: Vec<u8> = Vec::with_capacity(content_length as usize);
                let mut tmp = [0u8; 65536];
                let mut downloaded: u64 = 0;
                loop {
                    let n = response
                        .read(&mut tmp)
                        .map_err(|e| format!("Read error: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    downloaded += n as u64;
                    if let Some(pct) = downloaded
                        .checked_mul(100)
                        .and_then(|value| value.checked_div(content_length))
                    {
                        eprint!(
                            "\r[squirrel] Progress: {}/{} bytes ({}%)",
                            downloaded, content_length, pct
                        );
                    } else {
                        eprint!("\r[squirrel] Downloaded: {} bytes", downloaded);
                    }
                }
                eprintln!(); // newline after progress
                let total = buf.len();
                Ok((buf, total))
            })
            .await
            .map_err(|e| {
                secret_squirrel::error::SquirrelError::Config(format!(
                    "Download task panicked: {e}"
                ))
            })?
            .map_err(secret_squirrel::error::SquirrelError::Config)?;

            // Verify SHA256.
            let actual_hash = sha256_hex(&bytes);
            if actual_hash != asset.sha256 {
                eprintln!("[squirrel] ERROR: SHA256 mismatch!");
                eprintln!("[squirrel]   Expected: {}", asset.sha256);
                eprintln!("[squirrel]   Got:      {}", actual_hash);
                return Ok(2);
            }

            std::fs::write(&dest, &bytes)?;
            println!("[squirrel] Download complete: {} bytes", bytes_total);
            println!("[squirrel] SHA256 verified: OK");
            println!("[squirrel] Saved to: {}", dest.display());
        }

        ModelCommands::List => {
            println!("Available model tiers:");
            println!();
            println!(
                "  {:10}  {:25}  {:12}  DESCRIPTION",
                "TIER", "MODEL", "SIZE"
            );
            println!("  {}", "─".repeat(70));
            println!(
                "  {:10}  {:25}  {:12}  Default — no download required",
                "none", "Markov chain (embedded)", "~0 MB"
            );
            println!(
                "  {:10}  {:25}  {:12}  GitHub Actions tier",
                "tiny", "Char-CNN 500K params", "~2 MB"
            );
            println!(
                "  {:10}  {:25}  {:12}  Self-hosted CPU tier",
                "large", "Char-CNN 1M params", "~4 MB"
            );
            println!(
                "  {:10}  {:25}  {:12}  Self-hosted GPU tier",
                "enhanced", "TinyBERT 14M params", "~55 MB"
            );
            println!(
                "  {:10}  {:25}  {:12}  Maximum accuracy",
                "maximum", "DistilBERT 66M params", "~130 MB"
            );

            // List locally available models
            if let Some(home) = dirs::home_dir() {
                let model_dir = home.join(".squirrel").join("models");
                if model_dir.exists() {
                    println!();
                    println!("Downloaded models in {}:", model_dir.display());
                    match std::fs::read_dir(&model_dir) {
                        Ok(entries) => {
                            for entry in entries.flatten() {
                                if entry.path().extension().is_some_and(|e| e == "onnx") {
                                    println!("  ✅ {}", entry.file_name().to_string_lossy());
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Could not read model directory: {}", e);
                        }
                    }
                }
            }
        }

        ModelCommands::Remove { tier } => {
            let tier: ModelTier = tier.into();
            let tier_str = format!("{:?}", tier).to_lowercase();
            if let Some(home) = dirs::home_dir() {
                let model_path = home
                    .join(".squirrel")
                    .join("models")
                    .join(format!("{}.onnx", tier_str));
                if model_path.exists() {
                    std::fs::remove_file(&model_path)?;
                    println!("🗑️  Removed model: {}", model_path.display());
                } else {
                    println!("ℹ️  No downloaded model found for tier '{}'.", tier_str);
                }
            }
        }
    }

    Ok(0)
}
