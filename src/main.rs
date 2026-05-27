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
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    match cli.log_format {
        LogFormatArg::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json())
                .init();
        }
        LogFormatArg::Text => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().compact())
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
                if cfg!(feature = "gpu") { "enabled" } else { "disabled" }
            );
            println!(
                "  CNN (ONNX):      {}",
                if cfg!(feature = "cnn") { "enabled" } else { "disabled" }
            );
            println!(
                "  MCP server:      {}",
                if cfg!(feature = "mcp-server") { "enabled" } else { "disabled" }
            );
            println!(
                "  Semantic (AST):  {}",
                if cfg!(feature = "semantic") { "enabled" } else { "disabled" }
            );
            println!(
                "  CPU SIMD:        {}",
                if cfg!(feature = "cpu-simd") { "enabled" } else { "disabled" }
            );
            0
        }
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
    _extra_rules: Option<PathBuf>,
) -> Result<i32> {
    use secret_squirrel::engine::session::ScanSession;
    use secret_squirrel::report::get_reporter;
    use std::io::BufWriter;

    tracing::info!(
        source = ?source,
        format = ?config.output.format,
        "Starting scan"
    );

    println!("Scanning: {}", source.display());

    // Create session (will run full pipeline once engine is wired)
    let session = ScanSession::new(config.clone());

    // TODO Phase 1: invoke full pipeline here
    let findings = session.findings;

    // Write output
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

    // Exit 1 if any finding meets or exceeds the --fail-on threshold
    let has_failures = findings.iter().any(|f| f.severity >= fail_on);
    Ok(if has_failures { 1 } else { 0 })
}

/// Validate a specific finding by ID.
async fn run_validate(finding_id: String) -> Result<i32> {
    tracing::info!(finding_id = %finding_id, "Validating finding");
    println!("Validating finding {} — Phase 2 implementation", finding_id);
    Ok(0)
}

/// The pre-commit hook script written by `protect install`.
const PRE_COMMIT_HOOK: &str = "#!/bin/sh\n# Secret Squirrel pre-commit hook\n# Scans staged files for credentials before commit\nset -e\n\nexec squirrel detect --source git-staged --exit-code 1\n";

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

            println!("[squirrel] Pre-commit hook installed: {}", hook_path.display());
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
                None => {
                    match &tier {
                        ModelTier::Default => {
                            println!("[squirrel] Tier 'none' uses the built-in Markov scorer — no download needed.");
                            return Ok(0);
                        }
                        _ => {
                            eprintln!("[squirrel] ERROR: Model tier '{:?}' is not yet available.", tier);
                            eprintln!("[squirrel] Check back at https://github.com/Chrysalisms/Secret-Squirrel/releases");
                            return Ok(2);
                        }
                    }
                }
            };

            // Resolve ~/.squirrel/models/
            let model_dir = dirs::home_dir()
                .ok_or_else(|| secret_squirrel::error::SquirrelError::Config(
                    "Cannot determine home directory.".to_string(),
                ))?
                .join(".squirrel")
                .join("models");

            std::fs::create_dir_all(&model_dir)?;
            let dest = model_dir.join(asset.filename);

            // Skip download if the file already exists with the correct hash.
            if dest.exists() {
                let existing = std::fs::read(&dest)?;
                let existing_hash = sha256_hex(&existing);
                if existing_hash == asset.sha256 {
                    println!("[squirrel] Model already downloaded and verified: {}", dest.display());
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
                        return Err::<(Vec<u8>, usize), String>(
                            format!("HTTP {}: {}", response.status(), url)
                        );
                    }
                    let content_length = response.content_length().unwrap_or(0);
                    let mut buf: Vec<u8> = Vec::with_capacity(content_length as usize);
                    let mut tmp = [0u8; 65536];
                    let mut downloaded: u64 = 0;
                    loop {
                        let n = response.read(&mut tmp)
                            .map_err(|e| format!("Read error: {e}"))?;
                        if n == 0 { break; }
                        buf.extend_from_slice(&tmp[..n]);
                        downloaded += n as u64;
                        if content_length > 0 {
                            let pct = downloaded * 100 / content_length;
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
                },
            )
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
                "  {:10}  {:25}  {:12}  {}",
                "TIER", "MODEL", "SIZE", "DESCRIPTION"
            );
            println!("  {}", "─".repeat(70));
            println!(
                "  {:10}  {:25}  {:12}  {}",
                "none", "Markov chain (embedded)", "~0 MB", "Default — no download required"
            );
            println!(
                "  {:10}  {:25}  {:12}  {}",
                "tiny", "Char-CNN 500K params", "~2 MB", "GitHub Actions tier"
            );
            println!(
                "  {:10}  {:25}  {:12}  {}",
                "large", "Char-CNN 1M params", "~4 MB", "Self-hosted CPU tier"
            );
            println!(
                "  {:10}  {:25}  {:12}  {}",
                "enhanced", "TinyBERT 14M params", "~55 MB", "Self-hosted GPU tier"
            );
            println!(
                "  {:10}  {:25}  {:12}  {}",
                "maximum", "DistilBERT 66M params", "~130 MB", "Maximum accuracy"
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
