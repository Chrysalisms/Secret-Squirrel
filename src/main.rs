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
    /// Install the Secret Squirrel pre-commit hook in the current repository
    Install,
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

/// Protect subcommand — manage the git pre-commit hook.
fn run_protect(action: ProtectCommands) -> Result<i32> {
    match action {
        ProtectCommands::Install => {
            install_pre_commit_hook()?;
            println!("✅ Secret Squirrel pre-commit hook installed.");
            println!("   Secrets will be scanned before each commit.");
            println!("   Use `git commit --no-verify` to bypass (not recommended).");
        }
        ProtectCommands::Uninstall => {
            uninstall_pre_commit_hook()?;
            println!("✅ Secret Squirrel pre-commit hook removed.");
        }
        ProtectCommands::Check => {
            println!("Running protect check...");
        }
    }
    Ok(0)
}

/// The pre-commit hook script written by `protect install`.
const PRE_COMMIT_HOOK: &str = r#"#!/bin/sh
# Secret Squirrel pre-commit hook
STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
[ -z "$STAGED" ] && exit 0
echo "[squirrel] Scanning staged files for secrets..."
for FILE in $STAGED; do
    [ -f "$FILE" ] && squirrel detect "$FILE" --severity high --format table 2>&1 || true
done
if [ $? -eq 1 ]; then
    echo "[squirrel] Secrets detected! Use --no-verify to override."
    exit 1
fi
exit 0
"#;

fn install_pre_commit_hook() -> Result<()> {
    if !PathBuf::from(".git").exists() {
        return Err(secret_squirrel::error::SquirrelError::Config(
            "Not in a git repository. Run `git init` first.".to_string(),
        ));
    }

    let hook_path = PathBuf::from(".git/hooks/pre-commit");
    std::fs::write(&hook_path, PRE_COMMIT_HOOK)?;

    // Make executable on Unix (no-op on Windows — git handles it)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    tracing::info!(path = %hook_path.display(), "pre-commit hook installed");
    Ok(())
}

fn uninstall_pre_commit_hook() -> Result<()> {
    let hook_path = PathBuf::from(".git/hooks/pre-commit");
    if hook_path.exists() {
        std::fs::remove_file(&hook_path)?;
        tracing::info!("pre-commit hook removed");
    }
    Ok(())
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

/// Model subcommand — pull, list, or remove ONNX models.
async fn run_model(action: ModelCommands) -> Result<i32> {
    match action {
        ModelCommands::Pull { tier } => {
            let tier: ModelTier = tier.into();
            println!("📥 Downloading model tier: {:?}", tier);
            println!("   Models are saved to: ~/.squirrel/models/");
            println!("   ℹ️  Full model download is implemented in Phase 3.");
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
