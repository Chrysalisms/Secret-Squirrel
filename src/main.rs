use clap::{Parser, Subcommand, ValueEnum};
use secret_squirrel::{
    config::{LogFormat, ModelTier, OutputFormat, SquirrelConfig},
    error::Result,
    types::Severity,
};
use std::path::PathBuf;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// ============================
// CLI Definition
// ============================

/// 🐿️ Secret Squirrel — GPU-accelerated credential scanner
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

    /// Configuration file path (.squirrel.toml, .betterleaks.toml, or .gitleaks.toml)
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Output format
    #[arg(short = 'f', long, global = true, default_value = "table", value_name = "FORMAT")]
    format: OutputFormatArg,

    /// Output file (default: stdout)
    #[arg(short = 'o', long, global = true, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Minimum severity to report
    #[arg(short = 's', long, global = true, default_value = "low", value_name = "LEVEL")]
    severity: SeverityArg,

    /// Minimum confidence threshold (0.0–1.0)
    #[arg(long, global = true, default_value = "0.5", value_name = "FLOAT")]
    confidence: f64,

    /// Show redacted secret values (also requires SQUIRREL_ALLOW_SHOW_SECRETS=1)
    #[arg(long, global = true)]
    show_secrets: bool,

    /// Enable GPU acceleration threshold override (bytes, default: 100MB)
    #[arg(long, global = true, value_name = "BYTES")]
    gpu_threshold: Option<u64>,

    /// Enable cross-file credential chain detection
    #[arg(long, global = true)]
    correlate: bool,

    /// Enable semantic AST analysis (adds ~50ms per file)
    #[arg(long, global = true)]
    semantic: bool,

    /// Only report findings new since last scan
    #[arg(long, global = true)]
    baseline: bool,

    /// Verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Log format for CI environments
    #[arg(long, global = true, default_value = "text", value_name = "FORMAT")]
    log_format: LogFormatArg,

    /// Additional rules file to load
    #[arg(long, global = true, value_name = "FILE")]
    rules: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for secrets (default command)
    Detect {
        /// Source to scan (file, directory, git repo path, or URL)
        #[arg(value_name = "SOURCE")]
        source: Option<PathBuf>,

        /// Source type override
        #[arg(long, value_name = "TYPE")]
        source_type: Option<String>,

        /// Git history depth (0 = full history)
        #[arg(long, default_value = "0", value_name = "COMMITS")]
        depth: usize,

        /// Validate detected secrets against their providers (opt-in)
        #[arg(long)]
        validate: bool,

        /// ML model tier to use
        #[arg(long, default_value = "default", value_name = "TIER")]
        model_tier: ModelTierArg,
    },

    /// Validate a specific finding by ID
    Validate {
        /// Finding ID to validate
        finding_id: String,
    },

    /// Push protection — install as a git pre-commit hook
    Protect {
        #[command(subcommand)]
        action: ProtectCommands,
    },

    /// Rule management commands
    Rules {
        #[command(subcommand)]
        action: RulesCommands,
    },

    /// ML model management commands
    Model {
        #[command(subcommand)]
        action: ModelCommands,
    },

    /// Start MCP server for AI agent integration
    McpServer {
        /// Transport type
        #[arg(long, default_value = "stdio")]
        transport: String,

        /// Port for HTTP+SSE transport
        #[arg(long, default_value = "6277")]
        port: u16,
    },

    /// Print version information
    Version,
}

#[derive(Subcommand)]
enum ProtectCommands {
    /// Install pre-commit hook in current repository
    Install,
    /// Remove pre-commit hook
    Uninstall,
    /// Run a check on staged files (manual invocation)
    Check,
}

#[derive(Subcommand)]
enum RulesCommands {
    /// List all loaded rules
    List {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
    },
    /// Show details for a specific rule
    Show {
        /// Rule ID
        rule_id: String,
    },
    /// Validate a rules file
    Validate {
        /// Path to rules file
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum ModelCommands {
    /// Download a model tier
    Pull {
        /// Model tier to download
        #[arg(value_name = "TIER")]
        tier: ModelTierArg,
    },
    /// List available and downloaded models
    List,
    /// Remove a downloaded model
    Remove {
        #[arg(value_name = "TIER")]
        tier: ModelTierArg,
    },
}

// ============================
// Arg enums (for clap integration)
// ============================

#[derive(Clone, ValueEnum)]
enum OutputFormatArg {
    Json,
    Sarif,
    Table,
    Csv,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(a: OutputFormatArg) -> Self {
        match a {
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Sarif => OutputFormat::Sarif,
            OutputFormatArg::Table => OutputFormat::Table,
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

#[derive(Clone, ValueEnum)]
enum ModelTierArg {
    Default,
    Tiny,
    Large,
    Enhanced,
    Maximum,
}

impl From<ModelTierArg> for ModelTier {
    fn from(a: ModelTierArg) -> Self {
        match a {
            ModelTierArg::Default => ModelTier::Default,
            ModelTierArg::Tiny => ModelTier::Tiny,
            ModelTierArg::Large => ModelTier::Large,
            ModelTierArg::Enhanced => ModelTier::Enhanced,
            ModelTierArg::Maximum => ModelTier::Maximum,
        }
    }
}

// ============================
// Main
// ============================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let log_level = if cli.verbose { "debug" } else { "info" };
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

    // Load configuration
    let mut config = SquirrelConfig::load(cli.config.as_deref())?;

    // Apply CLI overrides to config
    config.output.format = cli.format.into();
    config.output.output_path = cli.output.clone();
    config.scan.severity_threshold = cli.severity.into();
    config.scan.confidence_threshold = cli.confidence;
    config.scan.correlate = cli.correlate;
    config.scan.semantic = cli.semantic;
    config.scan.baseline = cli.baseline;

    if let Some(threshold) = cli.gpu_threshold {
        config.gpu.threshold_bytes = threshold;
    }

    // Handle show_secrets security gate
    if cli.show_secrets {
        let env_gate = std::env::var("SQUIRREL_ALLOW_SHOW_SECRETS").unwrap_or_default();
        if env_gate != "1" {
            eprintln!(
                "❌ --show-secrets requires SQUIRREL_ALLOW_SHOW_SECRETS=1 environment variable to be set.\n   \
                 This prevents accidental secret exposure in logs and CI outputs."
            );
            std::process::exit(2);
        }
        config.scan.show_secrets = true;
    }

    // Execute the requested command
    let exit_code = match cli.command {
        Commands::Detect {
            source,
            source_type: _,
            depth,
            validate,
            model_tier,
        } => {
            config.scan.git_depth = depth;
            config.scan.validate = validate;
            config.scan.model_tier = model_tier.into();
            run_detect(source, config).await?
        }

        Commands::Validate { finding_id } => {
            run_validate(finding_id, config).await?
        }

        Commands::Protect { action } => {
            run_protect(action)?
        }

        Commands::Rules { action } => {
            run_rules(action, config, cli.rules.clone())?
        }

        Commands::Model { action } => {
            run_model(action).await?
        }

        Commands::McpServer { transport, port } => {
            run_mcp_server(transport, port, config).await?
        }

        Commands::Version => {
            println!("squirrel {}", env!("CARGO_PKG_VERSION"));
            println!("GPU: {}", if cfg!(feature = "gpu") { "enabled" } else { "disabled" });
            println!("CNN: {}", if cfg!(feature = "cnn") { "enabled" } else { "disabled" });
            println!("MCP: {}", if cfg!(feature = "mcp-server") { "enabled" } else { "disabled" });
            0
        }
    };

    std::process::exit(exit_code);
}

// ============================
// Command Handlers
// ============================

async fn run_detect(source: Option<PathBuf>, config: SquirrelConfig) -> Result<i32> {
    use secret_squirrel::engine::session::ScanSession;
    use secret_squirrel::report::get_reporter;
    use std::io::BufWriter;

    tracing::info!(
        source = ?source,
        format = ?config.output.format,
        "Starting scan"
    );

    let _source_path = source.unwrap_or_else(|| PathBuf::from("."));

    // Create scan session
    let session = ScanSession::new(config.clone());

    // TODO Phase 1 completion: wire up full pipeline execution here
    // For now: demonstrate the session framework and reporter output
    let findings = session.findings;

    // Get output writer
    let mut writer: Box<dyn std::io::Write> = match &config.output.output_path {
        Some(path) => {
            let file = std::fs::File::create(path)?;
            Box::new(BufWriter::new(file))
        }
        None => Box::new(BufWriter::new(std::io::stdout())),
    };

    // Write output
    let reporter = get_reporter(&config.output.format);
    reporter.write(&findings, &mut *writer)?;

    tracing::info!(
        findings_count = findings.len(),
        "Scan complete"
    );

    // Exit code: 0 = no findings, 1 = findings found
    Ok(if findings.is_empty() { 0 } else { 1 })
}

async fn run_validate(finding_id: String, _config: SquirrelConfig) -> Result<i32> {
    tracing::info!(finding_id = %finding_id, "Validating finding");
    println!("Validation for finding {} — Phase 2 implementation", finding_id);
    Ok(0)
}

fn run_protect(action: ProtectCommands) -> Result<i32> {
    match action {
        ProtectCommands::Install => {
            install_pre_commit_hook()?;
            println!("✅ Secret Squirrel pre-commit hook installed.");
            println!("   Secrets will be checked before each commit.");
            println!("   Use `git commit --no-verify` to bypass (not recommended).");
        }
        ProtectCommands::Uninstall => {
            uninstall_pre_commit_hook()?;
            println!("✅ Secret Squirrel pre-commit hook removed.");
        }
        ProtectCommands::Check => {
            println!("Running pre-commit check on staged files...");
            // TODO: wire up staged file scanning
            println!("ℹ️  Pre-commit check — full implementation in Phase 1 completion");
        }
    }
    Ok(0)
}

fn install_pre_commit_hook() -> Result<()> {
    let hook_path = PathBuf::from(".git/hooks/pre-commit");

    if !PathBuf::from(".git").exists() {
        return Err(secret_squirrel::error::SquirrelError::Config(
            "Not in a git repository. Run `git init` first.".to_string(),
        ));
    }

    let hook_script = format!(
        r#"#!/bin/sh
# Secret Squirrel pre-commit hook
# Auto-installed by `squirrel protect install`
# Remove with `squirrel protect uninstall`

set -e

echo "🐿️  Secret Squirrel: scanning staged files..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

# Run squirrel on staged content
git diff --cached -- $STAGED_FILES | squirrel detect --source - --format table --severity high

EXIT_CODE=$?
if [ $EXIT_CODE -eq 1 ]; then
    echo ""
    echo "❌ Secret Squirrel found potential secrets in staged files."
    echo "   Fix the issues above, or bypass with: git commit --no-verify"
    echo "   (not recommended — understand why these are flagged first)"
    exit 1
fi

exit 0
"#
    );

    std::fs::write(&hook_path, hook_script)?;

    // Make hook executable (Unix only — no-op on Windows)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    Ok(())
}

fn uninstall_pre_commit_hook() -> Result<()> {
    let hook_path = PathBuf::from(".git/hooks/pre-commit");
    if hook_path.exists() {
        std::fs::remove_file(&hook_path)?;
    }
    Ok(())
}

fn run_rules(action: RulesCommands, config: SquirrelConfig, cli_rules_path: Option<PathBuf>) -> Result<i32> {
    use secret_squirrel::rules::registry::RuleRegistry;
    let _ = config;
    let registry = RuleRegistry::load(cli_rules_path.as_deref())?;

    match action {
        RulesCommands::List { category } => {
            let rules = registry.rules();
            let filtered: Vec<_> = if let Some(cat) = &category {
                rules.iter().filter(|r| {
                    format!("{:?}", r.category).to_lowercase() == cat.to_lowercase()
                }).collect()
            } else {
                rules.iter().collect()
            };

            println!("Loaded {} rules:", filtered.len());
            println!("{:<40} {:<12} {:<10}", "ID", "Severity", "Category");
            println!("{}", "─".repeat(65));
            for rule in filtered {
                println!("{:<40} {:<12} {:?}",
                    &rule.id, format!("{}", rule.severity), rule.category);
            }
        }

        RulesCommands::Show { rule_id } => {
            if let Some(rule) = registry.by_id(&rule_id) {
                println!("Rule: {}", rule.id);
                println!("Description: {}", rule.description);
                println!("Severity: {}", rule.severity);
                println!("Category: {:?}", rule.category);
                if let Some(rem) = &rule.remediation {
                    println!("Remediation: {}", rem);
                }
            } else {
                eprintln!("Rule '{}' not found", rule_id);
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

async fn run_model(action: ModelCommands) -> Result<i32> {
    match action {
        ModelCommands::Pull { tier } => {
            let tier: ModelTier = tier.into();
            println!("📥 Downloading model tier: {:?}", tier);
            println!("   Model will be saved to ~/.squirrel/models/");
            println!("   ℹ️  Full model download in Phase 3 implementation");
        }
        ModelCommands::List => {
            println!("Available model tiers:");
            println!("  default  — Markov chain (embedded, no download, ~1MB overhead)");
            println!("  tiny     — Char-CNN 500K params (GitHub Actions, ~2MB ONNX)");
            println!("  large    — Char-CNN 1M params (self-hosted CPU, ~4MB ONNX)");
            println!("  enhanced — TinyBERT 14M params (self-hosted GPU, ~55MB ONNX)");
            println!("  maximum  — DistilBERT 66M params (maximum accuracy, ~130MB ONNX)");
        }
        ModelCommands::Remove { tier } => {
            let tier: ModelTier = tier.into();
            println!("🗑️  Removing model tier: {:?}", tier);
        }
    }
    Ok(0)
}

async fn run_mcp_server(transport: String, port: u16, _config: SquirrelConfig) -> Result<i32> {
    tracing::info!(transport = %transport, port = port, "Starting MCP server");
    println!("🐿️  Secret Squirrel MCP server");
    println!("   Transport: {}", transport);
    if transport == "http" {
        println!("   Listening on: 127.0.0.1:{}", port);
    }
    println!("   Full MCP implementation in Phase 2");
    // In Phase 2: start actual rmcp server
    Ok(0)
}
