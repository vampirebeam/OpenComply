//! `opencomply` CLI entry point: parses commands and dispatches to scanner modules.
//! Output goes to stdout (report only), diagnostics to stderr, so agents can parse stdout directly.

#![allow(clippy::print_stdout)]

mod guard;

use std::io::{Read, Write};

use clap::{Parser, Subcommand, ValueEnum};
use opencomply_core::redact::redact;
use opencomply_core::rules::{LoadError, RulePack, MAX_PACK_BYTES};
use opencomply_core::schema;
use opencomply_core::signing::{TrustedKey, MAX_SIGNATURE_FILE_BYTES};
use opencomply_core::{
    render_with, Assessment, Error, ExitCode, FailOn, Format, Limits, Module, RenderOptions,
    Report, RuleRegistry, Target, REPORT_SCHEMA_VERSION, SCANNER_VERSION, STANDARDS,
};
use opencomply_http::NetPolicy;

#[derive(Parser)]
#[command(
    name = "opencomply",
    version,
    about = "Security and compliance scanner. No telemetry; contacts only the targets you scan.",
    after_help = "OpenComply - Copyright 2026 vampirebeam - Apache-2.0 - https://github.com/vampirebeam/OpenComply"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a scanner module
    Scan {
        #[command(subcommand)]
        module: ScanModule,
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Summary, global = true)]
        format: OutputFormat,
        /// Include passing and not-applicable findings
        #[arg(long, global = true)]
        all: bool,
        /// With --format json: leave out the long guidance text and the evidence of passed checks
        #[arg(long, global = true)]
        compact: bool,
        /// Exit non-zero on `fail` (default), or also on undecided `review` items
        #[arg(long, value_enum, default_value_t = FailOnArg::Fail, global = true)]
        fail_on: FailOnArg,
        /// Allow private / internal addresses (e.g. a staging server you are authorised to scan); cloud metadata stays blocked
        #[arg(long, global = true)]
        allow_private: bool,
    },
    /// List supported standards, scanner version and report schema version
    Standards,
    /// Print a JSON Schema (rule pack files or the JSON report)
    Schema {
        #[arg(value_enum)]
        kind: SchemaKind,
    },
    /// Rule pack tools
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Check an AI agent's tool call (hook event on stdin) before it sends or saves scan results; used by the agent plugin
    Guard {
        /// Hook format of the agent
        #[arg(long, value_enum, default_value_t = guard::Agent::Claude)]
        agent: guard::Agent,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SchemaKind {
    RulePack,
    Report,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOnArg {
    Fail,
    Review,
}

impl From<FailOnArg> for FailOn {
    fn from(f: FailOnArg) -> Self {
        match f {
            FailOnArg::Fail => FailOn::Fail,
            FailOnArg::Review => FailOn::Review,
        }
    }
}

#[derive(Subcommand)]
enum RulesAction {
    /// Validate rule pack files (schema + semantic checks + conflicts between packs)
    Validate {
        #[arg(required = true, num_args = 1..=64)]
        files: Vec<std::path::PathBuf>,
    },
}

/// Only shipped modules are exposed; the CLI never lists or accepts a module that has no scanner.
#[derive(Subcommand)]
enum ScanModule {
    /// HTTP security headers of a URL (https:// is assumed when no scheme is given)
    Headers { url: String },
}

/// Modules with a working scanner, shown by `standards`.
const RELEASED: [Module; 1] = [Module::Headers];

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Summary,
    Json,
    Markdown,
}

impl From<OutputFormat> for Format {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Summary => Format::Summary,
            OutputFormat::Json => Format::Json,
            OutputFormat::Markdown => Format::Markdown,
        }
    }
}

impl ScanModule {
    fn into_parts(self) -> (Module, Target) {
        match self {
            ScanModule::Headers { url } => (Module::Headers, Target::Url(with_scheme(&url))),
        }
    }
}

/// People type `www.example.com`: a target without a scheme is scanned over HTTPS.
fn with_scheme(url: &str) -> String {
    let url = url.trim();
    if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    }
}

/// Diagnostics can quote the target URL or a server's reply (e.g. a network error naming `…?token=…`): they get the
/// same secret redaction and control-character stripping as the report before reaching the terminal or an agent.
fn safe(text: &str) -> String {
    redact(text)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Runs one scan on a single-threaded runtime; scanner warnings go to stderr so stdout stays the report.
fn run_scan(
    module: Module,
    target: &Target,
    limits: &Limits,
    policy: NetPolicy,
) -> Result<Report, Error> {
    limits.validate()?;
    match (module, target) {
        (Module::Headers, Target::Url(url)) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(Error::Io)?;
            let out = rt.block_on(opencomply_headers::scan_headers(url, limits, policy))?;
            for w in &out.warnings {
                eprintln!("opencomply: warning: {}", safe(w));
            }
            Ok(out.report)
        }
        _ => Err(Error::NotImplemented(module)),
    }
}

fn print_standards() {
    println!("opencomply {SCANNER_VERSION} report_schema={REPORT_SCHEMA_VERSION}");
    for s in STANDARDS.iter().filter(|s| RELEASED.contains(&s.module)) {
        let result = match s.assessment {
            Assessment::Grade => "grade",
            Assessment::Readiness => "readiness 0-4",
        };
        println!(
            "{} {} {} prefix={} result={}",
            s.module.name(),
            s.name,
            s.edition,
            s.rule_prefix,
            result
        );
    }
}

/// Reads at most `MAX_PACK_BYTES + 1` so an oversized file is rejected without loading it fully.
fn read_pack(path: &std::path::Path) -> Result<String, Error> {
    let mut src = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_PACK_BYTES as u64 + 1).read_to_string(&mut src))
        .map_err(Error::Io)?;
    Ok(src)
}

/// Detached signature `<pack>.sig` next to the pack, read only up to its size limit; absent → unsigned.
fn read_signature(pack: &std::path::Path) -> Option<String> {
    let mut sig_path = pack.as_os_str().to_owned();
    sig_path.push(".sig");
    let mut text = String::new();
    std::fs::File::open(sig_path)
        .and_then(|f| {
            f.take(MAX_SIGNATURE_FILE_BYTES as u64 + 1)
                .read_to_string(&mut text)
        })
        .ok()
        .map(|_| text)
}

/// Validates each file on its own, then adds valid packs to one registry to catch cross-pack conflicts.
fn validate_rules(files: &[std::path::PathBuf]) -> ExitCode {
    let mut registry = RuleRegistry::new();
    let trusted = TrustedKey::official();
    let mut code = ExitCode::Ok;
    for path in files {
        let name = path.display().to_string();
        let src = match read_pack(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("opencomply: {name}: {e}");
                return ExitCode::Error;
            }
        };
        match RulePack::from_toml(&src) {
            Ok(pack) => {
                let line = format!(
                    "ok {name} {} {} module={} rules={}",
                    pack.pack.id,
                    pack.pack.version,
                    pack.pack.module.name(),
                    pack.rules.len()
                );
                let sig = read_signature(path);
                match registry.add_file(&name, src.as_bytes(), sig.as_deref(), &trusted, true) {
                    Ok(prov) => println!(
                        "{line} sha256={} {}",
                        prov.sha256.as_deref().unwrap_or("-"),
                        prov.signed_by
                            .map_or_else(|| "unsigned".to_string(), |k| format!("signed_by={k}"))
                    ),
                    Err(e) => {
                        println!("REJECTED {e}");
                        code = ExitCode::Findings;
                    }
                }
            }
            Err(LoadError::Invalid(issues)) => {
                for issue in &issues {
                    println!("INVALID {name}: {issue}");
                }
                code = ExitCode::Findings;
            }
            Err(e) => {
                println!("INVALID {name}: {e}");
                code = ExitCode::Findings;
            }
        }
    }
    code
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Scan {
            module,
            format,
            all,
            compact,
            fail_on,
            allow_private,
        } => {
            let (module, target) = module.into_parts();
            if compact && !matches!(format, OutputFormat::Json) {
                eprintln!("opencomply: --compact needs --format json");
                return std::process::ExitCode::from(ExitCode::Usage as u8);
            }
            match run_scan(
                module,
                &target,
                &Limits::default(),
                NetPolicy { allow_private },
            ) {
                Ok(report) => {
                    let out = render_with(&report, format.into(), RenderOptions { all, compact });
                    let mut stdout = std::io::stdout().lock();
                    if stdout.write_all(out.as_bytes()).is_err() {
                        ExitCode::Error
                    } else {
                        report.exit_code(fail_on.into())
                    }
                }
                Err(e) => {
                    eprintln!("opencomply: {}", safe(&e.to_string()));
                    e.exit_code()
                }
            }
        }
        Command::Standards => {
            print_standards();
            ExitCode::Ok
        }
        Command::Schema { kind } => {
            let text = match kind {
                SchemaKind::RulePack => schema::rule_pack_schema(),
                SchemaKind::Report => schema::report_schema(),
            };
            print!("{text}");
            ExitCode::Ok
        }
        Command::Rules {
            action: RulesAction::Validate { files },
        } => validate_rules(&files),
        Command::Guard { agent } => {
            let mut event = Vec::new();
            let _ = std::io::stdin()
                .take(guard::MAX_EVENT_BYTES)
                .read_to_end(&mut event);
            if let Some(out) = guard::run(agent, &String::from_utf8_lossy(&event)) {
                println!("{out}");
            }
            ExitCode::Ok
        }
    };
    std::process::ExitCode::from(code as u8)
}
