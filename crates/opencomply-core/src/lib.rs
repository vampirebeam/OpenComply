//! `OpenComply` core: finding model, report, rendering, errors, resource limits and the scanner interface.
//! Depends on nothing scanner- or agent-specific; CLI and scanner crates depend on this crate, never the reverse.

mod builtin;
mod error;
mod evaluate;
mod finding;
mod grade;
pub mod limits;
pub mod platform;
pub mod redact;
mod registry;
mod render;
mod report;
pub mod rules;
mod scanner;
pub mod schema;
pub mod signing;
mod standards;
pub mod walk;

pub use builtin::HSTS_MIN_MAX_AGE;
pub use error::Error;
pub use evaluate::{
    evaluate_pack, evaluate_rule, EvalInput, FileProbe, HttpEvidence, InsecureProbe, RedirectHop,
};
pub use finding::{Evidence, EvidenceClass, Finding, Module, PlatformFix, Severity, Status};
pub use grade::{grade_headers, Grading, Upgrade, UpgradeStep};
pub use platform::{
    detect_from_html, detect_platforms, merge_platforms, DetectedPlatform, Layer,
    MAX_HTML_SCAN_BYTES,
};
pub use registry::{Provenance, RegistryError, RuleRegistry, Version, MAX_PACKS, MAX_TOTAL_RULES};
pub use render::{render, Format, MAX_EXAMPLE_CHARS, MAX_HINT_CHARS, MAX_NOTE_CHARS};
pub use report::{ExitCode, FailOn, Report, RulePackRef, Summary, Verdict, REPORT_SCHEMA_VERSION};
pub use scanner::{Limits, Scanner, Target};
pub use standards::{Assessment, Grade, ReadinessLevel, Standard, STANDARDS};

pub const SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Embeds a file by its path from the repository root (like `@/` imports), e.g. `root_file!("rules/x.toml")`.
/// The root comes from `OPENCOMPLY_ROOT` in `.cargo/config.toml`.
#[macro_export]
macro_rules! root_file {
    ($path:literal) => {
        include_str!(concat!(env!("OPENCOMPLY_ROOT"), "/", $path))
    };
}
