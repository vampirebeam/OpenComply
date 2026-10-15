//! Finding model: per-rule result with status, severity, evidence, a short fix hint and full remediation.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    Unknown,
    NotApplicable,
    NeedsReview,
    InsufficientEvidence,
}

impl Status {
    pub fn is_actionable(self) -> bool {
        !matches!(self, Status::Pass | Status::NotApplicable)
    }

    /// Sort order for output: what to fix first, then what to decide.
    pub fn priority(self) -> u8 {
        match self {
            Status::Fail => 0,
            Status::Unknown => 1,
            Status::NeedsReview => 2,
            Status::InsufficientEvidence => 3,
            Status::Pass => 4,
            Status::NotApplicable => 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Unknown => "UNKNOWN",
            Status::NotApplicable => "N/A",
            Status::NeedsReview => "REVIEW",
            Status::InsufficientEvidence => "NO-EVIDENCE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Verified,
    Inferred,
    ManualReview,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// How much work a fix usually takes, so the quick wins can be suggested first.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    Quick,
    Moderate,
    Involved,
}

impl Effort {
    pub fn label(self) -> &'static str {
        match self {
            Effort::Quick => "quick",
            Effort::Moderate => "moderate",
            Effort::Involved => "involved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub class: EvidenceClass,
    pub source: String,
    pub detail: String,
}

/// `reason` = why this result (scanner-generated, e.g. "response has no Permissions-Policy header").
/// `fix_hint` = one-line action; `example_fix` = a concrete, copy-ready setting (e.g. the exact header line to add);
/// `review_question` = the decision a person must make for review / unknown results; `remediation` = full guidance.
/// `advice` = an optional improvement on a result that already counts as passed (never changes verdict or grade);
/// `effort`, `depends_on` (rule IDs to fix first) and `group` (fixed in the same place) order and batch the work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub rule_id: String,
    pub rule_version: String,
    pub title: String,
    pub status: Status,
    pub severity: Severity,
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platform_fixes: Vec<PlatformFix>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_question: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Where and how to fix on a detected platform (e.g. Cloudflare dashboard path); `note` = platform caveat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlatformFix {
    pub platform: String,
    pub how: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Fix it here rather than at the other listed layer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub preferred: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Module {
    Headers,
    Tls,
    Iso27001,
    Iso42001,
}

impl Module {
    pub fn name(self) -> &'static str {
        match self {
            Module::Headers => "headers",
            Module::Tls => "tls",
            Module::Iso27001 => "iso27001",
            Module::Iso42001 => "iso42001",
        }
    }
}
