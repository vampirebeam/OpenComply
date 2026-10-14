//! Scan report, status counts and the process exit code derived from them.
//! `schema_version` is bumped on any breaking change to the JSON report shape.

use schemars::JsonSchema;
use serde::Serialize;

use crate::finding::{Finding, Module, Status};
use crate::grade::{grade_headers, Grading};
use crate::platform::DetectedPlatform;
use crate::rules::Rule;
use crate::SCANNER_VERSION;

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RulePackRef {
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Summary {
    pub pass: usize,
    pub fail: usize,
    pub unknown: usize,
    pub not_applicable: usize,
    pub needs_review: usize,
    pub insufficient_evidence: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Report {
    pub schema_version: u32,
    pub scanner_version: String,
    pub module: Module,
    pub target: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_packs: Vec<RulePackRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<DetectedPlatform>,
    /// Letter grade for graded modules (headers); `None` for others.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<Grading>,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(module: Module, target: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            scanner_version: SCANNER_VERSION.to_string(),
            module,
            target: target.into(),
            rule_packs: Vec::new(),
            platforms: Vec::new(),
            grade: None,
            findings,
        }
    }

    /// Attaches the module's grade computed from `rules` (weights / mandatory); modules without a grade are unchanged.
    #[must_use]
    pub fn graded(mut self, rules: &[&Rule]) -> Self {
        if self.module == Module::Headers {
            self.grade = Some(grade_headers(&self.findings, rules));
        }
        self
    }

    #[must_use]
    pub fn with_platforms(mut self, platforms: Vec<DetectedPlatform>) -> Self {
        self.platforms = platforms;
        self
    }

    #[must_use]
    pub fn with_rule_pack(mut self, id: impl Into<String>, version: impl Into<String>) -> Self {
        self.rule_packs.push(RulePackRef {
            id: id.into(),
            version: version.into(),
            sha256: None,
            signed_by: None,
        });
        self
    }

    pub fn summary(&self) -> Summary {
        let mut s = Summary::default();
        for f in &self.findings {
            match f.status {
                Status::Pass => s.pass += 1,
                Status::Fail => s.fail += 1,
                Status::Unknown => s.unknown += 1,
                Status::NotApplicable => s.not_applicable += 1,
                Status::NeedsReview => s.needs_review += 1,
                Status::InsufficientEvidence => s.insufficient_evidence += 1,
            }
        }
        s
    }

    /// Fail outranks Unknown: a report with any failure exits 1 even if other checks were incomplete.
    /// Default policy lets `review` exit 0; `FailOn::Review` (CI strict mode) makes undecided items exit 1.
    pub fn exit_code(&self, fail_on: FailOn) -> ExitCode {
        match (self.verdict(), fail_on) {
            (Verdict::Fail, _) | (Verdict::Review, FailOn::Review) => ExitCode::Findings,
            (Verdict::Incomplete, _) => ExitCode::Incomplete,
            (Verdict::Review, FailOn::Fail) | (Verdict::Pass, _) => ExitCode::Ok,
        }
    }

    /// One-word outcome for people and agents. Review items do not fail the exit code (CI stays green)
    /// but are surfaced as `review` so they are not silently ignored.
    pub fn verdict(&self) -> Verdict {
        let s = self.summary();
        if s.fail > 0 {
            Verdict::Fail
        } else if s.unknown > 0 {
            Verdict::Incomplete
        } else if s.needs_review + s.insufficient_evidence > 0 {
            Verdict::Review
        } else {
            Verdict::Pass
        }
    }
}

/// Which verdict makes the process fail. `Review` = strict mode for CI quality gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailOn {
    #[default]
    Fail,
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Review,
    Incomplete,
    Fail,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Review => "review",
            Verdict::Incomplete => "incomplete",
            Verdict::Fail => "fail",
        }
    }
}

/// Process exit codes. 2 matches clap's usage-error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Ok = 0,
    Findings = 1,
    Usage = 2,
    Incomplete = 3,
    Error = 4,
}
