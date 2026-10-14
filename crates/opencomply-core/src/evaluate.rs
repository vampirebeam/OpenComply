//! Finding evaluator: rule + collected evidence → `Finding`. Pure and deterministic — no I/O happens here;
//! scanners collect evidence (HTTP response, file probe) within `Limits` and pass it in.
//! Repeated headers are evaluated across every value. A missing ISO file is `InsufficientEvidence`, not `Fail`.
//! `html_only` rules are N/A when the response is known not to be a browser page (e.g. a JSON API).

use crate::builtin;
use crate::finding::{Evidence, EvidenceClass, Finding, Module, Status};
use crate::platform::DetectedPlatform;
use crate::report::Report;
use crate::rules::{Check, Rule, RulePack};

pub(crate) const MAX_EVIDENCE_CHARS: usize = 300;

/// Response evidence for header operators. `headers` keep the received order and repeats.
/// `https` = the evaluated response came over HTTPS; `insecure_probe` = what `http://` of the same site did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpEvidence {
    pub source: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub https: bool,
    pub insecure_probe: Option<InsecureProbe>,
}

/// One response in a redirect chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
    pub location: Option<String>,
}

/// Result of requesting the `http://` version of the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsecureProbe {
    /// Nothing answered on `http://` (closed port, refused, timed out).
    Unreachable(String),
    /// Every response in order; `final_url` is where the chain ended.
    Responded {
        chain: Vec<RedirectHop>,
        final_url: String,
    },
}

impl HttpEvidence {
    pub(crate) fn values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
            .collect()
    }

    /// False only when a Content-Type is present and is not HTML; unknown type counts as a page.
    fn is_page(&self) -> bool {
        self.values("content-type").first().is_none_or(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.contains("html") || ct.contains("xml+xhtml")
        })
    }
}

/// Read-only file access for file operators; implementations enforce traversal and size limits.
pub trait FileProbe {
    fn source(&self) -> String;
    fn exists(&self, rel_path: &str) -> Result<bool, String>;
    fn contains(&self, rel_path: &str, text: &str) -> Result<bool, String>;
}

pub enum EvalInput<'a> {
    Http(&'a HttpEvidence),
    Files(&'a dyn FileProbe),
}

/// `example` overrides the rule's static `example_fix` (built from the site's own values, e.g. its CSP).
pub(crate) struct Outcome {
    pub status: Status,
    pub detail: String,
    pub reason: Option<String>,
    pub missing: bool,
    pub example: Option<String>,
}

impl Outcome {
    fn new(status: Status, detail: impl AsRef<str>, reason: Option<String>) -> Self {
        Self {
            status,
            detail: clip(detail.as_ref()),
            reason,
            missing: false,
            example: None,
        }
    }
    pub fn pass(detail: String) -> Self {
        Self::new(Status::Pass, detail, None)
    }
    pub fn fail(detail: String, reason: String) -> Self {
        Self::new(Status::Fail, detail, Some(reason))
    }
    pub fn review(detail: String, reason: String) -> Self {
        Self::new(Status::NeedsReview, detail, Some(reason))
    }
    pub fn not_applicable(detail: String, reason: String) -> Self {
        Self::new(Status::NotApplicable, detail, Some(reason))
    }
    pub fn missing(header: &str) -> Self {
        Self {
            missing: true,
            ..Self::fail(
                "(header not present)".into(),
                format!("response has no {header} header"),
            )
        }
    }
    pub fn unknown(reason: String) -> Self {
        Self::new(Status::Unknown, "(not evaluated)", Some(reason))
    }
    #[must_use]
    pub fn with_example(mut self, example: Option<String>) -> Self {
        self.example = example;
        self
    }
}

pub(crate) fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(MAX_EVIDENCE_CHARS).collect();
    if s.chars().count() > MAX_EVIDENCE_CHARS {
        out.push('…');
    }
    out
}

pub(crate) fn shown(header: &str, values: &[&str]) -> String {
    values
        .iter()
        .map(|v| format!("{header}: {v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(crate) fn directive_value<'a>(value: &'a str, directive: &str) -> Option<&'a str> {
    value.split(';').map(str::trim).find_map(|part| {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        k.trim()
            .eq_ignore_ascii_case(directive)
            .then(|| v.trim().trim_matches('"'))
    })
}

fn eval_http(check: &Check, http: &HttpEvidence) -> Outcome {
    let header = match check {
        Check::HeaderPresent { header }
        | Check::HeaderAbsent { header }
        | Check::HeaderEquals { header, .. }
        | Check::HeaderContains { header, .. }
        | Check::HeaderOneOf { header, .. }
        | Check::HeaderDirectiveAtLeast { header, .. } => header.as_str(),
        Check::Builtin { name } => return builtin::run(*name, http),
        Check::FileExists { .. } | Check::FileContains { .. } => {
            return Outcome::unknown("file check cannot run against an HTTP response".into())
        }
    };
    let values = http.values(header);
    if let Check::HeaderAbsent { .. } = check {
        return if values.is_empty() {
            Outcome::pass(format!("{header} not present"))
        } else {
            Outcome::fail(
                shown(header, &values),
                format!("{header} is present: {}", values.join(", ")),
            )
        };
    }
    if values.is_empty() {
        return Outcome::missing(header);
    }
    let detail = shown(header, &values);
    match check {
        Check::HeaderEquals { value, .. } => {
            if values.iter().all(|v| v.eq_ignore_ascii_case(value)) {
                Outcome::pass(detail)
            } else {
                Outcome::fail(detail, format!("{header} is not \"{value}\""))
            }
        }
        Check::HeaderContains { value, .. } => {
            let needle = value.to_ascii_lowercase();
            if values
                .iter()
                .all(|v| v.to_ascii_lowercase().contains(&needle))
            {
                Outcome::pass(detail)
            } else {
                Outcome::fail(detail, format!("{header} does not contain \"{value}\""))
            }
        }
        Check::HeaderOneOf {
            values: allowed, ..
        } => {
            if values
                .iter()
                .all(|v| allowed.iter().any(|a| a.eq_ignore_ascii_case(v)))
            {
                Outcome::pass(detail)
            } else {
                Outcome::fail(
                    detail,
                    format!("{header} is not one of: {}", allowed.join(", ")),
                )
            }
        }
        Check::HeaderDirectiveAtLeast { directive, min, .. } => {
            let mut lowest: Option<u64> = None;
            for v in &values {
                match directive_value(v, directive) {
                    None => return Outcome::fail(detail, format!("{header} has no {directive}")),
                    Some(raw) => match raw.parse::<u64>() {
                        Ok(n) => lowest = Some(lowest.map_or(n, |l| l.min(n))),
                        Err(_) => {
                            return Outcome::unknown(format!(
                                "{directive}=\"{raw}\" is not a number"
                            ))
                        }
                    },
                }
            }
            match lowest {
                Some(n) if n >= *min => Outcome::pass(detail),
                Some(n) => Outcome::fail(detail, format!("{directive}={n} is below {min}")),
                None => Outcome::missing(header),
            }
        }
        Check::HeaderPresent { .. }
        | Check::HeaderAbsent { .. }
        | Check::FileExists { .. }
        | Check::FileContains { .. }
        | Check::Builtin { .. } => Outcome::pass(detail),
    }
}

fn eval_files(check: &Check, probe: &dyn FileProbe, module: Module) -> Outcome {
    let absent_status = if matches!(module, Module::Iso27001 | Module::Iso42001) {
        Status::InsufficientEvidence
    } else {
        Status::Fail
    };
    let result = match check {
        Check::FileExists { path } => probe.exists(path).map(|found| (found, path.as_str(), None)),
        Check::FileContains { path, text } => probe
            .contains(path, text)
            .map(|found| (found, path.as_str(), Some(text.as_str()))),
        _ => return Outcome::unknown("header check cannot run against files".into()),
    };
    match result {
        Ok((true, path, None)) => Outcome::pass(format!("{path} exists")),
        Ok((true, path, Some(text))) => Outcome::pass(format!("{path} contains \"{text}\"")),
        Ok((false, path, None)) => Outcome {
            missing: true,
            ..Outcome::new(
                absent_status,
                format!("{path} not found"),
                Some(format!("no {path} in the repository")),
            )
        },
        Ok((false, path, Some(text))) => Outcome::new(
            absent_status,
            format!("{path} does not contain \"{text}\""),
            Some(format!("{path} lacks \"{text}\"")),
        ),
        Err(e) => Outcome::unknown(format!("could not read files: {e}")),
    }
}

/// Evaluates one rule. Fix guidance (`fix_hint`, `example_fix`, `platform_fixes`, `review_question`,
/// `remediation`) is attached only to actionable results.
pub fn evaluate_rule(
    rule: &Rule,
    module: Module,
    input: &EvalInput<'_>,
    platforms: &[DetectedPlatform],
) -> Finding {
    let (outcome, source) = match input {
        EvalInput::Http(http) if rule.html_only && !http.is_page() => (
            Outcome::not_applicable(
                shown("content-type", &http.values("content-type")),
                "response is not an HTML page, so this browser protection does not apply".into(),
            ),
            http.source.clone(),
        ),
        EvalInput::Http(http) => (eval_http(&rule.check, http), http.source.clone()),
        EvalInput::Files(probe) => (eval_files(&rule.check, *probe, module), probe.source()),
    };
    let actionable = outcome.status.is_actionable();
    let title = if outcome.missing && !rule.title.to_ascii_lowercase().ends_with("missing") {
        format!("{} missing", rule.title)
    } else {
        rule.title.clone()
    };
    Finding {
        rule_id: rule.id.clone(),
        rule_version: rule.version.clone(),
        title,
        status: outcome.status,
        severity: rule.severity,
        evidence: vec![Evidence {
            class: EvidenceClass::Verified,
            source,
            detail: outcome.detail,
        }],
        reason: outcome.reason,
        fix_hint: actionable.then(|| rule.fix_hint.clone()),
        example_fix: if actionable {
            outcome.example.or_else(|| rule.example_fix.clone())
        } else {
            None
        },
        platform_fixes: if actionable {
            rule.platform_fixes(platforms)
        } else {
            Vec::new()
        },
        // The question is for undecided results only; on a FAIL it would point the reader at the wrong decision.
        review_question: if actionable && outcome.status != Status::Fail {
            rule.review_question.clone()
        } else {
            None
        },
        remediation: actionable.then(|| rule.remediation.clone()),
    }
}

/// Evaluates every rule in a pack and builds the report (rule pack id/version and platforms recorded).
pub fn evaluate_pack(
    pack: &RulePack,
    target: &str,
    input: &EvalInput<'_>,
    platforms: Vec<DetectedPlatform>,
) -> Report {
    let module = pack.pack.module;
    let findings = pack
        .rules
        .iter()
        .map(|r| evaluate_rule(r, module, input, &platforms))
        .collect();
    let rules: Vec<&Rule> = pack.rules.iter().collect();
    Report::new(module, target, findings)
        .with_rule_pack(pack.pack.id.clone(), pack.pack.version.clone())
        .with_platforms(platforms)
        .graded(&rules)
}
