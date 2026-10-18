//! Finding evaluator: rule + collected evidence → `Finding`. Pure and deterministic — no I/O happens here;
//! scanners collect evidence (HTTP response, file probe) within `Limits` and pass it in.
//! Repeated headers are evaluated across every value. A missing ISO file is `InsufficientEvidence`, not `Fail`.
//! `html_only` rules are N/A when the response is known not to be a browser page (e.g. a JSON API).

use crate::builtin;
use crate::finding::{Evidence, EvidenceClass, Finding, Module, Status};
use crate::platform::DetectedPlatform;
use crate::report::Report;
use crate::rules::{Check, LayerHint, Rule, RulePack};

pub(crate) const MAX_ADVICE_CHARS: usize = 300;

/// Response evidence for header operators. `headers` keep the received order and repeats.
/// `https` = the evaluated response came over HTTPS; `insecure_probe` = what `http://` of the same site did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpEvidence {
    pub source: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub https: bool,
    pub insecure_probe: Option<InsecureProbe>,
    /// Set-Cookie values from redirect responses served over HTTPS before the evaluated page.
    pub redirect_cookies: Vec<String>,
    /// `<meta name="generator">` content of the page (see `platform::meta_generator`), when it has one.
    pub html_generator: Option<String>,
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
    /// `http://` refused the connection: nothing is served there.
    Unreachable(String),
    /// `http://` gave no answer in time: a firewall dropping port 80, or a slow server — one probe cannot tell.
    TimedOut(String),
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

/// `example` overrides the rule's static `example_fix` (built from the site's own values, e.g. its CSP);
/// `layers` says which platform layers can fix what the evidence shows (overrides the rule's static `prefer`);
/// `question` replaces the rule's `review_question` when the check knows the actual decision;
/// `remediation` replaces the rule's `remediation` when the evidence calls for different guidance (builtin text wins
/// over the pack's, so the same pack can read differently across scanner versions);
/// `advice` = an optional improvement that leaves status, verdict and grade unchanged.
/// `detail` is kept whole: status is decided from the full evidence, and each format cuts `detail` only after
/// redaction (render).
pub(crate) struct Outcome {
    pub status: Status,
    pub detail: String,
    pub reason: Option<String>,
    pub missing: bool,
    pub example: Option<String>,
    pub layers: Option<LayerHint>,
    pub question: Option<String>,
    pub remediation: Option<String>,
    pub advice: Option<String>,
}

impl Outcome {
    fn new(status: Status, detail: impl AsRef<str>, reason: Option<String>) -> Self {
        Self {
            status,
            detail: detail.as_ref().to_string(),
            reason,
            missing: false,
            example: None,
            layers: None,
            question: None,
            remediation: None,
            advice: None,
        }
    }
    #[must_use]
    pub fn with_layers(mut self, layers: LayerHint) -> Self {
        self.layers = Some(layers);
        self
    }
    #[must_use]
    pub fn with_question(mut self, question: &str) -> Self {
        self.question = Some(question.to_string());
        self
    }
    #[must_use]
    pub fn with_remediation(mut self, remediation: Option<String>) -> Self {
        self.remediation = remediation;
        self
    }
    #[must_use]
    pub fn with_advice(mut self, advice: Option<String>) -> Self {
        self.advice = advice.map(|a| clip(&a));
        self
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
    let mut out: String = s.chars().take(MAX_ADVICE_CHARS).collect();
    if s.chars().count() > MAX_ADVICE_CHARS {
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
/// `remediation`, `effort`, `depends_on`, `group`) is attached only to actionable results; a passed result with
/// `advice` keeps the check's own example (never the rule's static fix, which was written for a failure).
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
            truncated: false,
        }],
        reason: outcome.reason,
        fix_hint: actionable.then(|| rule.fix_hint.clone()),
        example_fix: if actionable {
            outcome.example.or_else(|| rule.example_fix.clone())
        } else if outcome.advice.is_some() {
            outcome.example
        } else {
            None
        },
        platform_fixes: if actionable {
            rule.platform_fixes(platforms, outcome.layers.as_ref())
        } else {
            Vec::new()
        },
        // The question is for undecided results only; on a FAIL it would point the reader at the wrong decision.
        review_question: if actionable && outcome.status != Status::Fail {
            outcome.question.or_else(|| rule.review_question.clone())
        } else {
            None
        },
        remediation: if actionable {
            outcome
                .remediation
                .or_else(|| Some(rule.remediation.clone()))
        } else {
            None
        },
        advice: outcome.advice,
        effort: if actionable { rule.effort } else { None },
        depends_on: if actionable {
            rule.depends_on.clone()
        } else {
            Vec::new()
        },
        group: if actionable { rule.group.clone() } else { None },
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
