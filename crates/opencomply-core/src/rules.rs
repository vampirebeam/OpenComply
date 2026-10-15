//! Rule pack schema: data-only rules with an allowlisted set of check operators — no expressions, no code execution.
//! Loading = input size cap → typed TOML parse (unknown fields / operators rejected) → semantic validation that
//! collects every problem, so authors fix a pack in one pass.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::finding::{Effort, Module, PlatformFix, Severity};
use crate::platform::{platform_def, DetectedPlatform, Layer};
use crate::render::{MAX_EXAMPLE_CHARS, MAX_HINT_CHARS, MAX_NOTE_CHARS};

/// The official headers rule pack, embedded in the binary.
pub const OFFICIAL_HEADERS_PACK: &str = crate::root_file!("rules/opencomply-headers.toml");

// `OFFICIAL_HEADERS_SIG`: the detached signature of that pack, `None` in unsigned development builds (see build.rs).
include!(concat!(env!("OUT_DIR"), "/official_sigs.rs"));

pub const MAX_PACK_BYTES: usize = 1024 * 1024;
pub const MAX_RULES: usize = 1000;
pub const MAX_TEXT_CHARS: usize = 4096;
const MAX_VALUE_CHARS: usize = 1024;
const MAX_ID_CHARS: usize = 64;
const MAX_GROUP_CHARS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    pub pack: PackMeta,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackMeta {
    pub id: String,
    pub version: String,
    pub module: Module,
}

/// `mandatory` rules cap the grade when they fail; `weight` (0–100) is the rule's share of the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub version: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default)]
    pub mandatory: bool,
    pub weight: u8,
    pub check: Check,
    /// Only meaningful for pages rendered in a browser; a non-HTML response (e.g. a JSON API) makes it N/A.
    #[serde(default)]
    pub html_only: bool,
    pub fix_hint: String,
    #[serde(default)]
    pub example_fix: Option<String>,
    #[serde(default)]
    pub review_question: Option<String>,
    /// What passing this check costs or changes (e.g. nonces need server rendering), shown on the path to a higher grade.
    #[serde(default)]
    pub upgrade_impact: Option<String>,
    pub remediation: String,
    /// Platform-specific guidance keyed by platform id (e.g. `cloudflare`, `vercel`, `nginx`).
    #[serde(default)]
    pub platforms: BTreeMap<String, PlatformGuide>,
    /// How much work the fix usually takes.
    #[serde(default)]
    pub effort: Option<Effort>,
    /// Rule IDs in this pack to fix before this one (e.g. HSTS after the http:// → https:// redirect).
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Rules fixed in the same place share a group (e.g. `response-headers`).
    #[serde(default)]
    pub group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformGuide {
    pub how: String,
    #[serde(default)]
    pub note: Option<String>,
    /// The better place to fix it when several detected layers can (e.g. nonces belong in the app, not the CDN).
    #[serde(default)]
    pub prefer: bool,
}

/// At most this many platform fixes per finding (outermost layer first) to keep output short.
pub const MAX_PLATFORM_FIXES: usize = 2;

/// Which platform layers can fix what the evidence shows (e.g. a `Server` version is fixed in the web server, not the
/// app). `prefer` overrides the rule's static `prefer`; layers in `skip` are not offered as places to fix;
/// a non-empty `only` keeps just those platform ids (e.g. the load balancer that set a cookie); platforms in
/// `sources` emitted the flagged evidence themselves, so they are always offered, preferred and never capped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayerHint {
    pub prefer: Vec<Layer>,
    pub skip: Vec<Layer>,
    pub only: Vec<&'static str>,
    pub sources: Vec<&'static str>,
}

impl Rule {
    /// Guidance for the platforms detected on the target: sources of the evidence first, then the preferred layer,
    /// then CDN → framework order, capped at `MAX_PLATFORM_FIXES` (or the number of sources, if more).
    /// A `LayerHint` from the evidence decides relevance and preference.
    pub fn platform_fixes(
        &self,
        detected: &[DetectedPlatform],
        hint: Option<&LayerHint>,
    ) -> Vec<PlatformFix> {
        let is_source = |id: &str| hint.is_some_and(|h| h.sources.contains(&id));
        let mut fixes: Vec<(bool, PlatformFix)> = detected
            .iter()
            .filter(|d| {
                is_source(d.id)
                    || hint.is_none_or(|h| {
                        !h.skip.contains(&d.layer) && (h.only.is_empty() || h.only.contains(&d.id))
                    })
            })
            .filter_map(|d| {
                self.platforms.get(d.id).map(|g| {
                    (
                        is_source(d.id),
                        PlatformFix {
                            platform: d.id.to_string(),
                            how: g.how.clone(),
                            note: g.note.clone(),
                            preferred: is_source(d.id)
                                || hint.map_or(g.prefer, |h| h.prefer.contains(&d.layer)),
                        },
                    )
                })
            })
            .collect();
        fixes.sort_by_key(|(source, f)| (!source, !f.preferred));
        let sources = fixes.iter().filter(|(source, _)| *source).count();
        fixes.truncate(MAX_PLATFORM_FIXES.max(sources));
        fixes.into_iter().map(|(_, f)| f).collect()
    }
}

/// The complete operator allowlist. Header operators apply to the headers module, file operators to the ISO modules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    HeaderPresent {
        header: String,
    },
    HeaderAbsent {
        header: String,
    },
    HeaderEquals {
        header: String,
        value: String,
    },
    HeaderContains {
        header: String,
        value: String,
    },
    HeaderOneOf {
        header: String,
        values: Vec<String>,
    },
    HeaderDirectiveAtLeast {
        header: String,
        directive: String,
        min: u64,
    },
    FileExists {
        path: String,
    },
    FileContains {
        path: String,
        text: String,
    },
    /// A check implemented in the engine, selected by name from the closed `Builtin` list.
    Builtin {
        name: Builtin,
    },
}

/// Built-in header checks that need real parsing (CSP, HSTS, cookies, redirects). The list is closed:
/// a rule pack can only pick one by name, never add or change behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Builtin {
    Hsts,
    Csp,
    ReferrerPolicy,
    Clickjacking,
    HttpsRedirect,
    HeaderSyntax,
    Cookies,
    InfoDisclosure,
}

impl Check {
    pub fn op_name(&self) -> &'static str {
        match self {
            Check::HeaderPresent { .. } => "header_present",
            Check::HeaderAbsent { .. } => "header_absent",
            Check::HeaderEquals { .. } => "header_equals",
            Check::HeaderContains { .. } => "header_contains",
            Check::HeaderOneOf { .. } => "header_one_of",
            Check::HeaderDirectiveAtLeast { .. } => "header_directive_at_least",
            Check::FileExists { .. } => "file_exists",
            Check::FileContains { .. } => "file_contains",
            Check::Builtin { .. } => "builtin",
        }
    }

    fn allowed_for(&self, module: Module) -> bool {
        let header_op = matches!(
            self,
            Check::HeaderPresent { .. }
                | Check::HeaderAbsent { .. }
                | Check::HeaderEquals { .. }
                | Check::HeaderContains { .. }
                | Check::HeaderOneOf { .. }
                | Check::HeaderDirectiveAtLeast { .. }
                | Check::Builtin { .. }
        );
        match module {
            Module::Headers => header_op,
            Module::Iso27001 | Module::Iso42001 => !header_op,
            Module::Tls => false,
        }
    }

    fn validate(&self, at: &str, v: &mut Validator) {
        match self {
            Check::HeaderPresent { header } | Check::HeaderAbsent { header } => {
                v.token(&format!("{at}.check.header"), header);
            }
            Check::HeaderEquals { header, value } | Check::HeaderContains { header, value } => {
                v.token(&format!("{at}.check.header"), header);
                v.text(&format!("{at}.check.value"), value, MAX_VALUE_CHARS);
            }
            Check::HeaderOneOf { header, values } => {
                v.token(&format!("{at}.check.header"), header);
                if values.is_empty() {
                    v.push(&format!("{at}.check.values"), "must not be empty");
                }
                for (i, value) in values.iter().enumerate() {
                    v.text(&format!("{at}.check.values[{i}]"), value, MAX_VALUE_CHARS);
                }
            }
            Check::HeaderDirectiveAtLeast {
                header, directive, ..
            } => {
                v.token(&format!("{at}.check.header"), header);
                v.token(&format!("{at}.check.directive"), directive);
            }
            Check::FileExists { path } => v.rel_path(&format!("{at}.check.path"), path),
            Check::FileContains { path, text } => {
                v.rel_path(&format!("{at}.check.path"), path);
                v.text(&format!("{at}.check.text"), text, MAX_VALUE_CHARS);
            }
            Check::Builtin { .. } => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleIssue {
    pub location: String,
    pub message: String,
}

impl fmt::Display for RuleIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

#[derive(Debug)]
pub enum LoadError {
    TooLarge { size: usize, max: usize },
    Parse(String),
    Invalid(Vec<RuleIssue>),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::TooLarge { size, max } => {
                write!(f, "rule pack too large: {size} bytes (max {max})")
            }
            LoadError::Parse(why) => write!(f, "rule pack parse error: {why}"),
            LoadError::Invalid(issues) => write!(f, "rule pack invalid: {} issue(s)", issues.len()),
        }
    }
}

impl std::error::Error for LoadError {}

impl RulePack {
    pub fn from_toml(src: &str) -> Result<Self, LoadError> {
        if src.len() > MAX_PACK_BYTES {
            return Err(LoadError::TooLarge {
                size: src.len(),
                max: MAX_PACK_BYTES,
            });
        }
        let pack: RulePack =
            toml::from_str(src).map_err(|e| LoadError::Parse(clean(e.message(), 200)))?;
        let issues = pack.validate();
        if issues.is_empty() {
            Ok(pack)
        } else {
            Err(LoadError::Invalid(issues))
        }
    }

    pub fn validate(&self) -> Vec<RuleIssue> {
        let mut v = Validator::default();
        let module = self.pack.module;
        v.text("pack.id", &self.pack.id, MAX_ID_CHARS);
        v.semver("pack.version", &self.pack.version);
        if self.rules.is_empty() {
            v.push("pack", "no rules defined");
        }
        if self.rules.len() > MAX_RULES {
            v.push(
                "pack",
                &format!("too many rules ({} > {MAX_RULES})", self.rules.len()),
            );
        }
        let mut seen = HashSet::new();
        for (i, r) in self.rules.iter().take(MAX_RULES).enumerate() {
            let at = if valid_rule_id(module, &r.id) {
                r.id.clone()
            } else {
                v.push(
                    &format!("rule[{i}].id"),
                    &format!("must look like {}-001", id_prefix(module)),
                );
                format!("rule[{i}]")
            };
            if !seen.insert(r.id.as_str()) {
                v.push(&at, "duplicate rule id");
            }
            v.semver(&format!("{at}.version"), &r.version);
            v.text(&format!("{at}.title"), &r.title, MAX_TEXT_CHARS);
            v.text(&format!("{at}.fix_hint"), &r.fix_hint, MAX_HINT_CHARS);
            if let Some(e) = &r.example_fix {
                v.text(&format!("{at}.example_fix"), e, MAX_EXAMPLE_CHARS);
            }
            for (id, g) in &r.platforms {
                let loc = format!("{at}.platforms.{}", clean(id, 32));
                if platform_def(id).is_none() {
                    v.push(&loc, "unknown platform id");
                }
                v.text(&format!("{loc}.how"), &g.how, MAX_EXAMPLE_CHARS);
                if let Some(n) = &g.note {
                    v.text(&format!("{loc}.note"), n, MAX_NOTE_CHARS);
                }
            }
            if let Some(q) = &r.review_question {
                v.text(&format!("{at}.review_question"), q, MAX_HINT_CHARS);
            }
            if let Some(i) = &r.upgrade_impact {
                v.text(&format!("{at}.upgrade_impact"), i, MAX_NOTE_CHARS);
            }
            v.text(&format!("{at}.remediation"), &r.remediation, MAX_TEXT_CHARS);
            if r.weight > 100 {
                v.push(&format!("{at}.weight"), "must be 0–100");
            }
            if !r.check.allowed_for(module) {
                v.push(
                    &format!("{at}.check.op"),
                    &format!(
                        "'{}' is not allowed for module '{}'",
                        r.check.op_name(),
                        module.name()
                    ),
                );
            }
            r.check.validate(&at, &mut v);
            if let Some(g) = &r.group {
                let token = !g.is_empty()
                    && g.len() <= MAX_GROUP_CHARS
                    && g.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
                if !token {
                    v.push(
                        &format!("{at}.group"),
                        &format!("must be 1–{MAX_GROUP_CHARS} lowercase letters, digits or '-'"),
                    );
                }
            }
            for (n, dep) in r.depends_on.iter().enumerate() {
                let loc = format!("{at}.depends_on[{n}]");
                if dep == &r.id {
                    v.push(&loc, "a rule cannot depend on itself");
                } else if !self.rules.iter().any(|o| &o.id == dep) {
                    v.push(&loc, "no rule with this id in the pack");
                }
            }
        }
        for id in self.dependency_cycles() {
            v.push(&format!("{id}.depends_on"), "dependency cycle");
        }
        v.issues
    }

    /// Rule IDs that sit on a `depends_on` cycle. Iterative and bounded by the rule count, so a malformed pack
    /// cannot loop or overflow the stack.
    fn dependency_cycles(&self) -> Vec<String> {
        let rules: Vec<&Rule> = self.rules.iter().take(MAX_RULES).collect();
        let edges: Vec<Vec<usize>> = rules
            .iter()
            .map(|r| {
                r.depends_on
                    .iter()
                    .filter_map(|d| rules.iter().position(|o| &o.id == d))
                    .collect()
            })
            .collect();
        let mut on_cycle = Vec::new();
        for (start, rule) in rules.iter().enumerate() {
            let mut seen = vec![false; rules.len()];
            let mut stack: Vec<usize> = edges.get(start).cloned().unwrap_or_default();
            while let Some(i) = stack.pop() {
                if i == start {
                    on_cycle.push(rule.id.clone());
                    break;
                }
                if let Some(s) = seen.get_mut(i) {
                    if !*s {
                        *s = true;
                        stack.extend(edges.get(i).into_iter().flatten().copied());
                    }
                }
            }
        }
        on_cycle
    }
}

fn id_prefix(module: Module) -> &'static str {
    module.standard().rule_prefix
}

fn valid_rule_id(module: Module, id: &str) -> bool {
    id.strip_prefix(id_prefix(module))
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|n| n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit()))
}

fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[derive(Default)]
struct Validator {
    issues: Vec<RuleIssue>,
}

impl Validator {
    fn push(&mut self, location: &str, message: &str) {
        self.issues.push(RuleIssue {
            location: clean(location, 96),
            message: message.to_string(),
        });
    }

    fn text(&mut self, at: &str, s: &str, max: usize) {
        if s.trim().is_empty() {
            self.push(at, "must not be empty");
        } else if s.chars().count() > max {
            self.push(at, &format!("longer than {max} characters"));
        } else if s.chars().any(char::is_control) {
            self.push(at, "must not contain control characters");
        }
    }

    fn token(&mut self, at: &str, s: &str) {
        let ok = !s.is_empty()
            && s.len() <= MAX_ID_CHARS
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !ok {
            self.push(at, "must be a valid HTTP token (letters, digits, -)");
        }
    }

    fn semver(&mut self, at: &str, s: &str) {
        let parts: Vec<&str> = s.split('.').collect();
        let ok = parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 6 && p.bytes().all(|b| b.is_ascii_digit()));
        if !ok {
            self.push(at, "must be MAJOR.MINOR.PATCH");
        }
    }

    fn rel_path(&mut self, at: &str, p: &str) {
        let bad = p.is_empty()
            || p.len() > 512
            || p.starts_with('/')
            || p.contains('\\')
            || p.contains(':')
            || p.chars().any(char::is_control)
            || p.split('/').any(|seg| seg == ".." || seg.is_empty());
        if bad {
            self.push(
                at,
                "must be a relative path inside the repository (no '..', '\\', ':' or leading '/')",
            );
        }
    }
}
