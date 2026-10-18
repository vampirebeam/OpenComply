//! Output rendering for people and AI agents.
//! - Summary (default): verdict line, then per finding a status line plus short `why` / `fix` / `decide` lines, then
//!   `together` lines and a `next:` line. Fails first, then unknown, then review, then passed results with advice;
//!   within a status, dependencies first, then highest severity, then quickest fix.
//! - JSON: summary-first field order so an agent can stop reading early; empty fields omitted.
//! - Markdown: audit report with evidence, rule version and a dedicated "needs your review" section.
//!
//! All finding text is sanitised: control characters stripped (no terminal / log injection), Markdown cells escaped.

use std::fmt::Write;

use schemars::JsonSchema;
use serde::Serialize;

use crate::finding::{Finding, Module, Status};
use crate::grade::{Grading, Upgrade};
use crate::platform::DetectedPlatform;
use crate::redact::redact_report;
use crate::report::{Report, RulePackRef, Summary, Verdict};
use crate::standards::Grade;

pub const MAX_HINT_CHARS: usize = 100;
/// Examples are never truncated (a cut-off header value would be wrong to copy); rule validation bounds their length.
pub const MAX_EXAMPLE_CHARS: usize = 240;
pub const MAX_NOTE_CHARS: usize = 160;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Summary,
    Json,
    Markdown,
}

/// `all` includes every passing / not-applicable finding (otherwise only actionable ones and those with advice);
/// `compact` (JSON) drops `remediation` and the evidence of passed / not-applicable findings without advice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderOptions {
    pub all: bool,
    pub compact: bool,
}

pub fn render(report: &Report, format: Format, all: bool) -> String {
    render_with(
        report,
        format,
        RenderOptions {
            all,
            compact: false,
        },
    )
}

/// Secrets are always redacted, then every text field is stripped of control characters (C0, DEL and C1 —
/// JSON encoders leave DEL / C1 raw, and C1 `CSI` can drive terminals), whatever the format.
/// Order: status, then what must be fixed first (`depends_on`), severity, effort (quick first), rule ID.
pub fn render_with(report: &Report, format: Format, opts: RenderOptions) -> String {
    let mut redacted = redact_report(report);
    strip_controls(&mut redacted);
    limit_evidence(
        &mut redacted,
        if format == Format::Json {
            MAX_EVIDENCE_JSON
        } else {
            MAX_EVIDENCE_TEXT
        },
    );
    let report = &redacted;
    let depth = dependency_depth(&report.findings);
    let mut shown: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| opts.all || f.status.is_actionable() || f.advice.is_some())
        .collect();
    shown.sort_by(|a, b| {
        let d = |f: &Finding| depth.get(f.rule_id.as_str()).copied().unwrap_or(0);
        a.status
            .priority()
            .cmp(&b.status.priority())
            .then(d(a).cmp(&d(b)))
            .then(b.severity.cmp(&a.severity))
            .then(
                a.effort
                    .map_or(u8::MAX, |e| e as u8)
                    .cmp(&b.effort.map_or(u8::MAX, |e| e as u8)),
            )
            .then(a.rule_id.cmp(&b.rule_id))
    });
    match format {
        Format::Summary => render_summary(report, &shown, opts.all),
        Format::Json => render_json(report, &shown, opts.compact),
        Format::Markdown => render_markdown(report, &shown, opts.all),
    }
}

/// Evidence length per format: JSON keeps more for audit, summary and Markdown stay readable. Cut only after the whole
/// value was redacted and cleaned, so a cut can never leave part of a secret behind.
pub(crate) const MAX_EVIDENCE_JSON: usize = 4096;
pub(crate) const MAX_EVIDENCE_TEXT: usize = 300;

fn limit_evidence(r: &mut Report, max: usize) {
    let cut = |e: &mut crate::finding::Evidence| {
        if let Some(short) = clip_at(&e.detail, max) {
            e.detail = short;
            e.truncated = true;
        }
    };
    r.findings
        .iter_mut()
        .flat_map(|f| &mut f.evidence)
        .for_each(cut);
    r.platforms
        .iter_mut()
        .map(|p| &mut p.evidence)
        .for_each(cut);
}

/// At most `max` characters plus `…`, or `None` when it already fits. Never cuts inside a `[… REDACTED …]` label or a
/// `<U+XXXX>` marker: the cut moves back to where the label starts.
fn clip_at(s: &str, max: usize) -> Option<String> {
    let end = s.char_indices().nth(max)?.0;
    let head = &s[..end];
    let mut cut = end;
    if let Some(open) = head.rfind('[') {
        let label = &s[open..];
        let close = label.find(']').map_or(label.len(), |i| i + 1);
        if open + close > end && label[..close].to_ascii_lowercase().contains("redacted") {
            cut = open;
        }
    }
    if let Some(open) = head[..cut].rfind('<') {
        if open + 3 <= s.len() && s[open..].starts_with("<U+") && !head[open..cut].contains('>') {
            cut = open;
        }
    }
    let mut out = s[..cut].to_string();
    out.push('…');
    Some(out)
}
/// Longest chain of still-open (actionable) dependencies under each actionable finding. Computed over every
/// finding, not only the shown ones; bounded by the finding count so a cycle cannot loop.
fn dependency_depth(findings: &[Finding]) -> std::collections::BTreeMap<&str, usize> {
    let open: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.status.is_actionable())
        .collect();
    let mut depth: std::collections::BTreeMap<&str, usize> =
        open.iter().map(|f| (f.rule_id.as_str(), 0)).collect();
    for _ in 0..open.len() {
        let mut changed = false;
        for f in &open {
            let d = f
                .depends_on
                .iter()
                .filter_map(|dep| depth.get(dep.as_str()).map(|x| x + 1))
                .max()
                .unwrap_or(0)
                .min(open.len());
            if depth.get(f.rule_id.as_str()).is_some_and(|cur| *cur < d) {
                depth.insert(f.rule_id.as_str(), d);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    depth
}

/// Dependencies of `f` that are still open in this report (fix those first).
fn open_dependencies<'a>(report: &'a Report, f: &'a Finding) -> Vec<&'a str> {
    f.depends_on
        .iter()
        .filter(|dep| {
            report
                .findings
                .iter()
                .any(|o| &o.rule_id == *dep && o.status.is_actionable())
        })
        .map(String::as_str)
        .collect()
}

/// `(group, rule IDs)` for every group with at least two open findings (all open ones are shown), in shown order.
fn fix_together<'a>(shown: &[&'a Finding]) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
    for f in shown.iter().filter(|f| f.status.is_actionable()) {
        if let Some(g) = f.group.as_deref() {
            if !groups.iter().any(|(name, _)| *name == g) {
                groups.push((g, Vec::new()));
            }
        }
    }
    for (name, ids) in &mut groups {
        ids.extend(
            shown
                .iter()
                .filter(|f| f.status.is_actionable() && f.group.as_deref() == Some(*name))
                .map(|f| f.rule_id.as_str()),
        );
    }
    groups.retain(|(_, ids)| ids.len() > 1);
    groups
}

fn render_summary(report: &Report, shown: &[&Finding], all: bool) -> String {
    let s = report.summary();
    let verdict = report.verdict();
    let mut out = String::with_capacity(160 + shown.len() * 240);
    let grade = report.grade.as_ref().map_or_else(String::new, |g| {
        let score = g.score.map_or_else(String::new, |s| format!(" score={s}"));
        format!(" grade={}{score}", g.grade.label())
    });
    let _ = write!(
        out,
        "{} {} verdict={}{grade} pass={} fail={} unknown={} review={} no_evidence={} n/a={}",
        report.module.name(),
        one_line(&report.target),
        verdict.label(),
        s.pass,
        s.fail,
        s.unknown,
        s.needs_review,
        s.insufficient_evidence,
        s.not_applicable
    );
    if s.advice > 0 {
        let _ = write!(out, " advice={}", s.advice);
    }
    if !report.platforms.is_empty() {
        let ids: Vec<&str> = report.platforms.iter().map(|p| p.id).collect();
        let _ = write!(out, " platform={}", ids.join("+"));
    }
    out.push('\n');
    if let Some(g) = &report.grade {
        if !g.capped_by.is_empty() {
            let _ = writeln!(out, "grade capped: {}", one_line(&g.capped_by.join("; ")));
        }
        if let Some(note) = open_note(g, &s, verdict) {
            let _ = writeln!(out, "note: {note}");
        }
        summary_upgrades(&mut out, &g.upgrades, all);
    }
    for f in shown {
        let effort = f
            .effort
            .map_or_else(String::new, |e| format!(" · {}", e.label()));
        let _ = writeln!(
            out,
            "{} {} {} {}{effort}",
            f.status.label(),
            one_line(&f.rule_id),
            f.severity.label(),
            one_line(&f.title)
        );
        if f.status == Status::Pass || f.status == Status::NotApplicable {
            summary_advice(&mut out, f);
            continue;
        }
        let after = open_dependencies(report, f);
        if !after.is_empty() {
            let _ = writeln!(out, "  after: {}", one_line(&after.join(", ")));
        }
        if let Some(why) = why(f) {
            let _ = writeln!(out, "  why: {}", short(&why));
        }
        if f.status == Status::Fail {
            if let Some(fix) = &f.fix_hint {
                let _ = writeln!(out, "  fix: {}", short(fix));
            }
        } else if let Some(q) = f.review_question.as_ref().or(f.fix_hint.as_ref()) {
            let _ = writeln!(out, "  decide: {}", short(q));
        }
        if let Some(example) = &f.example_fix {
            let _ = writeln!(out, "  example: {}", one_line(example));
        }
        let several = f.platform_fixes.len() > 1;
        for pf in &f.platform_fixes {
            let id = one_line(&pf.platform);
            let tag = if pf.preferred && several {
                ", preferred"
            } else {
                ""
            };
            let _ = writeln!(out, "  how ({id}{tag}): {}", one_line(&pf.how));
            if let Some(note) = &pf.note {
                let _ = writeln!(out, "  note ({id}): {}", one_line(note));
            }
        }
        if let Some(advice) = &f.advice {
            let _ = writeln!(out, "  advice: {}", one_line(advice));
        }
    }
    for (group, ids) in fix_together(shown) {
        let _ = writeln!(
            out,
            "together ({}): {}",
            one_line(group),
            one_line(&ids.join(" · "))
        );
    }
    let _ = writeln!(out, "next: {}", next_steps(&s, verdict, true));
    out
}

/// A passed result's optional improvement: `advice:` and the check's own `example:`.
fn summary_advice(out: &mut String, f: &Finding) {
    if let Some(advice) = &f.advice {
        let _ = writeln!(out, "  advice: {}", one_line(advice));
        if let Some(example) = &f.example_fix {
            let _ = writeln!(out, "  example: {}", one_line(example));
        }
    }
}

/// `to B: HDR-007 +15 required · HDR-003 +10`, then the impact of each step toward the next grade (every step with
/// `all`), so the cost of a higher grade is visible without a long list on low-grade sites.
fn summary_upgrades(out: &mut String, upgrades: &[Upgrade], all: bool) {
    let mut explained: Vec<&str> = Vec::new();
    let same_path = upgrades.len() == 2 && upgrades[0].steps == upgrades[1].steps;
    for (n, u) in upgrades.iter().enumerate() {
        if same_path && n == 0 {
            continue;
        }
        let steps: Vec<String> = u
            .steps
            .iter()
            .map(|s| {
                let req = if s.required { " required" } else { "" };
                format!("{} +{}{req}", one_line(&s.rule_id), s.points)
            })
            .collect();
        let to = if same_path {
            format!("{} and {}", upgrades[0].to.label(), u.to.label())
        } else {
            u.to.label().to_string()
        };
        let _ = writeln!(
            out,
            "to {to}: {} → {} {}",
            steps.join(" · "),
            u.result.label(),
            u.result_score
        );
    }
    let shown = if all { upgrades.len() } else { 1 };
    for s in upgrades.iter().take(shown).flat_map(|u| &u.steps) {
        if let Some(impact) = &s.impact {
            if !explained.contains(&s.rule_id.as_str()) {
                explained.push(&s.rule_id);
                let _ = writeln!(
                    out,
                    "  impact ({}): {}",
                    one_line(&s.rule_id),
                    one_line(impact)
                );
            }
        }
    }
    let hidden = upgrades
        .iter()
        .flat_map(|u| &u.steps)
        .filter(|s| s.impact.is_some() && !explained.contains(&s.rule_id.as_str()))
        .map(|s| s.rule_id.as_str())
        .fold(Vec::new(), |mut v, id| {
            if !v.contains(&id) {
                v.push(id);
            }
            v
        });
    if !hidden.is_empty() {
        let _ = writeln!(out, "  impact of {}: --all", one_line(&hidden.join(", ")));
    }
}

fn md_upgrades(out: &mut String, upgrades: &[Upgrade]) {
    if upgrades.is_empty() {
        return;
    }
    out.push_str("\n## How to raise the grade\n\nThe grade weighs every check by severity; a grade reached here does not mean every check passes (the verdict lists what is still open).\n\n| Target | Check | Points | Required | Impact of passing it |\n|---|---|---|---|---|\n");
    // Same steps toward the next grade and toward A+ (one fix jumps both): one row set, as in the summary.
    let same_path = upgrades.len() == 2 && upgrades[0].steps == upgrades[1].steps;
    for (n, u) in upgrades.iter().enumerate() {
        if same_path && n == 0 {
            continue;
        }
        let to = if same_path {
            format!("{} and {}", upgrades[0].to.label(), u.to.label())
        } else {
            u.to.label().to_string()
        };
        let target = format!("{to} (→ {} {})", u.result.label(), u.result_score);
        for s in &u.steps {
            let _ = writeln!(
                out,
                "| {} | {} | +{} | {} | {} |",
                target,
                md_cell(&s.rule_id),
                s.points,
                if s.required { "yes" } else { "no" },
                s.impact.as_deref().map_or_else(|| "—".to_string(), md_cell)
            );
        }
    }
}

/// A top grade (A / A+) while checks are still open: say so, so the grade is not read as "everything passed".
fn open_note(g: &Grading, s: &Summary, verdict: Verdict) -> Option<String> {
    let open = s.fail + s.unknown + s.needs_review + s.insufficient_evidence;
    (matches!(g.grade, Grade::A | Grade::APlus) && verdict != Verdict::Pass && open > 0).then(|| {
        format!(
            "grade {} with {open} check{} still open; the grade weighs checks, the verdict lists what is open",
            g.grade.label(),
            if open == 1 { "" } else { "s" }
        )
    })
}
fn next_steps(s: &Summary, verdict: Verdict, pointer: bool) -> String {
    let advice = if s.advice > 0 {
        format!(" · advice {} (optional)", s.advice)
    } else {
        String::new()
    };
    if verdict == Verdict::Pass {
        return format!("nothing to fix{advice}");
    }
    let mut parts = Vec::new();
    if s.fail > 0 {
        parts.push(format!("fix {}", s.fail));
    }
    if s.unknown > 0 {
        parts.push(format!("re-run or check manually {}", s.unknown));
    }
    let decide = s.needs_review + s.insufficient_evidence;
    if decide > 0 {
        parts.push(format!("decide {decide}"));
    }
    let steps = format!("{}{advice}", parts.join(", "));
    if pointer {
        format!("{steps} · evidence: --format markdown")
    } else {
        steps
    }
}

/// The `--format json` document. Its JSON Schema (`schemas/report.schema.json`) is generated from this type.
#[derive(Serialize, JsonSchema)]
#[schemars(rename = "OpenComplyReport")]
pub(crate) struct JsonReport<'a> {
    schema_version: u32,
    scanner_version: &'a str,
    module: Module,
    target: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    rule_packs: &'a [RulePackRef],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    platforms: &'a [DetectedPlatform],
    verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    grade: Option<&'a Grading>,
    summary: Summary,
    findings: &'a [&'a Finding],
}

fn render_json(report: &Report, shown: &[&Finding], compact: bool) -> String {
    let trimmed: Vec<Finding>;
    let compacted: Vec<&Finding>;
    let shown = if compact {
        trimmed = shown
            .iter()
            .map(|f| {
                let mut f = (*f).clone();
                f.remediation = None;
                if !f.status.is_actionable() && f.advice.is_none() {
                    f.evidence.clear();
                }
                f
            })
            .collect();
        compacted = trimmed.iter().collect();
        &compacted[..]
    } else {
        shown
    };
    let doc = JsonReport {
        schema_version: report.schema_version,
        scanner_version: &report.scanner_version,
        module: report.module,
        target: &report.target,
        rule_packs: &report.rule_packs,
        platforms: &report.platforms,
        verdict: report.verdict(),
        grade: report.grade.as_ref(),
        summary: report.summary(),
        findings: shown,
    };
    serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// Without `all`, a passed finding is shown only for its advice, which has its own section.
fn render_markdown(report: &Report, shown: &[&Finding], all: bool) -> String {
    let mut out = String::with_capacity(512 + shown.len() * 400);
    md_overview(&mut out, report);
    if let Some(g) = &report.grade {
        md_upgrades(&mut out, &g.upgrades);
    }
    let pick = |pred: fn(Status) -> bool| -> Vec<&Finding> {
        shown.iter().copied().filter(|f| pred(f.status)).collect()
    };
    md_fails(&mut out, report, &pick(|s| s == Status::Fail));
    md_together(&mut out, shown);
    md_review(
        &mut out,
        report,
        &pick(|s| {
            matches!(
                s,
                Status::Unknown | Status::NeedsReview | Status::InsufficientEvidence
            )
        }),
    );
    let passed = pick(|s| matches!(s, Status::Pass | Status::NotApplicable));
    md_advice(
        &mut out,
        &passed
            .iter()
            .copied()
            .filter(|f| f.advice.is_some())
            .collect::<Vec<_>>(),
    );
    md_passed(
        &mut out,
        &passed
            .into_iter()
            .filter(|f| all || f.advice.is_none())
            .collect::<Vec<_>>(),
    );
    out
}

fn md_together(out: &mut String, shown: &[&Finding]) {
    let groups = fix_together(shown);
    if groups.is_empty() {
        return;
    }
    out.push_str(
        "\n## Fix together\n\nThese are set in the same place, so one change covers them.\n\n",
    );
    for (group, ids) in groups {
        let _ = writeln!(
            out,
            "- **{}:** {}",
            md_text(group),
            md_text(&ids.join(" · "))
        );
    }
}

fn md_advice(out: &mut String, advised: &[&Finding]) {
    if advised.is_empty() {
        return;
    }
    out.push_str("\n## Advice (optional — already passed)\n\n| Rule | Check | Advice | Example |\n|---|---|---|---|\n");
    for f in advised {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            md_cell(&f.rule_id),
            md_cell(&f.title),
            md_cell(f.advice.as_deref().unwrap_or("")),
            f.example_fix.as_deref().map(md_code).unwrap_or_default()
        );
    }
}

fn md_overview(out: &mut String, report: &Report) {
    let s = report.summary();
    let verdict = report.verdict();
    let _ = writeln!(out, "# OpenComply report — {}\n", report.module.name());
    out.push_str("| | |\n|---|---|\n");
    let _ = writeln!(out, "| Target | {} |", md_code(&report.target));
    let _ = writeln!(
        out,
        "| Verdict | **{}** — {} |",
        verdict.label().to_uppercase(),
        md_cell(&next_steps(&s, verdict, false))
    );
    if let Some(g) = &report.grade {
        let score = g.score.map_or_else(String::new, |s| format!(" ({s}/100)"));
        let capped = if g.capped_by.is_empty() {
            String::new()
        } else {
            format!(" — capped: {}", md_cell(&g.capped_by.join("; ")))
        };
        let open = open_note(g, &s, verdict).map_or_else(String::new, |n| format!(" — {n}"));
        let _ = writeln!(
            out,
            "| Grade | **{}**{score}{capped}{open} |",
            g.grade.label()
        );
    }
    let advice = if s.advice > 0 {
        format!(" · {} with advice", s.advice)
    } else {
        String::new()
    };
    let _ = writeln!(
        out,
        "| Results | {} passed · {} failed · {} unknown · {} needs review · {} no evidence · {} not applicable{advice} |",
        s.pass, s.fail, s.unknown, s.needs_review, s.insufficient_evidence, s.not_applicable
    );
    let _ = writeln!(
        out,
        "| Scanner | {} · report schema {} |",
        md_cell(&report.scanner_version),
        report.schema_version
    );
    if !report.rule_packs.is_empty() {
        let packs: Vec<String> = report
            .rule_packs
            .iter()
            .map(|p| {
                let trust = p.signed_by.as_deref().map_or_else(
                    || "unsigned".to_string(),
                    |k| format!("signed by {}", md_cell(k)),
                );
                let sha = p
                    .sha256
                    .as_deref()
                    .map(|s| format!(", sha256 `{}…`", &s[..s.len().min(12)]))
                    .unwrap_or_default();
                format!("{} {} ({trust}{sha})", md_cell(&p.id), md_cell(&p.version))
            })
            .collect();
        let _ = writeln!(out, "| Rule packs | {} |", packs.join(" · "));
    }
    if !report.platforms.is_empty() {
        let list: Vec<String> = report
            .platforms
            .iter()
            .map(|p| {
                format!(
                    "{} ({}, from {})",
                    md_cell(p.name),
                    p.layer.label(),
                    md_code(&p.evidence.detail)
                )
            })
            .collect();
        let _ = writeln!(
            out,
            "| Platform | {} — detected from response headers, used only for fix guidance |",
            list.join(" · ")
        );
    }
}

/// One cell per finding: `**platform, preferred:** how — ⚠ note`, places separated by ` · ` (how texts may end in `;`).
fn platform_cell(f: &Finding) -> String {
    let several = f.platform_fixes.len() > 1;
    f.platform_fixes
        .iter()
        .map(|pf| {
            let tag = if pf.preferred && several {
                ", preferred"
            } else {
                ""
            };
            let mut s = format!("**{}{tag}:** {}", md_cell(&pf.platform), md_cell(&pf.how));
            if let Some(n) = &pf.note {
                let _ = write!(s, " — ⚠ {}", md_cell(n));
            }
            s
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn md_fails(out: &mut String, report: &Report, fails: &[&Finding]) {
    if !fails.is_empty() {
        out.push_str("\n## Needs action\n\n| Rule | Version | Severity | Effort | Finding | Why | Evidence | Fix | Example | Where to fix |\n|---|---|---|---|---|---|---|---|---|---|\n");
        for f in fails {
            let after = open_dependencies(report, f);
            let after = if after.is_empty() {
                String::new()
            } else {
                format!("**After {}.** ", md_cell(&after.join(", ")))
            };
            let advice = f
                .advice
                .as_deref()
                .map(|a| format!(" Advice: {}", md_cell(a)))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {after}{}{advice} | {} | {} |",
                md_cell(&f.rule_id),
                md_cell(&f.rule_version),
                f.severity.label(),
                f.effort.map_or("—", |e| e.label()),
                md_cell(&f.title),
                md_cell(&why(f).unwrap_or_default()),
                evidence_cell(f),
                md_cell(
                    f.remediation
                        .as_deref()
                        .or(f.fix_hint.as_deref())
                        .unwrap_or("")
                ),
                f.example_fix.as_deref().map(md_code).unwrap_or_default(),
                platform_cell(f)
            );
        }
    }
}

fn md_review(out: &mut String, report: &Report, decide: &[&Finding]) {
    if !decide.is_empty() {
        out.push_str("\n## Needs your review\n");
        for f in decide {
            let _ = writeln!(
                out,
                "\n### {} · {}\n\n- **Status:** {} · severity {} · rule version {}",
                md_text(&f.rule_id),
                md_text(&f.title),
                f.status.label(),
                f.severity.label(),
                md_text(&f.rule_version)
            );
            if let Some(e) = f.effort {
                let _ = writeln!(out, "- **Effort:** {}", e.label());
            }
            let after = open_dependencies(report, f);
            if !after.is_empty() {
                let _ = writeln!(out, "- **After:** {}", md_text(&after.join(", ")));
            }
            if let Some(why) = why(f) {
                let _ = writeln!(out, "- **Why:** {}", md_text(&why));
            }
            for e in &f.evidence {
                let _ = writeln!(
                    out,
                    "- **Evidence ({}):** {} — {}",
                    evidence_class(e.class),
                    md_text(&e.source),
                    md_code(&e.detail)
                );
            }
            if let Some(q) = f.review_question.as_ref().or(f.fix_hint.as_ref()) {
                let _ = writeln!(out, "- **Decide:** {}", md_text(q));
            }
            if let Some(e) = &f.example_fix {
                let _ = writeln!(out, "- **Example:** {}", md_code(e));
            }
            let several = f.platform_fixes.len() > 1;
            for pf in &f.platform_fixes {
                let tag = if pf.preferred && several {
                    ", preferred"
                } else {
                    ""
                };
                let _ = writeln!(
                    out,
                    "- **How ({}{tag}):** {}",
                    md_text(&pf.platform),
                    md_text(&pf.how)
                );
                if let Some(n) = &pf.note {
                    let _ = writeln!(out, "  - ⚠ {}", md_text(n));
                }
            }
            if let Some(r) = &f.remediation {
                let _ = writeln!(out, "- **Guidance:** {}", md_text(r));
            }
            if let Some(a) = &f.advice {
                let _ = writeln!(out, "- **Advice:** {}", md_text(a));
            }
        }
    }
}

fn md_passed(out: &mut String, passed: &[&Finding]) {
    if !passed.is_empty() {
        out.push_str("\n## Passed and not applicable\n\n| Status | Rule | Version | Check | Evidence |\n|---|---|---|---|---|\n");
        for f in passed {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                f.status.label(),
                md_cell(&f.rule_id),
                md_cell(&f.rule_version),
                md_cell(&f.title),
                evidence_cell(f)
            );
        }
    }
}

/// Characters that change how text is shown without being seen: bidi overrides / isolates (reorder text), zero-width
/// and joiner characters, line / paragraph separators, BOM, soft hyphen, interlinear annotation and tag characters.
fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x61C | 0x180E | 0x200B..=0x200F | 0x2028 | 0x2029 | 0x202A..=0x202E
        | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0xE0000..=0xE007F)
}

/// One line of plain text: control characters (C0, DEL, C1) become spaces, invisible ones become a visible
/// `<U+XXXX>` so the evidence still shows they were there. Other characters (homoglyphs included) are kept as sent.
pub fn plain_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.push(' ');
        } else if is_invisible(c) {
            let _ = write!(out, "<U+{:04X}>", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn strip_controls(r: &mut Report) {
    fn clean(s: &mut String) {
        if s.chars().any(|c| c.is_control() || is_invisible(c)) {
            *s = plain_text(s);
        }
    }
    fn clean_opt(s: &mut Option<String>) {
        if let Some(v) = s {
            clean(v);
        }
    }
    clean(&mut r.target);
    for f in &mut r.findings {
        clean(&mut f.rule_id);
        clean(&mut f.rule_version);
        clean(&mut f.title);
        clean_opt(&mut f.reason);
        clean_opt(&mut f.fix_hint);
        clean_opt(&mut f.example_fix);
        clean_opt(&mut f.review_question);
        clean_opt(&mut f.remediation);
        clean_opt(&mut f.advice);
        clean_opt(&mut f.group);
        for d in &mut f.depends_on {
            clean(d);
        }
        for e in &mut f.evidence {
            clean(&mut e.source);
            clean(&mut e.detail);
        }
        for p in &mut f.platform_fixes {
            clean(&mut p.platform);
            clean(&mut p.how);
            clean_opt(&mut p.note);
        }
    }
    for p in &mut r.platforms {
        clean(&mut p.evidence.source);
        clean(&mut p.evidence.detail);
    }
    for p in &mut r.rule_packs {
        clean(&mut p.id);
        clean(&mut p.version);
        clean_opt(&mut p.signed_by);
    }
    if let Some(g) = &mut r.grade {
        g.capped_by.iter_mut().for_each(clean);
        for s in g.upgrades.iter_mut().flat_map(|u| &mut u.steps) {
            clean(&mut s.rule_id);
            clean_opt(&mut s.impact);
        }
    }
}

fn why(f: &Finding) -> Option<String> {
    f.reason
        .clone()
        .or_else(|| f.evidence.first().map(|e| e.detail.clone()))
        .filter(|s| !s.trim().is_empty())
}

fn evidence_class(c: crate::finding::EvidenceClass) -> &'static str {
    match c {
        crate::finding::EvidenceClass::Verified => "verified",
        crate::finding::EvidenceClass::Inferred => "inferred",
        crate::finding::EvidenceClass::ManualReview => "manual review",
    }
}

fn evidence_cell(f: &Finding) -> String {
    f.evidence
        .iter()
        .map(|e| format!("{} {}", md_cell(&e.source), md_code(&e.detail)))
        .collect::<Vec<_>>()
        .join("; ")
}

fn one_line(s: &str) -> String {
    plain_text(s)
}

fn short(s: &str) -> String {
    truncate(&one_line(s), MAX_HINT_CHARS)
}

/// A word a GFM renderer would turn into a link by itself: `scheme://host…`, `www.host…` or `name@host`.
fn autolinks(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    let alnum_at = |s: &str, i: usize| s[i..].chars().next().is_some_and(char::is_alphanumeric);
    let url = lower
        .match_indices("://")
        .any(|(i, _)| alnum_at(&lower, i + 3));
    let www = lower.match_indices("www.").any(|(i, _)| {
        lower[..i]
            .chars()
            .last()
            .is_none_or(|c| !c.is_alphanumeric())
            && alnum_at(&lower, i + 4)
    });
    let email = lower.match_indices('@').any(|(i, _)| {
        lower[..i].chars().last().is_some_and(char::is_alphanumeric) && alnum_at(&lower, i + 1)
    });
    url || www || email
}

/// Plain Markdown text, so text from a site can never become a link, a remote image or HTML (T11): HTML is escaped,
/// `\` `[` `]` are backslash-escaped, words a renderer would autolink are shown as code, and in a table cell `|` is
/// escaped so it cannot add a cell.
fn md_inline(s: &str, cell: bool) -> String {
    one_line(s)
        .split(' ')
        .map(|w| {
            if autolinks(w) {
                return md_code(w);
            }
            let w = w
                .replace('\\', "\\\\")
                .replace('[', "\\[")
                .replace(']', "\\]")
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            if cell {
                w.replace('|', "\\|")
            } else {
                w
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn md_text(s: &str) -> String {
    md_inline(s, false)
}

fn md_cell(s: &str) -> String {
    md_inline(s, true)
}

fn md_code(s: &str) -> String {
    format!("`{}`", one_line(s).replace('`', "'").replace('|', "\\|"))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Effort, Evidence, EvidenceClass, Severity};
    use crate::report::{ExitCode, FailOn};

    fn finding(id: &str, status: Status, severity: Severity) -> Finding {
        Finding {
            rule_id: id.into(),
            rule_version: "1.0.0".into(),
            title: format!("{id} title"),
            status,
            severity,
            evidence: vec![Evidence {
                class: EvidenceClass::Verified,
                source: "GET https://example.com".into(),
                detail: format!("{id} evidence"),
                truncated: false,
            }],
            reason: None,
            fix_hint: Some(format!("{id} fix")),
            example_fix: None,
            platform_fixes: vec![],
            review_question: None,
            remediation: None,
            advice: None,
            effort: None,
            depends_on: vec![],
            group: None,
        }
    }

    fn report(items: &[(Status, Severity)]) -> Report {
        let findings = items
            .iter()
            .enumerate()
            .map(|(i, (st, sv))| finding(&format!("HDR-{i:03}"), *st, *sv))
            .collect();
        Report::new(Module::Headers, "https://example.com", findings)
    }

    fn json_evidence(r: &Report) -> (String, bool) {
        let v: serde_json::Value = serde_json::from_str(&render(r, Format::Json, true)).unwrap();
        let e = &v["findings"][0]["evidence"][0];
        (
            e["detail"].as_str().unwrap().to_string(),
            e["truncated"] == true,
        )
    }

    fn with_detail(detail: String) -> Report {
        let mut f = finding("HDR-002", Status::Fail, Severity::High);
        f.evidence[0].detail = detail;
        Report::new(Module::Headers, "https://example.com", vec![f])
    }

    // D-2 boundaries: a value that fits is printed whole and not flagged; one character over is cut and flagged.
    #[test]
    fn evidence_limits_hold_at_each_boundary() {
        for (n, max) in [
            (299, 300),
            (300, 300),
            (301, 300),
            (4095, 4096),
            (4096, 4096),
            (4097, 4096),
        ] {
            let cut = clip_at(&"a".repeat(n), max);
            if n <= max {
                assert_eq!(cut, None, "{n}");
            } else {
                assert_eq!(cut.unwrap().chars().count(), max + 1, "{n}");
            }
        }
        for n in [4095, 4096, 4097] {
            let (d, truncated) = json_evidence(&with_detail("a".repeat(n)));
            assert_eq!(truncated, n > 4096, "{n}");
            assert_eq!(
                d.chars().count(),
                n.min(4096) + usize::from(n > 4096),
                "{n}"
            );
        }
        let md = render(&with_detail("a".repeat(301)), Format::Markdown, true);
        assert!(md.contains(&format!("{}…", "a".repeat(300))) && !md.contains(&"a".repeat(301)));
    }

    // JSON and Markdown differ only in length: the start of the value is the same in both.
    #[test]
    fn json_and_markdown_share_the_same_start() {
        let value: String = (b'a'..=b'z').cycle().take(5000).map(char::from).collect();
        let r = with_detail(value.clone());
        let (d, _) = json_evidence(&r);
        assert!(value.starts_with(d.trim_end_matches('…')));
        assert!(render(&r, Format::Markdown, true).contains(&value[..300]));
    }

    // Redaction runs on the whole value before any cut: a secret at the end, or across either cut point, never
    // leaves any part of itself in any format.
    #[test]
    fn secret_never_survives_a_cut() {
        let secret = concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyzAB");
        for at in [10, 280, 290, 299, 4080, 4090, 4095, 4999] {
            // Separated as in a header value (space, `=`, `;`); glued to letters it is not a token boundary.
            let mut v = "a".repeat(at);
            v.push(' ');
            v.push_str(secret);
            v.push_str(&"b".repeat(20));
            let r = with_detail(v);
            for format in [Format::Summary, Format::Json, Format::Markdown] {
                let out = render(&r, format, true);
                assert!(!out.contains("ghp_0123"), "{at} {format:?}");
                assert!(!out.contains("vwxyzAB"), "{at} {format:?}");
            }
        }
    }

    // A cut never splits our own labels, so a reader cannot mistake half a label for site text.
    #[test]
    fn cut_keeps_labels_whole() {
        let s = format!("{}[REDACTED api key] tail", "a".repeat(295));
        assert_eq!(clip_at(&s, 300).unwrap(), format!("{}…", "a".repeat(295)));
        let s = format!("{}<U+202E> tail", "a".repeat(296));
        assert_eq!(clip_at(&s, 300).unwrap(), format!("{}…", "a".repeat(296)));
        let s = format!("{}[x] {}", "a".repeat(10), "b".repeat(400));
        assert_eq!(clip_at(&s, 300).unwrap().chars().count(), 301);
    }

    // Invisible / bidi characters after the Markdown cut still show as markers in JSON and never reach any output raw.
    #[test]
    fn invisible_text_after_the_cut_stays_visible_or_gone() {
        let r = with_detail(format!("{}\u{202e}evil\u{200b}", "a".repeat(350)));
        for format in [Format::Summary, Format::Json, Format::Markdown] {
            let out = render(&r, format, true);
            assert!(
                !out.contains('\u{202e}') && !out.contains('\u{200b}'),
                "{format:?}"
            );
        }
        assert!(json_evidence(&r).0.contains("<U+202E>evil<U+200B>"));
    }

    // Markdown metacharacters in long evidence cannot break the table or the evidence line.
    #[test]
    fn markdown_metacharacters_in_long_evidence_stay_inert() {
        let r = with_detail(format!("{}| `x` [y](z) <b>*q*</b>", "a".repeat(250)));
        let md = render(&r, Format::Markdown, true);
        let outside: String = md.split('`').step_by(2).collect();
        assert!(!outside.contains("<b>"), "{md}");
        assert!(!outside.replace("\\](z)", "").contains("](z)"), "{md}");
        let row = md.lines().find(|l| l.starts_with("| HDR-002")).unwrap();
        let header = md.lines().find(|l| l.starts_with("| Rule")).unwrap();
        let cells = |l: &str| l.replace("\\|", "").matches('|').count();
        assert_eq!(cells(row), cells(header), "{md}");
    }

    // One fix that reaches both the next grade and A+ is shown once in Markdown, as in the summary.
    #[test]
    fn markdown_merges_identical_upgrade_paths() {
        let step = crate::grade::UpgradeStep {
            rule_id: "HDR-002".into(),
            points: 27,
            required: true,
            impact: None,
        };
        let up = |to| Upgrade {
            to,
            steps: vec![step.clone()],
            result: Grade::APlus,
            result_score: 95,
        };
        let mut out = String::new();
        md_upgrades(&mut out, &[up(Grade::C), up(Grade::APlus)]);
        assert_eq!(out.matches("| HDR-002 |").count(), 1, "{out}");
        assert!(out.contains("| C and A+ (→ A+ 95) |"), "{out}");
        assert!(out.contains("does not mean every check passes"), "{out}");
    }

    // D-1 = keep the policy: a low FAIL can still reach A+, and every format then says checks are still open.
    #[test]
    fn top_grade_with_open_checks_says_so() {
        let g = Grading {
            grade: Grade::APlus,
            score: Some(95),
            capped_by: vec![],
            upgrades: vec![],
        };
        let s = Summary {
            fail: 1,
            ..Summary::default()
        };
        let note = open_note(&g, &s, Verdict::Fail).unwrap();
        assert!(note.contains("1 check still open"), "{note}");
        assert_eq!(open_note(&g, &Summary::default(), Verdict::Pass), None);
        let low = Grading {
            grade: Grade::C,
            ..g
        };
        assert_eq!(open_note(&low, &s, Verdict::Fail), None);
    }

    // T11: link / image syntax from a site (evidence, or a reason that quotes it) never forms a live Markdown link or
    // remote image: outside code spans every `[` is escaped.
    #[test]
    fn markdown_keeps_site_links_inert() {
        let payload = r"PHP/8.1 ![t](https://evil.example/p.png) [x](https://evil.example/x) \[z](https://evil.example/z) `y`";
        for with_reason in [false, true] {
            let mut f = finding("HDR-010", Status::Fail, Severity::Low);
            f.evidence[0].detail = format!("x-powered-by: {payload}");
            if with_reason {
                f.reason = Some(format!("value {payload}"));
            }
            let r = Report::new(Module::Headers, "https://example.com", vec![f]);
            let md = render(&r, Format::Markdown, true);
            let mut outside = String::new();
            for (i, part) in md.split('`').enumerate() {
                if i % 2 == 0 {
                    outside.push_str(part);
                }
            }
            assert!(md.contains("evil.example"), "{md}");
            let unescaped = outside
                .char_indices()
                .filter(|&(i, c)| {
                    c == '['
                        && outside[..i]
                            .chars()
                            .rev()
                            .take_while(|&b| b == '\\')
                            .count()
                            % 2
                            == 0
                })
                .count();
            assert_eq!(unescaped, 0, "{md}");
        }
    }

    #[test]
    fn verdict_and_exit_code() {
        use Severity::Low;
        assert_eq!(report(&[(Status::Pass, Low)]).verdict(), Verdict::Pass);
        let review = report(&[(Status::NeedsReview, Low)]);
        assert_eq!(review.verdict(), Verdict::Review);
        assert_eq!(review.exit_code(FailOn::Fail), ExitCode::Ok);
        assert_eq!(review.exit_code(FailOn::Review), ExitCode::Findings);
        assert_eq!(
            report(&[(Status::InsufficientEvidence, Low)]).exit_code(FailOn::Review),
            ExitCode::Findings
        );
        assert_eq!(
            report(&[(Status::Pass, Low)]).exit_code(FailOn::Review),
            ExitCode::Ok
        );
        assert_eq!(
            report(&[(Status::Unknown, Low)]).exit_code(FailOn::Fail),
            ExitCode::Incomplete
        );
        assert_eq!(
            report(&[(Status::Unknown, Low), (Status::Fail, Low)]).exit_code(FailOn::Fail),
            ExitCode::Findings
        );
    }

    #[test]
    fn summary_orders_by_status_then_severity_and_explains() {
        let r = report(&[
            (Status::NeedsReview, Severity::Info),
            (Status::Fail, Severity::Low),
            (Status::Pass, Severity::High),
            (Status::Fail, Severity::High),
        ]);
        let out = render(&r, Format::Summary, false);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("headers https://example.com verdict=fail pass=1 fail=2"));
        assert!(lines[1].starts_with("FAIL HDR-003 high"));
        assert_eq!(lines[2], "  why: HDR-003 evidence");
        assert_eq!(lines[3], "  fix: HDR-003 fix");
        assert!(lines[4].starts_with("FAIL HDR-001 low"));
        assert!(lines[7].starts_with("REVIEW HDR-000 info"));
        assert_eq!(lines[9], "  decide: HDR-000 fix");
        assert_eq!(
            *lines.last().unwrap(),
            "next: fix 2, decide 1 · evidence: --format markdown"
        );
        assert!(!out.contains("HDR-002"));
    }

    #[test]
    fn review_question_preferred_over_fix_hint() {
        let mut r = report(&[(Status::NeedsReview, Severity::Info)]);
        r.findings[0].review_question = Some("is this acceptable?".into());
        r.findings[0].reason = Some("set by hosting platform".into());
        let out = render(&r, Format::Summary, false);
        assert!(out.contains("  why: set by hosting platform\n"));
        assert!(out.contains("  decide: is this acceptable?\n"));
        let md = render(&r, Format::Markdown, false);
        assert!(md.contains("## Needs your review"));
        assert!(md.contains("- **Decide:** is this acceptable?"));
        assert!(md.contains("rule version 1.0.0"));
    }

    #[test]
    fn all_pass_says_nothing_to_fix() {
        let r = report(&[(Status::Pass, Severity::High)]);
        assert_eq!(
            render(&r, Format::Summary, false),
            "headers https://example.com verdict=pass pass=1 fail=0 unknown=0 review=0 no_evidence=0 n/a=0\nnext: nothing to fix\n"
        );
    }

    #[test]
    fn hints_are_capped() {
        let mut r = report(&[(Status::Fail, Severity::Low)]);
        r.findings[0].fix_hint = Some("x".repeat(500));
        let out = render(&r, Format::Summary, false);
        let fix = out.lines().find(|l| l.starts_with("  fix: ")).unwrap();
        assert_eq!(
            fix.trim_start_matches("  fix: ").chars().count(),
            MAX_HINT_CHARS
        );
    }

    #[test]
    fn finding_text_cannot_inject() {
        let mut r = report(&[(Status::Fail, Severity::Low)]);
        r.findings[0].title = "evil\nFAIL HDR-999 fake\x1b[31m".into();
        r.findings[0].remediation = Some("a | b <script>".into());
        r.findings[0].evidence[0].detail = "x`y".into();
        let out = render(&r, Format::Summary, false);
        assert!(!out.contains('\x1b'));
        assert!(!out.lines().any(|l| l.starts_with("FAIL HDR-999")));
        let md = render(&r, Format::Markdown, false);
        assert!(md.contains("a \\| b &lt;script&gt;"));
        assert!(md.contains("`x'y`"));
    }

    /// Regression (found by property tests): JSON encoders leave DEL and C1 controls raw; C1 CSI drives terminals.
    #[test]
    fn no_control_characters_in_any_format() {
        let mut r = report(&[(Status::Fail, Severity::Low)]);
        r.findings[0].evidence[0].detail = "a\u{7f}b\u{9b}31mc\u{1b}[2J".into();
        r.findings[0].reason = Some("x\u{85}y".into());
        for format in [Format::Summary, Format::Json, Format::Markdown] {
            let out = render(&r, format, true);
            assert!(
                out.chars().all(|c| c == '\n' || !c.is_control()),
                "{format:?}: {out:?}"
            );
        }
    }

    #[test]
    fn json_is_summary_first_compact_and_omits_empty() {
        let r = report(&[(Status::Pass, Severity::Low), (Status::Fail, Severity::Low)]);
        let out = render(&r, Format::Json, false);
        assert!(!out.contains('\n'));
        assert!(!out.contains("rule_pack"));
        assert!(out.find("\"summary\"").unwrap() < out.find("\"findings\"").unwrap());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["verdict"], "fail");
        assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn markdown_has_version_severity_and_evidence() {
        let r = report(&[(Status::Fail, Severity::High)]);
        let md = render(&r, Format::Markdown, false);
        assert!(
            md.contains("| Rule | Version | Severity | Effort | Finding | Why | Evidence | Fix | Example | Where to fix |")
        );
        assert!(md.contains("| HDR-000 | 1.0.0 | high | — |"));
        // The source URL is shown as code so a Markdown viewer cannot turn it into a link (T11).
        assert!(md.contains("GET `https://example.com` `HDR-000 evidence`"));
    }

    #[test]
    fn platform_guidance_in_all_formats() {
        use crate::finding::PlatformFix;
        use crate::platform::detect_platforms;
        let headers = vec![
            ("Server".to_string(), "cloudflare".to_string()),
            ("x-powered-by".to_string(), "Next.js".to_string()),
        ];
        let mut r = report(&[(Status::Fail, Severity::Low)])
            .with_platforms(detect_platforms(&headers, "GET https://example.com"));
        r.findings[0].platform_fixes = vec![PlatformFix {
            platform: "cloudflare".into(),
            how: "Rules > Transform Rules > Modify Response Header".into(),
            note: Some("cannot generate per-request nonces".into()),
            preferred: false,
        }];
        let out = render(&r, Format::Summary, false);
        assert!(out
            .lines()
            .next()
            .unwrap()
            .ends_with(" platform=cloudflare+nextjs"));
        assert!(
            out.contains("  how (cloudflare): Rules > Transform Rules > Modify Response Header\n")
        );
        assert!(out.contains("  note (cloudflare): cannot generate per-request nonces\n"));
        let md = render(&r, Format::Markdown, false);
        assert!(md.contains(
            "| Platform | Cloudflare (CDN / WAF, from `Server: cloudflare`) · Next.js (framework / CMS"
        ));
        assert!(md.contains(
            "**cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header — ⚠ cannot"
        ));
        let v: serde_json::Value = serde_json::from_str(&render(&r, Format::Json, false)).unwrap();
        assert_eq!(v["platforms"][0]["id"], "cloudflare");
        assert_eq!(
            v["findings"][0]["platform_fixes"][0]["platform"],
            "cloudflare"
        );
    }

    fn planned(
        id: &str,
        severity: Severity,
        effort: Effort,
        deps: &[&str],
        group: Option<&str>,
    ) -> Finding {
        Finding {
            effort: Some(effort),
            depends_on: deps.iter().map(|d| (*d).to_string()).collect(),
            group: group.map(str::to_string),
            ..finding(id, Status::Fail, severity)
        }
    }

    /// A dependency that is still open moves its dependant down and adds `after:`; quick fixes go first among equals;
    /// rules fixed in the same place are listed once on a `together` line.
    #[test]
    fn summary_orders_by_dependency_and_effort_and_groups() {
        let findings = vec![
            planned(
                "HDR-001",
                Severity::High,
                Effort::Moderate,
                &["HDR-007"],
                Some("response-headers"),
            ),
            planned(
                "HDR-003",
                Severity::Medium,
                Effort::Quick,
                &[],
                Some("response-headers"),
            ),
            planned("HDR-004", Severity::Low, Effort::Moderate, &[], None),
            planned(
                "HDR-005",
                Severity::Low,
                Effort::Quick,
                &[],
                Some("response-headers"),
            ),
            planned("HDR-007", Severity::High, Effort::Moderate, &[], None),
        ];
        let r = Report::new(Module::Headers, "https://example.com", findings.clone());
        let out = render(&r, Format::Summary, false);
        let status: Vec<&str> = out.lines().filter(|l| l.starts_with("FAIL")).collect();
        assert_eq!(
            status,
            [
                "FAIL HDR-007 high HDR-007 title · moderate",
                "FAIL HDR-003 medium HDR-003 title · quick",
                "FAIL HDR-005 low HDR-005 title · quick",
                "FAIL HDR-004 low HDR-004 title · moderate",
                "FAIL HDR-001 high HDR-001 title · moderate",
            ]
        );
        assert!(out.contains("FAIL HDR-001 high HDR-001 title · moderate\n  after: HDR-007\n"));
        assert!(out.contains("together (response-headers): HDR-003 · HDR-005 · HDR-001\n"));
        let md = render(&r, Format::Markdown, false);
        assert!(md.contains("**After HDR-007.**"));
        assert!(md.contains("- **response-headers:** HDR-003 · HDR-005 · HDR-001"));

        let mut done = findings;
        if let Some(f) = done.iter_mut().find(|f| f.rule_id == "HDR-007") {
            f.status = Status::Pass;
        }
        let out = render(
            &Report::new(Module::Headers, "https://example.com", done),
            Format::Summary,
            false,
        );
        assert!(out.lines().nth(1).unwrap().starts_with("FAIL HDR-001 high"));
        assert!(!out.contains("after:"));
    }

    #[test]
    fn advice_is_shown_without_all_and_never_changes_the_verdict() {
        let mut r = report(&[
            (Status::Pass, Severity::High),
            (Status::Pass, Severity::Low),
        ]);
        r.findings[0].advice = Some("add includeSubDomains".into());
        r.findings[0].example_fix =
            Some("Strict-Transport-Security: max-age=1; includeSubDomains".into());
        assert_eq!(r.verdict(), Verdict::Pass);
        assert_eq!(r.summary().advice, 1);
        assert_eq!(
            render(&r, Format::Summary, false),
            "headers https://example.com verdict=pass pass=2 fail=0 unknown=0 review=0 no_evidence=0 n/a=0 advice=1\n\
             PASS HDR-000 high HDR-000 title\n  advice: add includeSubDomains\n  example: Strict-Transport-Security: max-age=1; includeSubDomains\n\
             next: nothing to fix · advice 1 (optional)\n"
        );
        let md = render(&r, Format::Markdown, false);
        assert!(md.contains("## Advice (optional — already passed)"));
        assert!(md.contains("| HDR-000 | HDR-000 title | add includeSubDomains |"));
        assert!(!md.contains("## Passed and not applicable"));
        assert!(md.contains("2 passed · 0 failed · 0 unknown · 0 needs review · 0 no evidence · 0 not applicable · 1 with advice"));
        assert!(render(&r, Format::Markdown, true).contains("## Passed and not applicable"));
        let v: serde_json::Value = serde_json::from_str(&render(&r, Format::Json, false)).unwrap();
        assert_eq!(v["summary"]["advice"], 1);
        assert_eq!(v["findings"][0]["advice"], "add includeSubDomains");
        assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn compact_json_drops_guidance_and_passed_evidence() {
        let mut r = report(&[
            (Status::Fail, Severity::High),
            (Status::Pass, Severity::Low),
        ]);
        r.findings[0].remediation = Some("long guidance".into());
        let opts = RenderOptions {
            all: true,
            compact: true,
        };
        let out = render_with(&r, Format::Json, opts);
        assert!(!out.contains("remediation"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["schema_version"], 1);
        let f = v["findings"].as_array().unwrap();
        assert_eq!(f[0]["evidence"][0]["detail"], "HDR-000 evidence");
        assert_eq!(f[1]["evidence"].as_array().unwrap().len(), 0);
        assert!(render(&r, Format::Json, true).contains("long guidance"));
    }

    #[test]
    fn missing_header_shows_copy_ready_example_untruncated() {
        let mut r = report(&[(Status::Fail, Severity::Low)]);
        let example = format!("Permissions-Policy: {}", "camera=(), ".repeat(15));
        r.findings[0].title = "Permissions-Policy missing".into();
        r.findings[0].reason = Some("response has no Permissions-Policy header".into());
        r.findings[0].example_fix = Some(example.clone());
        let out = render(&r, Format::Summary, false);
        assert!(out.contains("FAIL HDR-000 low Permissions-Policy missing\n"));
        assert!(out.contains("  why: response has no Permissions-Policy header\n"));
        assert!(out.contains(&format!("  example: {example}\n")));
        let md = render(&r, Format::Markdown, false);
        assert!(md.contains(&format!("`{example}`")));
    }
}
