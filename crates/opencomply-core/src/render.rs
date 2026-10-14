//! Output rendering for people and AI agents.
//! - Summary (default): verdict line, then per finding a status line plus short `why` / `fix` / `decide` lines, then a
//!   `next:` line. Fails first, then unknown, then review; within a status, highest severity first.
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

/// `all` includes passing / not-applicable findings; otherwise only actionable ones are rendered.
/// Secrets are always redacted, then every text field is stripped of control characters (C0, DEL and C1 —
/// JSON encoders leave DEL / C1 raw, and C1 `CSI` can drive terminals), whatever the format.
pub fn render(report: &Report, format: Format, all: bool) -> String {
    let mut redacted = redact_report(report);
    strip_controls(&mut redacted);
    let report = &redacted;
    let mut shown: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| all || f.status.is_actionable())
        .collect();
    shown.sort_by(|a, b| {
        a.status
            .priority()
            .cmp(&b.status.priority())
            .then(b.severity.cmp(&a.severity))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    match format {
        Format::Summary => render_summary(report, &shown, all),
        Format::Json => render_json(report, &shown),
        Format::Markdown => render_markdown(report, &shown),
    }
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
    if !report.platforms.is_empty() {
        let ids: Vec<&str> = report.platforms.iter().map(|p| p.id).collect();
        let _ = write!(out, " platform={}", ids.join("+"));
    }
    out.push('\n');
    if let Some(g) = &report.grade {
        if !g.capped_by.is_empty() {
            let _ = writeln!(out, "grade capped: {}", one_line(&g.capped_by.join("; ")));
        }
        summary_upgrades(&mut out, &g.upgrades, all);
    }
    for f in shown {
        let _ = writeln!(
            out,
            "{} {} {} {}",
            f.status.label(),
            one_line(&f.rule_id),
            f.severity.label(),
            one_line(&f.title)
        );
        if f.status == Status::Pass || f.status == Status::NotApplicable {
            continue;
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
    }
    let _ = writeln!(out, "next: {}", next_steps(&s, verdict, true));
    out
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
    out.push_str("\n## How to raise the grade\n\n| Target | Check | Points | Required | Impact of passing it |\n|---|---|---|---|---|\n");
    for u in upgrades {
        let target = format!(
            "{} (→ {} {})",
            u.to.label(),
            u.result.label(),
            u.result_score
        );
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

fn next_steps(s: &Summary, verdict: Verdict, pointer: bool) -> String {
    if verdict == Verdict::Pass {
        return "nothing to fix".to_string();
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
    let steps = parts.join(", ");
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

fn render_json(report: &Report, shown: &[&Finding]) -> String {
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

fn render_markdown(report: &Report, shown: &[&Finding]) -> String {
    let mut out = String::with_capacity(512 + shown.len() * 400);
    md_overview(&mut out, report);
    if let Some(g) = &report.grade {
        md_upgrades(&mut out, &g.upgrades);
    }
    let pick = |pred: fn(Status) -> bool| -> Vec<&Finding> {
        shown.iter().copied().filter(|f| pred(f.status)).collect()
    };
    md_fails(&mut out, &pick(|s| s == Status::Fail));
    md_review(
        &mut out,
        &pick(|s| {
            matches!(
                s,
                Status::Unknown | Status::NeedsReview | Status::InsufficientEvidence
            )
        }),
    );
    md_passed(
        &mut out,
        &pick(|s| matches!(s, Status::Pass | Status::NotApplicable)),
    );
    out
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
        let _ = writeln!(out, "| Grade | **{}**{score}{capped} |", g.grade.label());
    }
    let _ = writeln!(
        out,
        "| Results | {} passed · {} failed · {} unknown · {} needs review · {} no evidence · {} not applicable |",
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

fn platform_cell(f: &Finding) -> String {
    f.platform_fixes
        .iter()
        .map(|pf| {
            let mut s = format!("**{}:** {}", md_cell(&pf.platform), md_cell(&pf.how));
            if let Some(n) = &pf.note {
                let _ = write!(s, " — ⚠ {}", md_cell(n));
            }
            s
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn md_fails(out: &mut String, fails: &[&Finding]) {
    if !fails.is_empty() {
        out.push_str("\n## Needs action\n\n| Rule | Version | Severity | Finding | Why | Evidence | Fix | Example | Where to fix |\n|---|---|---|---|---|---|---|---|---|\n");
        for f in fails {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                md_cell(&f.rule_id),
                md_cell(&f.rule_version),
                f.severity.label(),
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

fn md_review(out: &mut String, decide: &[&Finding]) {
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

fn strip_controls(r: &mut Report) {
    fn clean(s: &mut String) {
        if s.chars().any(char::is_control) {
            *s = one_line(s);
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
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn short(s: &str) -> String {
    truncate(&one_line(s), MAX_HINT_CHARS)
}

fn md_text(s: &str) -> String {
    one_line(s)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn md_cell(s: &str) -> String {
    md_text(s).replace('|', "\\|")
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
    use crate::finding::{Evidence, EvidenceClass, Severity};
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
            }],
            reason: None,
            fix_hint: Some(format!("{id} fix")),
            example_fix: None,
            platform_fixes: vec![],
            review_question: None,
            remediation: None,
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
            md.contains("| Rule | Version | Severity | Finding | Why | Evidence | Fix | Example | Where to fix |")
        );
        assert!(md.contains("| HDR-000 | 1.0.0 | high |"));
        assert!(md.contains("GET https://example.com `HDR-000 evidence`"));
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
