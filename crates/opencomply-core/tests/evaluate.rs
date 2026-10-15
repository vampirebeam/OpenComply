//! Finding evaluator tests: every operator (pass / fail / missing), repeated headers, directive parsing,
//! missing-title wording, guidance only on actionable results, ISO missing files, and pack → report end-to-end.

#![allow(clippy::unwrap_used)]

use opencomply_core::rules::RulePack;
use opencomply_core::{
    detect_platforms, evaluate_pack, render, EvalInput, FileProbe, Format, HttpEvidence, Status,
};

const PACK: &str = r#"
[pack]
id = "test-headers"
version = "1.2.0"
module = "headers"

[[rule]]
id = "HDR-001"
version = "1.0.0"
title = "Strict-Transport-Security"
severity = "high"
weight = 20
fix_hint = "send HSTS with max-age of at least one year"
example_fix = "Strict-Transport-Security: max-age=31536000"
remediation = "Send HSTS on every HTTPS response."
check = { op = "header_directive_at_least", header = "strict-transport-security", directive = "max-age", min = 31536000 }
[rule.platforms.cloudflare]
how = "SSL/TLS > Edge Certificates > HSTS"

[[rule]]
id = "HDR-003"
version = "1.0.0"
title = "X-Content-Type-Options"
severity = "medium"
weight = 10
fix_hint = "send X-Content-Type-Options: nosniff"
remediation = "Send nosniff."
check = { op = "header_equals", header = "x-content-type-options", value = "nosniff" }

[[rule]]
id = "HDR-004"
version = "1.0.0"
title = "Referrer-Policy"
severity = "low"
weight = 5
fix_hint = "use a restrictive Referrer-Policy"
remediation = "Use strict-origin-when-cross-origin."
check = { op = "header_one_of", header = "referrer-policy", values = ["no-referrer", "same-origin", "strict-origin-when-cross-origin"] }

[[rule]]
id = "HDR-005"
version = "1.0.0"
title = "Permissions-Policy"
severity = "low"
weight = 5
fix_hint = "add a Permissions-Policy"
remediation = "Disable unused features."
check = { op = "header_present", header = "permissions-policy" }

[[rule]]
id = "HDR-010"
version = "1.0.0"
title = "X-Powered-By disclosed"
severity = "low"
weight = 5
fix_hint = "remove X-Powered-By"
remediation = "Remove it."
check = { op = "header_absent", header = "x-powered-by" }

[[rule]]
id = "HDR-011"
version = "1.0.0"
title = "CSP frame-ancestors"
severity = "medium"
weight = 5
fix_hint = "add frame-ancestors"
remediation = "Restrict framing."
check = { op = "header_contains", header = "content-security-policy", value = "frame-ancestors" }
"#;

fn http(headers: &[(&str, &str)]) -> HttpEvidence {
    HttpEvidence {
        source: "GET https://example.com/".into(),
        status: 200,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).into(), (*v).into()))
            .collect(),
        https: true,
        insecure_probe: None,
        redirect_cookies: vec![],
        html_generator: None,
    }
}

fn run(headers: &[(&str, &str)]) -> opencomply_core::Report {
    let pack = RulePack::from_toml(PACK).unwrap();
    let h = http(headers);
    let platforms = detect_platforms(&h.headers, &h.source);
    evaluate_pack(
        &pack,
        "https://example.com/",
        &EvalInput::Http(&h),
        platforms,
    )
}

fn status(r: &opencomply_core::Report, id: &str) -> Status {
    r.findings.iter().find(|f| f.rule_id == id).unwrap().status
}

#[test]
fn all_passing_headers() {
    let r = run(&[
        (
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains",
        ),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=()"),
        (
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'",
        ),
    ]);
    assert!(
        r.findings.iter().all(|f| f.status == Status::Pass),
        "{:?}",
        r.findings
    );
    assert!(r
        .findings
        .iter()
        .all(|f| f.fix_hint.is_none() && f.platform_fixes.is_empty()));
    assert_eq!(r.rule_packs[0].version, "1.2.0");
}

#[test]
fn missing_headers_fail_with_missing_title_and_guidance() {
    let r = run(&[("Server", "cloudflare")]);
    let hsts = r.findings.iter().find(|f| f.rule_id == "HDR-001").unwrap();
    assert_eq!(hsts.status, Status::Fail);
    assert_eq!(hsts.title, "Strict-Transport-Security missing");
    assert_eq!(
        hsts.reason.as_deref(),
        Some("response has no strict-transport-security header")
    );
    assert_eq!(hsts.evidence[0].detail, "(header not present)");
    assert_eq!(hsts.platform_fixes[0].platform, "cloudflare");
    assert_eq!(
        hsts.example_fix.as_deref(),
        Some("Strict-Transport-Security: max-age=31536000")
    );
    assert_eq!(status(&r, "HDR-010"), Status::Pass);
}

#[test]
fn weak_values_fail_with_reason() {
    let r = run(&[
        ("Strict-Transport-Security", "max-age=300"),
        ("X-Content-Type-Options", "sniff"),
        ("Referrer-Policy", "unsafe-url"),
        ("Content-Security-Policy", "default-src 'self'"),
    ]);
    let hsts = r.findings.iter().find(|f| f.rule_id == "HDR-001").unwrap();
    assert_eq!(
        hsts.reason.as_deref(),
        Some("max-age=300 is below 31536000")
    );
    assert_eq!(hsts.title, "Strict-Transport-Security");
    assert_eq!(status(&r, "HDR-003"), Status::Fail);
    assert_eq!(status(&r, "HDR-004"), Status::Fail);
    assert_eq!(status(&r, "HDR-011"), Status::Fail);
}

#[test]
fn repeated_headers_use_every_value() {
    let r = run(&[
        ("x-powered-by", "Next.js"),
        ("x-powered-by", "ARR/3.0"),
        ("x-powered-by", "ASP.NET"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Content-Type-Options", "other"),
    ]);
    let xpb = r.findings.iter().find(|f| f.rule_id == "HDR-010").unwrap();
    assert_eq!(xpb.status, Status::Fail);
    assert_eq!(
        xpb.reason.as_deref(),
        Some("x-powered-by is present: Next.js, ARR/3.0, ASP.NET")
    );
    assert!(xpb.evidence[0].detail.contains("x-powered-by: ARR/3.0"));
    assert_eq!(status(&r, "HDR-003"), Status::Fail);
}

#[test]
fn unparseable_directive_is_unknown_not_pass() {
    let r = run(&[("Strict-Transport-Security", "max-age=forever")]);
    assert_eq!(status(&r, "HDR-001"), Status::Unknown);
    assert_eq!(r.exit_code(opencomply_core::FailOn::Fail) as u8, 1);
}

#[test]
fn evidence_is_bounded() {
    let long = "x".repeat(5000);
    let r = run(&[("Permissions-Policy", long.as_str())]);
    let pp = r.findings.iter().find(|f| f.rule_id == "HDR-005").unwrap();
    assert!(pp.evidence[0].detail.chars().count() <= 301);
}

#[test]
fn end_to_end_summary() {
    let r = run(&[
        ("Server", "cloudflare"),
        ("X-Content-Type-Options", "nosniff"),
    ]);
    let out = render(&r, Format::Summary, false);
    assert!(out.starts_with("headers https://example.com/ verdict=fail"));
    assert!(out.contains("platform=cloudflare"));
    assert!(out.contains("FAIL HDR-001 high Strict-Transport-Security missing\n"));
    assert!(out.contains("  how (cloudflare): SSL/TLS > Edge Certificates > HSTS\n"));
}

struct FakeRepo;

impl FileProbe for FakeRepo {
    fn source(&self) -> String {
        "repo ./my-repo".into()
    }
    fn exists(&self, rel_path: &str) -> Result<bool, String> {
        Ok(rel_path == "SECURITY.md")
    }
    fn contains(&self, _rel_path: &str, _text: &str) -> Result<bool, String> {
        Err("permission denied".into())
    }
}

#[test]
fn iso_missing_file_is_insufficient_evidence_and_errors_are_unknown() {
    let pack = RulePack::from_toml(
        r#"
[pack]
id = "test-iso"
version = "1.0.0"
module = "iso27001"

[[rule]]
id = "ISO27-001"
version = "1.0.0"
title = "Security policy"
severity = "medium"
weight = 5
fix_hint = "add SECURITY.md"
remediation = "Document it."
check = { op = "file_exists", path = "SECURITY.md" }

[[rule]]
id = "ISO27-002"
version = "1.0.0"
title = "Incident response plan"
severity = "medium"
weight = 5
fix_hint = "add docs/incident-response.md"
remediation = "Document it."
check = { op = "file_exists", path = "docs/incident-response.md" }

[[rule]]
id = "ISO27-003"
version = "1.0.0"
title = "Policy mentions incidents"
severity = "low"
weight = 5
fix_hint = "describe incident handling"
remediation = "Document it."
check = { op = "file_contains", path = "SECURITY.md", text = "incident" }
"#,
    )
    .unwrap();
    let repo = FakeRepo;
    let r = evaluate_pack(&pack, "./my-repo", &EvalInput::Files(&repo), vec![]);
    assert_eq!(status(&r, "ISO27-001"), Status::Pass);
    assert_eq!(status(&r, "ISO27-002"), Status::InsufficientEvidence);
    assert_eq!(status(&r, "ISO27-003"), Status::Unknown);
}
