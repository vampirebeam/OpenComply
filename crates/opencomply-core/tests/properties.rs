//! Property-based / fuzz-style tests for every component that consumes untrusted input: rule pack loader,
//! renderer, platform detection (headers + HTML), redaction, evaluator, signature parser, path validation.
//! Invariants: never panic, stay bounded, never emit control characters into one-line output, never leak secrets.

#![allow(clippy::unwrap_used)]

use opencomply_core::rules::{Check, Rule, RulePack};
use opencomply_core::signing::{verify_pack, TrustedKey};
use opencomply_core::walk::safe_rel_path;
use opencomply_core::{
    detect_from_html, detect_platforms, evaluate_rule, redact::redact, render, EvalInput, Evidence,
    EvidenceClass, Finding, Format, HttpEvidence, InsecureProbe, Module, RedirectHop, Report,
    Severity, Status, Version, MAX_HTML_SCAN_BYTES,
};
use proptest::prelude::*;

fn any_text() -> impl Strategy<Value = String> {
    prop_oneof![
        ".{0,200}",
        "[\\x00-\\x1f\\x7f\u{80}-\u{9f}]{0,40}",
        "(\\[pack\\]|\\[\\[rule\\]\\]|id = \"|op = \"|=|\"|\n|\\{|\\}|header_present|../|\u{0e2a}){0,40}",
    ]
}

fn finding(title: String, detail: String, reason: String, status: Status) -> Finding {
    Finding {
        rule_id: "HDR-001".into(),
        rule_version: "1.0.0".into(),
        title,
        status,
        severity: Severity::Medium,
        evidence: vec![Evidence {
            class: EvidenceClass::Verified,
            source: "GET x".into(),
            detail,
        }],
        reason: Some(reason),
        fix_hint: Some("f".into()),
        example_fix: None,
        platform_fixes: vec![],
        review_question: None,
        remediation: Some("r".into()),
    }
}

fn status() -> impl Strategy<Value = Status> {
    prop_oneof![
        Just(Status::Pass),
        Just(Status::Fail),
        Just(Status::Unknown),
        Just(Status::NotApplicable),
        Just(Status::NeedsReview),
        Just(Status::InsufficientEvidence),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn rule_pack_loader_never_panics(src in any_text()) {
        let _ = RulePack::from_toml(&src);
    }

    #[test]
    fn summary_is_one_line_per_item_and_control_free(
        title in any_text(), detail in any_text(), reason in any_text(), st in status()
    ) {
        let r = Report::new(Module::Headers, "https://example.com", vec![finding(title, detail, reason, st)]);
        for format in [Format::Summary, Format::Json, Format::Markdown] {
            let out = render(&r, format, true);
            prop_assert!(!out.contains('\r'));
            prop_assert!(out.chars().all(|c| c == '\n' || !c.is_control()));
        }
        let summary = render(&r, Format::Summary, true);
        // header + status line + at most why/fix-or-decide lines + next
        prop_assert!(summary.lines().count() <= 5, "{summary}");
        let json = render(&r, Format::Json, true);
        prop_assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    #[test]
    fn platform_detection_never_panics(
        headers in proptest::collection::vec((any_text(), any_text()), 0..20), html in any_text()
    ) {
        let _ = detect_platforms(&headers, "GET x");
        let _ = detect_from_html(&html, "GET x");
    }

    #[test]
    fn html_scan_handles_multibyte_boundary(fill in 0usize..8) {
        let mut html = "ก".repeat(MAX_HTML_SCAN_BYTES / 3 + fill);
        html.push_str("/wp-content/");
        let _ = detect_from_html(&html, "GET x");
    }

    #[test]
    fn redaction_is_stable_and_hides_injected_secrets(prefix in ".{0,40}", suffix in ".{0,40}") {
        let secret = concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyzAB");
        let text = format!("{prefix} {secret} {suffix}");
        let once = redact(&text).into_owned();
        prop_assert!(!once.contains(secret));
        prop_assert_eq!(redact(&once).into_owned(), once);
    }

    #[test]
    fn redaction_never_panics(text in any_text()) {
        let _ = redact(&text);
    }

    #[test]
    fn evaluator_never_panics_on_header_values(
        values in proptest::collection::vec(any_text(), 0..4), min in any::<u64>()
    ) {
        let rule = Rule {
            id: "HDR-001".into(),
            version: "1.0.0".into(),
            title: "t".into(),
            severity: Severity::High,
            mandatory: false,
            weight: 1,
            check: Check::HeaderDirectiveAtLeast {
                header: "strict-transport-security".into(),
                directive: "max-age".into(),
                min,
            },
            html_only: false,
            fix_hint: "f".into(),
            example_fix: None,
            review_question: None,
            upgrade_impact: None,
            remediation: "r".into(),
            platforms: std::collections::BTreeMap::new(),
        };
        let http = HttpEvidence {
            source: "GET x".into(),
            status: 200,
            headers: values.into_iter().map(|v| ("Strict-Transport-Security".to_string(), v)).collect(),
            ..HttpEvidence::default()
        };
        let f = evaluate_rule(&rule, Module::Headers, &EvalInput::Http(&http), &[]);
        prop_assert!(f.evidence[0].detail.chars().count() <= 301);
    }

    #[test]
    fn official_headers_pack_never_panics_and_stays_bounded(
        csp in any_text(), hsts in any_text(), cookie in any_text(), xfo in any_text(),
        other in any_text(), status in any::<u16>(), https in any::<bool>()
    ) {
        let pack = RulePack::from_toml(opencomply_core::rules::OFFICIAL_HEADERS_PACK).unwrap();
        let http = HttpEvidence {
            source: "GET x".into(),
            status: 200,
            headers: vec![
                ("Content-Security-Policy".into(), csp),
                ("Strict-Transport-Security".into(), hsts),
                ("Set-Cookie".into(), format!("sid=SECRETCOOKIEVALUE;{cookie}")),
                ("X-Frame-Options".into(), xfo),
                ("Referrer-Policy".into(), other.clone()),
                ("Permissions-Policy".into(), other.clone()),
                ("Server".into(), other),
            ],
            https,
            insecure_probe: Some(InsecureProbe::Responded {
                chain: vec![RedirectHop { url: "http://x/".into(), status, location: None }],
                final_url: "http://x/".into(),
            }),
            redirect_cookies: vec![format!("hop=SECRETHOPVALUE;{cookie}")],
        };
        for rule in &pack.rules {
            let f = evaluate_rule(rule, Module::Headers, &EvalInput::Http(&http), &[]);
            prop_assert!(f.evidence[0].detail.chars().count() <= 301);
            prop_assert!(f.example_fix.as_ref().is_none_or(|e| e.chars().count() <= opencomply_core::MAX_EXAMPLE_CHARS));
            prop_assert!(!f.evidence[0].detail.contains("SECRETCOOKIEVALUE"), "{}", rule.id);
            prop_assert!(!f.evidence[0].detail.contains("SECRETHOPVALUE"), "{}", rule.id);
            prop_assert!(!f.reason.as_deref().unwrap_or("").contains("SECRETHOPVALUE"), "{}", rule.id);
        }
    }

    #[test]
    fn signature_parser_never_panics(sig in any_text(), pack in any_text()) {
        let keys: Vec<TrustedKey> = TrustedKey::official();
        let _ = verify_pack(pack.as_bytes(), Some(&sig), &keys);
    }

    #[test]
    fn rule_paths_with_parent_segments_are_always_rejected(a in "[a-z]{1,8}", b in "[a-z]{1,8}") {
        for p in [format!("../{a}"), format!("{a}/../{b}"), format!("{a}/.."), format!("/{a}"), format!("{a}\\{b}")] {
            prop_assert!(safe_rel_path(&p).is_err(), "{p}");
        }
        let ok = format!("{a}/{b}");
        prop_assert!(safe_rel_path(&ok).is_ok());
    }

    #[test]
    fn version_parse_never_panics(s in ".{0,30}") {
        let _ = Version::parse(&s);
    }
}
