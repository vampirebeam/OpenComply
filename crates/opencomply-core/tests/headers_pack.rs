//! Official headers rule pack (`rules/opencomply-headers.toml`) against synthetic responses: pack shape,
//! strong / bare / JSON API / weak-CSP sites, and the live-review behaviours D1, D2, D7, D9, D10, D12, D13, D14.

#![allow(clippy::unwrap_used)]

use opencomply_core::rules::RulePack;
use opencomply_core::{
    detect_platforms, evaluate_pack, render, EvalInput, Format, Grade, HttpEvidence, InsecureProbe,
    RedirectHop, Report, Status,
};

use opencomply_core::rules::OFFICIAL_HEADERS_PACK as PACK;

fn pack() -> RulePack {
    RulePack::from_toml(PACK).unwrap()
}

fn redirect(status: u16) -> InsecureProbe {
    InsecureProbe::Responded {
        chain: vec![
            RedirectHop {
                url: "http://example.com/".into(),
                status,
                location: Some("https://example.com/".into()),
            },
            RedirectHop {
                url: "https://example.com/".into(),
                status: 200,
                location: None,
            },
        ],
        final_url: "https://example.com/".into(),
    }
}

fn scan(headers: &[(&str, &str)], probe: InsecureProbe) -> Report {
    let http = HttpEvidence {
        source: "GET https://example.com/".into(),
        status: 200,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).into(), (*v).into()))
            .collect(),
        https: true,
        insecure_probe: Some(probe),
        redirect_cookies: vec![],
    };
    let platforms = detect_platforms(&http.headers, &http.source);
    evaluate_pack(
        &pack(),
        "https://example.com/",
        &EvalInput::Http(&http),
        platforms,
    )
}

fn finding<'a>(r: &'a Report, id: &str) -> &'a opencomply_core::Finding {
    r.findings.iter().find(|f| f.rule_id == id).unwrap()
}

#[test]
fn pack_shape() {
    let p = pack();
    assert_eq!(p.pack.id, "opencomply-headers");
    let ids: Vec<&str> = p.rules.iter().map(|r| r.id.as_str()).collect();
    let expected: Vec<String> = (1..=10).map(|n| format!("HDR-{n:03}")).collect();
    assert_eq!(ids, expected.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(
        p.rules.iter().map(|r| u32::from(r.weight)).sum::<u32>(),
        100
    );
    let mandatory: Vec<&str> = p
        .rules
        .iter()
        .filter(|r| r.mandatory)
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(mandatory, ["HDR-001", "HDR-002", "HDR-006", "HDR-007"]);
}

#[test]
fn strong_site_passes_everything() {
    let r = scan(
        &[
            ("Content-Type", "text/html; charset=utf-8"),
            ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; frame-ancestors 'self'; object-src 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=(), microphone=()"),
            ("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
            ("Server", "nginx"),
        ],
        redirect(301),
    );
    for f in &r.findings {
        assert_eq!(f.status, Status::Pass, "{} {:?}", f.rule_id, f.reason);
    }
    let g = r.grade.as_ref().unwrap();
    assert_eq!((g.grade, g.score), (Grade::APlus, Some(100)));
    assert!(render(&r, Format::Summary, false)
        .starts_with("headers https://example.com/ verdict=pass grade=A+ score=100 "));
}

/// Guidance follows the evidence: a `Server` version is fixed in the web server, never offered as an app setting;
/// an `X-Powered-By` from the app is fixed in the app first. (Found live: nginx `Server` version was sent to Next.js.)
#[test]
fn disclosure_guidance_follows_the_leaked_header() {
    let fixes = |headers: &[(&str, &str)]| {
        let r = scan(headers, redirect(301));
        finding(&r, "HDR-010")
            .platform_fixes
            .iter()
            .map(|p| (p.platform.clone(), p.preferred))
            .collect::<Vec<_>>()
    };
    let server_only = fixes(&[
        ("Content-Type", "text/html"),
        ("Server", "nginx/1.24.0 (Ubuntu)"),
        ("x-nextjs-cache", "HIT"),
    ]);
    assert_eq!(
        server_only,
        [("nginx".to_string(), true)],
        "{server_only:?}"
    );

    let behind_cdn = fixes(&[
        ("Content-Type", "text/html"),
        ("Server", "Apache/2.4.58"),
        ("Via", "1.1 abc.cloudfront.net (CloudFront)"),
    ]);
    assert_eq!(behind_cdn, [("apache".to_string(), true)], "{behind_cdn:?}");

    let app_only = fixes(&[
        ("Content-Type", "text/html"),
        ("Server", "nginx"),
        ("X-Powered-By", "Next.js"),
    ]);
    assert_eq!(app_only[0], ("nextjs".to_string(), true), "{app_only:?}");

    let both = scan(
        &[
            ("Content-Type", "text/html"),
            ("Server", "nginx/1.24.0"),
            ("X-Powered-By", "Next.js"),
        ],
        redirect(301),
    );
    let ids: Vec<&str> = finding(&both, "HDR-010")
        .platform_fixes
        .iter()
        .map(|p| p.platform.as_str())
        .collect();
    assert!(ids.contains(&"nginx") && ids.contains(&"nextjs"), "{ids:?}");

    let md = render(&both, Format::Markdown, false);
    assert!(
        md.contains("**nginx, preferred:**") || md.contains("**nextjs, preferred:**"),
        "{md}"
    );
    assert!(!md.contains(";;"), "no doubled separators");
}

/// Every software that emits a leaked value gets its own fix, even past the usual cap: a proxy's `ARR/3.0`
/// is removed in IIS, which neither app setting can do.
#[test]
fn disclosure_guidance_covers_every_leak_source() {
    let r = scan(
        &[
            ("Content-Type", "text/html"),
            ("Server", "cloudflare"),
            ("X-Powered-By", "Next.js"),
            ("X-Powered-By", "ARR/3.0"),
            ("X-Powered-By", "ASP.NET"),
        ],
        redirect(301),
    );
    let fixes: Vec<(&str, bool)> = finding(&r, "HDR-010")
        .platform_fixes
        .iter()
        .map(|p| (p.platform.as_str(), p.preferred))
        .collect();
    assert_eq!(
        fixes,
        [("iis", true), ("nextjs", true), ("aspnet", true)],
        "{fixes:?}"
    );

    let one_source = scan(
        &[
            ("Content-Type", "text/html"),
            ("Server", "cloudflare"),
            ("X-Powered-By", "Express"),
        ],
        redirect(301),
    );
    let fixes: Vec<(&str, bool)> = finding(&one_source, "HDR-010")
        .platform_fixes
        .iter()
        .map(|p| (p.platform.as_str(), p.preferred))
        .collect();
    assert_eq!(
        fixes,
        [("express", true), ("cloudflare", false)],
        "{fixes:?}"
    );
}

/// A value masked by a load balancer (`XXXXXXXX`) names no software: nothing leaks and nothing is offered to fix.
#[test]
fn masked_technology_headers_are_not_a_leak() {
    let r = scan(
        &[
            ("Content-Type", "text/html"),
            ("Server", "XXXXXX"),
            ("X-Powered-By", "XXXXXXXXXXX"),
            ("X-Powered-By", "XXXXXXXXX"),
        ],
        redirect(301),
    );
    let f = finding(&r, "HDR-010");
    assert_eq!(f.status, Status::Pass, "{:?}", f.reason);
    assert!(f.evidence[0].detail.contains("x-powered-by masked"));
    assert!(f.platform_fixes.is_empty());

    let mixed = scan(
        &[
            ("Content-Type", "text/html"),
            ("X-Powered-By", "XXXXXXXXX"),
            ("X-Powered-By", "PHP/8.2.1"),
        ],
        redirect(301),
    );
    let f = finding(&mixed, "HDR-010");
    assert_eq!(f.status, Status::Fail);
    assert_eq!(f.evidence[0].detail, "x-powered-by: PHP/8.2.1");
}

/// Load balancer / CDN cookies are not fixed in the app; app cookies are fixed in the framework first.
#[test]
fn cookie_guidance_follows_who_sets_the_cookie() {
    let fixes = |cookie: &str| {
        let r = scan(
            &[
                ("Content-Type", "text/html"),
                ("Server", "cloudflare"),
                ("X-Powered-By", "PHP/8.2"),
                ("Set-Cookie", cookie),
            ],
            redirect(301),
        );
        let f = finding(&r, "HDR-009");
        (
            f.status,
            f.platform_fixes
                .iter()
                .map(|p| (p.platform.clone(), p.preferred))
                .collect::<Vec<_>>(),
            f.reason.clone().unwrap_or_default(),
        )
    };
    // AWS load balancer cookie behind Cloudflare: no Cloudflare or PHP advice, and the reason names who sets it.
    let (status, lb, why) = fixes("AWSALB=abc; Path=/");
    assert_eq!(status, Status::Fail);
    assert!(lb.is_empty(), "{lb:?}");
    assert_eq!(
        why,
        "Secure missing on 1 aws-elb cookie, so it is also sent over http:// (fix it there)"
    );
    let (_, cf, _) = fixes("__cf_bm=abc; Path=/");
    assert_eq!(cf, [("cloudflare".to_string(), true)], "{cf:?}");
    let (_, app, why) = fixes("PHPSESSID=abc; Path=/");
    assert_eq!(app[0], ("php".to_string(), true), "{app:?}");
    assert!(!why.contains("fix it there"), "{why}");
}

#[test]
fn bare_site_fails_with_clear_reasons() {
    let probe = InsecureProbe::Responded {
        chain: vec![RedirectHop {
            url: "http://example.com/".into(),
            status: 200,
            location: None,
        }],
        final_url: "http://example.com/".into(),
    };
    let r = scan(
        &[
            ("Content-Type", "text/html"),
            ("Server", "nginx/1.18.0 (Ubuntu)"),
            ("X-Powered-By", "PHP/8.1.2"),
            ("X-Powered-By", "PleskLin"),
        ],
        probe,
    );
    for id in [
        "HDR-001", "HDR-002", "HDR-003", "HDR-004", "HDR-005", "HDR-006",
    ] {
        let f = finding(&r, id);
        assert_eq!(f.status, Status::Fail, "{id}");
        assert!(f.title.ends_with("missing"), "D9 {id}: {}", f.title);
        assert!(f.fix_hint.is_some() && f.example_fix.is_some(), "{id}");
    }
    let https = finding(&r, "HDR-007");
    assert_eq!(https.status, Status::Fail);
    assert!(
        https
            .reason
            .as_deref()
            .unwrap()
            .contains("traffic can be read or changed"),
        "D12"
    );
    assert_eq!(finding(&r, "HDR-008").status, Status::NotApplicable, "D10");
    let cookies = finding(&r, "HDR-009");
    assert_eq!(cookies.status, Status::NotApplicable, "D7");
    assert!(cookies
        .reason
        .as_deref()
        .unwrap()
        .contains("scan a page that does"));
    let leak = finding(&r, "HDR-010");
    assert_eq!(leak.status, Status::Fail);
    assert!(
        leak.evidence[0].detail.contains("x-powered-by: PleskLin"),
        "D13"
    );
    let hosts: Vec<&str> = finding(&r, "HDR-001")
        .platform_fixes
        .iter()
        .map(|p| p.platform.as_str())
        .collect();
    assert_eq!(hosts, ["plesk", "nginx"], "host panel first, then server");
    let g = r.grade.as_ref().unwrap();
    assert_eq!((g.grade, g.score), (Grade::F, Some(0)));
    let json: serde_json::Value = serde_json::from_str(&render(&r, Format::Json, false)).unwrap();
    assert_eq!(json["grade"]["grade"], "F");
    assert!(render(&r, Format::Markdown, false).contains("| Grade | **F** (0/100) |"));
}

#[test]
fn weak_csp_example_is_built_from_the_sites_policy() {
    let r = scan(
        &[
            ("Content-Type", "text/html"),
            ("Server", "cloudflare"),
            ("CF-RAY", "8a1b2c3d4e5f-BKK"),
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://challenges.cloudflare.com; frame-ancestors 'none'",
            ),
        ],
        redirect(301),
    );
    let csp = finding(&r, "HDR-002");
    assert_eq!(csp.status, Status::Fail);
    assert_eq!(csp.title, "Content-Security-Policy");
    let ex = csp.example_fix.as_deref().unwrap();
    assert!(ex.starts_with("change only script-src:"), "D2: {ex}");
    assert!(ex.contains("https://www.googletagmanager.com"), "D1: {ex}");
    assert!(ex.contains("https://challenges.cloudflare.com"), "D1: {ex}");
    assert!(!ex.contains("unsafe-inline"), "{ex}");
    assert!(
        csp.review_question.is_none(),
        "no decision question on a FAIL"
    );
    assert_eq!(
        csp.platform_fixes[0].platform, "cloudflare",
        "no app layer detected"
    );
    assert!(csp.platform_fixes[0]
        .note
        .as_deref()
        .unwrap()
        .contains("nonce"));
    assert_eq!(finding(&r, "HDR-006").status, Status::Pass);
}

#[test]
fn app_layer_is_preferred_over_cdn_for_nonces() {
    let r = scan(
        &[
            ("Content-Type", "text/html"),
            ("Server", "cloudflare"),
            ("X-Powered-By", "Next.js"),
            (
                "Content-Security-Policy",
                "script-src 'self' 'unsafe-inline'",
            ),
        ],
        redirect(301),
    );
    let csp = finding(&r, "HDR-002");
    let order: Vec<(&str, bool)> = csp
        .platform_fixes
        .iter()
        .map(|p| (p.platform.as_str(), p.preferred))
        .collect();
    assert_eq!(order, [("nextjs", true), ("cloudflare", false)], "D3");
    assert!(render(&r, Format::Summary, false).contains("  how (nextjs, preferred): "));
}

#[test]
fn low_grade_summary_explains_only_the_next_step_unless_all() {
    let r = scan(&[("Content-Type", "text/html")], redirect(301));
    let short = render(&r, Format::Summary, false);
    let impacts = short
        .lines()
        .filter(|l| l.starts_with("  impact ("))
        .count();
    let next_steps = r.grade.as_ref().unwrap().upgrades[0].steps.len();
    assert_eq!(impacts, next_steps, "{short}");
    assert!(
        short
            .lines()
            .any(|l| l.starts_with("  impact of ") && l.ends_with(": --all")),
        "{short}"
    );
    let full = render(&r, Format::Summary, true);
    assert!(full.lines().filter(|l| l.starts_with("  impact (")).count() > impacts);
    assert!(!full.contains(": --all\n"), "{full}");
}

#[test]
fn one_fix_to_a_plus_is_shown_once() {
    let r = scan(
        &[
            ("Content-Type", "text/html"),
            ("Strict-Transport-Security", "max-age=31536000"),
            (
                "Content-Security-Policy",
                "script-src 'self' 'unsafe-inline'; frame-ancestors 'self'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "camera=()"),
        ],
        redirect(301),
    );
    let out = render(&r, Format::Summary, false);
    assert!(
        out.lines()
            .filter(|l| l.starts_with("  why: "))
            .all(|l| !l.ends_with('…')),
        "why lines must fit: {out}"
    );
    assert!(out.contains("grade=C score=74"), "{out}");
    assert!(
        out.contains("\nto B and A+: HDR-002 +26 required → A+ 100\n"),
        "{out}"
    );
    assert!(!out.contains("\nto B: "), "{out}");
}

#[test]
fn temporary_redirect_is_review_not_pass_or_fail() {
    let r = scan(&[("Content-Type", "text/html")], redirect(302));
    let f = finding(&r, "HDR-007");
    assert_eq!(f.status, Status::NeedsReview, "D14");
    assert!(f.review_question.is_some());
    assert_eq!(
        f.evidence[0].detail,
        "GET http://example.com/ → 302 → https://example.com/ 200"
    );
}

#[test]
fn json_api_skips_browser_only_rules() {
    let r = scan(
        &[
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("X-Content-Type-Options", "nosniff"),
        ],
        redirect(301),
    );
    for id in ["HDR-002", "HDR-005", "HDR-006"] {
        assert_eq!(finding(&r, id).status, Status::NotApplicable, "{id}");
    }
    assert_eq!(finding(&r, "HDR-001").status, Status::Pass);
}

#[test]
fn summary_output_shows_site_specific_example() {
    let r = scan(
        &[
            ("Content-Type", "text/html"),
            (
                "Content-Security-Policy",
                "script-src 'self' 'unsafe-inline' https://cdn.example.net",
            ),
        ],
        redirect(301),
    );
    let out = render(&r, Format::Summary, false);
    assert!(
        out.lines()
            .any(|l| l.starts_with("to A+:") && l.contains("HDR-002 +")),
        "{out}"
    );
    assert!(out.contains("  impact (HDR-002): Nonces need"), "{out}");
    assert!(render(&r, Format::Markdown, false).contains("## How to raise the grade"));
    assert!(
        out.contains("change only script-src: script-src 'self' 'nonce-<random-per-request>' https://cdn.example.net"),
        "{out}"
    );
}
