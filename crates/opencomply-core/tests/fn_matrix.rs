//! False-negative matrix: for every rule of the official headers pack, responses that leave the browser unprotected
//! must never PASS (FAIL / REVIEW / UNKNOWN are all acceptable), judged by what browsers actually do. Runs through
//! `evaluate_pack` with the official pack, the same path as a real scan. A few cases pin results that are correct
//! as they are (`Is`), so a later change cannot silently turn them into false negatives or false positives.
//! Synthetic responses only (example.com).

#![allow(clippy::unwrap_used)]

use opencomply_core::rules::{RulePack, OFFICIAL_HEADERS_PACK};
use opencomply_core::{evaluate_pack, EvalInput, HttpEvidence, InsecureProbe, RedirectHop, Status};

enum Expect {
    /// Any status but PASS, with a reason.
    NotPass,
    Is(Status),
    /// PASS with advice (advice never changes the grade).
    PassWithAdvice,
}

struct Case {
    rule: &'static str,
    name: &'static str,
    headers: &'static [(&'static str, &'static str)],
    https: bool,
    probe: Option<InsecureProbe>,
    generator: Option<&'static str>,
    expect: Expect,
}

fn hop(url: &str, status: u16) -> RedirectHop {
    RedirectHop {
        url: url.into(),
        status,
        location: None,
    }
}

fn permanent() -> InsecureProbe {
    InsecureProbe::Responded {
        chain: vec![
            hop("http://example.com/", 301),
            hop("https://example.com/", 200),
        ],
        final_url: "https://example.com/".into(),
    }
}

fn case(
    rule: &'static str,
    name: &'static str,
    headers: &'static [(&'static str, &'static str)],
    expect: Expect,
) -> Case {
    Case {
        rule,
        name,
        headers,
        https: true,
        probe: Some(permanent()),
        generator: None,
        expect,
    }
}

fn not_pass(
    rule: &'static str,
    name: &'static str,
    headers: &'static [(&'static str, &'static str)],
) -> Case {
    case(rule, name, headers, Expect::NotPass)
}

const CSP: &str = "Content-Security-Policy";
const HSTS: &str = "Strict-Transport-Security";

fn probe(rule: &'static str, name: &'static str, probe: Option<InsecureProbe>) -> Case {
    Case {
        probe,
        ..not_pass(rule, name, &[])
    }
}

fn on_http(
    rule: &'static str,
    name: &'static str,
    headers: &'static [(&'static str, &'static str)],
) -> Case {
    Case {
        https: false,
        ..not_pass(rule, name, headers)
    }
}

fn generator(name: &'static str, content: &'static str) -> Case {
    Case {
        generator: Some(content),
        ..not_pass("HDR-010", name, &[])
    }
}

fn cases() -> Vec<Case> {
    [
        hsts_cases(),
        csp_cases(),
        nosniff_cases(),
        page_header_cases(),
        clickjacking_cases(),
        transport_cases(),
        error_answer_cases(),
        app_cases(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn hsts_cases() -> Vec<Case> {
    use Expect::Is;
    vec![
        // HDR-001 HSTS
        not_pass("HDR-001", "missing", &[]),
        not_pass("HDR-001", "max-age=0", &[(HSTS, "max-age=0")]),
        not_pass("HDR-001", "one day", &[(HSTS, "max-age=86400")]),
        not_pass("HDR-001", "no max-age", &[(HSTS, "includeSubDomains")]),
        not_pass("HDR-001", "max-age not a number", &[(HSTS, "max-age=abc")]),
        not_pass(
            "HDR-001",
            "max-age twice (header invalid)",
            &[(HSTS, "max-age=31536000; max-age=31536000")],
        ),
        not_pass(
            "HDR-001",
            "two headers, first one short",
            &[(HSTS, "max-age=60"), (HSTS, "max-age=31536000")],
        ),
        on_http(
            "HDR-001",
            "page served over http://",
            &[(HSTS, "max-age=31536000")],
        ),
        case(
            "HDR-001",
            "quoted max-age is valid",
            &[(HSTS, "max-age=\"31536000\"; includeSubDomains")],
            Is(Status::Pass),
        ),
        case(
            "HDR-001",
            "directive names are case-insensitive",
            &[(HSTS, "MAX-AGE=31536000; INCLUDESUBDOMAINS")],
            Is(Status::Pass),
        ),
    ]
}

fn csp_cases() -> Vec<Case> {
    use Expect::Is;
    vec![
        // HDR-002 CSP
        not_pass("HDR-002", "missing", &[]),
        not_pass(
            "HDR-002",
            "report-only only",
            &[("Content-Security-Policy-Report-Only", "default-src 'self'")],
        ),
        not_pass("HDR-002", "unsafe-inline", &[(CSP, "script-src 'self' 'unsafe-inline'")]),
        not_pass("HDR-002", "wildcard", &[(CSP, "script-src *")]),
        not_pass("HDR-002", "scheme only", &[(CSP, "script-src 'self' https:")]),
        not_pass("HDR-002", "https://* host wildcard", &[(CSP, "script-src 'self' https://*")]),
        not_pass("HDR-002", "http://* host wildcard", &[(CSP, "script-src 'self' http://*")]),
        not_pass("HDR-002", "data: scripts", &[(CSP, "script-src 'self' data:")]),
        not_pass(
            "HDR-002",
            "empty nonce does not cancel unsafe-inline",
            &[(CSP, "script-src 'self' 'unsafe-inline' 'nonce-'; base-uri 'self'")],
        ),
        not_pass(
            "HDR-002",
            "strict-dynamic without a valid nonce",
            &[(CSP, "script-src 'strict-dynamic' 'nonce-' https:; base-uri 'self'")],
        ),
        not_pass("HDR-002", "default-src *", &[(CSP, "default-src *")]),
        not_pass("HDR-002", "no script directive", &[(CSP, "img-src 'self'")]),
        not_pass(
            "HDR-002",
            "inline event handlers",
            &[(CSP, "script-src 'self'; script-src-attr 'unsafe-inline'")],
        ),
        case(
            "HDR-002",
            "real nonce makes unsafe-inline ignored",
            &[(CSP, "script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; base-uri 'self'")],
            Is(Status::Pass),
        ),
        case(
            "HDR-002",
            "unsafe-hashes with a hash",
            &[(
                CSP,
                "script-src 'self' 'unsafe-hashes' 'sha256-abc='; object-src 'none'; base-uri 'self'",
            )],
            Is(Status::Pass),
        ),
        case(
            "HDR-002",
            "subdomain wildcard is a host list",
            &[(CSP, "script-src https://*.example.com; object-src 'none'; base-uri 'self'")],
            Is(Status::Pass),
        ),
        // SVG can run scripts, but html_only rules target pages: kept N/A on purpose.
        case(
            "HDR-002",
            "SVG response is not a page",
            &[("Content-Type", "image/svg+xml")],
            Is(Status::NotApplicable),
        ),
    ]
}

/// `nosniff` repeated is REVIEW until browser compatibility tests show every browser applies it; any other token
/// fails, whatever its position.
fn nosniff_cases() -> Vec<Case> {
    use Expect::Is;
    const XCTO: &str = "X-Content-Type-Options";
    vec![
        case("HDR-003", "missing header", &[], Is(Status::Fail)),
        case(
            "HDR-003",
            "single nosniff",
            &[(XCTO, "nosniff")],
            Is(Status::Pass),
        ),
        case(
            "HDR-003",
            "case-insensitive",
            &[(XCTO, "NoSniff")],
            Is(Status::Pass),
        ),
        case(
            "HDR-003",
            "duplicate in one value",
            &[(XCTO, "nosniff, nosniff")],
            Is(Status::NeedsReview),
        ),
        case(
            "HDR-003",
            "duplicate header lines",
            &[(XCTO, "nosniff"), (XCTO, "nosniff")],
            Is(Status::NeedsReview),
        ),
        case(
            "HDR-003",
            "valid then invalid",
            &[(XCTO, "nosniff, sniff")],
            Is(Status::Fail),
        ),
        case(
            "HDR-003",
            "invalid then valid",
            &[(XCTO, "sniff"), (XCTO, "nosniff")],
            Is(Status::Fail),
        ),
        case(
            "HDR-003",
            "valid with an empty member",
            &[(XCTO, "nosniff,")],
            Is(Status::Fail),
        ),
    ]
}

/// Other browser-page headers (HDR-003 – HDR-005).
fn page_header_cases() -> Vec<Case> {
    use Expect::Is;
    vec![
        // HDR-003 X-Content-Type-Options
        not_pass("HDR-003", "missing", &[]),
        not_pass("HDR-003", "empty", &[("X-Content-Type-Options", "")]),
        not_pass(
            "HDR-003",
            "wrong value",
            &[("X-Content-Type-Options", "sniff")],
        ),
        not_pass(
            "HDR-003",
            "conflicting values",
            &[
                ("X-Content-Type-Options", "nosniff"),
                ("X-Content-Type-Options", "none"),
            ],
        ),
        // HDR-004 Referrer-Policy
        not_pass("HDR-004", "missing", &[]),
        not_pass("HDR-004", "empty", &[("Referrer-Policy", "")]),
        not_pass(
            "HDR-004",
            "unsafe-url",
            &[("Referrer-Policy", "unsafe-url")],
        ),
        not_pass(
            "HDR-004",
            "last known token wins",
            &[("Referrer-Policy", "no-referrer, unsafe-url")],
        ),
        not_pass(
            "HDR-004",
            "unknown token only",
            &[("Referrer-Policy", "made-up")],
        ),
        not_pass(
            "HDR-004",
            "origin to http://",
            &[("Referrer-Policy", "origin-when-cross-origin")],
        ),
        // HDR-005 Permissions-Policy
        not_pass("HDR-005", "missing", &[]),
        not_pass("HDR-005", "empty", &[("Permissions-Policy", "")]),
        not_pass(
            "HDR-005",
            "Feature-Policy syntax",
            &[("Permissions-Policy", "camera 'none'")],
        ),
        not_pass(
            "HDR-005",
            "allowlist *",
            &[("Permissions-Policy", "camera=*, microphone=()")],
        ),
        not_pass(
            "HDR-005",
            "several long features with *",
            &[(
                "Permissions-Policy",
                "publickey-credentials-create=*, xr-spatial-tracking=*, attribution-reporting=*",
            )],
        ),
        not_pass(
            "HDR-005",
            "allowlist (*)",
            &[("Permissions-Policy", "geolocation=(*)")],
        ),
        case(
            "HDR-005",
            "features turned off",
            &[("Permissions-Policy", "camera=(), geolocation=(self)")],
            Is(Status::Pass),
        ),
    ]
}

fn clickjacking_cases() -> Vec<Case> {
    use Expect::Is;
    vec![
        // HDR-006 Clickjacking
        not_pass("HDR-006", "missing", &[]),
        not_pass(
            "HDR-006",
            "frame-ancestors *",
            &[(CSP, "frame-ancestors *")],
        ),
        not_pass(
            "HDR-006",
            "frame-ancestors https://*",
            &[(CSP, "frame-ancestors https://*")],
        ),
        not_pass(
            "HDR-006",
            "frame-ancestors https:",
            &[(CSP, "frame-ancestors https:")],
        ),
        not_pass(
            "HDR-006",
            "frame-ancestors only in report-only",
            &[(
                "Content-Security-Policy-Report-Only",
                "frame-ancestors 'none'",
            )],
        ),
        not_pass(
            "HDR-006",
            "ALLOW-FROM is ignored",
            &[("X-Frame-Options", "ALLOW-FROM https://a.example.com")],
        ),
        not_pass(
            "HDR-006",
            "conflicting X-Frame-Options",
            &[
                ("X-Frame-Options", "DENY"),
                ("X-Frame-Options", "SAMEORIGIN"),
            ],
        ),
        not_pass(
            "HDR-006",
            "invalid X-Frame-Options",
            &[("X-Frame-Options", "ALLOWALL")],
        ),
        not_pass(
            "HDR-006",
            "frame-ancestors overrides X-Frame-Options",
            &[(CSP, "frame-ancestors *"), ("X-Frame-Options", "DENY")],
        ),
        case(
            "HDR-006",
            "subdomain wildcard is a host list",
            &[(CSP, "frame-ancestors https://*.example.com")],
            Is(Status::Pass),
        ),
    ]
}

/// HTTPS enforcement and header syntax.
fn transport_cases() -> Vec<Case> {
    use Expect::Is;
    vec![
        // HDR-007 HTTPS enforcement
        probe("HDR-007", "http:// not checked", None),
        probe(
            "HDR-007",
            "http:// timed out",
            Some(InsecureProbe::TimedOut("timed out".into())),
        ),
        probe(
            "HDR-007",
            "http:// serves the page",
            Some(InsecureProbe::Responded {
                chain: vec![hop("http://example.com/", 200)],
                final_url: "http://example.com/".into(),
            }),
        ),
        probe(
            "HDR-007",
            "temporary redirect",
            Some(InsecureProbe::Responded {
                chain: vec![
                    hop("http://example.com/", 302),
                    hop("https://example.com/", 200),
                ],
                final_url: "https://example.com/".into(),
            }),
        ),
        probe(
            "HDR-007",
            "redirect that stays on http://",
            Some(InsecureProbe::Responded {
                chain: vec![
                    hop("http://example.com/", 301),
                    hop("http://www.example.com/", 200),
                ],
                final_url: "http://www.example.com/".into(),
            }),
        ),
        Case {
            probe: Some(InsecureProbe::Refused("connection refused".into())),
            ..case("HDR-007", "http:// refused", &[], Is(Status::Pass))
        },
        probe(
            "HDR-007",
            "http:// connection reset (WAF or middlebox)",
            Some(InsecureProbe::Failed("connection reset by peer".into())),
        ),
        probe(
            "HDR-007",
            "http:// host does not resolve",
            Some(InsecureProbe::NotResolved("dns error".into())),
        ),
        // HDR-008 Header syntax
        not_pass(
            "HDR-008",
            "HSTS twice with different values",
            &[(HSTS, "max-age=1"), (HSTS, "max-age=2")],
        ),
        not_pass(
            "HDR-008",
            "max-age twice",
            &[(HSTS, "max-age=1; max-age=2")],
        ),
        not_pass(
            "HDR-008",
            "CSP directive twice",
            &[(CSP, "script-src 'self'; script-src *")],
        ),
        not_pass(
            "HDR-008",
            "Feature-Policy syntax",
            &[("Permissions-Policy", "camera 'none'")],
        ),
        not_pass(
            "HDR-008",
            "X-Frame-Options twice with different values",
            &[
                ("X-Frame-Options", "DENY"),
                ("X-Frame-Options", "SAMEORIGIN"),
            ],
        ),
    ]
}

/// HDR-007 when http:// answers with an error status.
fn error_answer_cases() -> Vec<Case> {
    // An error answer on http:// does not show that every visitor gets it (a WAF may block only scanners) or that
    // http:// normally serves nothing (5xx may be temporary).
    let mut cases = Vec::new();
    for (status, name) in [
        (400, "http:// answers 400"),
        (401, "http:// answers 401"),
        (403, "http:// answers 403 (WAF or bot block)"),
        (404, "http:// answers 404"),
        (500, "http:// answers 500"),
        (502, "http:// answers 502"),
        (503, "http:// answers 503 (temporarily unavailable)"),
        (504, "http:// answers 504"),
    ] {
        cases.push(probe(
            "HDR-007",
            name,
            Some(InsecureProbe::Responded {
                chain: vec![hop("http://example.com/", status)],
                final_url: "http://example.com/".into(),
            }),
        ));
    }
    cases
}

/// What the application sends: cookies and technology details.
fn app_cases() -> Vec<Case> {
    use Expect::Is;
    vec![
        // HDR-009 Cookies
        not_pass(
            "HDR-009",
            "Secure missing",
            &[("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax")],
        ),
        not_pass(
            "HDR-009",
            "SameSite=None without Secure",
            &[("Set-Cookie", "sid=1; HttpOnly; SameSite=None")],
        ),
        not_pass(
            "HDR-009",
            "HttpOnly missing",
            &[("Set-Cookie", "sid=1; Secure; SameSite=Lax")],
        ),
        not_pass(
            "HDR-009",
            "Secure inside the Path value",
            &[("Set-Cookie", "sid=1; Path=/Secure; HttpOnly; SameSite=Lax")],
        ),
        on_http(
            "HDR-009",
            "page served over http://",
            &[("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax")],
        ),
        not_pass(
            "HDR-009",
            "session cookie on a shared cacheable response",
            &[
                ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"),
                ("Cache-Control", "public, max-age=600"),
            ],
        ),
        case(
            "HDR-009",
            "SameSite missing is advice",
            &[("Set-Cookie", "sid=1; Secure; HttpOnly")],
            Expect::PassWithAdvice,
        ),
        // HDR-010 Technology disclosure
        not_pass("HDR-010", "X-Powered-By", &[("X-Powered-By", "Express")]),
        not_pass(
            "HDR-010",
            "Server version after /",
            &[("Server", "nginx/1.24.0")],
        ),
        not_pass(
            "HDR-010",
            "Server version after a space",
            &[("Server", "Apache 2.4.57")],
        ),
        not_pass(
            "HDR-010",
            "Server version in parentheses",
            &[("Server", "Jetty(9.4.44.v20210927)")],
        ),
        not_pass(
            "HDR-010",
            "X-Redirect-By",
            &[("X-Redirect-By", "WordPress")],
        ),
        not_pass(
            "HDR-010",
            "X-AspNet-Version",
            &[("X-AspNet-Version", "4.0.30319")],
        ),
        generator("meta generator with a version", "WordPress 6.5.2"),
        case(
            "HDR-010",
            "CDN node name is not a version",
            &[("Server", "BunnyCDN-AB1-0042")],
            Is(Status::Pass),
        ),
        case(
            "HDR-010",
            "Server name only",
            &[("Server", "cloudflare")],
            Is(Status::Pass),
        ),
        // An API version header usually names the API contract, not the software: kept PASS on purpose.
        case(
            "HDR-010",
            "generic version header",
            &[("X-App-Version", "3.2.1")],
            Is(Status::Pass),
        ),
    ]
}

#[test]
fn risky_responses_never_pass() {
    let pack = RulePack::from_toml(OFFICIAL_HEADERS_PACK).unwrap();
    let cases = cases();
    let mut wrong = Vec::new();
    for c in &cases {
        let http = HttpEvidence {
            source: format!(
                "GET {}://example.com/",
                if c.https { "https" } else { "http" }
            ),
            status: 200,
            headers: c
                .headers
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
            https: c.https,
            insecure_probe: c.probe.clone(),
            redirect_cookies: vec![],
            html_generator: c.generator.map(str::to_string),
        };
        let report = evaluate_pack(
            &pack,
            "https://example.com/",
            &EvalInput::Http(&http),
            vec![],
        );
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == c.rule)
            .unwrap();
        let ok = match c.expect {
            Expect::NotPass => {
                f.status != Status::Pass && f.reason.as_deref().is_some_and(|r| !r.is_empty())
            }
            Expect::Is(s) => f.status == s,
            Expect::PassWithAdvice => f.status == Status::Pass && f.advice.is_some(),
        };
        if !ok {
            wrong.push(format!(
                "{} {}: got {:?} ({:?})",
                c.rule, c.name, f.status, f.reason
            ));
        }
        // The summary cuts reasons at 100 characters; a cut reason hides why the result is not PASS.
        for g in &report.findings {
            if g.reason.as_deref().is_some_and(|r| r.chars().count() > 100) {
                wrong.push(format!(
                    "{} on {}: reason over 100: {:?}",
                    g.rule_id, c.name, g.reason
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Every rule in the pack has at least four risky cases, so a new rule cannot ship without its own matrix rows.
#[test]
fn every_rule_has_cases() {
    let pack = RulePack::from_toml(OFFICIAL_HEADERS_PACK).unwrap();
    let cases = cases();
    for rule in &pack.rules {
        let n = cases
            .iter()
            .filter(|c| c.rule == rule.id && matches!(c.expect, Expect::NotPass))
            .count();
        assert!(n >= 4, "{} has {n} risky cases", rule.id);
    }
}
