//! Secret redaction applied to every rendered report (summary, JSON, Markdown): evidence, reasons and platform
//! evidence pass through `redact` so tokens, keys, passwords and session cookies never leave the scanner.
//! Uses the `regex` crate (linear-time, no catastrophic backtracking). Labels keep the kind and, where safe, the
//! key name, so a reader still knows *what* was found without seeing the value.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Captures, Regex, RegexBuilder};

use crate::report::Report;

struct Pattern {
    kind: &'static str,
    re: Regex,
    /// Capture group holding the secret; other text in the match is kept.
    group: usize,
}

fn compile(kind: &'static str, pattern: &str, group: usize) -> Option<Pattern> {
    RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .ok()
        .map(|re| Pattern { kind, re, group })
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    [
        ("private key", r"(?s)(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)", 1),
        ("url credentials", r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@", 1),
        (
            "wp-config secret",
            r#"(?i)define\(\s*['"](?:DB_PASSWORD|(?:SECURE_)?AUTH_(?:KEY|SALT)|LOGGED_IN_(?:KEY|SALT)|NONCE_(?:KEY|SALT))['"]\s*,\s*['"]([^'"]*)['"]"#,
            1,
        ),
        // A whole `<name>` placeholder (a copy-ready example such as `session=<value>`) is matched first and kept.
        (
            "cookie value",
            r"(?i)\b(?:set-cookie|cookie)\s*:\s*[^=;\s]+=(?:<[A-Za-z0-9_-]+>(?:[;\s]|$)|([^;\s]+))",
            1,
        ),
        ("authorization", r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{12,})", 1),
        ("aws access key", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", 1),
        ("github token", r"\b((?:gh[pousr]_[A-Za-z0-9]{36,})|github_pat_[A-Za-z0-9_]{50,})", 1),
        ("slack token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,})", 1),
        ("stripe key", r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})", 1),
        ("google api key", r"\b(AIza[0-9A-Za-z_-]{35})", 1),
        ("api key", r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})", 1),
        ("jwt", r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})", 1),
        (
            "credential",
            r#"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\s*[=:]\s*['"]?([^'"\s;,&\[][^'"\s;,&]{3,})"#,
            1,
        ),
    ]
    .into_iter()
    .filter_map(|(kind, pattern, group)| compile(kind, pattern, group))
    .collect()
});

static SITE_LABEL: LazyLock<Option<Regex>> =
    LazyLock::new(|| RegexBuilder::new(r"(?i)\[\s*redacted\b").build().ok());

/// Marks text that imitates one of our labels (`[REDACTED …]`, any case or spacing) as `[site text: REDACTED …]`, so a
/// reader can tell the scanner's labels from the site's. Run once on captured text, before `redact` — never on text
/// `redact` has already labelled (it would mark the scanner's own labels).
pub fn mark_site_labels(text: &str) -> Cow<'_, str> {
    match SITE_LABEL.as_ref() {
        Some(re) if re.is_match(text) => {
            Cow::Owned(re.replace_all(text, "[site text: REDACTED").into_owned())
        }
        _ => Cow::Borrowed(text),
    }
}

/// Replaces secrets with `[REDACTED <kind>]`. Idempotent. Returns the input unchanged (no allocation) when nothing
/// matches.
pub fn redact(text: &str) -> Cow<'_, str> {
    let mut out: Cow<'_, str> = Cow::Borrowed(text);
    for p in PATTERNS.iter() {
        if !p.re.is_match(&out) {
            continue;
        }
        let replaced =
            p.re.replace_all(&out, |caps: &Captures<'_>| {
                let whole = caps.get(0).map_or("", |m| m.as_str());
                match caps.get(p.group) {
                    Some(secret) => {
                        let start = secret.start() - caps.get(0).map_or(0, |m| m.start());
                        let end = start + secret.len();
                        format!("{}[REDACTED {}]{}", &whole[..start], p.kind, &whole[end..])
                    }
                    None => whole.to_string(),
                }
            })
            .into_owned();
        // A match can keep everything (a `<value>` placeholder): then the input stays borrowed.
        if replaced != *out {
            out = Cow::Owned(replaced);
        }
    }
    out
}

/// Copy of the report with every text field marked (`mark_site_labels`) and redacted: besides evidence, checks build
/// reasons, advice and examples from site values (a CSP example keeps the site's own sources), and custom packs can
/// put anything in the rest. Takes the unredacted report (rendering calls it once).
pub fn redact_report(report: &Report) -> Report {
    fn red(s: &mut String) {
        let marked = mark_site_labels(s);
        if let Cow::Owned(v) = redact(&marked) {
            *s = v;
        } else if let Cow::Owned(v) = marked {
            *s = v;
        }
    }
    fn red_opt(s: &mut Option<String>) {
        if let Some(v) = s {
            red(v);
        }
    }
    let mut r = report.clone();
    red(&mut r.target);
    for f in &mut r.findings {
        red(&mut f.rule_id);
        red(&mut f.rule_version);
        red(&mut f.title);
        for e in &mut f.evidence {
            red(&mut e.source);
            red(&mut e.detail);
        }
        red_opt(&mut f.reason);
        red_opt(&mut f.fix_hint);
        red_opt(&mut f.example_fix);
        red_opt(&mut f.review_question);
        red_opt(&mut f.remediation);
        red_opt(&mut f.advice);
        red_opt(&mut f.group);
        f.depends_on.iter_mut().for_each(red);
        for p in &mut f.platform_fixes {
            red(&mut p.platform);
            red(&mut p.how);
            red_opt(&mut p.note);
        }
    }
    for p in &mut r.platforms {
        red(&mut p.evidence.source);
        red(&mut p.evidence.detail);
    }
    for p in &mut r.rule_packs {
        red(&mut p.id);
        red(&mut p.version);
        red_opt(&mut p.signed_by);
    }
    if let Some(g) = &mut r.grade {
        g.capped_by.iter_mut().for_each(red);
        for s in g.upgrades.iter_mut().flat_map(|u| &mut u.steps) {
            red(&mut s.rule_id);
            red_opt(&mut s.impact);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic secrets are split with concat! so secret scanners do not flag the source; the tested value is unchanged.
    #[test]
    fn redacts_known_secret_formats() {
        let cases = [
            (
                concat!("key AKIA", "IOSFODNN7EXAMPLE used"),
                "key [REDACTED aws access key] used",
            ),
            (
                concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyzAB"),
                "[REDACTED github token]",
            ),
            (
                concat!("xoxb-", "1234567890-abcdefghij"),
                "[REDACTED slack token]",
            ),
            (
                concat!("sk_live_", "0123456789abcdefABCD"),
                "[REDACTED stripe key]",
            ),
            (
                concat!("AIza", "SyA0123456789abcdefghijklmnopqrstuv"),
                "[REDACTED google api key]",
            ),
            (
                concat!("sk-ant-", "api03-abcdefghijklmnopqrstuvwx"),
                "[REDACTED api key]",
            ),
            (
                concat!(
                    "eyJhbGciOiJIUzI1NiJ9.",
                    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
                    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
                ),
                "[REDACTED jwt]",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(redact(input), expected, "{input}");
        }
    }

    #[test]
    fn keeps_context_but_hides_value() {
        assert_eq!(
            redact("set-cookie: laravelcom_session=eyJpdiI6IjEyMyJ9; path=/"),
            "set-cookie: laravelcom_session=[REDACTED cookie value]; path=/"
        );
        assert_eq!(
            redact("https://admin:hunter22@db.example.com/x"),
            "https://admin:[REDACTED url credentials]@db.example.com/x"
        );
        assert_eq!(
            redact("Authorization: Bearer abcdefghijklmnop.qrst"),
            "Authorization: Bearer [REDACTED authorization]"
        );
        assert_eq!(
            redact("DB password=S3cr3t!x;"),
            "DB password=[REDACTED credential];"
        );
        // A cookie named like a credential is redacted once, not re-labelled by the credential pattern.
        assert_eq!(
            redact("set-cookie: XSRF-TOKEN=eyJpdiI6IjEyMyJ9abc"),
            "set-cookie: XSRF-TOKEN=[REDACTED cookie value]"
        );
        // Only a whole placeholder is kept: a value that merely starts like one is still a value.
        assert_eq!(
            redact("set-cookie: sid=<value>SECRET1; Path=/"),
            "set-cookie: sid=[REDACTED cookie value]; Path=/"
        );
        assert_eq!(
            redact("define( 'DB_PASSWORD', 'p@ss w0rd' );"),
            "define( 'DB_PASSWORD', '[REDACTED wp-config secret]' );"
        );
    }

    #[test]
    fn site_text_that_imitates_a_label_is_marked() {
        for (input, expected) in [
            (
                "x [REDACTED api key] y",
                "x [site text: REDACTED api key] y",
            ),
            (
                "[ redacted cookie value ]",
                "[site text: REDACTED cookie value ]",
            ),
            ("[Redacted]", "[site text: REDACTED]"),
        ] {
            assert_eq!(mark_site_labels(input), expected, "{input}");
        }
        assert!(matches!(
            mark_site_labels("[REDACTEDX] redacted"),
            Cow::Borrowed(_)
        ));
        // Marking first, then redacting: the scanner's own label stays plain.
        let both = redact(&mark_site_labels(concat!(
            "[REDACTED x] AKIA",
            "IOSFODNN7EXAMPLE"
        )))
        .into_owned();
        assert_eq!(both, "[site text: REDACTED x] [REDACTED aws access key]");
    }

    #[test]
    fn redacts_private_key_blocks() {
        let pem = concat!(
            "x -----BEGIN RSA PRIVATE",
            " KEY-----\nMIIabc\n-----END RSA PRIVATE",
            " KEY----- y"
        );
        assert_eq!(redact(pem), "x [REDACTED private key] y");
    }

    #[test]
    fn leaves_ordinary_security_text_alone() {
        for text in [
            "Strict-Transport-Security: max-age=63072000; includeSubDomains",
            "script-src 'self' 'nonce-<per-response-random>'",
            "CF-RAY: a4a635d208c575d8-BKK",
            "password policy requires 12 characters",
            "token bucket rate limiting",
            "x-powered-by: Next.js",
            "Set-Cookie: session=<value>; Path=/; Secure; HttpOnly; SameSite=Lax",
            "Set-Cookie: session=<value>",
        ] {
            assert!(matches!(redact(text), Cow::Borrowed(_)), "{text}");
        }
    }

    #[test]
    fn report_fields_are_redacted() {
        use crate::finding::{Evidence, EvidenceClass, Finding, Module, Severity, Status};
        use crate::platform::detect_platforms;
        let headers = vec![(
            "set-cookie".to_string(),
            "laravel_session=eyJpdiI6IjEyMyJ9".to_string(),
        )];
        let finding = Finding {
            rule_id: "HDR-009".into(),
            rule_version: "1.0.0".into(),
            title: "Cookie security".into(),
            status: Status::Fail,
            severity: Severity::Medium,
            evidence: vec![Evidence {
                class: EvidenceClass::Verified,
                source: "GET https://u:pw12345@example.com/".into(),
                detail: "Set-Cookie: sid=abcdef123456; Path=/".into(),
                truncated: false,
            }],
            reason: Some("token=abcd1234 found".into()),
            fix_hint: None,
            example_fix: None,
            platform_fixes: vec![],
            review_question: None,
            remediation: None,
            advice: Some("password=hunter2xyz".into()),
            effort: None,
            depends_on: vec![],
            group: None,
        };
        let r = Report::new(Module::Headers, "https://example.com", vec![finding])
            .with_platforms(detect_platforms(&headers, "GET x"));
        let red = redact_report(&r);
        let all = format!("{red:?}");
        for secret in [
            "eyJpdiI6IjEyMyJ9",
            "abcdef123456",
            "pw12345",
            "abcd1234",
            "hunter2xyz",
        ] {
            assert!(!all.contains(secret), "{secret} leaked");
        }
    }
}
