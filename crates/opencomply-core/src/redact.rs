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
        ("cookie value", r"(?i)\b(?:set-cookie|cookie)\s*:\s*[^=;\s]+=([^;\s]+)", 1),
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
            r#"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\s*[=:]\s*['"]?([^'"\s;,&]{4,})"#,
            1,
        ),
    ]
    .into_iter()
    .filter_map(|(kind, pattern, group)| compile(kind, pattern, group))
    .collect()
});

/// Replaces secrets with `[REDACTED <kind>]`. Returns the input unchanged (no allocation) when nothing matches.
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
        out = Cow::Owned(replaced);
    }
    out
}

/// Copy of the report with every free-text field that can carry captured data redacted.
pub fn redact_report(report: &Report) -> Report {
    let mut r = report.clone();
    r.target = redact(&r.target).into_owned();
    for f in &mut r.findings {
        for e in &mut f.evidence {
            e.source = redact(&e.source).into_owned();
            e.detail = redact(&e.detail).into_owned();
        }
        if let Some(reason) = &f.reason {
            f.reason = Some(redact(reason).into_owned());
        }
        if let Some(advice) = &f.advice {
            f.advice = Some(redact(advice).into_owned());
        }
    }
    for p in &mut r.platforms {
        p.evidence.detail = redact(&p.evidence.detail).into_owned();
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
        assert_eq!(
            redact("define( 'DB_PASSWORD', 'p@ss w0rd' );"),
            "define( 'DB_PASSWORD', '[REDACTED wp-config secret]' );"
        );
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
