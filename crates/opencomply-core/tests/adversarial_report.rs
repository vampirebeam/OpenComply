//! Adversarial report tests: hostile values from a scanned site (and hostile text in every finding field) rendered in
//! every format must keep the Security Contract in `.claude/reviews/qa/qa-v0.3.6-adversarial.md` (C1–C10): no raw
//! control / invisible / bidi characters, no extra lines, inert Markdown (no link, image, autolink, HTML, extra table
//! cell or broken code span), parseable JSON, no redacted secret anywhere, site text that imitates a redaction label
//! marked as site text, homoglyphs kept as evidence. Synthetic data only; secrets are split with concat! so secret
//! scanners do not flag the source.

#![allow(clippy::unwrap_used)]

use opencomply_core::rules::{RulePack, OFFICIAL_HEADERS_PACK};
use opencomply_core::{
    detect_platforms, evaluate_pack, render_with, EvalInput, Evidence, EvidenceClass, Finding,
    Format, HttpEvidence, InsecureProbe, Module, PlatformFix, RedirectHop, RenderOptions, Report,
    Severity, Status,
};

/// C2: characters that change how text is shown without being visible.
fn invisible(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x61C | 0x180E | 0x200B..=0x200F | 0x2028 | 0x2029 | 0x202A..=0x202E
        | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0xE0000..=0xE007F)
}

const SECRETS: [&str; 5] = [
    "Sup3rS3cretTok",
    "Hunt3rS3cret9",
    "Pa55wordX",
    "S3cretPw77",
    "IOSFODNN7EXAMPLE",
];

const HOMOGLYPH: &str = "p\u{0430}ypal";

fn all_outputs(report: &Report) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, format) in [
        ("summary", Format::Summary),
        ("json", Format::Json),
        ("markdown", Format::Markdown),
    ] {
        for all in [false, true] {
            for compact in [false, true] {
                if compact && format != Format::Json {
                    continue;
                }
                out.push((
                    format!("{name} all={all} compact={compact}"),
                    render_with(report, format, RenderOptions { all, compact }),
                ));
            }
        }
    }
    out
}

/// C1, C2: no raw control character other than the renderer's own line breaks, no invisible character.
fn raw_char_violations(text: &str) -> Vec<String> {
    text.chars()
        .filter(|&c| (c.is_control() && c != '\n') || invisible(c))
        .map(|c| format!("raw U+{:04X}", c as u32))
        .collect()
}

/// Escape-aware positions of `|` that a GFM table would split on (code spans included: tables split first).
fn unescaped_pipes(line: &str) -> usize {
    let mut n = 0;
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '|' {
            n += 1;
        }
    }
    n
}

/// Text outside code spans, with each backslash escape kept as `\x`.
fn outside_code(line: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for c in line.chars() {
        if c == '`' {
            in_code = !in_code;
            out.push(' ');
        } else if !in_code {
            out.push(c);
        }
    }
    out
}

/// C4, C5, C6 on one rendered Markdown document.
fn markdown_violations(md: &str) -> Vec<String> {
    let mut bad = Vec::new();
    let lines: Vec<&str> = md.lines().collect();
    let mut table_cols: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        if line.matches('`').count() % 2 != 0 {
            bad.push(format!("C6 odd backticks: {line}"));
        }
        let text = outside_code(line);
        let chars: Vec<char> = text.chars().collect();
        let mut k = 0;
        while k < chars.len() {
            let c = chars[k];
            if c == '\\' {
                k += 2;
                continue;
            }
            if matches!(c, '[' | ']' | '<' | '>') {
                bad.push(format!("C4 unescaped {c}: {line}"));
            }
            if c == '&' {
                let rest: String = chars[k + 1..].iter().take(4).collect();
                if !(rest.starts_with("amp;") || rest.starts_with("lt;") || rest.starts_with("gt;"))
                {
                    bad.push(format!("C4 raw entity: {line}"));
                }
            }
            let alnum = |j: usize| chars.get(j).is_some_and(|ch| ch.is_alphanumeric());
            if c == '@' && k > 0 && alnum(k - 1) && alnum(k + 1) {
                bad.push(format!("C4 email autolink: {line}"));
            }
            k += 1;
        }
        let lower = text.to_lowercase();
        for (at, _) in lower.match_indices("://") {
            if lower[at + 3..]
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric)
            {
                bad.push(format!("C4 url autolink: {line}"));
            }
        }
        for (at, _) in lower.match_indices("www.") {
            let before_ok = lower[..at]
                .chars()
                .last()
                .is_none_or(|ch| !ch.is_alphanumeric());
            if before_ok
                && lower[at + 4..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric)
            {
                bad.push(format!("C4 www autolink: {line}"));
            }
        }
        // C5: a table starts at a header row followed by a `|---` separator; every row keeps the header's cell count.
        if line.starts_with('|') {
            if lines.get(i + 1).is_some_and(|n| n.starts_with("|---")) {
                table_cols = Some(unescaped_pipes(line));
            } else if let Some(cols) = table_cols {
                if unescaped_pipes(line) != cols {
                    bad.push(format!("C5 cell count: {line}"));
                }
            }
        } else {
            table_cols = None;
        }
    }
    bad
}

/// Every rule check on every output; returns what broke, labelled by output.
fn contract_violations(report: &Report) -> Vec<String> {
    let mut bad = Vec::new();
    for (name, out) in all_outputs(report) {
        let mut v = raw_char_violations(&out);
        if name.starts_with("markdown") {
            v.extend(markdown_violations(&out));
        }
        if name.starts_with("json") {
            if let Err(e) = serde_json::from_str::<serde_json::Value>(&out) {
                v.push(format!("C7 json: {e}"));
            }
        }
        for s in SECRETS {
            if out.contains(s) {
                v.push(format!("C8 secret {s} leaked"));
            }
        }
        bad.extend(v.into_iter().map(|e| format!("[{name}] {e}")));
    }
    bad
}

const HOSTILE_SERVER: &str =
    "nginx/1.24.0 \u{202E}evil\u{202C} p\u{0430}ypal [REDACTED api key] a\r\nX-Injected: 1\u{2028}b";

fn site(newline: &str, invisible_char: &str) -> HttpEvidence {
    // The plain twin turns every line break (U+2028 included) into a space; the hostile one keeps them as sent.
    let mut server = HOSTILE_SERVER
        .replace("\r\n", newline)
        .replace('\u{202E}', invisible_char);
    if newline == " " {
        server = server.replace('\u{2028}', " ");
    }
    let headers: Vec<(String, String)> = vec![
        ("Server".into(), server),
        (
            "X-Powered-By".into(),
            concat!("PHP/8.1 token=", "Sup3rS3cretTok").into(),
        ),
        (
            "Content-Security-Policy".into(),
            concat!(
                "script-src 'self' 'unsafe-inline' https://cdn.example.com/?password=",
                "Hunt3rS3cret9 https://u:",
                "Pa55wordX@cdn2.example.com https://www.evil.example [x](https://evil.example)"
            )
            .into(),
        ),
        (
            "Set-Cookie".into(),
            format!("{HOMOGLYPH}\u{202E}[x](https://evil.example)<img>{invisible_char}=v; Path=/"),
        ),
        (
            "Set-Cookie".into(),
            "u@evil.example=v; Secure; HttpOnly".into(),
        ),
        (
            "Referrer-Policy".into(),
            format!("unsafe-url{newline}| injected | cell | `code"),
        ),
        (
            "Permissions-Policy".into(),
            "camera=*, ![i](https://evil.example/i.png)=()".into(),
        ),
        (
            "Server-Timing".into(),
            "origin;desc=\"web-03.prod.internal\"".into(),
        ),
        (
            "X-Frame-Options".into(),
            format!("[ redacted cookie value ] <script>alert(1)</script>{newline}&#x27;"),
        ),
    ];
    HttpEvidence {
        source: concat!(
            "GET https://u:",
            "S3cretPw77",
            "@example.com/landing\u{202E}[x](https://evil.example)"
        )
        .into(),
        status: 200,
        headers,
        https: true,
        insecure_probe: Some(InsecureProbe::Responded {
            chain: vec![RedirectHop {
                url: "http://example.com/".into(),
                status: 200,
                location: None,
            }],
            final_url: "http://example.com/".into(),
        }),
        redirect_cookies: vec![],
        html_generator: Some(
            concat!(
                "WordPress 6.5 AKIA",
                "IOSFODNN7EXAMPLE <a href=https://evil.example>x</a>"
            )
            .into(),
        ),
    }
}

fn scan(http: &HttpEvidence) -> Report {
    let pack = RulePack::from_toml(OFFICIAL_HEADERS_PACK).unwrap();
    let platforms = detect_platforms(&http.headers, &http.source);
    evaluate_pack(
        &pack,
        concat!("https://u:", "S3cretPw77", "@example.com/\u{202E}"),
        &EvalInput::Http(http),
        platforms,
    )
}

#[test]
fn site_values_cannot_inject_into_any_format() {
    let report = scan(&site("\r\n", "\u{202E}"));
    let bad = contract_violations(&report);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// C3: line breaks inside site values add no line in any format (same line count as the same site without them).
#[test]
fn site_line_breaks_add_no_lines() {
    let hostile = scan(&site("\r\n", "\u{202E}"));
    let plain = scan(&site(" ", "x"));
    for ((name, a), (_, b)) in all_outputs(&hostile).iter().zip(all_outputs(&plain).iter()) {
        assert_eq!(a.lines().count(), b.lines().count(), "{name}\n{a}");
    }
}

/// C2, C7, C9, C10 on the exact evidence value: invisible characters shown as `<U+XXXX>`, line breaks as spaces, a
/// site-made redaction label marked as site text, homoglyphs kept.
#[test]
fn evidence_keeps_what_the_site_sent_in_visible_form() {
    let report = scan(&site("\r\n", "\u{202E}"));
    let json: serde_json::Value = serde_json::from_str(&render_with(
        &report,
        Format::Json,
        RenderOptions {
            all: true,
            compact: false,
        },
    ))
    .unwrap();
    let detail = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "HDR-010")
        .unwrap()["evidence"][0]["detail"]
        .as_str()
        .unwrap()
        .to_string();
    let expected = format!(
        "server: nginx/1.24.0 <U+202E>evil<U+202C> {HOMOGLYPH} [site text: REDACTED api key] a  X-Injected: 1<U+2028>b"
    );
    assert!(detail.starts_with(&expected), "{detail}");
    for (name, out) in all_outputs(&report) {
        assert!(out.contains(HOMOGLYPH), "{name}: homoglyph changed");
        assert!(out.contains("U+202E"), "{name}: bidi override not shown");
        assert!(
            !out.to_ascii_lowercase().contains("[redacted api key]")
                && !out.to_ascii_lowercase().contains("\\[redacted api key\\]"),
            "{name}: site-made label looks like a real one"
        );
    }
}

/// C9: the scanner's own labels stay plain, and only site text is marked. Checked where evidence is shown (JSON,
/// Markdown); the summary prints reasons, not evidence.
#[test]
fn real_redaction_labels_are_not_marked_as_site_text() {
    let report = scan(&site("\r\n", "\u{202E}"));
    for (name, out) in all_outputs(&report)
        .into_iter()
        .filter(|(n, _)| !n.starts_with("summary"))
    {
        assert!(
            out.contains("[REDACTED aws access key]")
                || out.contains("\\[REDACTED aws access key\\]"),
            "{name}: real label missing"
        );
        assert!(
            !out.contains("site text: REDACTED aws"),
            "{name}: real label marked as site text"
        );
    }
}

/// Redaction covers every field, so the official pack's own guidance (copy-ready examples with `<value>`
/// placeholders, words like "token" or "session") must come out of marking and redaction unchanged.
#[test]
fn official_guidance_is_not_redacted() {
    use opencomply_core::redact::{mark_site_labels, redact};
    let pack = RulePack::from_toml(OFFICIAL_HEADERS_PACK).unwrap();
    let mut changed = Vec::new();
    for r in &pack.rules {
        let mut texts: Vec<&str> = vec![&r.title, &r.fix_hint, &r.remediation];
        texts.extend(r.example_fix.as_deref());
        texts.extend(r.review_question.as_deref());
        texts.extend(r.upgrade_impact.as_deref());
        for g in r.platforms.values() {
            texts.push(&g.how);
            texts.extend(g.note.as_deref());
        }
        for t in texts {
            let out = redact(&mark_site_labels(t)).into_owned();
            if out != t {
                changed.push(format!("{}: {t} → {out}", r.id));
            }
        }
    }
    assert!(changed.is_empty(), "{}", changed.join("\n"));
}

fn hostile(field: &str) -> String {
    format!(
        "{field} \u{202E}x\u{200B}y\u{FEFF} [a](https://evil.example) ![i](https://evil.example/i.png) <img src=x onerror=alert(1)> &#x27; | cell | `tick` www.evil.example a@evil.example [REDACTED api key]\r\nnext: {}",
        concat!("password=", "Hunt3rS3cret9")
    )
}

fn finding(status: Status) -> Finding {
    Finding {
        rule_id: hostile("id"),
        rule_version: hostile("v"),
        title: hostile("title"),
        status,
        severity: Severity::High,
        evidence: vec![Evidence {
            class: EvidenceClass::Verified,
            source: hostile("source"),
            detail: hostile("detail"),
        }],
        reason: Some(hostile("reason")),
        fix_hint: Some(hostile("fix")),
        example_fix: Some(hostile("example")),
        platform_fixes: vec![PlatformFix {
            platform: hostile("platform"),
            how: hostile("how"),
            note: Some(hostile("note")),
            preferred: true,
        }],
        review_question: Some(hostile("question")),
        remediation: Some(hostile("remediation")),
        advice: Some(hostile("advice")),
        effort: None,
        depends_on: vec![hostile("dep")],
        group: Some(hostile("group")),
    }
}

/// Every text field of a finding (custom packs and future scanners can put anything there) keeps the contract.
#[test]
fn every_text_field_keeps_the_contract() {
    let report = Report::new(
        Module::Headers,
        hostile("target"),
        vec![
            finding(Status::Fail),
            finding(Status::NeedsReview),
            finding(Status::Pass),
        ],
    )
    .with_rule_pack(hostile("pack"), hostile("1.0"));
    let bad = contract_violations(&report);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
