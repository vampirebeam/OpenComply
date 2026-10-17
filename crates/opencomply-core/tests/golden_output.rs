//! Golden output: one fixed synthetic site (example.com) through the official pack, rendered in every format and
//! compared byte for byte with `tests/golden/`. A change to checks, grading, ordering, wording or the pack shows up as
//! a diff of these files, so a release can compare its output with the previous version's.
//! Deterministic: nothing depends on time, the machine or the build — the scanner version and the pack's signer are
//! pinned below (the pack checksum is real, so a pack edit is visible), the input order is fixed, and files are LF.
//! Update after an intended change: review why the output differs first, then
//! `OPENCOMPLY_BLESS=1 cargo test -p opencomply-core --test golden_output` and review the file diff again.
//! Scope: a regression baseline for one fixed site — not evidence that every rule or security scenario is covered
//! (`fn_matrix.rs`, `adversarial_report.rs` do that). `signed_by` is pinned text here; signatures are verified only
//! in `official_signature.rs`.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use opencomply_core::rules::{RulePack, OFFICIAL_HEADERS_PACK};
use opencomply_core::signing::sha256_hex;
use opencomply_core::{
    detect_from_html, detect_platforms, evaluate_pack, merge_platforms, meta_generator,
    render_with, EvalInput, Format, HttpEvidence, InsecureProbe, RedirectHop, RenderOptions,
    Report, RulePackRef,
};

const PINNED_VERSION: &str = "0.0.0-golden";
const PINNED_SIGNER: &str = "opencomply-2026";
const HTML: &str = r#"<html><head><meta name="generator" content="WordPress 6.5.2"><link rel="stylesheet" href="/wp-content/themes/x.css"></head></html>"#;

fn site() -> HttpEvidence {
    let headers: Vec<(String, String)> = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Server", "nginx/1.24.0"),
        ("X-Powered-By", "PHP/8.2.1"),
        ("Strict-Transport-Security", "max-age=31536000"),
        (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com",
        ),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=*, geolocation=()"),
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Set-Cookie", "sid=abc123; Path=/; Secure; HttpOnly"),
        ("Set-Cookie", "theme=dark; Path=/; Secure; SameSite=Lax"),
        ("CF-Ray", "0123456789abcdef-BKK"),
    ]
    .iter()
    .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
    .collect();
    HttpEvidence {
        source: "GET https://example.com/".into(),
        status: 200,
        headers,
        https: true,
        insecure_probe: Some(InsecureProbe::Responded {
            chain: vec![
                RedirectHop {
                    url: "http://example.com/".into(),
                    status: 302,
                    location: Some("https://example.com/".into()),
                },
                RedirectHop {
                    url: "https://example.com/".into(),
                    status: 200,
                    location: None,
                },
            ],
            final_url: "https://example.com/".into(),
        }),
        redirect_cookies: vec![],
        html_generator: meta_generator(HTML),
    }
}

/// The report a scan of `site()` produces, with the build-dependent fields pinned.
fn report() -> Report {
    let http = site();
    let pack = RulePack::from_toml(OFFICIAL_HEADERS_PACK).unwrap();
    let platforms = merge_platforms(
        detect_platforms(&http.headers, &http.source),
        detect_from_html(HTML, &http.source),
    );
    let mut r = evaluate_pack(
        &pack,
        "https://example.com/",
        &EvalInput::Http(&http),
        platforms,
    );
    r.scanner_version = PINNED_VERSION.into();
    r.rule_packs = vec![RulePackRef {
        id: pack.pack.id.clone(),
        version: pack.pack.version.clone(),
        sha256: Some(sha256_hex(OFFICIAL_HEADERS_PACK.as_bytes())),
        signed_by: Some(PINNED_SIGNER.into()),
    }];
    r
}

fn outputs(r: &Report) -> Vec<(&'static str, String)> {
    let opts = |all, compact| RenderOptions { all, compact };
    vec![
        (
            "summary.txt",
            render_with(r, Format::Summary, opts(false, false)),
        ),
        (
            "summary-all.txt",
            render_with(r, Format::Summary, opts(true, false)),
        ),
        (
            "report.json",
            render_with(r, Format::Json, opts(false, false)),
        ),
        (
            "report-all.json",
            render_with(r, Format::Json, opts(true, false)),
        ),
        (
            "report-compact.json",
            render_with(r, Format::Json, opts(false, true)),
        ),
        (
            "report.md",
            render_with(r, Format::Markdown, opts(false, false)),
        ),
        (
            "report-all.md",
            render_with(r, Format::Markdown, opts(true, false)),
        ),
    ]
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
}

#[test]
fn output_matches_golden_files() {
    let bless = std::env::var_os("OPENCOMPLY_BLESS").is_some();
    let mut wrong = Vec::new();
    for (name, out) in outputs(&report()) {
        let path = golden_dir().join(name);
        if bless {
            std::fs::create_dir_all(golden_dir()).unwrap();
            std::fs::write(&path, &out).unwrap();
            continue;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (run with OPENCOMPLY_BLESS=1)", path.display()));
        if expected != out {
            let line = expected
                .lines()
                .zip(out.lines())
                .position(|(a, b)| a != b)
                .map_or_else(
                    || {
                        format!(
                            "line count {} → {}",
                            expected.lines().count(),
                            out.lines().count()
                        )
                    },
                    |i| {
                        format!(
                            "line {}:\n  golden: {}\n  now:    {}",
                            i + 1,
                            expected.lines().nth(i).unwrap_or(""),
                            out.lines().nth(i).unwrap_or("")
                        )
                    },
                );
            wrong.push(format!("{name} differs at {line}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The golden JSON records the checksum of the pack this build embeds: any pack edit fails here with its own message,
/// even when the edit changes no other output, so it is reviewed before the files are blessed again.
#[test]
fn golden_records_the_current_pack_checksum() {
    if std::env::var_os("OPENCOMPLY_BLESS").is_some() {
        return;
    }
    let golden: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(golden_dir().join("report.json")).unwrap())
            .unwrap();
    let recorded = golden["rule_packs"][0]["sha256"].as_str().unwrap_or("");
    let current = sha256_hex(OFFICIAL_HEADERS_PACK.as_bytes());
    assert_eq!(
        recorded, current,
        "the official pack changed since the golden files were made: review the pack diff, then bless"
    );
}

/// Same input → same bytes, every time (no hash-map order, clock or allocation dependence).
#[test]
fn rendering_is_deterministic() {
    let first = outputs(&report());
    for _ in 0..20 {
        assert_eq!(outputs(&report()), first);
    }
    let handles: Vec<_> = (0..4)
        .map(|_| std::thread::spawn(|| outputs(&report())))
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), first);
    }
}

/// The pinned fields are the only build-dependent values: nothing else in the output names this build.
#[test]
fn golden_output_names_no_build_specific_value() {
    for (name, out) in outputs(&report()) {
        assert!(
            !out.contains(opencomply_core::SCANNER_VERSION)
                || opencomply_core::SCANNER_VERSION == PINNED_VERSION,
            "{name} contains the real scanner version"
        );
        for local in ["/workspace", "/target", "\\Users\\", "/home/"] {
            assert!(!out.contains(local), "{name} contains a local path {local}");
        }
    }
}
