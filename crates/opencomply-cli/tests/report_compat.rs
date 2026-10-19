//! JSON report contract (`--format json` is the API for other plugins and agents): reports produced by the real
//! renderer of earlier releases (`tests/compat/`, synthetic example.com data from tagged README / docs / golden files)
//! and of this build must all read with a consumer that knows only the fields `OUTPUT.md` promises. New fields are
//! optional and never break such a consumer; a higher `schema_version` is not assumed compatible (fail closed, T36).

#![allow(clippy::unwrap_used)]

use std::process::Command;

use serde::Deserialize;

/// The fields `plugins/opencomply/skills/opencomply/reference/OUTPUT.md` tells an agent to read. Unknown fields are
/// ignored, as any tolerant consumer would.
#[derive(Deserialize)]
struct Consumer {
    schema_version: u32,
    scanner_version: String,
    module: String,
    target: String,
    verdict: String,
    grade: Option<Grade>,
    summary: Summary,
    findings: Vec<ConsumerFinding>,
}

#[derive(Deserialize)]
struct Grade {
    grade: String,
}

#[derive(Deserialize)]
struct Summary {
    pass: u32,
    fail: u32,
}

#[derive(Deserialize)]
struct ConsumerFinding {
    rule_id: String,
    status: String,
    severity: String,
    evidence: Vec<ConsumerEvidence>,
}

#[derive(Deserialize)]
struct ConsumerEvidence {
    source: String,
}

/// The highest `schema_version` this contract describes; a consumer must not trust grades above it.
const SUPPORTED_SCHEMA: u32 = 1;

fn read(json: &str) -> Consumer {
    let c: Consumer = serde_json::from_str(json).unwrap();
    assert!(!c.scanner_version.is_empty() && !c.target.is_empty());
    assert_eq!(c.module, "headers");
    assert!(
        ["pass", "fail", "review", "incomplete"].contains(&c.verdict.as_str()),
        "{}",
        c.verdict
    );
    for f in &c.findings {
        assert!(f.rule_id.starts_with("HDR-"), "{}", f.rule_id);
        assert!(!f.status.is_empty() && !f.severity.is_empty());
        assert!(f.evidence.iter().all(|e| !e.source.is_empty()) || f.evidence.is_empty());
    }
    c
}

const EARLIER: [(&str, &str); 7] = [
    ("v0.1.0 README", include_str!("compat/readme-v0.1.0.json")),
    ("v0.2.4 README", include_str!("compat/readme-v0.2.4.json")),
    ("v0.3.0 README", include_str!("compat/readme-v0.3.0.json")),
    (
        "v0.3.5 REPORTS",
        include_str!("compat/reports-doc-v0.3.5.json"),
    ),
    (
        "v0.3.10 golden",
        include_str!("compat/golden-v0.3.10-report-all.json"),
    ),
    (
        "v0.3.10 golden compact",
        include_str!("compat/golden-v0.3.10-report-compact.json"),
    ),
    (
        "v0.3.11 REPORTS",
        include_str!("compat/reports-doc-v0.3.11.json"),
    ),
];

#[test]
fn reports_of_earlier_releases_still_read() {
    for (name, json) in EARLIER {
        let c = read(json);
        assert_eq!(c.schema_version, SUPPORTED_SCHEMA, "{name}");
        assert!(c.grade.is_some_and(|g| !g.grade.is_empty()), "{name}");
        assert!(c.summary.pass + c.summary.fail > 0, "{name}");
    }
}

#[test]
fn this_build_still_reads_and_keeps_the_schema_version() {
    let schema = opencomply_core::schema::report_schema();
    let v: serde_json::Value = serde_json::from_str(&schema).unwrap();
    for field in [
        "schema_version",
        "scanner_version",
        "module",
        "target",
        "verdict",
        "summary",
        "findings",
    ] {
        assert!(
            v["required"].as_array().unwrap().iter().any(|r| r == field),
            "{field} must stay required"
        );
    }
    assert_eq!(opencomply_core::REPORT_SCHEMA_VERSION, SUPPORTED_SCHEMA);
    let out = Command::new(env!("CARGO_BIN_EXE_opencomply"))
        .args(["standards", "--format", "json"])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["report_schema"], SUPPORTED_SCHEMA);
}

#[test]
fn a_new_optional_field_does_not_break_a_consumer() {
    let mut v: serde_json::Value = serde_json::from_str(EARLIER[4].1).unwrap();
    v["some_future_field"] = serde_json::json!({"x": 1});
    v["findings"][0]["another_future_field"] = serde_json::json!("y");
    read(&v.to_string());
}

#[test]
fn output_contract_tells_agents_to_fail_closed_on_a_newer_schema() {
    let output =
        opencomply_core::root_file!("plugins/opencomply/skills/opencomply/reference/OUTPUT.md");
    assert!(
        output.contains(&format!("`schema_version` {SUPPORTED_SCHEMA}")),
        "OUTPUT.md must name the supported schema"
    );
    assert!(
        output.contains("do not state a grade, verdict, PASS or FAIL"),
        "OUTPUT.md must say what to do on a newer schema"
    );
}
