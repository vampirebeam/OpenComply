//! `opencomply standards`: text and JSON list the same released modules, and no public output (standards, help,
//! published schemas) names a module that is not released (T37).

#![allow(clippy::unwrap_used)]

use std::process::Command;

use opencomply_core::{Module, RELEASED};

fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_opencomply"))
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// Words that would reveal an unreleased module: its id, its standard's name and its rule prefix.
fn unreleased_words() -> Vec<String> {
    Module::ALL
        .iter()
        .filter(|m| !RELEASED.contains(m))
        .flat_map(|m| {
            let s = m.standard();
            [
                m.name().to_string(),
                s.name.to_string(),
                format!("{}-", s.rule_prefix),
            ]
        })
        .collect()
}

#[test]
fn text_and_json_list_the_same_released_modules() {
    let text = run(&["standards"]);
    let json: serde_json::Value =
        serde_json::from_str(&run(&["standards", "--format", "json"])).unwrap();
    assert_eq!(json["standards_schema"], 1);
    assert_eq!(json["scanner_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        json["report_schema"],
        opencomply_core::REPORT_SCHEMA_VERSION
    );
    let listed: Vec<&str> = json["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["module"].as_str().unwrap())
        .collect();
    let released: Vec<&str> = RELEASED.iter().map(|m| m.name()).collect();
    assert_eq!(listed, released);
    for m in json["modules"].as_array().unwrap() {
        let line = format!(
            "{} {} {} prefix={}",
            m["module"].as_str().unwrap(),
            m["name"].as_str().unwrap(),
            m["edition"].as_str().unwrap(),
            m["rule_prefix"].as_str().unwrap()
        );
        assert!(text.contains(&line), "{line}\n{text}");
    }
    assert_eq!(text.lines().count(), 1 + RELEASED.len(), "{text}");
}

#[test]
fn public_output_names_no_unreleased_module() {
    let schemas = [
        opencomply_core::root_file!("schemas/report.schema.json"),
        opencomply_core::root_file!("schemas/rule-pack.schema.json"),
        opencomply_core::root_file!("schemas/standards.schema.json"),
    ];
    let outputs = [
        run(&["standards"]),
        run(&["standards", "--format", "json"]),
        run(&["--help"]),
        run(&["scan", "--help"]),
        run(&["standards", "--help"]),
        run(&["schema", "standards"]),
    ];
    let words = unreleased_words();
    assert!(!words.is_empty());
    for text in outputs.iter().map(String::as_str).chain(schemas) {
        for w in &words {
            assert!(!text.contains(&format!("\"{w}\"")), "{w}");
            assert!(!text.contains(&format!(" {w} ")), "{w}");
        }
        assert!(!text.contains("readiness"), "readiness");
    }
}
