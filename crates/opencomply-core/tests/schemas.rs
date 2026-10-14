//! Drift guard: committed schemas in `schemas/` must equal the schemas generated from the code.
//! Regenerate with `opencomply schema rule-pack > schemas/rule-pack.schema.json` (same for `report`).

use opencomply_core::schema::{report_schema, rule_pack_schema};

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[test]
fn rule_pack_schema_is_up_to_date() {
    let committed = opencomply_core::root_file!("schemas/rule-pack.schema.json");
    assert_eq!(
        normalize(committed),
        rule_pack_schema(),
        "schemas/rule-pack.schema.json is stale — regenerate it"
    );
}

#[test]
fn report_schema_is_up_to_date() {
    let committed = opencomply_core::root_file!("schemas/report.schema.json");
    assert_eq!(
        normalize(committed),
        report_schema(),
        "schemas/report.schema.json is stale — regenerate it"
    );
}

#[test]
fn schemas_describe_key_constraints() {
    let rules = rule_pack_schema();
    for op in [
        "header_present",
        "header_absent",
        "header_equals",
        "header_contains",
        "header_one_of",
        "header_directive_at_least",
        "file_exists",
        "file_contains",
        "builtin",
    ] {
        assert!(rules.contains(&format!("\"const\": \"{op}\"")), "{op}");
    }
    assert!(rules.contains("\"additionalProperties\": false"));
    let report = report_schema();
    for field in [
        "schema_version",
        "verdict",
        "summary",
        "findings",
        "rule_packs",
        "platforms",
    ] {
        assert!(report.contains(&format!("\"{field}\"")), "{field}");
    }
}
