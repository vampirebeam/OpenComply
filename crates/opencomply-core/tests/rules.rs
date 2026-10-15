//! Rule pack schema tests: valid pack loads; unknown fields/operators, bad ids, cross-module operators, path traversal,
//! oversize text and oversize input are all rejected.

use opencomply_core::rules::{Check, LoadError, RulePack, MAX_PACK_BYTES};

const VALID: &str = r#"
[pack]
id = "test-headers"
version = "1.0.0"
module = "headers"

[[rule]]
id = "HDR-001"
version = "1.0.0"
title = "Strict-Transport-Security"
severity = "high"
mandatory = true
weight = 20
fix_hint = "add Strict-Transport-Security with a long max-age"
remediation = "Send Strict-Transport-Security on every HTTPS response."
check = { op = "header_directive_at_least", header = "strict-transport-security", directive = "max-age", min = 31536000 }

[[rule]]
id = "HDR-003"
version = "1.0.0"
title = "X-Content-Type-Options"
severity = "medium"
weight = 10
fix_hint = "add X-Content-Type-Options: nosniff"
remediation = "Send X-Content-Type-Options: nosniff."
check = { op = "header_equals", header = "x-content-type-options", value = "nosniff" }
"#;

fn issues(src: &str) -> Vec<String> {
    match RulePack::from_toml(src) {
        Err(LoadError::Invalid(issues)) => issues.iter().map(ToString::to_string).collect(),
        other => vec![format!("unexpected result: {other:?}")],
    }
}

#[test]
fn valid_pack_loads() {
    let pack = RulePack::from_toml(VALID).unwrap();
    assert_eq!(pack.rules.len(), 2);
    assert!(pack.rules[0].mandatory);
    assert!(matches!(
        pack.rules[0].check,
        Check::HeaderDirectiveAtLeast {
            min: 31_536_000,
            ..
        }
    ));
}

#[test]
fn unknown_operator_is_rejected_at_parse() {
    let src = VALID.replace("header_equals", "run_script");
    assert!(matches!(
        RulePack::from_toml(&src),
        Err(LoadError::Parse(_))
    ));
}

#[test]
fn unknown_field_is_rejected_at_parse() {
    let src = VALID.replace("weight = 10", "weight = 10\ncommand = \"rm -rf /\"");
    assert!(matches!(
        RulePack::from_toml(&src),
        Err(LoadError::Parse(_))
    ));
}

#[test]
fn semantic_problems_are_all_reported() {
    let src = VALID
        .replace("HDR-003", "HDR-001")
        .replace(
            "version = \"1.0.0\"\ntitle = \"X",
            "version = \"1.0\"\ntitle = \"X",
        )
        .replace("weight = 10", "weight = 150");
    let found = issues(&src);
    assert!(
        found.iter().any(|i| i.contains("duplicate rule id")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|i| i.contains("MAJOR.MINOR.PATCH")),
        "{found:?}"
    );
    assert!(found.iter().any(|i| i.contains("0–100")), "{found:?}");
}

/// `effort`, `depends_on` and `group` are optional; dependencies must name another rule of the pack without a cycle.
#[test]
fn work_order_fields_are_validated() {
    let with = |a: &str, b: &str| {
        VALID
            .replace("weight = 20", &format!("weight = 20\n{a}"))
            .replace("weight = 10", &format!("weight = 10\n{b}"))
    };
    let ok = RulePack::from_toml(&with(
        "effort = \"moderate\"\ndepends_on = [\"HDR-003\"]\ngroup = \"response-headers\"",
        "effort = \"quick\"\ngroup = \"response-headers\"",
    ))
    .unwrap();
    assert_eq!(ok.rules[0].depends_on, ["HDR-003"]);
    assert_eq!(ok.rules[1].effort, Some(opencomply_core::Effort::Quick));
    assert!(matches!(
        RulePack::from_toml(&with("effort = \"hard\"", "")),
        Err(LoadError::Parse(_))
    ));
    let cycle = issues(&with(
        "depends_on = [\"HDR-003\"]",
        "depends_on = [\"HDR-001\"]",
    ));
    assert!(
        cycle
            .iter()
            .filter(|i| i.contains("dependency cycle"))
            .count()
            == 2,
        "{cycle:?}"
    );
    let bad = issues(&with(
        "depends_on = [\"HDR-001\", \"HDR-009\"]\ngroup = \"Response Headers!\"",
        "",
    ));
    assert!(
        bad.iter().any(|i| i.contains("cannot depend on itself")),
        "{bad:?}"
    );
    assert!(
        bad.iter().any(|i| i.contains("no rule with this id")),
        "{bad:?}"
    );
    assert!(bad.iter().any(|i| i.contains(".group")), "{bad:?}");
}

#[test]
fn bad_id_and_cross_module_operator_are_rejected() {
    let src = VALID.replace("HDR-003", "TLS-003").replace(
        "{ op = \"header_equals\", header = \"x-content-type-options\", value = \"nosniff\" }",
        "{ op = \"file_exists\", path = \"SECURITY.md\" }",
    );
    let found = issues(&src);
    assert!(found.iter().any(|i| i.contains("HDR-001")), "{found:?}");
    assert!(
        found
            .iter()
            .any(|i| i.contains("not allowed for module 'headers'")),
        "{found:?}"
    );
}

#[test]
fn path_traversal_is_rejected() {
    let src = r#"
[pack]
id = "test-iso"
version = "1.0.0"
module = "iso27001"

[[rule]]
id = "ISO27-001"
version = "1.0.0"
title = "Security policy"
severity = "medium"
weight = 5
fix_hint = "add a SECURITY.md"
remediation = "Document the security policy."
check = { op = "file_exists", path = "../../etc/passwd" }
"#;
    assert!(issues(src).iter().any(|i| i.contains("relative path")));
}

#[test]
fn long_fix_hint_and_control_chars_are_rejected() {
    let long = "x".repeat(200);
    let src = VALID
        .replace("add X-Content-Type-Options: nosniff", &long)
        .replace("Send X-Content-Type-Options: nosniff.", "line1\\nline2");
    let found = issues(&src);
    assert!(
        found.iter().any(|i| i.contains("fix_hint: longer than")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|i| i.contains("control characters")),
        "{found:?}"
    );
}

#[test]
fn oversize_input_is_rejected_before_parsing() {
    let big = "#".repeat(MAX_PACK_BYTES + 1);
    assert!(matches!(
        RulePack::from_toml(&big),
        Err(LoadError::TooLarge { .. })
    ));
}
