//! Plugin layout: one skill (`opencomply`, the router) and nothing else that can start a scan. The former
//! `security-headers` alias is gone, so a request can never be routed through two skills and scanned twice.

#![allow(clippy::unwrap_used)]

use std::path::Path;

#[test]
fn only_the_router_skill_exists() {
    let skills = Path::new(env!("OPENCOMPLY_ROOT")).join("plugins/opencomply/skills");
    let mut names: Vec<String> = std::fs::read_dir(&skills)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["opencomply"], "skills: {names:?}");
    let skill = opencomply_core::root_file!("plugins/opencomply/skills/opencomply/SKILL.md");
    assert!(skill.contains("name: opencomply"));
    assert!(
        skill.contains("opencomply standards --format json"),
        "router must ask the CLI what it checks"
    );
}
