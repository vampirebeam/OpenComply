//! JSON Schemas generated from the exact types the scanner parses (rule packs) and emits (`--format json`), so the
//! published schemas cannot drift from the code. Committed copies live in `schemas/`; a test fails if they differ.
//! Published schemas name only released modules (`RELEASED`): unreleased ones are internal scaffolding.

use schemars::{schema_for, Schema};

use crate::render::JsonReport;
use crate::rules::RulePack;
use crate::standards::{released_standards, StandardsDoc, RELEASED};

fn pretty(schema: &Schema) -> String {
    let mut value = schema.as_value().clone();
    if let Some(names) = value
        .pointer_mut("/$defs/Module/enum")
        .and_then(|v| v.as_array_mut())
    {
        names.retain(|n| RELEASED.iter().any(|m| n.as_str() == Some(m.name())));
    }
    if let Some(kinds) = value
        .pointer_mut("/$defs/Assessment/enum")
        .and_then(|v| v.as_array_mut())
    {
        kinds.retain(|k| {
            released_standards()
                .any(|s| serde_json::to_value(s.assessment).ok().as_ref() == Some(k))
        });
    }
    // Back into a `Schema` so its serializer keeps the usual keyword order (`$schema`, `title`, … first).
    let filtered = Schema::try_from(value).unwrap_or_else(|_| schema.clone());
    let mut out = serde_json::to_string_pretty(&filtered).unwrap_or_default();
    out.push('\n');
    out
}

/// Schema for rule pack files (TOML editors such as Taplo / Even Better TOML accept JSON Schema).
pub fn rule_pack_schema() -> String {
    pretty(&schema_for!(RulePack))
}

/// Schema for the JSON report (`opencomply scan … --format json`).
pub fn report_schema() -> String {
    pretty(&schema_for!(JsonReport<'static>))
}

/// Schema for `opencomply standards --format json`.
pub fn standards_schema() -> String {
    pretty(&schema_for!(StandardsDoc))
}
