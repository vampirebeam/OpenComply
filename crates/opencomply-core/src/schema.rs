//! JSON Schemas generated from the exact types the scanner parses (rule packs) and emits (`--format json`), so the
//! published schemas cannot drift from the code. Committed copies live in `schemas/`; a test fails if they differ.

use schemars::{schema_for, Schema};

use crate::render::JsonReport;
use crate::rules::RulePack;

fn pretty(schema: &Schema) -> String {
    let mut out = serde_json::to_string_pretty(schema).unwrap_or_default();
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
