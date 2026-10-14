//! Embeds official rule pack signatures (`rules/<pack>.toml.sig`) when they exist, so the binary verifies its own
//! packs; development builds without a signature still compile and report the pack as unsigned.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=OPENCOMPLY_ROOT");
    let root = std::env::var("OPENCOMPLY_ROOT").unwrap_or_default();
    let sig = format!("{root}/rules/opencomply-headers.toml.sig");
    println!("cargo:rerun-if-changed={root}/rules");
    let code = if !root.is_empty() && Path::new(&sig).is_file() {
        format!("pub const OFFICIAL_HEADERS_SIG: Option<&str> = Some(include_str!({sig:?}));\n")
    } else {
        "pub const OFFICIAL_HEADERS_SIG: Option<&str> = None;\n".to_string()
    };
    let out = std::env::var("OUT_DIR").unwrap_or_default();
    if let Err(e) = std::fs::write(Path::new(&out).join("official_sigs.rs"), code) {
        eprintln!("cannot write official_sigs.rs: {e}");
        std::process::exit(1);
    }
}
