//! Release guard: the agent plugin, its skill and both installers must name the same version as the binary,
//! otherwise the installer would download a release that does not match the skill.

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn plugin_and_installers_match_the_binary_version() {
    let plugin = opencomply_core::root_file!("plugins/opencomply/.claude-plugin/plugin.json");
    assert!(
        plugin.contains(&format!("\"version\": \"{VERSION}\"")),
        "plugin.json"
    );

    let sh = opencomply_core::root_file!(
        "plugins/opencomply/skills/security-headers/scripts/install.sh"
    );
    assert!(
        sh.contains(&format!("OPENCOMPLY_VERSION:-{VERSION}}}")),
        "install.sh"
    );

    let ps1 = opencomply_core::root_file!(
        "plugins/opencomply/skills/security-headers/scripts/install.ps1"
    );
    assert!(
        ps1.contains(&format!("else {{ '{VERSION}' }}")),
        "install.ps1"
    );

    let skill = opencomply_core::root_file!("plugins/opencomply/skills/security-headers/SKILL.md");
    assert!(
        skill.contains(&format!("opencomply {VERSION}")),
        "SKILL.md version check"
    );
}
