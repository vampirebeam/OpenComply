//! Rule registry: holds validated rule packs, rejects id collisions, applies "newer version replaces older" for the
//! same pack id, and selects rules per module in a stable order. Pure (no I/O) — callers load pack bytes within limits.
//! Packs loaded from files go through `add_file`: SHA-256 is recorded, a detached signature is verified, and
//! `opencomply-*` packs must be signed by an official key. `add` is for packs compiled into the binary.

use std::cmp::Ordering;
use std::fmt;

use crate::evaluate::{evaluate_rule, EvalInput};
use crate::finding::Module;
use crate::platform::DetectedPlatform;
use crate::report::{Report, RulePackRef};
use crate::rules::{LoadError, Rule, RulePack};
use crate::signing::{sha256_hex, verify_pack, PackTrust, TrustedKey, OFFICIAL_PREFIX};

pub const MAX_PACKS: usize = 64;
pub const MAX_TOTAL_RULES: usize = 5_000;

/// `MAJOR.MINOR.PATCH` with numeric ordering (`1.10.0` > `1.9.0`). Rule-pack validation guarantees the format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    pub fn parse(s: &str) -> Option<Self> {
        let mut it = s.split('.').map(str::parse::<u32>);
        let v = Version(it.next()?.ok()?, it.next()?.ok()?, it.next()?.ok()?);
        it.next().is_none().then_some(v)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryError {
    Load {
        source: String,
        message: String,
    },
    NotNewer {
        pack: String,
        loaded: String,
        offered: String,
    },
    DuplicateRule {
        rule: String,
        pack: String,
        other_pack: String,
    },
    TooManyPacks {
        max: usize,
    },
    TooManyRules {
        max: usize,
    },
    Untrusted {
        source: String,
        message: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::Load { source, message }
            | RegistryError::Untrusted { source, message } => write!(f, "{source}: {message}"),
            RegistryError::NotNewer {
                pack,
                loaded,
                offered,
            } => {
                write!(
                    f,
                    "pack {pack} {offered} ignored: {loaded} is already loaded"
                )
            }
            RegistryError::DuplicateRule {
                rule,
                pack,
                other_pack,
            } => {
                write!(
                    f,
                    "rule {rule} in pack {pack} is already defined by pack {other_pack}"
                )
            }
            RegistryError::TooManyPacks { max } => write!(f, "too many rule packs (max {max})"),
            RegistryError::TooManyRules { max } => write!(f, "too many rules in total (max {max})"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Where a loaded pack came from: its checksum and who signed it (`None` = unsigned or built-in).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance {
    pub sha256: Option<String>,
    pub signed_by: Option<String>,
}

#[derive(Debug, Default)]
pub struct RuleRegistry {
    packs: Vec<RulePack>,
    provenance: Vec<Provenance>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a pack file: checksum, signature check, official-prefix policy, then validation and `add`.
    /// `allow_unsigned` permits unsigned non-official packs (e.g. an organisation's own rules).
    pub fn add_file(
        &mut self,
        source: &str,
        bytes: &[u8],
        signature: Option<&str>,
        trusted: &[TrustedKey],
        allow_unsigned: bool,
    ) -> Result<Provenance, RegistryError> {
        let untrusted = |message: String| RegistryError::Untrusted {
            source: source.to_string(),
            message,
        };
        let text =
            std::str::from_utf8(bytes).map_err(|_| untrusted("pack is not valid UTF-8".into()))?;
        let trust = verify_pack(bytes, signature, trusted).map_err(|e| untrusted(e.to_string()))?;
        let pack = parse(source, text)?;
        let official = pack.pack.id.starts_with(OFFICIAL_PREFIX);
        let signed_by = match trust {
            PackTrust::Verified { key_id } => Some(key_id),
            PackTrust::Unsigned if official => {
                return Err(untrusted(format!(
                    "pack id \"{}\" is reserved for official packs, which must be signed",
                    pack.pack.id
                )))
            }
            PackTrust::Unsigned if !allow_unsigned => {
                return Err(untrusted(
                    "unsigned pack (allow unsigned packs explicitly to load it)".into(),
                ))
            }
            PackTrust::Unsigned => None,
        };
        let provenance = Provenance {
            sha256: Some(sha256_hex(bytes)),
            signed_by,
        };
        self.insert(pack, provenance.clone())?;
        Ok(provenance)
    }

    /// Parses + validates `text` (see `RulePack::from_toml`) and adds it. `source` names the input in errors.
    pub fn add_toml(&mut self, source: &str, text: &str) -> Result<(), RegistryError> {
        let pack = parse(source, text)?;
        self.add(pack)
    }

    /// Adds a validated pack compiled into the binary (trusted by construction, no file provenance).
    pub fn add(&mut self, pack: RulePack) -> Result<(), RegistryError> {
        self.insert(pack, Provenance::default())
    }

    /// Same pack id: only a strictly newer version replaces the loaded one.
    fn insert(&mut self, pack: RulePack, provenance: Provenance) -> Result<(), RegistryError> {
        let offered = Version::parse(&pack.pack.version);
        let existing = self.packs.iter().position(|p| p.pack.id == pack.pack.id);
        if let Some(i) = existing {
            let loaded = Version::parse(&self.packs[i].pack.version);
            if offered.cmp(&loaded) != Ordering::Greater {
                return Err(RegistryError::NotNewer {
                    pack: pack.pack.id.clone(),
                    loaded: self.packs[i].pack.version.clone(),
                    offered: pack.pack.version.clone(),
                });
            }
        } else if self.packs.len() >= MAX_PACKS {
            return Err(RegistryError::TooManyPacks { max: MAX_PACKS });
        }
        for rule in &pack.rules {
            let clash = self
                .packs
                .iter()
                .enumerate()
                .find(|(i, p)| Some(*i) != existing && p.rules.iter().any(|r| r.id == rule.id));
            if let Some((_, other)) = clash {
                return Err(RegistryError::DuplicateRule {
                    rule: rule.id.clone(),
                    pack: pack.pack.id.clone(),
                    other_pack: other.pack.id.clone(),
                });
            }
        }
        let others: usize = self
            .packs
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != existing)
            .map(|(_, p)| p.rules.len())
            .sum();
        if others + pack.rules.len() > MAX_TOTAL_RULES {
            return Err(RegistryError::TooManyRules {
                max: MAX_TOTAL_RULES,
            });
        }
        if let Some(i) = existing {
            self.packs[i] = pack;
            self.provenance[i] = provenance;
        } else {
            self.packs.push(pack);
            self.provenance.push(provenance);
        }
        Ok(())
    }

    fn provenance_of(&self, pack_id: &str) -> Provenance {
        self.packs
            .iter()
            .position(|p| p.pack.id == pack_id)
            .and_then(|i| self.provenance.get(i).cloned())
            .unwrap_or_default()
    }

    pub fn packs(&self) -> &[RulePack] {
        &self.packs
    }

    /// Packs for a module, ordered by pack id.
    pub fn packs_for(&self, module: Module) -> Vec<&RulePack> {
        let mut v: Vec<&RulePack> = self
            .packs
            .iter()
            .filter(|p| p.pack.module == module)
            .collect();
        v.sort_by(|a, b| a.pack.id.cmp(&b.pack.id));
        v
    }

    /// Rules for a module, ordered by rule id (stable, reproducible output).
    pub fn rules_for(&self, module: Module) -> Vec<&Rule> {
        let mut v: Vec<&Rule> = self
            .packs_for(module)
            .into_iter()
            .flat_map(|p| p.rules.iter())
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Evaluates every rule of `module` across all loaded packs and records every pack used.
    pub fn evaluate(
        &self,
        module: Module,
        target: &str,
        input: &EvalInput<'_>,
        platforms: Vec<DetectedPlatform>,
    ) -> Report {
        let rules = self.rules_for(module);
        let findings = rules
            .iter()
            .map(|r| evaluate_rule(r, module, input, &platforms))
            .collect();
        let mut report = Report::new(module, target, findings)
            .with_platforms(platforms)
            .graded(&rules);
        report.rule_packs = self
            .packs_for(module)
            .iter()
            .map(|p| {
                let prov = self.provenance_of(&p.pack.id);
                RulePackRef {
                    id: p.pack.id.clone(),
                    version: p.pack.version.clone(),
                    sha256: prov.sha256,
                    signed_by: prov.signed_by,
                }
            })
            .collect();
        report
    }
}

fn parse(source: &str, text: &str) -> Result<RulePack, RegistryError> {
    RulePack::from_toml(text).map_err(|e| RegistryError::Load {
        source: source.to_string(),
        message: match e {
            LoadError::Invalid(issues) => issues
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
            other => other.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    fn pack(id: &str, version: &str, module: &str, rules: &[&str]) -> String {
        let prefix = match module {
            "headers" => "HDR",
            "iso27001" => "ISO27",
            _ => "TLS",
        };
        let mut s =
            format!("[pack]\nid = \"{id}\"\nversion = \"{version}\"\nmodule = \"{module}\"\n");
        for r in rules {
            let check = if module == "headers" {
                "{ op = \"header_present\", header = \"x-test\" }"
            } else {
                "{ op = \"file_exists\", path = \"SECURITY.md\" }"
            };
            let _ = writeln!(
                s,
                "[[rule]]\nid = \"{prefix}-{r}\"\nversion = \"1.0.0\"\ntitle = \"t\"\nseverity = \"low\"\nweight = 1\nfix_hint = \"f\"\nremediation = \"r\"\ncheck = {check}"
            );
        }
        s
    }

    #[test]
    fn version_ordering_is_numeric() {
        assert!(Version::parse("1.10.0") > Version::parse("1.9.0"));
        assert_eq!(Version::parse("1.2"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
    }

    #[test]
    fn rules_are_merged_per_module_in_id_order() {
        let mut reg = RuleRegistry::new();
        reg.add_toml(
            "b.toml",
            &pack("b-pack", "1.0.0", "headers", &["003", "001"]),
        )
        .unwrap();
        reg.add_toml("a.toml", &pack("a-pack", "1.0.0", "headers", &["002"]))
            .unwrap();
        reg.add_toml("iso.toml", &pack("iso-pack", "1.0.0", "iso27001", &["001"]))
            .unwrap();
        let ids: Vec<_> = reg
            .rules_for(Module::Headers)
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(ids, ["HDR-001", "HDR-002", "HDR-003"]);
        assert_eq!(reg.rules_for(Module::Iso27001).len(), 1);
        assert!(reg.rules_for(Module::Tls).is_empty());
    }

    #[test]
    fn duplicate_rule_across_packs_is_rejected() {
        let mut reg = RuleRegistry::new();
        reg.add_toml("a", &pack("a-pack", "1.0.0", "headers", &["001"]))
            .unwrap();
        let err = reg
            .add_toml("b", &pack("b-pack", "1.0.0", "headers", &["001"]))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "rule HDR-001 in pack b-pack is already defined by pack a-pack"
        );
    }

    #[test]
    fn newer_version_replaces_older_is_ignored() {
        let mut reg = RuleRegistry::new();
        reg.add_toml("v1", &pack("p", "1.9.0", "headers", &["001"]))
            .unwrap();
        reg.add_toml("v2", &pack("p", "1.10.0", "headers", &["001", "002"]))
            .unwrap();
        assert_eq!(reg.packs().len(), 1);
        assert_eq!(reg.rules_for(Module::Headers).len(), 2);
        let err = reg
            .add_toml("old", &pack("p", "1.2.0", "headers", &["001"]))
            .unwrap_err();
        assert!(matches!(err, RegistryError::NotNewer { .. }));
        assert_eq!(reg.packs()[0].pack.version, "1.10.0");
    }

    #[test]
    fn invalid_pack_reports_source() {
        let mut reg = RuleRegistry::new();
        let err = reg.add_toml("broken.toml", "not = [valid").unwrap_err();
        assert!(err
            .to_string()
            .starts_with("broken.toml: rule pack parse error"));
    }

    #[test]
    fn signed_official_pack_loads_with_provenance_in_report() {
        use crate::evaluate::HttpEvidence;
        use crate::signing::test_keys::{sign, trusted};
        let keys = [trusted("official-2026", 7)];
        let text = pack("opencomply-headers", "1.0.0", "headers", &["001"]);
        let sig = sign("official-2026", 7, text.as_bytes());
        let mut reg = RuleRegistry::new();
        let prov = reg
            .add_file("official.toml", text.as_bytes(), Some(&sig), &keys, false)
            .unwrap();
        assert_eq!(prov.signed_by.as_deref(), Some("official-2026"));
        assert_eq!(prov.sha256.as_deref().map(str::len), Some(64));
        let http = HttpEvidence {
            source: "GET x".into(),
            status: 200,
            ..HttpEvidence::default()
        };
        let report = reg.evaluate(Module::Headers, "x", &EvalInput::Http(&http), vec![]);
        assert_eq!(
            report.rule_packs[0].signed_by.as_deref(),
            Some("official-2026")
        );
        assert_eq!(report.rule_packs[0].sha256, prov.sha256);
    }

    #[test]
    fn integrity_policy() {
        use crate::signing::test_keys::{sign, trusted};
        let keys = [trusted("official-2026", 7)];
        let official = pack("opencomply-headers", "1.0.0", "headers", &["001"]);
        let custom = pack("acme-headers", "1.0.0", "headers", &["002"]);
        let mut reg = RuleRegistry::new();
        let err = reg
            .add_file("o.toml", official.as_bytes(), None, &keys, true)
            .unwrap_err();
        assert!(
            err.to_string().contains("reserved for official packs"),
            "{err}"
        );
        let mut tampered = official.clone().into_bytes();
        let sig = sign("official-2026", 7, &tampered);
        tampered.extend_from_slice(b"\n# injected\n");
        let err = reg
            .add_file("o.toml", &tampered, Some(&sig), &keys, true)
            .unwrap_err();
        assert!(err.to_string().contains("does not match the pack"), "{err}");
        assert!(reg
            .add_file("c.toml", custom.as_bytes(), None, &keys, false)
            .is_err());
        let prov = reg
            .add_file("c.toml", custom.as_bytes(), None, &keys, true)
            .unwrap();
        assert_eq!(prov.signed_by, None);
        assert_eq!(reg.packs().len(), 1);
        assert!(reg
            .add_file("bin", &[0xff, 0xfe], None, &keys, true)
            .is_err());
    }

    #[test]
    fn pack_count_is_bounded() {
        let mut reg = RuleRegistry::new();
        for i in 0..MAX_PACKS {
            reg.add_toml(
                "p",
                &pack(&format!("p{i}"), "1.0.0", "headers", &[&format!("{i:03}")]),
            )
            .unwrap();
        }
        let err = reg
            .add_toml("x", &pack("extra", "1.0.0", "headers", &["999"]))
            .unwrap_err();
        assert_eq!(err, RegistryError::TooManyPacks { max: MAX_PACKS });
    }
}
