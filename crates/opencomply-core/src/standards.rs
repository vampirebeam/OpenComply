//! Standard registry: one entry per module describing the standard it assesses, its rule ID prefix and result type
//! (letter grade for technical scans, readiness level for ISO). Single source of truth for module metadata.

use serde::Serialize;

use crate::finding::Module;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Grade,
    Readiness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Standard {
    pub module: Module,
    pub name: &'static str,
    pub edition: &'static str,
    pub rule_prefix: &'static str,
    pub assessment: Assessment,
    pub annex_a_controls: Option<u16>,
}

pub const STANDARDS: [Standard; 4] = [
    Standard {
        module: Module::Headers,
        name: "HTTP Security Headers",
        edition: "OpenComply criteria",
        rule_prefix: "HDR",
        assessment: Assessment::Grade,
        annex_a_controls: None,
    },
    Standard {
        module: Module::Tls,
        name: "SSL/TLS Configuration",
        edition: "OpenComply criteria",
        rule_prefix: "TLS",
        assessment: Assessment::Grade,
        annex_a_controls: None,
    },
    Standard {
        module: Module::Iso27001,
        name: "ISO/IEC 27001",
        edition: "2022",
        rule_prefix: "ISO27",
        assessment: Assessment::Readiness,
        annex_a_controls: Some(93),
    },
    Standard {
        module: Module::Iso42001,
        name: "ISO/IEC 42001",
        edition: "2023",
        rule_prefix: "ISO42",
        assessment: Assessment::Readiness,
        annex_a_controls: Some(38),
    },
];

impl Module {
    pub const ALL: [Module; 4] = [
        Module::Headers,
        Module::Tls,
        Module::Iso27001,
        Module::Iso42001,
    ];

    pub fn standard(self) -> &'static Standard {
        match self {
            Module::Headers => &STANDARDS[0],
            Module::Tls => &STANDARDS[1],
            Module::Iso27001 => &STANDARDS[2],
            Module::Iso42001 => &STANDARDS[3],
        }
    }
}

/// Letter grades. Headers uses A+–F; TLS additionally uses A-, E, T (untrusted), M (hostname mismatch).
/// `NotAssessed` = a required probe did not complete; it is never upgraded to a letter grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub enum Grade {
    #[serde(rename = "A+")]
    APlus,
    A,
    #[serde(rename = "A-")]
    AMinus,
    B,
    C,
    D,
    E,
    F,
    T,
    M,
    #[serde(rename = "N/A")]
    NotAssessed,
}

impl Grade {
    pub fn label(self) -> &'static str {
        match self {
            Grade::APlus => "A+",
            Grade::A => "A",
            Grade::AMinus => "A-",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::E => "E",
            Grade::F => "F",
            Grade::T => "T",
            Grade::M => "M",
            Grade::NotAssessed => "N/A",
        }
    }

    pub fn allowed_for(self, module: Module) -> bool {
        match module {
            Module::Headers => matches!(
                self,
                Grade::APlus
                    | Grade::A
                    | Grade::B
                    | Grade::C
                    | Grade::D
                    | Grade::F
                    | Grade::NotAssessed
            ),
            Module::Tls => true,
            Module::Iso27001 | Module::Iso42001 => false,
        }
    }
}

/// ISO readiness levels. Level 4 is an `OpenComply` classification, never a certification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(into = "u8")]
pub enum ReadinessLevel {
    NotAssessed = 0,
    Initial = 1,
    Developing = 2,
    ImplementedEvidence = 3,
    InternalAuditPreparationReady = 4,
}

impl From<ReadinessLevel> for u8 {
    fn from(l: ReadinessLevel) -> u8 {
        l as u8
    }
}

impl ReadinessLevel {
    pub fn name(self) -> &'static str {
        match self {
            ReadinessLevel::NotAssessed => "Not Assessed",
            ReadinessLevel::Initial => "Initial",
            ReadinessLevel::Developing => "Developing",
            ReadinessLevel::ImplementedEvidence => "Implemented Evidence",
            ReadinessLevel::InternalAuditPreparationReady => "Internal Audit Preparation Ready",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn registry_covers_every_module_once_with_unique_prefixes() {
        for m in Module::ALL {
            assert_eq!(m.standard().module, m);
        }
        let prefixes: HashSet<_> = STANDARDS.iter().map(|s| s.rule_prefix).collect();
        assert_eq!(prefixes.len(), STANDARDS.len());
    }

    #[test]
    fn grade_scales_match_module_type() {
        assert!(!Grade::AMinus.allowed_for(Module::Headers));
        assert!(Grade::T.allowed_for(Module::Tls));
        assert!(!Grade::APlus.allowed_for(Module::Iso27001));
        assert_eq!(serde_json::to_string(&Grade::APlus).unwrap(), "\"A+\"");
        assert_eq!(
            serde_json::to_string(&ReadinessLevel::InternalAuditPreparationReady).unwrap(),
            "4"
        );
    }
}
