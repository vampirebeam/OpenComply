//! Letter grade for the headers module (A+–F) from the findings and each rule's `weight` / `mandatory` flag.
//! Score = earned / possible weight over applicable rules (`Pass` = full, `NeedsReview` = half, anything else = 0).
//! Caps, so a high score never hides a serious gap:
//! - a mandatory rule `Unknown` → `N/A` (not assessed): the grade cannot be confirmed, so none is given
//! - a mandatory rule fails → at most C
//! - a high / critical rule fails → at most B
//! - A+ only when every mandatory rule passes and no high / critical rule is undecided

use schemars::JsonSchema;
use serde::Serialize;

use crate::finding::{Finding, Severity, Status};
use crate::rules::Rule;
use crate::standards::Grade;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Grading {
    pub grade: Grade,
    /// 0–100; absent when not assessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    /// Why the grade is lower than the score alone would give, e.g. "HDR-002 is mandatory and fails".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capped_by: Vec<String>,
    /// Path to the next grade and to A+, so a lower grade comes with what it would take to raise it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upgrades: Vec<Upgrade>,
}

fn band(score: u8) -> Grade {
    match score {
        95..=100 => Grade::APlus,
        90..=94 => Grade::A,
        80..=89 => Grade::B,
        70..=79 => Grade::C,
        50..=69 => Grade::D,
        _ => Grade::F,
    }
}

/// What it takes to reach `to`: the fewest checks to fix, in order, with the points each adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Upgrade {
    pub to: Grade,
    pub steps: Vec<UpgradeStep>,
    /// Grade and score after all steps; can be higher than `to` (one fix may jump several grades).
    pub result: Grade,
    pub result_score: u8,
}

/// `required` = `to` cannot be reached without this check (a cap); `impact` = what passing it costs or changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct UpgradeStep {
    pub rule_id: String,
    pub points: u8,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
}

#[derive(Clone, Copy)]
struct Item<'a> {
    rule: &'a Rule,
    status: Status,
    severity: Severity,
}

const LADDER: [Grade; 6] = [
    Grade::F,
    Grade::D,
    Grade::C,
    Grade::B,
    Grade::A,
    Grade::APlus,
];

/// Grade plus the path to the next grade and to A+ (one entry when the next grade is A+).
pub fn grade_headers(findings: &[Finding], rules: &[&Rule]) -> Grading {
    let items: Vec<Item> = findings
        .iter()
        .filter_map(|f| {
            rules.iter().find(|r| r.id == f.rule_id).map(|rule| Item {
                rule,
                status: f.status,
                severity: f.severity,
            })
        })
        .collect();
    let mut grading = assess(&items);
    let Some(pos) = LADDER.iter().position(|g| *g == grading.grade) else {
        return grading;
    };
    let mut targets = Vec::new();
    if let Some(next) = LADDER.get(pos + 1) {
        targets.push(*next);
    }
    if pos + 1 < LADDER.len() - 1 {
        targets.push(Grade::APlus);
    }
    grading.upgrades = targets.into_iter().map(|t| upgrade(&items, t)).collect();
    grading
}

fn with_passed<'a>(items: &[Item<'a>], fixed: &[usize]) -> Vec<Item<'a>> {
    items
        .iter()
        .enumerate()
        .map(|(i, it)| {
            if fixed.contains(&i) {
                Item {
                    status: Status::Pass,
                    ..*it
                }
            } else {
                *it
            }
        })
        .collect()
}

fn reaches(items: &[Item], fixed: &[usize], target: Grade) -> bool {
    assess(&with_passed(items, fixed)).grade <= target
}

/// Greedy: repeatedly fix the check that improves the grade most (then the score), until `target` is reached.
fn upgrade(items: &[Item], target: Grade) -> Upgrade {
    let open: Vec<usize> = (0..items.len())
        .filter(|&i| !matches!(items[i].status, Status::Pass | Status::NotApplicable))
        .collect();
    let mut fixed: Vec<usize> = Vec::new();
    while !reaches(items, &fixed, target) {
        let best = open
            .iter()
            .filter(|i| !fixed.contains(i))
            .map(|&i| {
                let mut trial = fixed.clone();
                trial.push(i);
                let g = assess(&with_passed(items, &trial));
                (
                    std::cmp::Reverse(g.grade),
                    g.score,
                    std::cmp::Reverse(items[i].rule.id.clone()),
                    i,
                )
            })
            .max();
        match best {
            Some((_, _, _, i)) => fixed.push(i),
            None => break,
        }
    }
    let mut before = assess(items).score.unwrap_or(0);
    let steps = fixed
        .iter()
        .enumerate()
        .map(|(n, &i)| {
            let after = assess(&with_passed(items, &fixed[..=n]))
                .score
                .unwrap_or(before);
            let others: Vec<usize> = fixed.iter().copied().filter(|&j| j != i).collect();
            let step = UpgradeStep {
                rule_id: items[i].rule.id.clone(),
                points: after.saturating_sub(before),
                required: !reaches(items, &others, target),
                impact: items[i].rule.upgrade_impact.clone(),
            };
            before = after;
            step
        })
        .collect();
    let after = assess(&with_passed(items, &fixed));
    Upgrade {
        to: target,
        steps,
        result: after.grade,
        result_score: after.score.unwrap_or(0),
    }
}

fn assess(items: &[Item]) -> Grading {
    let mut possible: u32 = 0;
    let mut earned_halves: u32 = 0;
    let mut cap = Grade::APlus;
    let mut capped_by = Vec::new();
    let mut lower = |to: Grade, why: String, cap: &mut Grade| {
        if to > *cap {
            *cap = to;
        }
        capped_by.push(why);
    };
    for f in items {
        let rule = f.rule;
        if f.status == Status::NotApplicable {
            continue;
        }
        let w = u32::from(rule.weight);
        possible += w;
        earned_halves += match f.status {
            Status::Pass => 2 * w,
            Status::NeedsReview => w,
            _ => 0,
        };
        let serious = matches!(f.severity, Severity::High | Severity::Critical);
        match (f.status, rule.mandatory) {
            (Status::Unknown, true) => {
                return Grading {
                    grade: Grade::NotAssessed,
                    score: None,
                    capped_by: vec![format!("{} is mandatory and could not be checked", rule.id)],
                    upgrades: Vec::new(),
                };
            }
            (Status::Fail, true) => {
                lower(
                    Grade::C,
                    format!("{} is mandatory and fails", rule.id),
                    &mut cap,
                );
            }
            (Status::Fail, false) if serious => {
                lower(
                    Grade::B,
                    format!("{} is {} and fails", rule.id, f.severity.label()),
                    &mut cap,
                );
            }
            (Status::Pass, _) => {}
            (_, true) => lower(
                Grade::A,
                format!("{} is mandatory and not passed", rule.id),
                &mut cap,
            ),
            (_, false) if serious => {
                lower(
                    Grade::A,
                    format!("{} is {} and undecided", rule.id, f.severity.label()),
                    &mut cap,
                );
            }
            _ => {}
        }
    }
    if possible == 0 {
        return Grading {
            grade: Grade::NotAssessed,
            score: None,
            capped_by: vec!["no applicable checks".into()],
            upgrades: Vec::new(),
        };
    }
    let score = u8::try_from((earned_halves * 100 + possible) / (2 * possible)).unwrap_or(100);
    let base = band(score);
    let grade = if cap > base { cap } else { base };
    Grading {
        grade,
        score: Some(score),
        capped_by: if grade == base { Vec::new() } else { capped_by },
        upgrades: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RulePack;

    fn pack() -> RulePack {
        RulePack::from_toml(crate::rules::OFFICIAL_HEADERS_PACK).unwrap()
    }

    fn findings(p: &RulePack, status_of: &dyn Fn(&str) -> Status) -> Vec<Finding> {
        p.rules
            .iter()
            .map(|r| Finding {
                rule_id: r.id.clone(),
                rule_version: r.version.clone(),
                title: r.title.clone(),
                status: status_of(&r.id),
                severity: r.severity,
                evidence: vec![],
                reason: None,
                fix_hint: None,
                example_fix: None,
                platform_fixes: vec![],
                review_question: None,
                remediation: None,
                advice: None,
                effort: None,
                depends_on: vec![],
                group: None,
            })
            .collect()
    }

    fn grade(status_of: &dyn Fn(&str) -> Status) -> Grading {
        let p = pack();
        let rules: Vec<&Rule> = p.rules.iter().collect();
        grade_headers(&findings(&p, status_of), &rules)
    }

    #[test]
    fn every_grade_is_reachable() {
        let all = grade(&|_| Status::Pass);
        assert_eq!((all.grade, all.score), (Grade::APlus, Some(100)));
        // Lose 5 (HDR-010, low): 95 → still A+.
        assert_eq!(
            grade(&|id| if id == "HDR-010" {
                Status::Fail
            } else {
                Status::Pass
            })
            .grade,
            Grade::APlus
        );
        // Lose 10 (HDR-003 + HDR-004): 90 → A.
        let a = grade(&|id| {
            if matches!(id, "HDR-004" | "HDR-005") {
                Status::Fail
            } else {
                Status::Pass
            }
        });
        assert_eq!((a.grade, a.score), (Grade::A, Some(90)));
        // Lose 15, no mandatory: 85 → B.
        let b = grade(&|id| {
            if matches!(id, "HDR-003" | "HDR-004") {
                Status::Fail
            } else {
                Status::Pass
            }
        });
        assert_eq!((b.grade, b.score), (Grade::B, Some(85)));
        // Mandatory CSP fails: 75 → C (also the cap).
        assert_eq!(
            grade(&|id| if id == "HDR-002" {
                Status::Fail
            } else {
                Status::Pass
            })
            .grade,
            Grade::C
        );
        // CSP + HSTS fail: 60 → D.
        assert_eq!(
            grade(&|id| if matches!(id, "HDR-001" | "HDR-002") {
                Status::Fail
            } else {
                Status::Pass
            })
            .grade,
            Grade::D
        );
        let f = grade(&|_| Status::Fail);
        assert_eq!((f.grade, f.score), (Grade::F, Some(0)));
    }

    /// Every PASS / FAIL combination of the official rules: a failing mandatory rule never grades above C, and each
    /// upgrade path's `result` is exactly the grade those steps give (caps included) and reaches its target.
    #[test]
    fn caps_hold_for_every_pass_fail_combination() {
        let p = pack();
        let rules: Vec<&Rule> = p.rules.iter().collect();
        let ids: Vec<String> = p.rules.iter().map(|r| r.id.clone()).collect();
        for mask in 0u32..(1 << ids.len()) {
            let failing = |id: &str| {
                ids.iter()
                    .position(|i| i == id)
                    .is_some_and(|n| mask & (1 << n) != 0)
            };
            let g = grade(&|id| {
                if failing(id) {
                    Status::Fail
                } else {
                    Status::Pass
                }
            });
            if p.rules.iter().any(|r| r.mandatory && failing(&r.id)) {
                assert!(g.grade >= Grade::C, "mask {mask:#b}: {:?}", g.grade);
            }
            for up in &g.upgrades {
                let fixed: Vec<&str> = up.steps.iter().map(|s| s.rule_id.as_str()).collect();
                let after = grade_headers(
                    &findings(&p, &|id| {
                        if failing(id) && !fixed.contains(&id) {
                            Status::Fail
                        } else {
                            Status::Pass
                        }
                    }),
                    &rules,
                );
                assert_eq!(after.grade, up.result, "mask {mask:#b} → {:?}", up.to);
                assert!(
                    up.result <= up.to,
                    "mask {mask:#b}: {:?} misses {:?}",
                    up.result,
                    up.to
                );
            }
        }
    }

    #[test]
    fn mandatory_failure_caps_a_high_score() {
        // HTTPS enforcement fails, everything else passes: score 85 but capped at C.
        let g = grade(&|id| {
            if id == "HDR-007" {
                Status::Fail
            } else {
                Status::Pass
            }
        });
        assert_eq!(g.score, Some(85));
        assert_eq!(g.grade, Grade::C);
        assert_eq!(g.capped_by, ["HDR-007 is mandatory and fails"]);
    }

    #[test]
    fn review_on_mandatory_blocks_a_plus() {
        // Temporary redirect (review) on HDR-007: half of 15 lost → 92.5 → 93, A; A+ blocked anyway.
        let g = grade(&|id| {
            if id == "HDR-007" {
                Status::NeedsReview
            } else {
                Status::Pass
            }
        });
        assert_eq!((g.grade, g.score), (Grade::A, Some(93)));
    }

    #[test]
    fn grade_a_explains_what_a_plus_costs() {
        // Static front-end: CSP needs 'unsafe-eval' (review) → 88, B; the path up names CSP and its impact.
        let g = grade(&|id| {
            if id == "HDR-002" {
                Status::NeedsReview
            } else {
                Status::Pass
            }
        });
        assert_eq!((g.grade, g.score), (Grade::B, Some(88)));
        assert_eq!(
            g.upgrades.iter().map(|u| u.to).collect::<Vec<_>>(),
            [Grade::A, Grade::APlus]
        );
        let up = &g.upgrades[1];
        assert_eq!(up.to, Grade::APlus);
        assert_eq!(up.steps.len(), 1);
        assert_eq!(up.steps[0].rule_id, "HDR-002");
        assert!(up.steps[0].required);
        assert_eq!(up.steps[0].points, 12);
        assert!(up.steps[0]
            .impact
            .as_deref()
            .unwrap()
            .contains("static pages"));
        assert!(grade(&|_| Status::Pass).upgrades.is_empty());
        // Temporary redirect only: A (93), and A+ needs HDR-007.
        let a = grade(&|id| {
            if id == "HDR-007" {
                Status::NeedsReview
            } else {
                Status::Pass
            }
        });
        assert_eq!(a.grade, Grade::A);
        assert_eq!(a.upgrades.len(), 1);
        assert_eq!(a.upgrades[0].steps[0].rule_id, "HDR-007");
        assert_eq!(a.upgrades[0].steps[0].points, 7);
    }

    #[test]
    fn low_grade_shows_next_grade_and_a_plus() {
        // HDR-007 (mandatory) + HDR-003 + HDR-004 fail: 70 → C.
        let g = grade(&|id| {
            if matches!(id, "HDR-007" | "HDR-003" | "HDR-004") {
                Status::Fail
            } else {
                Status::Pass
            }
        });
        assert_eq!((g.grade, g.score), (Grade::C, Some(70)));
        let to: Vec<Grade> = g.upgrades.iter().map(|u| u.to).collect();
        assert_eq!(to, [Grade::B, Grade::APlus]);
        // To B the mandatory HTTPS check is required and alone is enough (85).
        let b = &g.upgrades[0].steps;
        assert_eq!(
            b.iter()
                .map(|s| (s.rule_id.as_str(), s.points, s.required))
                .collect::<Vec<_>>(),
            [("HDR-007", 15, true)]
        );
        // To A+ the two biggest are enough (95); the low-severity HDR-004 is not needed.
        let top: Vec<(&str, u8)> = g.upgrades[1]
            .steps
            .iter()
            .map(|s| (s.rule_id.as_str(), s.points))
            .collect();
        assert_eq!(top, [("HDR-007", 15), ("HDR-003", 10)]);
        assert!(g.upgrades[1].steps.iter().all(|s| s.required));
    }

    /// A low-severity REVIEW (e.g. an internal name in Server-Timing) costs half its weight and keeps A+.
    #[test]
    fn low_severity_review_keeps_a_plus() {
        let g = grade(&|id| {
            if id == "HDR-010" {
                Status::NeedsReview
            } else {
                Status::Pass
            }
        });
        assert_eq!((g.grade, g.score), (Grade::APlus, Some(98)));
        assert!(g.capped_by.is_empty());
    }

    #[test]
    fn unknown_mandatory_is_not_assessed() {
        let g = grade(&|id| {
            if id == "HDR-007" {
                Status::Unknown
            } else {
                Status::Pass
            }
        });
        assert_eq!((g.grade, g.score), (Grade::NotAssessed, None));
    }

    #[test]
    fn not_applicable_rules_leave_the_score() {
        // JSON API: CSP, Permissions-Policy, clickjacking N/A; the rest pass → 100.
        let g = grade(&|id| {
            if matches!(id, "HDR-002" | "HDR-005" | "HDR-006") {
                Status::NotApplicable
            } else {
                Status::Pass
            }
        });
        assert_eq!((g.grade, g.score), (Grade::APlus, Some(100)));
        let none = grade(&|_| Status::NotApplicable);
        assert_eq!(none.grade, Grade::NotAssessed);
    }
}
