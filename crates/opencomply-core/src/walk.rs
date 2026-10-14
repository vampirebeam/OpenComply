//! Safe, read-only directory traversal for repository and `WordPress` scans.
//! Policy: symlinks are never followed (reported, and flagged when they point outside the root); every directory is
//! canonicalised and must stay inside the root (also catches Windows junctions); cycles are impossible (visited set);
//! only regular files are returned; depth, file count and bytes are bounded by `Limits`; iterative (no recursion).
//! A limit hit stops the walk and is reported in `truncated` so the scan becomes "incomplete", never a hang.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::evaluate::FileProbe;
use crate::limits::{read_limited_string, Budget, Deadline};
use crate::scanner::Limits;

/// Directories skipped by default (version control and dependency caches, not project evidence).
pub const DEFAULT_EXCLUDES: &[&str] = &[".git", ".hg", ".svn", "node_modules", "target"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Path relative to the root, `/`-separated.
    pub rel: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    Symlink { points_outside_root: bool },
    OutsideRoot,
    Excluded,
    TooDeep,
    NotRegularFile,
    Unreadable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub rel: String,
    pub reason: SkipReason,
}

#[derive(Debug, Default)]
pub struct WalkReport {
    pub files: Vec<FileEntry>,
    pub skipped: Vec<Skipped>,
    /// Set when a limit stopped the walk early; results are partial.
    pub truncated: Option<Error>,
}

fn rel_of(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Validates a rule-supplied relative path: no absolute paths, `..`, backslashes, drive letters or empty segments.
pub fn safe_rel_path(rel: &str) -> Result<&str, Error> {
    let bad = rel.is_empty()
        || rel.starts_with('/')
        || rel.contains('\\')
        || rel.contains(':')
        || rel.contains('\0')
        || rel
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..");
    if bad {
        Err(Error::InvalidTarget(format!("unsafe relative path: {rel}")))
    } else {
        Ok(rel)
    }
}

#[derive(Debug)]
pub struct SafeRoot {
    root: PathBuf,
    limits: Limits,
    excludes: Vec<String>,
}

impl SafeRoot {
    /// `root` must be an existing directory; it is canonicalised once and every access is checked against it.
    pub fn open(root: &Path, limits: &Limits) -> Result<Self, Error> {
        limits.validate()?;
        let root = fs::canonicalize(root)
            .map_err(|e| Error::InvalidTarget(format!("{}: {e}", root.display())))?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(Error::InvalidTarget(format!(
                "{} is not a directory",
                root.display()
            )));
        }
        Ok(Self {
            root,
            limits: limits.clone(),
            excludes: DEFAULT_EXCLUDES.iter().map(|s| (*s).to_string()).collect(),
        })
    }

    #[must_use]
    pub fn with_excludes(mut self, excludes: &[&str]) -> Self {
        self.excludes = excludes.iter().map(|s| (*s).to_string()).collect();
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn inside(&self, path: &Path) -> bool {
        fs::canonicalize(path).is_ok_and(|c| c.starts_with(&self.root))
    }

    /// Walks the tree breadth-first within limits. Never follows symlinks.
    pub fn walk(&self, deadline: &Deadline) -> WalkReport {
        let mut report = WalkReport::default();
        let mut visited: HashSet<PathBuf> = HashSet::new();
        let mut queue: Vec<(PathBuf, u16)> = vec![(self.root.clone(), 0)];
        visited.insert(self.root.clone());
        let mut seen: u64 = 0;
        while let Some((dir, depth)) = queue.pop() {
            if let Err(e) = deadline.check("directory walk") {
                report.truncated = Some(e);
                break;
            }
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    report.skipped.push(Skipped {
                        rel: rel_of(&self.root, &dir),
                        reason: SkipReason::Unreadable(e.kind().to_string()),
                    });
                    continue;
                }
            };
            for entry in entries.flatten() {
                seen += 1;
                if seen > self.limits.max_files {
                    report.truncated = Some(Error::LimitExceeded {
                        limit: "max_files",
                        max: self.limits.max_files,
                    });
                    return report;
                }
                let path = entry.path();
                let rel = rel_of(&self.root, &path);
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    report.skipped.push(Skipped {
                        rel,
                        reason: SkipReason::Unreadable("metadata".into()),
                    });
                    continue;
                };
                let name = entry.file_name().to_string_lossy().into_owned();
                if meta.file_type().is_symlink() {
                    let outside = !self.inside(&path);
                    report.skipped.push(Skipped {
                        rel,
                        reason: SkipReason::Symlink {
                            points_outside_root: outside,
                        },
                    });
                } else if meta.is_dir() {
                    if self.excludes.contains(&name) {
                        report.skipped.push(Skipped {
                            rel,
                            reason: SkipReason::Excluded,
                        });
                    } else if depth + 1 > self.limits.max_depth {
                        report.skipped.push(Skipped {
                            rel,
                            reason: SkipReason::TooDeep,
                        });
                    } else {
                        match fs::canonicalize(&path) {
                            Ok(c) if c.starts_with(&self.root) => {
                                if visited.insert(c.clone()) {
                                    queue.push((c, depth + 1));
                                }
                            }
                            _ => report.skipped.push(Skipped {
                                rel,
                                reason: SkipReason::OutsideRoot,
                            }),
                        }
                    }
                } else if meta.is_file() {
                    report.files.push(FileEntry {
                        rel,
                        size: meta.len(),
                    });
                } else {
                    report.skipped.push(Skipped {
                        rel,
                        reason: SkipReason::NotRegularFile,
                    });
                }
            }
        }
        report.files.sort_by(|a, b| a.rel.cmp(&b.rel));
        report.skipped.sort_by(|a, b| a.rel.cmp(&b.rel));
        report
    }

    /// Resolves a rule-supplied relative path to a regular file inside the root (no symlinks anywhere on the path).
    fn resolve_file(&self, rel: &str) -> Result<Option<(PathBuf, u64)>, Error> {
        let rel = safe_rel_path(rel)?;
        let mut path = self.root.clone();
        for segment in rel.split('/') {
            path.push(segment);
            match fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => return Ok(None),
                Ok(_) => {}
                Err(_) => return Ok(None),
            }
        }
        if !self.inside(&path) {
            return Ok(None);
        }
        let meta = fs::symlink_metadata(&path)?;
        Ok(meta.is_file().then_some((path, meta.len())))
    }

    /// Reads a file within the per-file and total byte budget (lossy UTF-8).
    pub fn read(&self, rel: &str, budget: &mut Budget) -> Result<Option<String>, Error> {
        let Some((path, size)) = self.resolve_file(rel)? else {
            return Ok(None);
        };
        budget.charge_file(size)?;
        let file = fs::File::open(&path)?;
        read_limited_string(file, self.limits.max_file_bytes, "max_file_bytes").map(Some)
    }
}

/// `FileProbe` over a `SafeRoot` for rule evaluation (`file_exists`, `file_contains`).
pub struct RootProbe<'a> {
    root: &'a SafeRoot,
    budget: std::cell::RefCell<Budget>,
}

impl<'a> RootProbe<'a> {
    pub fn new(root: &'a SafeRoot) -> Self {
        Self {
            root,
            budget: std::cell::RefCell::new(Budget::new(&root.limits)),
        }
    }
}

impl FileProbe for RootProbe<'_> {
    fn source(&self) -> String {
        format!("files in {}", self.root.root.display())
    }

    fn exists(&self, rel_path: &str) -> Result<bool, String> {
        self.root
            .resolve_file(rel_path)
            .map(|r| r.is_some())
            .map_err(|e| e.to_string())
    }

    fn contains(&self, rel_path: &str, text: &str) -> Result<bool, String> {
        let mut budget = self.budget.borrow_mut();
        match self.root.read(rel_path, &mut budget) {
            Ok(Some(body)) => Ok(body.to_lowercase().contains(&text.to_lowercase())),
            Ok(None) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "opencomply-walk-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn file(&self, rel: &str, body: &str) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn deadline() -> Deadline {
        Deadline::start(Duration::from_secs(30))
    }

    #[test]
    fn walks_files_and_skips_excluded_dirs() {
        let t = TempTree::new();
        t.file("wp-config.php", "<?php define('DB_NAME','x');");
        t.file("wp-content/uploads/2026/a.jpg", "jpg");
        t.file(".git/config", "x");
        t.file("node_modules/x/index.js", "x");
        let root = SafeRoot::open(&t.0, &Limits::default()).unwrap();
        let r = root.walk(&deadline());
        let rels: Vec<_> = r.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, ["wp-config.php", "wp-content/uploads/2026/a.jpg"]);
        assert!(r
            .skipped
            .iter()
            .any(|s| s.rel == ".git" && s.reason == SkipReason::Excluded));
        assert!(r.truncated.is_none());
    }

    #[test]
    fn depth_and_file_limits_truncate_safely() {
        let t = TempTree::new();
        t.file("a/b/c/deep.txt", "x");
        for i in 0..5 {
            t.file(&format!("f{i}.txt"), "x");
        }
        let shallow = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let r = SafeRoot::open(&t.0, &shallow).unwrap().walk(&deadline());
        assert!(r
            .skipped
            .iter()
            .any(|s| s.rel == "a/b" && s.reason == SkipReason::TooDeep));
        let few = Limits {
            max_files: 3,
            ..Limits::default()
        };
        let r = SafeRoot::open(&t.0, &few).unwrap().walk(&deadline());
        assert!(matches!(
            r.truncated,
            Some(Error::LimitExceeded {
                limit: "max_files",
                ..
            })
        ));
    }

    #[test]
    fn expired_deadline_truncates() {
        let t = TempTree::new();
        t.file("a.txt", "x");
        let r = SafeRoot::open(&t.0, &Limits::default())
            .unwrap()
            .walk(&Deadline::start(Duration::ZERO));
        assert!(matches!(r.truncated, Some(Error::Timeout { .. })));
    }

    #[test]
    fn rule_paths_cannot_escape() {
        for bad in [
            "../etc/passwd",
            "/etc/passwd",
            "a/../../x",
            "C:/x",
            "a\\b",
            "",
            "a//b",
            "./a",
        ] {
            assert!(safe_rel_path(bad).is_err(), "{bad}");
        }
        assert!(safe_rel_path("wp-content/uploads/x.php").is_ok());
    }

    #[test]
    fn probe_reads_within_budget() {
        let t = TempTree::new();
        t.file("SECURITY.md", "Report incidents to security@example.com");
        t.file("big.txt", &"x".repeat(100));
        let limits = Limits {
            max_file_bytes: 50,
            ..Limits::default()
        };
        let root = SafeRoot::open(&t.0, &limits).unwrap();
        let probe = RootProbe::new(&root);
        assert_eq!(probe.exists("SECURITY.md"), Ok(true));
        assert_eq!(probe.exists("missing.md"), Ok(false));
        assert_eq!(probe.contains("SECURITY.md", "INCIDENTS"), Ok(true));
        assert!(probe
            .contains("big.txt", "x")
            .unwrap_err()
            .contains("max_file_bytes"));
        assert!(probe.exists("../outside").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed_and_escapes_are_flagged() {
        let t = TempTree::new();
        let outside = TempTree::new();
        outside.file("secret.txt", "TOP SECRET");
        t.file("inside.txt", "ok");
        std::os::unix::fs::symlink(outside.0.join("secret.txt"), t.0.join("link-out")).unwrap();
        std::os::unix::fs::symlink(&outside.0, t.0.join("dir-out")).unwrap();
        std::os::unix::fs::symlink(t.0.join("inside.txt"), t.0.join("link-in")).unwrap();
        std::os::unix::fs::symlink(&t.0, t.0.join("loop")).unwrap();
        let root = SafeRoot::open(&t.0, &Limits::default()).unwrap();
        let r = root.walk(&deadline());
        let rels: Vec<_> = r.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, ["inside.txt"]);
        let reason = |n: &str| {
            r.skipped
                .iter()
                .find(|s| s.rel == n)
                .map(|s| s.reason.clone())
        };
        assert_eq!(
            reason("link-out"),
            Some(SkipReason::Symlink {
                points_outside_root: true
            })
        );
        assert_eq!(
            reason("dir-out"),
            Some(SkipReason::Symlink {
                points_outside_root: true
            })
        );
        assert_eq!(
            reason("link-in"),
            Some(SkipReason::Symlink {
                points_outside_root: false
            })
        );
        let probe = RootProbe::new(&root);
        assert_eq!(probe.exists("link-out"), Ok(false));
        assert_eq!(probe.contains("dir-out/secret.txt", "SECRET"), Ok(false));
    }
}
