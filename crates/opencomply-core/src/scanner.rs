//! Scanner interface and resource limits. Every module implements `Scanner` and must honour `Limits`:
//! all I/O bounded by timeouts and the overall deadline, concurrency bounded, input sizes capped, limits hit → `Error`, never a hang.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::Error;
use crate::finding::Module;
use crate::report::Report;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Url(String),
    Path(PathBuf),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Url(u) => f.write_str(u),
            Target::Path(p) => write!(f, "{}", p.display()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub deadline: Duration,
    pub max_concurrency: usize,
    pub max_per_host: usize,
    pub max_redirects: u8,
    pub max_body_bytes: u64,
    pub max_header_bytes: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: u16,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            deadline: Duration::from_secs(60),
            max_concurrency: 8,
            max_per_host: 2,
            max_redirects: 5,
            max_body_bytes: 1024 * 1024,
            max_header_bytes: 64 * 1024,
            max_files: 50_000,
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_depth: 32,
        }
    }
}

pub trait Scanner {
    const MODULE: Module;

    fn scan(
        &self,
        target: &Target,
        limits: &Limits,
    ) -> impl Future<Output = Result<Report, Error>> + Send;
}
