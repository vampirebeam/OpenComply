//! Enforcement helpers for `Limits`, shared by every scanner. Runtime-agnostic and synchronous: bounded reads,
//! an overall deadline, a file/byte budget, a redirect budget and header-size checks. Hitting any limit returns
//! `Error::Timeout` / `Error::LimitExceeded` (exit 3, "incomplete") — never a hang, OOM or panic.
//! Concurrency (semaphore) lives in the async network layer, which takes its permits count from `Limits`.

use std::io::Read;
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::scanner::Limits;

/// Hard ceilings a user-supplied `Limits` may not exceed (protects the host even when misconfigured).
pub const CEILING_DEADLINE: Duration = Duration::from_secs(600);
pub const CEILING_CONCURRENCY: usize = 64;
pub const CEILING_BODY_BYTES: u64 = 16 * 1024 * 1024;
pub const CEILING_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const CEILING_FILES: u64 = 1_000_000;
pub const CEILING_DEPTH: u16 = 128;
pub const CEILING_REDIRECTS: u8 = 20;

impl Limits {
    /// Rejects zero values (would block every scan) and values above the hard ceilings.
    pub fn validate(&self) -> Result<(), Error> {
        let bad = |what: &str| Err(Error::InvalidConfig(what.to_string()));
        if self.connect_timeout.is_zero() || self.io_timeout.is_zero() || self.deadline.is_zero() {
            return bad("timeouts must be greater than zero");
        }
        if self.deadline > CEILING_DEADLINE {
            return bad("deadline above 600s");
        }
        if self.io_timeout > self.deadline || self.connect_timeout > self.deadline {
            return bad("per-operation timeouts must not exceed the overall deadline");
        }
        if self.max_concurrency == 0 || self.max_concurrency > CEILING_CONCURRENCY {
            return bad("max_concurrency must be 1-64");
        }
        if self.max_per_host == 0 || self.max_per_host > self.max_concurrency {
            return bad("max_per_host must be 1..=max_concurrency");
        }
        if self.max_redirects > CEILING_REDIRECTS {
            return bad("max_redirects above 20");
        }
        if self.max_body_bytes == 0 || self.max_body_bytes > CEILING_BODY_BYTES {
            return bad("max_body_bytes must be 1 B - 16 MiB");
        }
        if self.max_header_bytes == 0 || self.max_header_bytes > self.max_body_bytes {
            return bad("max_header_bytes must be 1..=max_body_bytes");
        }
        if self.max_files == 0 || self.max_files > CEILING_FILES {
            return bad("max_files must be 1 - 1,000,000");
        }
        if self.max_file_bytes == 0 || self.max_file_bytes > self.max_total_bytes {
            return bad("max_file_bytes must be 1..=max_total_bytes");
        }
        if self.max_total_bytes > CEILING_TOTAL_BYTES {
            return bad("max_total_bytes above 2 GiB");
        }
        if self.max_depth == 0 || self.max_depth > CEILING_DEPTH {
            return bad("max_depth must be 1-128");
        }
        Ok(())
    }
}

/// Reads at most `max` bytes; one extra byte is read to detect overflow without buffering the rest.
pub fn read_limited<R: Read>(reader: R, max: u64, what: &'static str) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(usize::try_from(max.min(64 * 1024)).unwrap_or(64 * 1024));
    reader.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(Error::LimitExceeded { limit: what, max });
    }
    Ok(buf)
}

/// `read_limited` + lossy UTF-8 (invalid bytes become U+FFFD; scanners never trust encoding).
pub fn read_limited_string<R: Read>(
    reader: R,
    max: u64,
    what: &'static str,
) -> Result<String, Error> {
    read_limited(reader, max, what).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Overall scan deadline. Every I/O step asks for `budget(op_timeout)` to get min(op timeout, time left).
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    start: Instant,
    total: Duration,
}

impl Deadline {
    pub fn start(total: Duration) -> Self {
        Self {
            start: Instant::now(),
            total,
        }
    }

    pub fn remaining(&self) -> Duration {
        self.total.saturating_sub(self.start.elapsed())
    }

    pub fn check(&self, operation: &'static str) -> Result<(), Error> {
        if self.remaining().is_zero() {
            Err(Error::Timeout {
                operation,
                after: self.total,
            })
        } else {
            Ok(())
        }
    }

    /// Timeout to use for the next operation: the smaller of `op_timeout` and the time left.
    pub fn budget(&self, op_timeout: Duration, operation: &'static str) -> Result<Duration, Error> {
        self.check(operation)?;
        Ok(op_timeout.min(self.remaining()))
    }
}

/// Counts files and bytes read during a scan against `max_files`, `max_file_bytes` and `max_total_bytes`.
#[derive(Debug, Clone)]
pub struct Budget {
    files: u64,
    bytes: u64,
    max_files: u64,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl Budget {
    pub fn new(limits: &Limits) -> Self {
        Self {
            files: 0,
            bytes: 0,
            max_files: limits.max_files,
            max_file_bytes: limits.max_file_bytes,
            max_total_bytes: limits.max_total_bytes,
        }
    }

    /// Call before reading a file of `size` bytes; nothing is charged when it is refused.
    pub fn charge_file(&mut self, size: u64) -> Result<(), Error> {
        if self.files >= self.max_files {
            return Err(Error::LimitExceeded {
                limit: "max_files",
                max: self.max_files,
            });
        }
        if size > self.max_file_bytes {
            return Err(Error::LimitExceeded {
                limit: "max_file_bytes",
                max: self.max_file_bytes,
            });
        }
        if self.bytes.saturating_add(size) > self.max_total_bytes {
            return Err(Error::LimitExceeded {
                limit: "max_total_bytes",
                max: self.max_total_bytes,
            });
        }
        self.files += 1;
        self.bytes += size;
        Ok(())
    }

    pub fn used(&self) -> (u64, u64) {
        (self.files, self.bytes)
    }
}

/// Counts redirects followed for one request chain.
#[derive(Debug, Clone, Copy)]
pub struct RedirectBudget {
    left: u8,
    max: u8,
}

impl RedirectBudget {
    pub fn new(limits: &Limits) -> Self {
        Self {
            left: limits.max_redirects,
            max: limits.max_redirects,
        }
    }

    pub fn follow(&mut self) -> Result<(), Error> {
        if self.left == 0 {
            return Err(Error::LimitExceeded {
                limit: "max_redirects",
                max: u64::from(self.max),
            });
        }
        self.left -= 1;
        Ok(())
    }
}

/// Checks total header size (names + values + 4 bytes per line) against `max_header_bytes`.
pub fn check_headers(headers: &[(String, String)], limits: &Limits) -> Result<(), Error> {
    let total: u64 = headers
        .iter()
        .map(|(n, v)| (n.len() + v.len() + 4) as u64)
        .sum();
    if total > limits.max_header_bytes {
        return Err(Error::LimitExceeded {
            limit: "max_header_bytes",
            max: limits.max_header_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::ExitCode;

    #[test]
    fn default_limits_are_valid_and_bad_ones_rejected() {
        assert!(Limits::default().validate().is_ok());
        let cases: [fn(&mut Limits); 6] = [
            |l| l.deadline = Duration::ZERO,
            |l| l.deadline = Duration::from_secs(3600),
            |l| l.max_concurrency = 0,
            |l| l.max_per_host = 99,
            |l| l.max_body_bytes = 1 << 40,
            |l| l.max_depth = 0,
        ];
        for mutate in cases {
            let mut l = Limits::default();
            mutate(&mut l);
            let err = l.validate().unwrap_err();
            assert_eq!(err.exit_code(), ExitCode::Usage, "{err}");
        }
    }

    #[test]
    fn read_limited_accepts_exact_and_rejects_overflow() {
        assert_eq!(read_limited(&b"12345"[..], 5, "body").unwrap().len(), 5);
        let err = read_limited(&b"123456"[..], 5, "body").unwrap_err();
        assert_eq!(err.to_string(), "limit exceeded: body (max 5)");
        assert_eq!(err.exit_code(), ExitCode::Incomplete);
    }

    #[test]
    fn read_limited_stops_early_on_endless_input() {
        let endless = std::io::repeat(b'a');
        assert!(read_limited(endless, 1024, "body").is_err());
    }

    #[test]
    fn read_limited_string_is_lossy() {
        let s = read_limited_string(&[0x66, 0xff, 0x6f][..], 10, "body").unwrap();
        assert_eq!(s, "f\u{fffd}o");
    }

    #[test]
    fn deadline_expires_and_budget_shrinks() {
        let d = Deadline::start(Duration::from_secs(60));
        assert!(d.budget(Duration::from_secs(10), "connect").unwrap() <= Duration::from_secs(10));
        let expired = Deadline::start(Duration::ZERO);
        let err = expired.check("scan").unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Incomplete);
    }

    #[test]
    fn file_budget_enforces_all_three_limits() {
        let limits = Limits {
            max_files: 2,
            max_file_bytes: 10,
            max_total_bytes: 15,
            ..Limits::default()
        };
        let mut b = Budget::new(&limits);
        assert!(b.charge_file(11).is_err());
        b.charge_file(10).unwrap();
        assert!(b.charge_file(6).is_err());
        b.charge_file(5).unwrap();
        assert_eq!(b.used(), (2, 15));
        let err = b.charge_file(0).unwrap_err();
        assert_eq!(err.to_string(), "limit exceeded: max_files (max 2)");
    }

    #[test]
    fn redirects_and_headers_are_bounded() {
        let limits = Limits {
            max_redirects: 1,
            max_header_bytes: 20,
            ..Limits::default()
        };
        let mut r = RedirectBudget::new(&limits);
        r.follow().unwrap();
        assert!(r.follow().is_err());
        assert!(check_headers(&[("a".into(), "b".into())], &limits).is_ok());
        assert!(check_headers(&[("x".into(), "y".repeat(30))], &limits).is_err());
    }
}
