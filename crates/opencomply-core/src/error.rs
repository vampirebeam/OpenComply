//! Scanner error type. Every variant maps to an exit code; resource limits and timeouts are "incomplete", never a hang or panic.

use std::fmt;
use std::time::Duration;

use crate::finding::Module;
use crate::report::ExitCode;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    InvalidTarget(String),
    InvalidConfig(String),
    Timeout {
        operation: &'static str,
        after: Duration,
    },
    LimitExceeded {
        limit: &'static str,
        max: u64,
    },
    Network(String),
    Io(std::io::Error),
    NotImplemented(Module),
}

impl Error {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Error::InvalidTarget(_) | Error::InvalidConfig(_) => ExitCode::Usage,
            Error::Timeout { .. } | Error::LimitExceeded { .. } => ExitCode::Incomplete,
            Error::Network(_) | Error::Io(_) | Error::NotImplemented(_) => ExitCode::Error,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTarget(why) => write!(f, "invalid target: {why}"),
            Error::InvalidConfig(why) => write!(f, "invalid configuration: {why}"),
            Error::Timeout { operation, after } => {
                write!(f, "{operation} timed out after {}s", after.as_secs())
            }
            Error::LimitExceeded { limit, max } => write!(f, "limit exceeded: {limit} (max {max})"),
            Error::Network(why) => write!(f, "network error: {why}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::NotImplemented(m) => write!(f, "'{}' scanner is not implemented yet", m.name()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_timeouts_are_incomplete_not_errors() {
        let t = Error::Timeout {
            operation: "connect",
            after: Duration::from_secs(5),
        };
        let l = Error::LimitExceeded {
            limit: "max_body_bytes",
            max: 1024,
        };
        assert_eq!(t.exit_code(), ExitCode::Incomplete);
        assert_eq!(l.exit_code(), ExitCode::Incomplete);
        assert_eq!(
            Error::InvalidTarget("x".into()).exit_code(),
            ExitCode::Usage
        );
        assert_eq!(t.to_string(), "connect timed out after 5s");
    }
}
