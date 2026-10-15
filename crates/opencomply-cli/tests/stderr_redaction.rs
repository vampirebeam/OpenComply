//! The real binary's diagnostics: an error that quotes the target URL (here a refused loopback port, no internet
//! needed) must not print the tokens in its query string, and credentials in the URL are refused before any request.

#![allow(clippy::unwrap_used)]

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_opencomply"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn network_errors_never_print_url_secrets() {
    let (code, stdout, stderr) = run(&[
        "scan",
        "headers",
        "http://127.0.0.1:9/?token=tok_SECRET123&api_key=sk-test-AbC123xyz",
        "--allow-private",
    ]);
    assert_eq!(code, 4, "{stderr}");
    assert!(stdout.is_empty());
    assert!(stderr.starts_with("opencomply: "), "{stderr}");
    for secret in ["tok_SECRET123", "sk-test-AbC123xyz"] {
        assert!(!stderr.contains(secret), "{secret} leaked: {stderr}");
    }
    assert!(stderr.contains("REDACTED"), "{stderr}");
}

/// A bare host (`www.example.com`) is scanned over HTTPS instead of failing as a "relative URL".
#[test]
fn a_target_without_scheme_is_scanned_over_https() {
    let (code, _, stderr) = run(&["scan", "headers", "127.0.0.1:9"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(!stderr.contains("relative URL"), "{stderr}");
    assert!(stderr.contains("private"), "{stderr}");
}

#[test]
fn credentials_in_the_url_are_refused_without_echoing_them() {
    let (code, _, stderr) = run(&["scan", "headers", "https://admin:S3cretPass@example.com/"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(!stderr.contains("S3cretPass"), "{stderr}");
}
