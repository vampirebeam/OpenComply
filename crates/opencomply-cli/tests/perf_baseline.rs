//! Performance baseline (not a gate): time and peak memory of a scan against a local server, for a typical page and
//! for a worst case near the input limits (84 header lines — the HTTP client allows 100 — tens of KB of security
//! headers under the 64 KiB cap, 1 MiB HTML at the body cap). Ignored by default — timings on
//! shared machines vary, so CI never fails on them. Run on purpose and record the numbers in the QA report:
//! `cargo test --release -p opencomply-cli --test perf_baseline -- --ignored --nocapture`

#![allow(clippy::unwrap_used)]
// Printing the measurements is this test's output.
#![allow(clippy::print_stdout)]

use std::fmt::Write as _;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

use opencomply_core::rules::{RulePack, OFFICIAL_HEADERS_PACK};
use opencomply_core::{
    detect_platforms, evaluate_pack, render, EvalInput, Format, HttpEvidence, InsecureProbe,
    Limits, RedirectHop,
};
use opencomply_http::NetPolicy;

const RUNS: usize = 30;

fn typical() -> String {
    let body = format!(
        "<html><head><meta name=\"generator\" content=\"WordPress 6.5.2\"></head><body>{}</body></html>",
        "<p>content</p>".repeat(3000)
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx/1.24.0\r\nX-Powered-By: PHP/8.2.1\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nSet-Cookie: sid=1; Path=/; Secure; HttpOnly\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Every parsed header near its share of the 64 KiB header limit, and a body at the 1 MiB limit.
fn worst_headers() -> Vec<(String, String)> {
    let sources = (0..1200).fold(String::new(), |mut s, i| {
        let _ = write!(s, " https://h{i}.example.com");
        s
    });
    let mut h = vec![
        ("Content-Type".to_string(), "text/html".to_string()),
        (
            "Content-Security-Policy".to_string(),
            format!("default-src 'self'; script-src 'self' 'unsafe-inline'{sources}"),
        ),
        (
            "Permissions-Policy".to_string(),
            (0..200)
                .map(|i| format!("feature{i}=*"))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        (
            "Server-Timing".to_string(),
            (0..150)
                .map(|i| format!("m{i};desc=\"web-{i}.prod.internal\";dur=1.5"))
                .collect::<Vec<_>>()
                .join(", "),
        ),
    ];
    // The HTTP client refuses a response with more than 100 header lines, so the worst case stays under that.
    for i in 0..80 {
        h.push((
            "Set-Cookie".to_string(),
            format!("cookie_number_{i}=value{i}; Path=/; HttpOnly"),
        ));
    }
    h
}

fn worst_body() -> String {
    let unit = "<link rel=\"stylesheet\" href=\"/wp-content/themes/x.css\"><script src=\"/_next/static/a.js\"></script>";
    let mut b = String::from("<html><head><meta name=\"generator\" content=\"WordPress 6.5.2\">");
    while b.len() + unit.len() < 1024 * 1024 - 32 {
        b.push_str(unit);
    }
    b.push_str("</head></html>");
    b
}

fn worst() -> String {
    let headers = worst_headers().iter().fold(String::new(), |mut s, (n, v)| {
        let _ = write!(s, "{n}: {v}\r\n");
        s
    });
    let body = worst_body();
    format!(
        "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// One canned response per connection, on a background thread.
fn serve(response: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let r = response.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(r.as_bytes());
            });
        }
    });
    format!("http://{addr}/")
}

fn stats(mut d: Vec<Duration>) -> String {
    d.sort();
    let ms = |x: Duration| x.as_secs_f64() * 1000.0;
    // Nearest-rank percentile: index (n - 1) · pct / 100.
    let p = |pct: usize| ms(d[(d.len() - 1) * pct / 100]);
    format!(
        "p50 {:7.2} ms · p95 {:7.2} ms · max {:7.2} ms",
        p(50),
        p(95),
        ms(d[d.len() - 1])
    )
}

/// Peak resident memory of this process (Linux), in MiB.
fn peak_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: f64 = status
        .lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb / 1024.0)
}

#[test]
#[ignore = "baseline measurement, run on purpose"]
fn performance_baseline() {
    let pages = [("typical", typical()), ("worst case", worst())];
    let header_bytes: usize = worst_headers().iter().map(|(n, v)| n.len() + v.len()).sum();
    println!(
        "\nresponse sizes: typical {} B, worst case {} B ({} header lines, {header_bytes} B of headers)",
        pages[0].1.len(),
        pages[1].1.len(),
        worst_headers().len()
    );

    // 1. The CLI binary end to end (process start, both requests, evaluation, JSON output).
    for (name, page) in &pages {
        let url = serve(page.clone());
        let mut times = Vec::new();
        for _ in 0..RUNS {
            let t = Instant::now();
            let out = Command::new(env!("CARGO_BIN_EXE_opencomply"))
                .args([
                    "scan",
                    "headers",
                    &url,
                    "--allow-private",
                    "--format",
                    "json",
                ])
                .output()
                .unwrap();
            times.push(t.elapsed());
            assert!(
                !out.stdout.is_empty(),
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        println!("cli scan       {name:<10} {}", stats(times));
    }

    // 2. In process: the scan as the CLI runs it, with peak memory.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (name, page) in &pages {
        let url = serve(page.clone());
        let mut times = Vec::new();
        for _ in 0..RUNS {
            let t = Instant::now();
            let out = rt
                .block_on(opencomply_headers::scan_headers(
                    &url,
                    &Limits::default(),
                    NetPolicy {
                        allow_private: true,
                    },
                ))
                .unwrap();
            let _ = render(&out.report, Format::Json, true);
            times.push(t.elapsed());
        }
        println!("in-process     {name:<10} {}", stats(times));
    }
    if let Some(mib) = peak_rss_mib() {
        println!("peak RSS of the test process after all in-process scans: {mib:.1} MiB");
    }

    // 3. Engine only on the worst case: evaluation + all three formats (no network).
    let pack = RulePack::from_toml(OFFICIAL_HEADERS_PACK).unwrap();
    let http = HttpEvidence {
        source: "GET https://example.com/".into(),
        status: 200,
        headers: worst_headers(),
        https: true,
        insecure_probe: Some(InsecureProbe::Responded {
            chain: vec![RedirectHop {
                url: "http://example.com/".into(),
                status: 301,
                location: None,
            }],
            final_url: "https://example.com/".into(),
        }),
        redirect_cookies: vec![],
        html_generator: Some("WordPress 6.5.2".into()),
    };
    let mut times = Vec::new();
    for _ in 0..RUNS * 10 {
        let t = Instant::now();
        let platforms = detect_platforms(&http.headers, &http.source);
        let r = evaluate_pack(
            &pack,
            "https://example.com/",
            &EvalInput::Http(&http),
            platforms,
        );
        for f in [Format::Summary, Format::Json, Format::Markdown] {
            let _ = render(&r, f, true);
        }
        times.push(t.elapsed());
    }
    println!("engine only    worst case {}", stats(times));
    let body = worst_body();
    let t = Instant::now();
    let _ = opencomply_core::detect_from_html(&body, "GET x");
    let _ = opencomply_core::meta_generator(&body);
    println!(
        "html scan      1 MiB body {:7.2} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
}
