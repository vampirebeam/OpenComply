//! `SafeClient` against a local test server (offline): private targets blocked by default, redirect chain recorded,
//! redirect loops / bad schemes / oversized bodies / slow servers all end safely within limits.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use opencomply_core::limits::Deadline;
use opencomply_core::{Error, Limits};
use opencomply_http::{FetchOptions, NetPolicy, SafeClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Minimal HTTP/1.1 server: routes by path, one response per connection.
async fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                if path == "/stall" {
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 100\r\nConnection: close\r\n\r\n<html")
                        .await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    return;
                }
                let resp = match path.as_str() {
                    "/start" => "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/final" => "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nServer: nginx/1.25\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_string(),
                    "/loop" => "HTTP/1.1 301 Moved\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/meta" => "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/meta6" => "HTTP/1.1 302 Found\r\nLocation: http://[::ffff:169.254.169.254]/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/ftp" => "HTTP/1.1 302 Found\r\nLocation: ftp://example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/big" => {
                        let body = "x".repeat(10_000);
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                    }
                    "/slow" => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                    }
                    p if p.starts_with("/hop/") => {
                        let n: u32 = p.trim_start_matches("/hop/").parse().unwrap_or(0);
                        format!("HTTP/1.1 302 Found\r\nLocation: /hop/{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", n + 1)
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                };
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

fn private_ok() -> NetPolicy {
    NetPolicy {
        allow_private: true,
    }
}

fn follow() -> FetchOptions {
    FetchOptions {
        follow_redirects: true,
        read_body: true,
    }
}

fn deadline() -> Deadline {
    Deadline::start(Duration::from_secs(20))
}

#[tokio::test]
async fn private_targets_are_blocked_by_default() {
    let base = serve().await;
    let client = SafeClient::new(&Limits::default(), NetPolicy::default()).unwrap();
    let err = client
        .fetch(&format!("{base}/final"), follow(), &deadline())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidTarget(_)), "{err}");
}

/// `localhost` resolves to loopback: the resolver refuses it and the error is a refused target, not a network error.
#[tokio::test]
async fn hostname_resolving_to_loopback_is_an_invalid_target() {
    let base = serve().await;
    let port = base.rsplit(':').next().unwrap();
    let client = SafeClient::new(&Limits::default(), NetPolicy::default()).unwrap();
    let err = client
        .fetch(
            &format!("http://localhost:{port}/final"),
            follow(),
            &deadline(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidTarget(_)), "{err}");
    assert!(err.to_string().contains("private or reserved"), "{err}");
}

#[tokio::test]
async fn redirect_chain_is_recorded() {
    let base = serve().await;
    let client = SafeClient::new(&Limits::default(), private_ok()).unwrap();
    let r = client
        .fetch(&format!("{base}/start"), follow(), &deadline())
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.chain.len(), 2);
    assert_eq!(r.chain[0].status, 302);
    assert_eq!(r.chain[0].location.as_deref(), Some("/final"));
    assert!(r.final_url.ends_with("/final"));
    assert!(r
        .headers
        .iter()
        .any(|(n, v)| n == "x-content-type-options" && v == "nosniff"));
    assert_eq!(r.body.as_deref(), Some("hello"));
}

#[tokio::test]
async fn not_following_keeps_the_first_response() {
    let base = serve().await;
    let client = SafeClient::new(&Limits::default(), private_ok()).unwrap();
    let opts = FetchOptions {
        follow_redirects: false,
        read_body: false,
    };
    let r = client
        .fetch(&format!("{base}/start"), opts, &deadline())
        .await
        .unwrap();
    assert_eq!(r.status, 302);
    assert_eq!(r.chain.len(), 1);
    assert!(r.body.is_none());
}

#[tokio::test]
async fn redirect_loop_hits_the_limit() {
    let base = serve().await;
    let limits = Limits {
        max_redirects: 3,
        ..Limits::default()
    };
    let client = SafeClient::new(&limits, private_ok()).unwrap();
    // A redirect back to a visited URL is reported as a loop, before the redirect limit.
    let err = client
        .fetch(&format!("{base}/loop"), follow(), &deadline())
        .await
        .unwrap_err();
    match &err {
        Error::RedirectLoop(urls) => {
            assert_eq!(urls.len(), 2, "{urls:?}");
            assert!(urls.iter().all(|u| u.ends_with("/loop")), "{urls:?}");
        }
        other => panic!("expected a redirect loop, got {other}"),
    }
    assert!(err.to_string().contains("may block bots"), "{err}");

    // A long chain without repeats still stops at max_redirects.
    let err = client
        .fetch(&format!("{base}/hop/0"), follow(), &deadline())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::LimitExceeded {
                limit: "max_redirects",
                ..
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn redirect_to_other_scheme_is_rejected() {
    let base = serve().await;
    let client = SafeClient::new(&Limits::default(), private_ok()).unwrap();
    let err = client
        .fetch(&format!("{base}/ftp"), follow(), &deadline())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidTarget(_)), "{err}");
}

#[tokio::test]
async fn body_is_truncated_at_the_limit() {
    let base = serve().await;
    let limits = Limits {
        max_body_bytes: 1024,
        max_header_bytes: 1024,
        ..Limits::default()
    };
    let client = SafeClient::new(&limits, private_ok()).unwrap();
    let r = client
        .fetch(&format!("{base}/big"), follow(), &deadline())
        .await
        .unwrap();
    assert!(r.body_truncated);
    assert_eq!(r.body.unwrap().len(), 1024);
}

#[tokio::test]
async fn slow_server_times_out_instead_of_hanging() {
    let base = serve().await;
    let limits = Limits {
        io_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let client = SafeClient::new(&limits, private_ok()).unwrap();
    let started = std::time::Instant::now();
    let err = client
        .fetch(&format!("{base}/slow"), follow(), &deadline())
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "took {:?}",
        started.elapsed()
    );
    assert!(
        matches!(err, Error::Timeout { .. } | Error::Network(_)),
        "{err}"
    );
}

#[tokio::test]
async fn stalled_body_keeps_the_headers_and_the_part_already_read() {
    let base = serve().await;
    let limits = Limits {
        io_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let client = SafeClient::new(&limits, private_ok()).unwrap();
    let started = std::time::Instant::now();
    let r = client
        .fetch(&format!("{base}/stall"), follow(), &deadline())
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(r.status, 200);
    assert!(r.headers.iter().any(|(n, v)| n == "server" && v == "nginx"));
    assert!(r.body_truncated);
    assert_eq!(r.body.as_deref(), Some("<html"));
}

#[tokio::test]
async fn redirect_to_cloud_metadata_is_refused_at_that_hop() {
    let base = serve().await;
    let client = SafeClient::new(&Limits::default(), private_ok()).unwrap();
    for path in ["/meta", "/meta6"] {
        let err = client
            .fetch(&format!("{base}{path}"), follow(), &deadline())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidTarget(_)), "{path}: {err}");
    }
}
