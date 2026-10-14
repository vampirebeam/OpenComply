//! End-to-end `scan_headers` against a local server (offline, `allow_private`): real requests, the official pack,
//! platform detection from headers + HTML, grading; private targets refused without `allow_private`.

#![allow(clippy::unwrap_used)]

use opencomply_core::{Error, Grade, Limits, Status};
use opencomply_headers::scan_headers;
use opencomply_http::NetPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serve(response: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

const WORDPRESS_ON_HTTP: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.58 (Ubuntu)\r\nX-Powered-By: PHP/8.2.1\r\nSet-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/\r\nContent-Length: 75\r\nConnection: close\r\n\r\n<html><head><link rel='stylesheet' href='/wp-content/themes/x.css'></head></html>";

#[tokio::test]
async fn plain_http_site_is_scanned_end_to_end() {
    let url = serve(WORDPRESS_ON_HTTP).await;
    let out = scan_headers(
        &url,
        &Limits::default(),
        NetPolicy {
            allow_private: true,
        },
    )
    .await
    .unwrap();
    let r = &out.report;
    let status = |id: &str| r.findings.iter().find(|f| f.rule_id == id).unwrap().status;
    assert_eq!(r.findings.len(), 10);
    assert_eq!(
        status("HDR-001"),
        Status::Fail,
        "HSTS cannot work over http://"
    );
    assert_eq!(status("HDR-007"), Status::Fail, "http:// serves the page");
    assert_eq!(status("HDR-010"), Status::Fail);
    assert_eq!(
        status("HDR-009"),
        Status::NeedsReview,
        "cookie without HttpOnly over http"
    );
    let ids: Vec<&str> = r.platforms.iter().map(|p| p.id).collect();
    assert!(
        ids.contains(&"apache") && ids.contains(&"wordpress") && ids.contains(&"php"),
        "{ids:?}"
    );
    let g = r.grade.as_ref().unwrap();
    assert_eq!(g.grade, Grade::F);
    assert!(!g.upgrades.is_empty());
    assert!(
        out.warnings.iter().any(|w| w.contains("not signed"))
            || opencomply_core::rules::OFFICIAL_HEADERS_SIG.is_some()
    );
}

#[tokio::test]
async fn private_target_is_refused_by_default() {
    let url = serve(WORDPRESS_ON_HTTP).await;
    let err = scan_headers(&url, &Limits::default(), NetPolicy::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidTarget(_)), "{err}");
}

#[tokio::test]
async fn error_page_is_flagged() {
    let url =
        serve("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    let out = scan_headers(
        &url,
        &Limits::default(),
        NetPolicy {
            allow_private: true,
        },
    )
    .await
    .unwrap();
    assert!(
        out.warnings.iter().any(|w| w.contains("answered 503")),
        "{:?}",
        out.warnings
    );
}
