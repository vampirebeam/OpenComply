//! Security headers scanner. Two requests per scan, both through the SSRF-safe client:
//! 1. the target, redirects followed, body capped (for platform fingerprints and the page's meta generator);
//! 2. the `http://` version of the same URL, to see whether it serves the page or moves to HTTPS.
//!
//! An `http://` target reuses request 1 for both. Evidence → official headers pack → findings + grade.

use opencomply_core::limits::Deadline;
use opencomply_core::rules::{RulePack, OFFICIAL_HEADERS_PACK, OFFICIAL_HEADERS_SIG};
use opencomply_core::signing::TrustedKey;
use opencomply_core::{
    detect_from_html, detect_platforms, merge_platforms, meta_generator, without_host_infra, Error,
    EvalInput, HttpEvidence, InsecureProbe, Limits, Module, Report, RuleRegistry,
};
use opencomply_http::{validate_target, FetchOptions, FetchResult, NetPolicy, SafeClient};
use url::Url;

/// The report plus notes for the person running the scan (stderr), e.g. an error-page response.
#[derive(Debug)]
pub struct ScanOutput {
    pub report: Report,
    pub warnings: Vec<String>,
}

/// Official pack, signature-verified when the build carries a signature; otherwise loaded as a development build.
fn official_registry(warnings: &mut Vec<String>) -> Result<RuleRegistry, Error> {
    let mut reg = RuleRegistry::new();
    let bad = |e: &dyn std::fmt::Display| Error::InvalidConfig(format!("official rule pack: {e}"));
    if let Some(sig) = OFFICIAL_HEADERS_SIG {
        reg.add_file(
            "opencomply-headers.toml",
            OFFICIAL_HEADERS_PACK.as_bytes(),
            Some(sig),
            &TrustedKey::official(),
            false,
        )
        .map_err(|e| bad(&e))?;
    } else {
        let pack = RulePack::from_toml(OFFICIAL_HEADERS_PACK).map_err(|e| bad(&e))?;
        reg.add(pack).map_err(|e| bad(&e))?;
        warnings.push("development build: the official rule pack is not signed".into());
    }
    Ok(reg)
}

/// `http://` twin of an `https://` target on the default port; `None` for custom ports (no fair comparison).
fn insecure_url(url: &Url) -> Option<String> {
    if url.port().is_some() {
        return None;
    }
    let mut u = url.clone();
    u.set_scheme("http").ok()?;
    Some(u.to_string())
}

/// What a failed `http://` request says about the port: a timeout (including a connect timeout) is told apart from a
/// refused connection; other errors say nothing.
fn closed(e: &Error) -> Option<InsecureProbe> {
    let why = e.to_string();
    match e {
        Error::Timeout { .. } => Some(InsecureProbe::TimedOut(why)),
        Error::Network(m) => {
            let m = m.to_ascii_lowercase();
            if m.contains("timed out") || m.contains("timeout") {
                Some(InsecureProbe::TimedOut(why))
            } else if m.contains("connect") || m.contains("refused") {
                Some(InsecureProbe::Unreachable(why))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn responded(r: FetchResult) -> InsecureProbe {
    InsecureProbe::Responded {
        chain: r.chain,
        final_url: r.final_url,
    }
}

/// Follows the `http://` chain. Any failure along it (refused, timed out, blocked address) may come from a later
/// hop, so the first hop is then requested alone: its response and where it points decide, and only its own failure
/// means nothing is served over `http://` (refused) or that it is unclear (timed out).
async fn probe_insecure(
    client: &SafeClient,
    url: &str,
    deadline: &Deadline,
) -> Option<InsecureProbe> {
    let follow = FetchOptions {
        follow_redirects: true,
        read_body: false,
    };
    if let Ok(r) = client.fetch(url, follow, deadline).await {
        return Some(responded(r));
    }
    let first = FetchOptions {
        follow_redirects: false,
        read_body: false,
    };
    match client.fetch(url, first, deadline).await {
        Ok(r) => {
            let target = r
                .chain
                .first()
                .and_then(|h| h.location.as_deref())
                .and_then(|loc| Url::parse(url).ok()?.join(loc).ok())
                .map(|u| u.to_string());
            Some(InsecureProbe::Responded {
                final_url: target.unwrap_or_else(|| r.final_url.clone()),
                chain: r.chain,
            })
        }
        Err(e) => closed(&e),
    }
}

pub async fn scan_headers(
    target: &str,
    limits: &Limits,
    policy: NetPolicy,
) -> Result<ScanOutput, Error> {
    let mut warnings = Vec::new();
    let registry = official_registry(&mut warnings)?;
    let url = validate_target(target, policy)?;
    let client = SafeClient::new(limits, policy)?;
    let deadline = Deadline::start(limits.deadline);
    let page = FetchOptions {
        follow_redirects: true,
        read_body: true,
    };
    let (main, probe) = if url.scheme() == "http" {
        let main = client.fetch(url.as_str(), page, &deadline).await?;
        let probe = Some(InsecureProbe::Responded {
            chain: main.chain.clone(),
            final_url: main.final_url.clone(),
        });
        (main, probe)
    } else {
        let insecure = insecure_url(&url);
        let (main, probe) = tokio::join!(client.fetch(url.as_str(), page, &deadline), async {
            match &insecure {
                Some(u) => probe_insecure(&client, u, &deadline).await,
                None => None,
            }
        });
        (main?, probe)
    };
    if probe.is_none() {
        warnings.push(
            "the http:// version could not be checked (custom port or blocked redirect)".into(),
        );
    }
    if main.status >= 400 {
        warnings.push(format!(
            "the page answered {}; its headers may come from an error page",
            main.status
        ));
    }
    let source = format!("GET {}", main.final_url);
    let mut platforms = detect_platforms(&main.headers, &source);
    if let Some(body) = &main.body {
        platforms = merge_platforms(platforms, detect_from_html(body, &source));
    }
    let platforms = without_host_infra(platforms);
    let evidence = HttpEvidence {
        source,
        status: main.status,
        https: main.final_url.starts_with("https://"),
        headers: main.headers,
        insecure_probe: probe,
        redirect_cookies: main.redirect_cookies,
        html_generator: main.body.as_deref().and_then(meta_generator),
    };
    let report = registry.evaluate(
        Module::Headers,
        url.as_str(),
        &EvalInput::Http(&evidence),
        platforms,
    );
    Ok(ScanOutput { report, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_twin_of_https() {
        let u = Url::parse("https://example.com/a?b=1").unwrap();
        assert_eq!(
            insecure_url(&u).as_deref(),
            Some("http://example.com/a?b=1")
        );
        assert_eq!(
            insecure_url(&Url::parse("https://example.com:8443/").unwrap()),
            None
        );
    }

    /// One canned response per connection; `None` accepts and never answers (a stalled port 80).
    async fn serve(response: Option<&'static str>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    match response {
                        Some(r) => {
                            let _ = sock.write_all(r.as_bytes()).await;
                        }
                        None => tokio::time::sleep(std::time::Duration::from_secs(30)).await,
                    }
                });
            }
        });
        format!("http://{addr}/")
    }

    /// A port nothing listens on (bound, then released).
    async fn closed_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }

    /// Windows reports a refused local connection only after ~2 s (it retries the SYN), so the request timeout must stay
    /// well above that or "refused" would read as "timed out"; a stalled server still times out.
    async fn probe(url: &str) -> Option<InsecureProbe> {
        let limits = Limits {
            io_timeout: std::time::Duration::from_secs(4),
            ..Limits::default()
        };
        let policy = NetPolicy {
            allow_private: true,
        };
        let client = SafeClient::new(&limits, policy).unwrap();
        probe_insecure(&client, url, &Deadline::start(limits.deadline)).await
    }

    fn first_status(p: Option<&InsecureProbe>) -> Option<u16> {
        match p {
            Some(InsecureProbe::Responded { chain, .. }) => chain.first().map(|h| h.status),
            _ => None,
        }
    }

    /// What `http://` itself did decides the probe: refused or timed out only when the first hop did; a redirect
    /// whose next hop fails is still that redirect (302 → REVIEW, 301 to http:// → FAIL, never "not reachable").
    #[tokio::test]
    async fn probe_reports_what_the_first_hop_did() {
        let refused = format!("http://127.0.0.1:{}/", closed_port().await);
        assert!(matches!(
            probe(&refused).await,
            Some(InsecureProbe::Unreachable(_))
        ));
        assert!(matches!(
            probe(&serve(None).await).await,
            Some(InsecureProbe::TimedOut(_))
        ));
        let page = probe(
            &serve(Some(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ))
            .await,
        )
        .await;
        assert_eq!(first_status(page.as_ref()), Some(200));

        let dead = closed_port().await;
        let to_dead: &'static str = Box::leak(
            format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{dead}/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .into_boxed_str(),
        );
        let p = probe(&serve(Some(to_dead)).await).await;
        assert_eq!(first_status(p.as_ref()), Some(302), "{p:?}");
        match &p {
            Some(InsecureProbe::Responded { final_url, .. }) => {
                assert_eq!(final_url, &format!("http://127.0.0.1:{dead}/x"));
            }
            other => panic!("expected the redirect, got {other:?}"),
        }
        let stalled = serve(None).await;
        let to_stalled: &'static str = Box::leak(
            format!("HTTP/1.1 301 Moved\r\nLocation: {stalled}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .into_boxed_str(),
        );
        let p = probe(&serve(Some(to_stalled)).await).await;
        assert_eq!(first_status(p.as_ref()), Some(301), "{p:?}");
    }

    #[test]
    fn refused_is_closed_and_timeout_is_told_apart() {
        assert!(matches!(
            closed(&Error::Network(
                "error sending request: client error (Connect): Connection refused".into()
            )),
            Some(InsecureProbe::Unreachable(_))
        ));
        assert!(matches!(
            closed(&Error::Timeout {
                operation: "http request",
                after: std::time::Duration::from_secs(1)
            }),
            Some(InsecureProbe::TimedOut(_))
        ));
        assert!(matches!(
            closed(&Error::Network(
                "error sending request: client error (Connect): operation timed out".into()
            )),
            Some(InsecureProbe::TimedOut(_))
        ));
        assert!(closed(&Error::Network("invalid HTTP version parsed".into())).is_none());
    }
}
