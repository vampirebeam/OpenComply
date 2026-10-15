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

fn closed(e: &Error) -> bool {
    match e {
        Error::Timeout { .. } => true,
        Error::Network(m) => {
            let m = m.to_ascii_lowercase();
            m.contains("connect") || m.contains("refused")
        }
        _ => false,
    }
}

fn responded(r: FetchResult) -> InsecureProbe {
    InsecureProbe::Responded {
        chain: r.chain,
        final_url: r.final_url,
    }
}

/// Follows the `http://` chain; if a later hop is refused (e.g. a blocked address), keeps the first response and
/// where it points. Connection refused / timed out = nothing served over `http://`.
async fn probe_insecure(
    client: &SafeClient,
    url: &str,
    deadline: &Deadline,
) -> Option<InsecureProbe> {
    let follow = FetchOptions {
        follow_redirects: true,
        read_body: false,
    };
    match client.fetch(url, follow, deadline).await {
        Ok(r) => return Some(responded(r)),
        Err(e) if closed(&e) => return Some(InsecureProbe::Unreachable(e.to_string())),
        Err(_) => {}
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
        Err(e) if closed(&e) => Some(InsecureProbe::Unreachable(e.to_string())),
        Err(_) => None,
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

    #[test]
    fn refused_and_timeout_mean_closed() {
        assert!(closed(&Error::Network(
            "error sending request: client error (Connect): Connection refused".into()
        )));
        assert!(closed(&Error::Timeout {
            operation: "http request",
            after: std::time::Duration::from_secs(1)
        }));
        assert!(!closed(&Error::Network(
            "invalid HTTP version parsed".into()
        )));
    }
}
