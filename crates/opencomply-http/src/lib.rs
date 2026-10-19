//! SSRF-safe HTTP client shared by every network scanner.
//! - Target validation: only http/https, no credentials in the URL, literal IPs checked against the address policy.
//! - DNS rebinding: a custom resolver returns only allowed addresses and reqwest connects to exactly those
//!   (resolution and connection use the same answer); the peer address is re-checked after connecting.
//! - Redirects are followed manually (each hop re-validated, chain recorded, bounded by `max_redirects`).
//! - Every request is bounded by connect / io timeouts within the scan `Deadline`; headers and body are size-capped.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use opencomply_core::limits::{check_headers, Deadline, RedirectBudget};
use opencomply_core::{Error, Limits, NetFailure, RedirectHop, SCANNER_VERSION};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{redirect, Url};

/// Whether private / internal addresses may be scanned. Default: public only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetPolicy {
    pub allow_private: bool,
}

/// True for globally routable unicast addresses. Everything internal, reserved or special-purpose is false.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let seg = ip.segments();
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        let o = ip.octets();
        return is_public_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00
        || (seg[0] & 0xffc0) == 0xfe80
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        || (seg[0] == 0x0100 && seg[1..4] == [0, 0, 0]))
}

/// Cloud instance metadata endpoints (AWS / GCP / Azure / `OpenStack`, AWS ECS, Alibaba, AWS on IPv6), also as
/// IPv4-mapped or NAT64. Blocked even with `allow_private`: scanning an internal site never needs them.
fn is_metadata(ip: IpAddr) -> bool {
    const V4: [Ipv4Addr; 3] = [
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(169, 254, 170, 2),
        Ipv4Addr::new(100, 100, 100, 200),
    ];
    match ip {
        IpAddr::V4(v4) => V4.contains(&v4),
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let o = v6.octets();
            let embedded = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
            v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
                || v6.to_ipv4_mapped().is_some_and(|m| V4.contains(&m))
                || (seg[0] == 0x64
                    && seg[1] == 0xff9b
                    && seg[2..6] == [0, 0, 0, 0]
                    && V4.contains(&embedded))
        }
    }
}

fn allowed(ip: IpAddr, policy: NetPolicy) -> bool {
    !is_metadata(ip) && (policy.allow_private || is_public(ip))
}

/// Validates a scan target URL before any network activity.
pub fn validate_target(raw: &str, policy: NetPolicy) -> Result<Url, Error> {
    let url = Url::parse(raw.trim()).map_err(|e| Error::InvalidTarget(format!("{raw}: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::InvalidTarget(format!(
            "unsupported scheme \"{}\" (use http or https)",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidTarget(
            "credentials in the URL are not allowed".into(),
        ));
    }
    let literal = match url.host() {
        None => return Err(Error::InvalidTarget("URL has no host".into())),
        Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => None,
    };
    if let Some(ip) = literal {
        if !allowed(ip, policy) {
            return Err(Error::InvalidTarget(format!(
                "{ip} is a private or reserved address"
            )));
        }
    }
    Ok(url)
}

#[derive(Debug)]
struct Blocked(String);

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} resolves only to private or reserved addresses",
            self.0
        )
    }
}

impl std::error::Error for Blocked {}

/// The system resolver found no address for the host (kept as a type so the failure is not told from its text).
#[derive(Debug)]
struct Unresolved(String);

impl std::fmt::Display for Unresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Unresolved {}

/// Resolver that drops disallowed addresses; reqwest then connects only to what it returns.
struct GuardedResolver {
    policy: NetPolicy,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let found: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| {
                    Box::new(Unresolved(e.to_string())) as Box<dyn std::error::Error + Send + Sync>
                })?
                .collect();
            let ok: Vec<SocketAddr> = found
                .into_iter()
                .filter(|a| allowed(a.ip(), policy))
                .collect();
            if ok.is_empty() {
                return Err(Box::new(Blocked(host)) as Box<dyn std::error::Error + Send + Sync>);
            }
            let addrs: Addrs = Box::new(ok.into_iter());
            Ok(addrs)
        })
    }
}

#[derive(Debug, Clone)]
pub struct FetchResult {
    pub final_url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// First `max_body_bytes` of the body (lossy UTF-8) when requested.
    pub body: Option<String>,
    pub body_truncated: bool,
    /// Every response in order, including the final one.
    pub chain: Vec<RedirectHop>,
    /// Set-Cookie values from redirect responses served over HTTPS (at most `MAX_REDIRECT_COOKIES`).
    pub redirect_cookies: Vec<String>,
    pub peer: Option<SocketAddr>,
}

const MAX_REDIRECT_COOKIES: usize = 50;

#[derive(Debug, Clone, Copy)]
pub struct FetchOptions {
    pub follow_redirects: bool,
    pub read_body: bool,
}

pub struct SafeClient {
    client: reqwest::Client,
    limits: Limits,
    policy: NetPolicy,
}

pub fn user_agent() -> String {
    format!("OpenComply/{SCANNER_VERSION} (+https://github.com/vampirebeam/OpenComply)")
}

/// The message keeps the whole source chain; the kind comes only from types in it (`io::ErrorKind`, `Unresolved`).
fn net_err(e: &reqwest::Error) -> Error {
    let mut msg = e.to_string();
    let mut kind = if e.is_timeout() {
        NetFailure::TimedOut
    } else {
        NetFailure::Other
    };
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        // A host resolving only to blocked addresses is a refused target (exit 2), not a network failure.
        if let Some(blocked) = s.downcast_ref::<Blocked>() {
            return Error::InvalidTarget(blocked.to_string());
        }
        if s.is::<Unresolved>() {
            kind = NetFailure::Unresolved;
        } else if let Some(io) = s.downcast_ref::<std::io::Error>() {
            kind = match io.kind() {
                std::io::ErrorKind::ConnectionRefused => NetFailure::Refused,
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof => NetFailure::Reset,
                std::io::ErrorKind::TimedOut => NetFailure::TimedOut,
                _ => kind,
            };
        }
        msg = format!("{msg}: {s}");
        source = s.source();
    }
    Error::Network {
        kind,
        message: msg.chars().take(300).collect(),
    }
}

impl SafeClient {
    pub fn new(limits: &Limits, policy: NetPolicy) -> Result<Self, Error> {
        limits.validate()?;
        let client = reqwest::Client::builder()
            .user_agent(user_agent())
            .redirect(redirect::Policy::none())
            .connect_timeout(limits.connect_timeout)
            .timeout(limits.io_timeout)
            .pool_max_idle_per_host(limits.max_per_host)
            .dns_resolver(Arc::new(GuardedResolver { policy }))
            .build()
            .map_err(|e| net_err(&e))?;
        Ok(Self {
            client,
            limits: limits.clone(),
            policy,
        })
    }

    /// GET `target`, following redirects manually when asked. Every hop is validated and bounded.
    pub async fn fetch(
        &self,
        target: &str,
        opts: FetchOptions,
        deadline: &Deadline,
    ) -> Result<FetchResult, Error> {
        let mut url = validate_target(target, self.policy)?;
        let mut redirects = RedirectBudget::new(&self.limits);
        let mut chain = Vec::new();
        let mut redirect_cookies = Vec::new();
        loop {
            let budget = deadline.budget(self.limits.io_timeout, "http request")?;
            let resp = tokio::time::timeout(budget, self.client.get(url.clone()).send())
                .await
                .map_err(|_| Error::Timeout {
                    operation: "http request",
                    after: budget,
                })?
                .map_err(|e| net_err(&e))?;
            let peer = resp.remote_addr();
            if let Some(p) = peer {
                if !allowed(p.ip(), self.policy) {
                    return Err(Error::InvalidTarget(format!(
                        "connected to disallowed address {}",
                        p.ip()
                    )));
                }
            }
            let status = resp.status().as_u16();
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(n, v)| {
                    (
                        n.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
            check_headers(&headers, &self.limits)?;
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
            chain.push(RedirectHop {
                url: url.to_string(),
                status,
                location: location.clone(),
            });
            if opts.follow_redirects && resp.status().is_redirection() {
                if let Some(loc) = location {
                    if url.scheme() == "https" {
                        for (n, v) in &headers {
                            if n.eq_ignore_ascii_case("set-cookie")
                                && redirect_cookies.len() < MAX_REDIRECT_COOKIES
                            {
                                redirect_cookies.push(v.clone());
                            }
                        }
                    }
                    let next = url
                        .join(&loc)
                        .map_err(|e| Error::InvalidTarget(format!("bad redirect: {e}")))?;
                    if let Some(first) = chain.iter().position(|h| h.url == next.as_str()) {
                        let mut cycle: Vec<String> =
                            chain[first..].iter().map(|h| h.url.clone()).collect();
                        cycle.push(next.to_string());
                        return Err(Error::RedirectLoop(cycle));
                    }
                    redirects.follow()?;
                    url = validate_target(next.as_str(), self.policy)?;
                    continue;
                }
            }
            let (body, body_truncated) = if opts.read_body {
                read_body(resp, self.limits.max_body_bytes, deadline).await?
            } else {
                (None, false)
            };
            return Ok(FetchResult {
                final_url: url.to_string(),
                status,
                headers,
                body,
                body_truncated,
                chain,
                redirect_cookies,
                peer,
            });
        }
    }
}

/// Streams the body and stops at `max` bytes. The body only feeds platform fingerprints (near the start), so a
/// stalled, timed-out or broken body ends as truncated with what was read — the headers are already complete.
async fn read_body(
    mut resp: reqwest::Response,
    max: u64,
    deadline: &Deadline,
) -> Result<(Option<String>, bool), Error> {
    let cap = usize::try_from(max).unwrap_or(usize::MAX);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let Ok(budget) = deadline.budget(std::time::Duration::from_secs(10), "http body") else {
            return Ok((Some(String::from_utf8_lossy(&buf).into_owned()), true));
        };
        let Ok(Ok(chunk)) = tokio::time::timeout(budget, resp.chunk()).await else {
            return Ok((Some(String::from_utf8_lossy(&buf).into_owned()), true));
        };
        let Some(chunk) = chunk else { break };
        let room = cap.saturating_sub(buf.len());
        if chunk.len() > room {
            buf.extend_from_slice(&chunk[..room]);
            return Ok((Some(String::from_utf8_lossy(&buf).into_owned()), true));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok((Some(String::from_utf8_lossy(&buf).into_owned()), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_policy() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(
                !is_public(blocked.parse().unwrap()),
                "{blocked} should be blocked"
            );
        }
        for open in [
            "1.1.1.1",
            "8.8.8.8",
            "104.16.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(is_public(open.parse().unwrap()), "{open} should be allowed");
        }
    }

    #[test]
    fn target_validation() {
        let p = NetPolicy::default();
        assert!(validate_target("https://example.com/", p).is_ok());
        for bad in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "https://user:pass@example.com/",
            "http://127.0.0.1/",
            "http://2130706433/",
            "http://0x7f.1/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "not a url",
        ] {
            assert!(validate_target(bad, p).is_err(), "{bad} should be rejected");
        }
        assert!(validate_target(
            "http://127.0.0.1/",
            NetPolicy {
                allow_private: true
            }
        )
        .is_ok());
    }

    #[test]
    fn metadata_is_blocked_even_when_private_targets_are_allowed() {
        let p = NetPolicy {
            allow_private: true,
        };
        for meta in [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.170.2/v2/credentials",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fd00:ec2::254]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[64:ff9b::a9fe:a9fe]/",
            "http://2852039166/",
            "http://0xa9.0xfe.0xa9.0xfe/",
        ] {
            assert!(
                validate_target(meta, p).is_err(),
                "{meta} should be rejected"
            );
        }
        assert!(validate_target("http://10.0.0.5/", p).is_ok());
        assert!(validate_target("http://169.254.1.1/", p).is_ok());
    }

    #[test]
    fn user_agent_identifies_scanner() {
        assert!(user_agent().starts_with("OpenComply/"));
    }
}
