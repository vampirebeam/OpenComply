//! Platform detection from response headers (CDN/WAF → host → web server → framework/CMS), used only to tailor fix
//! guidance. Headers can be spoofed, so detections are `Inferred` evidence and never change a pass/fail result.
//! Pure function over already-collected headers: no extra requests, linear in header count.
//! Signals are calibrated against a corpus of real vendor / project sites; add a corpus case when adding a signal.

use schemars::JsonSchema;
use serde::Serialize;

use crate::finding::{Evidence, EvidenceClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Cdn,
    Host,
    Server,
    Framework,
    Frontend,
}

impl Layer {
    pub fn label(self) -> &'static str {
        match self {
            Layer::Cdn => "CDN / WAF",
            Layer::Host => "host",
            Layer::Server => "web server",
            Layer::Framework => "framework / CMS",
            Layer::Frontend => "frontend",
        }
    }
}

/// Only the first part of an HTML body is fingerprinted (markers live in `<head>` and early `<body>`).
pub const MAX_HTML_SCAN_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformDef {
    pub id: &'static str,
    pub name: &'static str,
    pub layer: Layer,
}

const fn p(id: &'static str, name: &'static str, layer: Layer) -> PlatformDef {
    PlatformDef { id, name, layer }
}

pub const PLATFORMS: &[PlatformDef] = &[
    p("cloudflare", "Cloudflare", Layer::Cdn),
    p("cloudfront", "AWS CloudFront", Layer::Cdn),
    p("fastly", "Fastly", Layer::Cdn),
    p("akamai", "Akamai", Layer::Cdn),
    p("azure", "Azure Front Door / CDN", Layer::Cdn),
    p("google-cloud", "Google Cloud", Layer::Cdn),
    p("bunnycdn", "BunnyCDN", Layer::Cdn),
    p("sucuri", "Sucuri WAF", Layer::Cdn),
    p("imperva", "Imperva", Layer::Cdn),
    p("f5", "F5", Layer::Cdn),
    p("netscaler", "Citrix NetScaler", Layer::Cdn),
    p("fortiweb", "Fortinet FortiWeb", Layer::Cdn),
    p("aws-elb", "AWS Load Balancer", Layer::Cdn),
    p("plesk", "Plesk", Layer::Host),
    p("vercel", "Vercel", Layer::Host),
    p("netlify", "Netlify", Layer::Host),
    p("github-pages", "GitHub Pages", Layer::Host),
    p("fly", "Fly.io", Layer::Host),
    p("render", "Render", Layer::Host),
    p("heroku", "Heroku", Layer::Host),
    p("wix", "Wix", Layer::Host),
    p("squarespace", "Squarespace", Layer::Host),
    p("shopify", "Shopify", Layer::Host),
    p("webflow", "Webflow", Layer::Host),
    p("nginx", "nginx", Layer::Server),
    p("openresty", "OpenResty", Layer::Server),
    p("apache", "Apache HTTP Server", Layer::Server),
    p("iis", "Microsoft IIS", Layer::Server),
    p("litespeed", "LiteSpeed", Layer::Server),
    p("caddy", "Caddy", Layer::Server),
    p("tomcat", "Apache Tomcat", Layer::Server),
    p("jetty", "Eclipse Jetty", Layer::Server),
    p("wordpress", "WordPress", Layer::Framework),
    p("joomla", "Joomla", Layer::Framework),
    p("drupal", "Drupal", Layer::Framework),
    p("magento", "Magento / Adobe Commerce", Layer::Framework),
    p("ghost", "Ghost", Layer::Framework),
    p("laravel", "Laravel", Layer::Framework),
    p("django", "Django", Layer::Framework),
    p("rails", "Ruby on Rails", Layer::Framework),
    p("java", "Java (Servlet / Spring)", Layer::Framework),
    p("nextjs", "Next.js", Layer::Framework),
    p("nuxt", "Nuxt", Layer::Framework),
    p("express", "Express", Layer::Framework),
    p("php", "PHP", Layer::Framework),
    p("aspnet", "ASP.NET", Layer::Framework),
    p("react", "React", Layer::Frontend),
    p("react-router", "React Router / Remix", Layer::Frontend),
    p("vue", "Vue", Layer::Frontend),
    p("angular", "Angular", Layer::Frontend),
    p("svelte", "Svelte / SvelteKit", Layer::Frontend),
    p("astro", "Astro", Layer::Frontend),
    p("gatsby", "Gatsby", Layer::Frontend),
];

pub fn platform_def(id: &str) -> Option<&'static PlatformDef> {
    PLATFORMS.iter().find(|p| p.id == id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DetectedPlatform {
    pub id: &'static str,
    pub name: &'static str,
    pub layer: Layer,
    pub evidence: Evidence,
}

enum Signal {
    Present(&'static str),
    ValueIs(&'static str, &'static str),
    ValueStarts(&'static str, &'static str),
    ValueContains(&'static str, &'static str),
}

use Signal::{Present, ValueContains, ValueIs, ValueStarts};

const SIGNALS: &[(&str, Signal)] = &[
    ("cloudflare", Present("cf-ray")),
    ("cloudflare", ValueIs("server", "cloudflare")),
    ("cloudfront", Present("x-amz-cf-id")),
    ("cloudfront", ValueContains("via", "cloudfront")),
    ("fastly", Present("x-fastly-request-id")),
    ("fastly", ValueStarts("x-served-by", "cache-")),
    ("akamai", Present("akamai-grn")),
    ("akamai", ValueStarts("server", "akamaighost")),
    ("azure", Present("x-azure-ref")),
    ("azure", Present("x-msedge-ref")),
    ("google-cloud", ValueIs("server", "google frontend")),
    ("google-cloud", ValueIs("server", "esf")),
    ("google-cloud", ValueContains("via", "google")),
    ("bunnycdn", ValueStarts("server", "bunnycdn")),
    ("sucuri", Present("x-sucuri-id")),
    ("sucuri", ValueStarts("server", "sucuri")),
    ("imperva", ValueIs("x-cdn", "imperva")),
    ("imperva", Present("x-iinfo")),
    ("f5", ValueStarts("server", "volt-adc")),
    ("f5", ValueContains("server", "bigip")),
    ("f5", ValueContains("set-cookie", "bigipserver")),
    ("netscaler", ValueStarts("set-cookie", "nsc_")),
    ("netscaler", ValueStarts("set-cookie", "citrix_ns_id")),
    ("fortiweb", ValueStarts("set-cookie", "fortiwafsid=")),
    ("aws-elb", ValueStarts("set-cookie", "awsalb")),
    ("aws-elb", ValueStarts("server", "awselb")),
    ("plesk", ValueStarts("x-powered-by", "plesk")),
    ("vercel", Present("x-vercel-id")),
    ("vercel", ValueIs("server", "vercel")),
    ("netlify", Present("x-nf-request-id")),
    ("netlify", ValueStarts("server", "netlify")),
    ("github-pages", ValueIs("server", "github.com")),
    ("github-pages", Present("x-github-request-id")),
    ("fly", Present("fly-request-id")),
    ("fly", ValueStarts("server", "fly/")),
    ("render", Present("x-render-origin-server")),
    ("heroku", ValueContains("via", "vegur")),
    ("wix", Present("x-wix-request-id")),
    ("wix", ValueIs("server", "pepyaka")),
    ("squarespace", ValueIs("server", "squarespace")),
    ("shopify", Present("x-shopify-stage")),
    ("shopify", Present("x-shopid")),
    ("nginx", ValueStarts("server", "nginx")),
    ("openresty", ValueStarts("server", "openresty")),
    ("apache", ValueIs("server", "apache")),
    ("apache", ValueStarts("server", "apache/")),
    ("iis", ValueStarts("server", "microsoft-iis")),
    ("iis", ValueStarts("x-powered-by", "arr/")),
    ("litespeed", ValueStarts("server", "litespeed")),
    ("litespeed", Present("x-litespeed-cache")),
    (
        "litespeed",
        ValueContains("x-turbo-charged-by", "litespeed"),
    ),
    ("caddy", ValueIs("server", "caddy")),
    ("tomcat", ValueStarts("server", "apache-coyote")),
    ("jetty", ValueStarts("server", "jetty")),
    ("wordpress", ValueContains("link", "api.w.org")),
    ("wordpress", ValueContains("x-pingback", "xmlrpc.php")),
    ("drupal", Present("x-drupal-cache")),
    ("drupal", Present("x-drupal-dynamic-cache")),
    ("drupal", ValueContains("x-generator", "drupal")),
    ("nextjs", ValueContains("x-powered-by", "next.js")),
    ("nextjs", Present("x-nextjs-cache")),
    ("nuxt", ValueContains("x-powered-by", "nuxt")),
    ("express", ValueIs("x-powered-by", "express")),
    ("php", ValueStarts("x-powered-by", "php")),
    ("aspnet", ValueStarts("x-powered-by", "asp.net")),
    ("aspnet", Present("x-aspnet-version")),
    ("wordpress", ValueStarts("set-cookie", "wordpress_")),
    ("wordpress", ValueStarts("set-cookie", "wp-settings")),
    ("magento", ValueStarts("set-cookie", "form_key=")),
    ("laravel", ValueContains("set-cookie", "=eyjpdi")),
    ("django", ValueStarts("set-cookie", "csrftoken=")),
    ("java", ValueStarts("set-cookie", "jsessionid=")),
    ("php", ValueStarts("set-cookie", "phpsessid=")),
    ("aspnet", ValueStarts("set-cookie", "asp.net_sessionid=")),
];

/// A header that rules a platform out even when one of its signals matched (e.g. GitHub's API shares
/// `server: github.com` with GitHub Pages but adds API-only headers).
const EXCLUDES: &[(&str, &str)] = &[
    ("github-pages", "x-github-media-type"),
    ("github-pages", "x-github-api-version-selected"),
];

/// Where an HTML marker must appear to count. Text that only mentions a platform (an article, a code sample,
/// a link to another site) must not change the guidance.
#[derive(Clone, Copy)]
enum Marker {
    /// Inside a tag or a `<script>` body — not page text.
    Markup(&'static str),
    /// In a `<script src>` / `<link href>` the page loads, or another `src` / `href` on this site (relative or the
    /// same host): the page's own assets.
    OwnPath(&'static str),
    /// The host of a `<script src>` / `<link href>`: theme assets served by a hosted platform.
    AssetHost(&'static str),
}

/// Lowercase markers that identify a platform in HTML. Kept specific to avoid matching ordinary content.
const HTML_MARKERS: &[(&str, Marker)] = &[
    ("shopify", Marker::AssetHost("cdn.shopify.com")),
    ("wix", Marker::Markup("content=\"wix.com website builder")),
    ("wix", Marker::AssetHost("static.wixstatic.com")),
    ("wix", Marker::AssetHost("static.parastorage.com")),
    ("squarespace", Marker::AssetHost("static1.squarespace.com")),
    ("webflow", Marker::Markup("data-wf-site=")),
    ("webflow", Marker::Markup("data-wf-page=")),
    ("wordpress", Marker::OwnPath("/wp-content/")),
    ("wordpress", Marker::OwnPath("/wp-includes/")),
    ("joomla", Marker::Markup("content=\"joomla")),
    ("joomla", Marker::OwnPath("/media/jui/")),
    ("joomla", Marker::OwnPath("/media/system/js/")),
    ("drupal", Marker::Markup("content=\"drupal")),
    ("drupal", Marker::Markup("drupal-settings-json")),
    ("magento", Marker::Markup("mage/cookies")),
    ("magento", Marker::Markup("magento_")),
    ("ghost", Marker::Markup("content=\"ghost")),
    ("django", Marker::Markup("csrfmiddlewaretoken")),
    ("rails", Marker::Markup("content=\"authenticity_token\"")),
    ("nextjs", Marker::Markup("__next_data__")),
    ("nextjs", Marker::OwnPath("/_next/static")),
    ("nuxt", Marker::Markup("__nuxt__")),
    ("nuxt", Marker::OwnPath("/_nuxt/")),
    ("react", Marker::Markup("data-reactroot")),
    ("react", Marker::Markup("react-dom")),
    ("react-router", Marker::Markup("__remixcontext")),
    ("react-router", Marker::Markup("__reactroutercontext")),
    ("vue", Marker::Markup("data-v-app")),
    ("vue", Marker::Markup("data-v-")),
    ("angular", Marker::Markup("ng-version=")),
    ("svelte", Marker::Markup("__sveltekit")),
    ("svelte", Marker::Markup("data-sveltekit")),
    ("astro", Marker::OwnPath("/_astro/")),
    ("astro", Marker::Markup("astro-island")),
    ("gatsby", Marker::Markup("___gatsby")),
];

/// True when `pos` is inside a tag (`<…>`) or inside a `<script>…</script>` body.
fn in_markup(body: &str, pos: usize) -> bool {
    let before = &body[..pos];
    let in_tag = before.rfind('<') > before.rfind('>');
    let in_script = before.rfind("<script") > before.rfind("</script");
    in_tag || in_script
}

/// `(tag, url)` for every `src=` / `href=` attribute value that sits inside a tag.
fn asset_urls(body: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for attr in ["src=", "href="] {
        for (at, _) in body.match_indices(attr) {
            let preceded_by_space = body[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_whitespace());
            if !preceded_by_space || !in_markup(body, at) {
                continue;
            }
            let rest = &body[at + attr.len()..];
            let url = match rest.chars().next() {
                Some(q @ ('"' | '\'')) => rest[1..].split(q).next().unwrap_or(""),
                _ => rest
                    .split(|c: char| c.is_ascii_whitespace() || c == '>')
                    .next()
                    .unwrap_or(""),
            };
            let tag_start = body[..at].rfind('<').map_or(at, |i| i + 1);
            let tag = body[tag_start..at]
                .split(|c: char| c.is_ascii_whitespace())
                .next()
                .unwrap_or("");
            out.push((tag, url));
        }
    }
    out
}

/// Host of an absolute or protocol-relative URL; `None` for a relative one.
fn url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("//")
        .or_else(|| url.split_once("://").map(|(_, r)| r))?;
    rest.split(['/', ':', '?', '#']).next()
}

/// Same site: equal hosts, or one is a subdomain of the other once a leading `www.` is dropped.
fn same_site(host: &str, page_host: &str) -> bool {
    let a = host.trim_start_matches("www.");
    let b = page_host.trim_start_matches("www.");
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

fn marker_matches(
    marker: Marker,
    body: &str,
    assets: &[(&str, &str)],
    page_host: Option<&str>,
) -> bool {
    match marker {
        Marker::Markup(needle) => body
            .match_indices(needle)
            .any(|(pos, _)| in_markup(body, pos)),
        // A script or stylesheet the page loads is its own asset even from a CDN host (e.g. Next.js `assetPrefix`);
        // a link or image elsewhere only counts on the same site.
        Marker::OwnPath(needle) => assets.iter().any(|(tag, url)| {
            (url.contains(needle) || url.starts_with(needle.trim_start_matches('/')))
                && (matches!(*tag, "script" | "link")
                    || match url_host(url) {
                        None => true,
                        Some(h) => page_host.is_some_and(|p| same_site(h, p)),
                    })
        }),
        Marker::AssetHost(host) => assets
            .iter()
            .any(|(tag, url)| matches!(*tag, "script" | "link") && url_host(url) == Some(host)),
    }
}

fn needle(marker: Marker) -> &'static str {
    match marker {
        Marker::Markup(n) | Marker::OwnPath(n) | Marker::AssetHost(n) => n,
    }
}

/// Fingerprints frontends and CMSs from an HTML body (first `MAX_HTML_SCAN_BYTES` only). Same ordering and
/// evidence rules as `detect_platforms`; merge both with `merge_platforms`. `source` (`GET <url>`) gives the
/// page's host, so assets of another site are not taken as this site's.
pub fn detect_from_html(html: &str, source: &str) -> Vec<DetectedPlatform> {
    let mut end = html.len().min(MAX_HTML_SCAN_BYTES);
    while !html.is_char_boundary(end) {
        end -= 1;
    }
    let body = html[..end].to_ascii_lowercase();
    let page_url = source.rsplit(' ').next().unwrap_or("").to_ascii_lowercase();
    let page_host = url_host(&page_url);
    let assets = asset_urls(&body);
    let mut found: Vec<DetectedPlatform> = Vec::new();
    for (id, marker) in HTML_MARKERS {
        if found.iter().any(|d| d.id == *id) || !marker_matches(*marker, &body, &assets, page_host)
        {
            continue;
        }
        if let Some(def) = platform_def(id) {
            found.push(DetectedPlatform {
                id: def.id,
                name: def.name,
                layer: def.layer,
                evidence: Evidence {
                    class: EvidenceClass::Inferred,
                    source: source.to_string(),
                    detail: format!("HTML contains \"{}\"", needle(*marker)),
                },
            });
        }
    }
    found.sort_by_key(|d| d.layer);
    found
}
/// CDNs that a hosted platform runs itself: the site owner cannot configure them, so guidance must not send
/// them there (Shopify and Webflow sites sit behind those companies' Cloudflare, Wix behind Google Cloud,
/// GitHub Pages behind Fastly).
const HOST_OWN_INFRA: &[(&str, &str)] = &[
    ("shopify", "cloudflare"),
    ("webflow", "cloudflare"),
    ("wix", "google-cloud"),
    ("github-pages", "fastly"),
];

/// Drops a CDN detection when it is the infrastructure of a detected hosted platform (see `HOST_OWN_INFRA`).
pub fn without_host_infra(platforms: Vec<DetectedPlatform>) -> Vec<DetectedPlatform> {
    let hidden: Vec<&str> = HOST_OWN_INFRA
        .iter()
        .filter(|(host, _)| platforms.iter().any(|p| p.id == *host))
        .map(|(_, infra)| *infra)
        .collect();
    platforms
        .into_iter()
        .filter(|p| !hidden.contains(&p.id))
        .collect()
}

/// Union of header- and HTML-based detections; the first evidence for a platform wins.
pub fn merge_platforms(
    mut primary: Vec<DetectedPlatform>,
    extra: Vec<DetectedPlatform>,
) -> Vec<DetectedPlatform> {
    for d in extra {
        if !primary.iter().any(|p| p.id == d.id) {
            primary.push(d);
        }
    }
    primary.sort_by_key(|d| d.layer);
    primary
}

fn signal_matches(signal: &Signal, name: &str, value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    match signal {
        Present(h) => name.eq_ignore_ascii_case(h),
        ValueIs(h, v) => name.eq_ignore_ascii_case(h) && value == *v,
        ValueStarts(h, v) => name.eq_ignore_ascii_case(h) && value.starts_with(v),
        ValueContains(h, v) => name.eq_ignore_ascii_case(h) && value.contains(v),
    }
}

/// Platforms that a single header names by itself (e.g. `x-powered-by: ARR/3.0` → IIS): the software that
/// emits it, and so the place that can remove it.
pub fn platforms_named_by(name: &str, value: &str) -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = Vec::new();
    for (id, signal) in SIGNALS {
        if !ids.contains(id) && signal_matches(signal, name, value) {
            ids.push(*id);
        }
    }
    ids
}

/// `headers` = (name, value) pairs as received; `source` describes the request, e.g. `GET https://example.com/`.
/// Returns one entry per platform (first matching signal wins), ordered CDN → host → server → framework.
pub fn detect_platforms(headers: &[(String, String)], source: &str) -> Vec<DetectedPlatform> {
    let mut found: Vec<DetectedPlatform> = Vec::new();
    for (id, signal) in SIGNALS {
        let excluded = EXCLUDES
            .iter()
            .any(|(p, h)| p == id && headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(h)));
        if excluded || found.iter().any(|d| d.id == *id) {
            continue;
        }
        let hit = headers
            .iter()
            .find(|(name, value)| signal_matches(signal, name, value));
        if let (Some((name, value)), Some(def)) = (hit, platform_def(id)) {
            found.push(DetectedPlatform {
                id: def.id,
                name: def.name,
                layer: def.layer,
                evidence: Evidence {
                    class: EvidenceClass::Inferred,
                    source: source.to_string(),
                    detail: format!("{name}: {}", value.chars().take(120).collect::<String>()),
                },
            });
        }
    }
    found.sort_by_key(|d| d.layer);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(pairs: &[(&str, &str)]) -> Vec<&'static str> {
        let headers: Vec<(String, String)> = pairs
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect();
        detect_platforms(&headers, "GET x")
            .iter()
            .map(|d| d.id)
            .collect()
    }

    #[test]
    fn layer_order_and_evidence() {
        let headers = vec![
            ("x-powered-by".to_string(), "Next.js".to_string()),
            ("Server".to_string(), "cloudflare".to_string()),
            ("CF-RAY".to_string(), "a4a635d208c575d8-BKK".to_string()),
        ];
        let found = detect_platforms(&headers, "GET https://example.com/");
        let got: Vec<_> = found.iter().map(|d| d.id).collect();
        assert_eq!(got, ["cloudflare", "nextjs"]);
        assert_eq!(found[0].evidence.class, EvidenceClass::Inferred);
        assert_eq!(found[0].evidence.detail, "CF-RAY: a4a635d208c575d8-BKK");
    }

    type Case = (
        &'static [(&'static str, &'static str)],
        &'static [&'static str],
    );

    /// Header shapes captured from real sites (corpus 2026-10-14), reduced to the fingerprinting headers.
    const CORPUS: &[Case] = &[
        (
            &[
                ("server", "Server"),
                ("x-amz-cf-id", "FW61"),
                ("via", "1.1 x.cloudfront.net (CloudFront)"),
            ],
            &["cloudfront"],
        ),
        (
            &[
                ("x-powered-by", "ASP.NET"),
                ("x-azure-ref", "20261014T1209"),
            ],
            &["azure", "aspnet"],
        ),
        (&[("server", "ESF")], &["google-cloud"]),
        (&[("server", "Google Frontend")], &["google-cloud"]),
        (
            &[
                ("server", "Fly/ad0302a95"),
                ("via", "1.1 fly.io"),
                ("fly-request-id", "01M4"),
            ],
            &["fly"],
        ),
        (&[("server", "OpenResty Edge")], &["openresty"]),
        (
            &[("x-sucuri-id", "18012"), ("server", "Sucuri/Cloudproxy")],
            &["sucuri"],
        ),
        (
            &[("x-cdn", "Imperva"), ("x-iinfo", "48-52115916")],
            &["imperva"],
        ),
        (
            &[
                ("x-served-by", "cache-sjc1000099-SJC"),
                ("server", "Artisanal bits"),
            ],
            &["fastly"],
        ),
        (&[("server", "BunnyCDN-TH1-1154")], &["bunnycdn"]),
        (
            &[("server", "volt-adc"), ("x-vercel-id", "sin1::x")],
            &["f5", "vercel"],
        ),
        (&[("server", "Squarespace")], &["squarespace"]),
        (
            &[
                ("x-wix-request-id", "1791"),
                ("server", "Pepyaka"),
                ("via", "1.1 google"),
            ],
            &["google-cloud", "wix"],
        ),
        (
            &[
                ("server", "cloudflare"),
                ("x-render-origin-server", "Render"),
            ],
            &["cloudflare", "render"],
        ),
        (
            &[
                ("server", "GitHub.com"),
                ("x-github-request-id", "CF58"),
                ("x-fastly-request-id", "db48"),
            ],
            &["fastly", "github-pages"],
        ),
        (
            &[("server", "cloudflare"), ("x-github-request-id", "6C58")],
            &["cloudflare", "github-pages"],
        ),
        (
            &[
                ("server", "github.com"),
                ("x-github-request-id", "C1A2"),
                ("x-github-media-type", "github.v3; format=json"),
            ],
            &[],
        ),
        (
            &[
                ("server", "cloudflare"),
                ("x-turbo-charged-by", "LiteSpeed"),
            ],
            &["cloudflare", "litespeed"],
        ),
        (
            &[("server", "LiteSpeed"), ("x-powered-by", "PHP/7.4.26")],
            &["litespeed", "php"],
        ),
        (
            &[("server", "Apache"), ("x-drupal-cache", "MISS")],
            &["apache", "drupal"],
        ),
        (
            &[("server", "Vercel"), ("x-powered-by", "Nuxt")],
            &["vercel", "nuxt"],
        ),
        (
            &[
                ("server", "cloudflare"),
                (
                    "link",
                    "<https://site/wp-json/>; rel=\"https://api.w.org/\"",
                ),
            ],
            &["cloudflare", "wordpress"],
        ),
        (
            &[
                ("server", "nginx"),
                ("x-pingback", "https://site/xmlrpc.php"),
            ],
            &["nginx", "wordpress"],
        ),
        (
            &[
                ("server", "Microsoft-IIS/10.0"),
                ("x-powered-by", "ASP.NET"),
            ],
            &["iis", "aspnet"],
        ),
        (
            &[
                ("x-powered-by", "Next.js"),
                ("x-powered-by", "ARR/3.0"),
                ("x-powered-by", "ASP.NET"),
            ],
            &["iis", "nextjs", "aspnet"],
        ),
        (
            &[("server", "BigIP"), ("set-cookie", "BIGipServerpool=1.2.3")],
            &["f5"],
        ),
        (&[("via", "1.1 vegur")], &["heroku"]),
        (&[("server", "custom")], &[]),
    ];

    #[test]
    fn corpus_cases() {
        for (headers, expected) in CORPUS {
            assert_eq!(ids(headers), *expected, "{headers:?}");
        }
    }

    #[test]
    fn cookie_signals() {
        assert_eq!(
            ids(&[("set-cookie", "laravelcom_session=eyJpdiI6IjEyMyJ9; path=/")]),
            ["laravel"]
        );
        assert_eq!(ids(&[("Set-Cookie", "JSESSIONID=ABC; Path=/")]), ["java"]);
        assert_eq!(ids(&[("set-cookie", "csrftoken=x; Path=/")]), ["django"]);
        assert_eq!(
            ids(&[("set-cookie", "wordpress_test_cookie=WP; path=/")]),
            ["wordpress"]
        );
        assert_eq!(
            ids(&[
                ("set-cookie", "NSC_vsl_xxx=ffffffff; path=/"),
                ("server", "Apache-Coyote/1.1"),
                ("set-cookie", "JSESSIONID=1"),
            ]),
            ["netscaler", "tomcat", "java"]
        );
        assert_eq!(
            ids(&[
                ("set-cookie", "AWSALB=abc; Path=/"),
                ("x-powered-by", "PleskLin")
            ]),
            ["aws-elb", "plesk"]
        );
        assert_eq!(ids(&[("set-cookie", "FORTIWAFSID=x")]), ["fortiweb"]);
        assert_eq!(ids(&[("server", "Jetty(9.4.z)")]), ["jetty"]);
    }

    fn html_ids(html: &str) -> Vec<&'static str> {
        detect_from_html(html, "GET x")
            .iter()
            .map(|d| d.id)
            .collect()
    }

    /// Markers verified against real homepages (corpus 2026-10-14).
    #[test]
    fn html_corpus_cases() {
        let cases: &[(&str, &[&str])] = &[
            (
                r#"<link rel="stylesheet" href="/wp-content/themes/x.css">"#,
                &["wordpress"],
            ),
            (
                r#"<meta name="generator" content="Joomla! - Open Source">"#,
                &["joomla"],
            ),
            (
                r#"<script type="application/json" data-drupal-selector="drupal-settings-json">"#,
                &["drupal"],
            ),
            (r#"<meta name="generator" content="Ghost 5.0">"#, &["ghost"]),
            (
                r#"<script src="/_nuxt/entry.js"></script><div data-v-1a2b3c4d>"#,
                &["nuxt", "vue"],
            ),
            (r#"<div id="app" data-v-app><p data-v-7a9b>"#, &["vue"]),
            (r#"<app-root ng-version="20.1.0">"#, &["angular"]),
            ("<script>__sveltekit_1x = {}</script>", &["svelte"]),
            (
                r#"<script type="module" src="/_astro/hoisted.js"></script>"#,
                &["astro"],
            ),
            (r#"<div id="___gatsby">"#, &["gatsby"]),
            (
                r#"<script id="__NEXT_DATA__" type="application/json">"#,
                &["nextjs"],
            ),
            (
                "<script>window.__reactRouterContext = {}</script>",
                &["react-router"],
            ),
            (
                r#"<link href="https://cdn.shopify.com/s/files/x.css">"#,
                &["shopify"],
            ),
            (
                r#"<meta name="generator" content="Wix.com Website Builder">"#,
                &["wix"],
            ),
            (
                r#"<link rel="icon" href="https://static.wixstatic.com/media/x.png">"#,
                &["wix"],
            ),
            (
                r#"<input type="hidden" name="csrfmiddlewaretoken" value="x">"#,
                &["django"],
            ),
            (
                r#"<meta name="csrf-param" content="authenticity_token" />"#,
                &["rails"],
            ),
            ("<p>We love React and Vue tutorials</p>", &[]),
        ];
        for (html, expected) in cases {
            assert_eq!(html_ids(html), *expected, "{html}");
        }
    }

    /// Pages that only mention, link to or embed another platform must not be fingerprinted as it.
    #[test]
    fn html_mentions_links_and_embeds_are_not_the_sites_platform() {
        let page = "GET https://blog.example.org/post";
        let ids = |html: &str| -> Vec<&'static str> {
            detect_from_html(html, page).iter().map(|d| d.id).collect()
        };
        let cases: &[(&str, &[&str])] = &[
            (
                "<p>Themes live in /wp-content/themes and Vue adds data-v- attributes.</p>",
                &[],
            ),
            (
                "<pre><code>&lt;div data-v-app&gt; window.__NUXT__ ng-version=</code></pre>",
                &[],
            ),
            (
                r#"<a href="https://other-site.com/wp-content/uploads/a.jpg">photo</a>"#,
                &[],
            ),
            (
                r#"<img src="https://cdn.shopify.com/s/files/product.jpg">"#,
                &[],
            ),
            (
                r#"<img src="https://static.wixstatic.com/media/x.png">"#,
                &[],
            ),
            (
                r#"<img src="https://other.com/_next/static/media/a.png">"#,
                &[],
            ),
            // Build assets from the site's own CDN host (Next.js assetPrefix) still count.
            (
                r#"<script src="https://b.cdn-example.net/_next/static/chunks/a.js"></script>"#,
                &["nextjs"],
            ),
            // The site's own assets still count: relative, same host, or a subdomain of it.
            (
                r#"<link rel="stylesheet" href="wp-content/themes/x.css">"#,
                &["wordpress"],
            ),
            (
                r#"<script src="https://example.org/wp-includes/js/x.js"></script>"#,
                &["wordpress"],
            ),
            (
                r#"<script src="//static.blog.example.org/_next/static/a.js"></script>"#,
                &["nextjs"],
            ),
            (
                "<script src='https://cdn.shopify.com/s/files/theme.js'></script>",
                &["shopify"],
            ),
        ];
        for (html, expected) in cases {
            assert_eq!(ids(html), *expected, "{html}");
        }
    }

    #[test]
    fn html_scan_is_bounded_and_merge_dedupes() {
        let mut big = "a".repeat(MAX_HTML_SCAN_BYTES);
        big.push_str("/wp-content/");
        assert!(html_ids(&big).is_empty());
        let headers = vec![("x-powered-by".to_string(), "Next.js".to_string())];
        let merged = merge_platforms(
            detect_platforms(&headers, "GET x"),
            detect_from_html(
                "<script id=\"__NEXT_DATA__\"></script><div data-v-app>",
                "GET x",
            ),
        );
        let got: Vec<_> = merged.iter().map(|d| d.id).collect();
        assert_eq!(got, ["nextjs", "vue"]);
        assert!(merged[0].evidence.detail.starts_with("x-powered-by"));
    }

    #[test]
    fn a_hosted_platforms_own_cdn_is_not_offered_as_a_place_to_fix() {
        let ids = |headers: &[(&str, &str)], html: &str| -> Vec<&'static str> {
            let h: Vec<(String, String)> = headers
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect();
            let page = "GET https://shop.example.com/";
            without_host_infra(merge_platforms(
                detect_platforms(&h, page),
                detect_from_html(html, page),
            ))
            .iter()
            .map(|d| d.id)
            .collect()
        };
        let wix = ids(&[("via", "1.1 google"), ("x-wix-request-id", "1")], "");
        assert!(
            wix.contains(&"wix") && !wix.contains(&"google-cloud"),
            "{wix:?}"
        );
        let shop = ids(
            &[("cf-ray", "1-BKK")],
            r#"<script src="https://cdn.shopify.com/s/t.js"></script>"#,
        );
        assert_eq!(shop, ["shopify"]);
        // Without the hosted platform the CDN is the site's own and stays.
        assert_eq!(ids(&[("cf-ray", "1-BKK")], ""), ["cloudflare"]);
        for (host, infra) in HOST_OWN_INFRA {
            assert!(
                platform_def(host).is_some() && platform_def(infra).is_some(),
                "{host} {infra}"
            );
        }
    }

    #[test]
    fn every_signal_references_a_known_platform() {
        for (id, _) in SIGNALS.iter().map(|(i, s)| (i, s)) {
            assert!(platform_def(id).is_some(), "{id}");
        }
        for (id, marker) in HTML_MARKERS {
            assert!(platform_def(id).is_some(), "{id}");
            assert_eq!(
                needle(*marker),
                needle(*marker).to_ascii_lowercase(),
                "{id}"
            );
        }
    }
}
