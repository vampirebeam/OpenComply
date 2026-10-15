//! Built-in header checks selected by name from the closed `Builtin` list. Pure: evidence in → outcome out.
//! Browser behaviour they follow: first HSTS header wins; every enforced CSP must allow a script, so the strongest
//! policy decides; nonces / hashes make 'unsafe-inline' ignored; frame-ancestors overrides X-Frame-Options.
//! Cookie evidence shows names and attributes only — never cookie values.

use std::collections::BTreeMap;

use crate::evaluate::{directive_value, shown, HttpEvidence, InsecureProbe, Outcome};
use crate::platform::{platforms_named_by, Layer, PLATFORMS};
use crate::render::MAX_EXAMPLE_CHARS;
use crate::rules::{Builtin, LayerHint};

/// 180 days: shorter policies expire between visits of occasional users.
pub const HSTS_MIN_MAX_AGE: u64 = 15_552_000;
/// One year: the shortest max-age browsers accept for building HTTPS-only into the browser (preload).
const HSTS_PRELOAD_MAX_AGE: u64 = 31_536_000;

const NONCE_PLACEHOLDER: &str = "'nonce-<random-per-request>'";

pub(crate) fn run(check: Builtin, http: &HttpEvidence) -> Outcome {
    match check {
        Builtin::Hsts => hsts(http),
        Builtin::Csp => csp(http),
        Builtin::ReferrerPolicy => referrer_policy(http),
        Builtin::Clickjacking => clickjacking(http),
        Builtin::HttpsRedirect => https_redirect(http),
        Builtin::HeaderSyntax => header_syntax(http),
        Builtin::Cookies => cookies(http),
        Builtin::InfoDisclosure => info_disclosure(http),
    }
}

fn hsts(http: &HttpEvidence) -> Outcome {
    let values = http.values("strict-transport-security");
    if !http.https {
        return Outcome::fail(
            "(page served over http://)".into(),
            "page is not served over HTTPS, so browsers ignore HSTS".into(),
        );
    }
    let Some(first) = values.first() else {
        return Outcome::missing("Strict-Transport-Security");
    };
    let detail = shown("strict-transport-security", &values);
    match directive_value(first, "max-age").map(str::parse::<u64>) {
        None => Outcome::fail(detail, "HSTS has no max-age, so browsers ignore it".into()),
        Some(Err(_)) => Outcome::fail(
            detail,
            "max-age is not a number, so browsers ignore the header".into(),
        ),
        Some(Ok(0)) => Outcome::fail(detail, "max-age=0 switches HSTS off".into()),
        Some(Ok(n)) if n < HSTS_MIN_MAX_AGE => Outcome::fail(
            detail,
            format!("max-age={n} ({} days) is shorter than 180 days", n / 86_400),
        ),
        Some(Ok(n)) => {
            let sub = directive_value(first, "includesubdomains").is_some();
            let preload = directive_value(first, "preload").is_some();
            let (advice, example) = if !sub {
                (
                    "add includeSubDomains once every subdomain serves HTTPS, so subdomains are protected too",
                    format!("Strict-Transport-Security: max-age={n}; includeSubDomains"),
                )
            } else if !preload && n >= HSTS_PRELOAD_MAX_AGE {
                (
                    "optional: preload lets browsers use HTTPS even on the first visit; it is slow to undo",
                    format!("Strict-Transport-Security: max-age={n}; includeSubDomains; preload"),
                )
            } else {
                return Outcome::pass(detail);
            };
            Outcome::pass(detail)
                .with_advice(Some(advice.to_string()))
                .with_example(Some(example))
        }
    }
}

/// One CSP policy: directive name (lowercase) → source tokens. Only the first occurrence counts, as in browsers.
pub(crate) type Policy = BTreeMap<String, Vec<String>>;

pub(crate) fn parse_policies(values: &[&str]) -> Vec<Policy> {
    values
        .iter()
        .flat_map(|v| v.split(','))
        .map(|p| {
            let mut policy = Policy::new();
            for part in p.split(';') {
                let mut tokens = part.split_ascii_whitespace();
                if let Some(name) = tokens.next() {
                    policy
                        .entry(name.to_ascii_lowercase())
                        .or_insert_with(|| tokens.map(str::to_string).collect());
                }
            }
            policy
        })
        .filter(|p| !p.is_empty())
        .collect()
}

fn duplicate_directives(value: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut dups = Vec::new();
    for policy in value.split(',') {
        seen.clear();
        for part in policy.split(';') {
            if let Some(name) = part.split_ascii_whitespace().next() {
                let name = name.to_ascii_lowercase();
                if !seen.insert(name.clone()) && !dups.contains(&name) {
                    dups.push(name);
                }
            }
        }
    }
    dups
}

enum ScriptControl {
    Strong,
    Review(String),
    Weak(String),
}

fn is_nonce_or_hash(t: &str) -> bool {
    let t = t.to_ascii_lowercase();
    ["'nonce-", "'sha256-", "'sha384-", "'sha512-"]
        .iter()
        .any(|p| t.starts_with(p))
}

fn is_wildcard_source(t: &str) -> bool {
    matches!(
        t.to_ascii_lowercase().as_str(),
        "*" | "http:" | "https:" | "data:" | "blob:" | "filesystem:"
    )
}

/// The directive a browser applies, following CSP fallback: `first` → `script-src` → `default-src`.
fn effective<'a>(policy: &'a Policy, first: &'static str) -> Option<(&'static str, &'a [String])> {
    [first, "script-src", "default-src"]
        .into_iter()
        .find_map(|d| policy.get(d).map(|s| (d, s.as_slice())))
}

/// Sources for `<script>` elements (`script-src-elem` → `script-src` → `default-src`).
fn script_sources(policy: &Policy) -> Option<(&'static str, &[String])> {
    effective(policy, "script-src-elem")
}

fn script_control(policy: &Policy) -> ScriptControl {
    let Some((dir, sources)) = script_sources(policy) else {
        return ScriptControl::Weak(
            "no script-src or default-src, so scripts from any site can run".into(),
        );
    };
    let has = |t: &str| sources.iter().any(|s| s.eq_ignore_ascii_case(t));
    let nonce_or_hash = sources.iter().any(|s| is_nonce_or_hash(s));
    let strict_dynamic = nonce_or_hash && has("'strict-dynamic'");
    if has("'unsafe-inline'") && !nonce_or_hash {
        return ScriptControl::Weak(format!(
            "{dir} allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run"
        ));
    }
    if !strict_dynamic {
        if let Some(w) = sources.iter().find(|s| is_wildcard_source(s)) {
            return ScriptControl::Weak(format!(
                "{dir} allows {w}, so scripts from any site can run"
            ));
        }
    }
    // Event handler attributes (onclick=…) cannot carry a nonce: only 'unsafe-inline' in the attribute
    // directive allows them, and a nonce or hash in that same directive makes browsers ignore it.
    if let Some((attr_dir, attr)) = effective(policy, "script-src-attr") {
        let inline = attr
            .iter()
            .any(|s| s.eq_ignore_ascii_case("'unsafe-inline'"));
        if inline && !attr.iter().any(|s| is_nonce_or_hash(s)) {
            return ScriptControl::Weak(format!(
                "{attr_dir} allows 'unsafe-inline', so injected event handlers (onclick=…) can run"
            ));
        }
    }
    // eval() follows script-src → default-src; script-src-elem does not govern it.
    let eval_dir = ["script-src", "default-src"]
        .into_iter()
        .find_map(|d| policy.get(d).map(|s| (d, s)));
    if let Some((eval_dir, eval_sources)) = eval_dir {
        if eval_sources
            .iter()
            .any(|s| s.eq_ignore_ascii_case("'unsafe-eval'"))
        {
            return ScriptControl::Review(format!("{eval_dir} allows 'unsafe-eval'"));
        }
    }
    ScriptControl::Strong
}
/// The fix for a weak policy, built from the site's own sources so its existing hosts keep working:
/// drop 'unsafe-inline' and wildcards, add a nonce placeholder, change only the script directive.
fn csp_example(policy: &Policy) -> String {
    let Some((dir, sources)) = script_sources(policy) else {
        return format!("add to your CSP: script-src 'self' {NONCE_PLACEHOLDER}; object-src 'none'; base-uri 'self'");
    };
    let elements_weak = {
        let has = |t: &str| sources.iter().any(|s| s.eq_ignore_ascii_case(t));
        let nonce_or_hash = sources.iter().any(|s| is_nonce_or_hash(s));
        (has("'unsafe-inline'") && !nonce_or_hash)
            || (!(nonce_or_hash && has("'strict-dynamic'"))
                && sources.iter().any(|s| is_wildcard_source(s)))
    };
    if !elements_weak {
        // Only event handler attributes are open.
        return if policy.contains_key("script-src-attr") {
            "change only script-src-attr: script-src-attr 'none'".to_string()
        } else {
            "add (keep the rest): script-src-attr 'none'".to_string()
        };
    }
    let mut kept: Vec<&str> = sources
        .iter()
        .map(String::as_str)
        .filter(|s| !s.eq_ignore_ascii_case("'unsafe-inline'") && !is_wildcard_source(s))
        .collect();
    let self_at = kept
        .iter()
        .position(|s| s.eq_ignore_ascii_case("'self'"))
        .unwrap_or_else(|| {
            kept.insert(0, "'self'");
            0
        });
    if !sources.iter().any(|s| is_nonce_or_hash(s)) {
        kept.insert(self_at + 1, NONCE_PLACEHOLDER);
    }
    let lead = if dir == "script-src" || dir == "script-src-elem" {
        format!("change only {dir}: {dir}")
    } else {
        "add script-src (keep default-src): script-src".to_string()
    };
    let budget = MAX_EXAMPLE_CHARS - " …keep your other sources".len();
    let mut out = lead;
    let mut dropped = false;
    for s in kept {
        if out.chars().count() + 1 + s.chars().count() > budget {
            dropped = true;
            continue;
        }
        out.push(' ');
        out.push_str(s);
    }
    if dropped {
        out.push_str(" …keep your other sources");
    }
    out
}

/// True when the policy lets scripts run because of a nonce or `'strict-dynamic'`, whatever their URL: an injected
/// `<base>` then moves the page's own relative script URLs to another site. Hashes alone do not (the content must
/// match), and a host list rejects the other site.
fn trusts_nonce(policy: &Policy) -> bool {
    script_sources(policy).is_some_and(|(_, sources)| {
        sources.iter().any(|s| {
            s.to_ascii_lowercase().starts_with("'nonce-")
                || s.eq_ignore_ascii_case("'strict-dynamic'")
        })
    })
}

/// Advice and example for the directives no enforced policy sets: `base-uri` (does not fall back to
/// `default-src`) and `object-src` (covered by `default-src`). Browsers enforce every policy, so one is enough.
fn missing_hardening(policies: &[Policy]) -> (Option<String>, Option<String>) {
    let has = |d: &str| policies.iter().any(|p| p.contains_key(d));
    let mut add = Vec::new();
    if !has("base-uri") {
        add.push("base-uri 'self'");
    }
    if !has("object-src") && !has("default-src") {
        add.push("object-src 'none'");
    }
    if add.is_empty() {
        return (None, None);
    }
    (
        Some(format!(
            "add {} to close less common injection paths",
            add.join(" and ")
        )),
        Some(format!("add (keep the rest): {}", add.join("; "))),
    )
}

fn csp(http: &HttpEvidence) -> Outcome {
    let enforced = http.values("content-security-policy");
    if enforced.is_empty() {
        let report_only = http.values("content-security-policy-report-only");
        if report_only.is_empty() {
            return Outcome::missing("Content-Security-Policy");
        }
        return Outcome::fail(
            shown("content-security-policy-report-only", &report_only),
            "CSP is report-only: violations are logged but nothing is blocked".into(),
        );
    }
    let detail = shown("content-security-policy", &enforced);
    let policies = parse_policies(&enforced);
    let mut strong: Vec<&Policy> = Vec::new();
    let mut review = None;
    let mut weak = None;
    for p in &policies {
        match script_control(p) {
            ScriptControl::Strong => strong.push(p),
            ScriptControl::Review(r) => review = review.or(Some(r)),
            ScriptControl::Weak(r) => weak = weak.or(Some((r, p))),
        }
    }
    let (add_advice, add_example) = missing_hardening(&policies);
    if !strong.is_empty() {
        let base_missing = !policies.iter().any(|p| p.contains_key("base-uri"));
        if base_missing && strong.iter().all(|p| trusts_nonce(p)) {
            return Outcome::review(
                detail,
                "CSP trusts nonces but has no base-uri, so an injected <base> tag can redirect its scripts"
                    .into(),
            )
            .with_question("Does any page need a <base> tag to another site? If not, add base-uri 'self'.")
            .with_example(add_example);
        }
        return Outcome::pass(detail)
            .with_advice(add_advice)
            .with_example(add_example);
    }
    if let Some(r) = review {
        return Outcome::review(detail, r).with_advice(add_advice);
    }
    match weak {
        Some((r, p)) => Outcome::fail(detail, r).with_example(Some(csp_example(p))),
        None => Outcome::fail(detail, "CSP has no directives".into()),
    }
}

const REFERRER_OK: [&str; 4] = [
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
];
const REFERRER_WEAK: [&str; 4] = [
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "unsafe-url",
];

fn referrer_policy(http: &HttpEvidence) -> Outcome {
    let values = http.values("referrer-policy");
    if values.is_empty() {
        return Outcome::missing("Referrer-Policy");
    }
    let detail = shown("referrer-policy", &values);
    // Browsers apply the last token they understand.
    let effective = values
        .iter()
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .rfind(|t| REFERRER_OK.contains(&t.as_str()) || REFERRER_WEAK.contains(&t.as_str()));
    match effective {
        None => Outcome::fail(
            detail,
            "no valid Referrer-Policy value, so browsers use their default".into(),
        ),
        Some(t) if REFERRER_OK.contains(&t.as_str()) => Outcome::pass(detail),
        Some(t) => {
            let leak = if t == "unsafe-url" || t == "no-referrer-when-downgrade" {
                "the full page URL (including query strings)"
            } else {
                "your origin, even to http:// sites"
            };
            Outcome::fail(detail, format!("{t} sends {leak} to other sites"))
        }
    }
}

/// Browsers enforce every CSP policy, so one `frame-ancestors` without a wildcard is enough to pass; it fails only
/// when every policy that sets it allows any site. X-Frame-Options is used only when no policy sets it.
fn clickjacking(http: &HttpEvidence) -> Outcome {
    let csp = http.values("content-security-policy");
    let policies = parse_policies(&csp);
    let ancestors: Vec<&Vec<String>> = policies
        .iter()
        .filter_map(|p| p.get("frame-ancestors"))
        .collect();
    if let Some(strict) = ancestors
        .iter()
        .find(|fa| !fa.iter().any(|s| is_wildcard_source(s)))
    {
        return Outcome::pass(format!("frame-ancestors {}", strict.join(" ")));
    }
    if let Some(fa) = ancestors.first() {
        let w = fa
            .iter()
            .find(|s| is_wildcard_source(s))
            .map_or("*", String::as_str);
        return Outcome::fail(
            format!("frame-ancestors {}", fa.join(" ")),
            format!("frame-ancestors allows {w}, so any site can frame this page"),
        );
    }
    let xfo = http.values("x-frame-options");
    if xfo.is_empty() {
        return Outcome {
            missing: true,
            ..Outcome::fail(
                "(no frame-ancestors, no X-Frame-Options)".into(),
                "any site can show this page inside a frame (clickjacking)".into(),
            )
        };
    }
    let detail = shown("x-frame-options", &xfo);
    let first = xfo[0].to_ascii_uppercase();
    if xfo.iter().any(|v| !v.eq_ignore_ascii_case(&first)) {
        return Outcome::fail(
            detail,
            "conflicting X-Frame-Options values, so browsers may ignore them".into(),
        );
    }
    match first.as_str() {
        "DENY" | "SAMEORIGIN" => Outcome::pass(detail),
        v if v.starts_with("ALLOW-FROM") => Outcome::fail(
            detail,
            "ALLOW-FROM is ignored by current browsers; use CSP frame-ancestors".into(),
        ),
        _ => Outcome::fail(
            detail,
            "X-Frame-Options value is invalid, so browsers ignore it".into(),
        ),
    }
}

fn chain_detail(chain: &[crate::evaluate::RedirectHop]) -> String {
    chain
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            if i == 0 {
                format!("GET {} → {}", hop.url, hop.status)
            } else {
                format!(" → {} {}", hop.url, hop.status)
            }
        })
        .collect()
}

fn https_redirect(http: &HttpEvidence) -> Outcome {
    match &http.insecure_probe {
        None => Outcome::unknown("the http:// version was not checked".into()),
        Some(InsecureProbe::Unreachable(why)) => {
            Outcome::pass(format!("http:// not reachable ({why})"))
        }
        Some(InsecureProbe::Responded { chain, final_url }) => {
            let Some(first) = chain.first() else {
                return Outcome::unknown("the http:// check returned no response".into());
            };
            let detail = chain_detail(chain);
            if first.status >= 400 {
                return Outcome::pass(detail);
            }
            if !(300..400).contains(&first.status) {
                return Outcome::fail(
                    detail,
                    format!(
                        "http:// returns the page ({}) instead of HTTPS, so traffic can be read or changed",
                        first.status
                    ),
                );
            }
            if !final_url.starts_with("https://") {
                return Outcome::fail(
                    detail,
                    "http:// redirects but never reaches an https:// page".into(),
                );
            }
            if matches!(first.status, 301 | 308) {
                Outcome::pass(detail)
            } else {
                Outcome::review(
                    detail,
                    format!(
                        "http:// moves to https:// with a temporary redirect ({}), which browsers do not remember",
                        first.status
                    ),
                )
            }
        }
    }
}

const SECURITY_HEADERS: [&str; 6] = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];

/// Headers current browsers no longer use. `X-XSS-Protection: 0` is the recommended way to switch the old filter off,
/// so only other values are flagged.
const DEPRECATED_HEADERS: [&str; 5] = [
    "x-xss-protection",
    "expect-ct",
    "feature-policy",
    "public-key-pins",
    "public-key-pins-report-only",
];

/// Deprecated headers on this response, as advice (they change nothing in current browsers).
fn deprecated_advice(http: &HttpEvidence) -> Option<String> {
    let found: Vec<&str> = DEPRECATED_HEADERS
        .iter()
        .copied()
        .filter(|h| {
            let v = http.values(h);
            let off = *h == "x-xss-protection" && v.iter().all(|x| x.starts_with('0'));
            !v.is_empty() && !off
        })
        .collect();
    if found.is_empty() {
        return None;
    }
    let xss = if found.contains(&"x-xss-protection") {
        " (or send X-XSS-Protection: 0)"
    } else {
        ""
    };
    Some(format!(
        "remove {}: current browsers ignore {}{xss}",
        found.join(", "),
        if found.len() == 1 { "it" } else { "them" }
    ))
}

fn header_syntax(http: &HttpEvidence) -> Outcome {
    let present: Vec<&str> = SECURITY_HEADERS
        .iter()
        .chain(DEPRECATED_HEADERS.iter())
        .copied()
        .filter(|h| !http.values(h).is_empty())
        .collect();
    let advice = deprecated_advice(http);
    if present.is_empty() {
        return Outcome::not_applicable(
            "(no security headers)".into(),
            "no security policy headers on this response, so there is nothing to validate".into(),
        );
    }
    let mut problems: Vec<String> = Vec::new();
    for h in [
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    ] {
        let v = http.values(h);
        if v.iter().any(|x| !x.eq_ignore_ascii_case(v[0])) {
            problems.push(format!("{h} is sent more than once with different values"));
        }
    }
    if let Some(first) = http.values("strict-transport-security").first() {
        let max_age_count = first
            .split(';')
            .filter(|p| {
                p.split('=')
                    .next()
                    .is_some_and(|k| k.trim().eq_ignore_ascii_case("max-age"))
            })
            .count();
        if max_age_count > 1 {
            problems.push("max-age appears twice in HSTS, so browsers ignore it".into());
        }
    }
    for v in http.values("content-security-policy") {
        for d in duplicate_directives(v) {
            problems.push(format!(
                "{d} appears twice in one CSP; browsers ignore the second"
            ));
        }
    }
    for v in http.values("permissions-policy") {
        let bad = v
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .any(|e| {
                let (k, _) = e.split_once('=').unwrap_or((e, ""));
                !e.contains('=')
                    || k.is_empty()
                    || !k
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
        if bad {
            problems.push(
                "Permissions-Policy uses the old Feature-Policy syntax, so browsers ignore it"
                    .into(),
            );
        }
    }
    let detail = format!("checked: {}", present.join(", "));
    match problems.split_first() {
        None => Outcome::pass(detail),
        Some((first, [])) => Outcome::fail(detail, first.clone()),
        Some((first, rest)) => Outcome::fail(
            detail,
            format!("{first} (+{} more: {})", rest.len(), rest.join("; ")),
        ),
    }
    .with_advice(advice)
}

struct Cookie {
    name: String,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    /// Set by a redirect response before the final page, not by the page itself.
    on_redirect: bool,
}

/// CSRF cookies that frameworks make readable on purpose (the page script copies them into a request header).
const SCRIPT_READABLE_COOKIES: [&str; 2] = ["xsrf-token", "csrftoken"];

fn parse_cookie(v: &str) -> Cookie {
    let mut parts = v.split(';');
    let name: String = parts
        .next()
        .and_then(|p| p.split('=').next())
        .unwrap_or("")
        .trim()
        .chars()
        .take(64)
        .collect();
    let mut c = Cookie {
        name: if name.is_empty() {
            "(unnamed)".into()
        } else {
            name
        },
        secure: false,
        http_only: false,
        same_site: None,
        on_redirect: false,
    };
    for attr in parts {
        let (k, val) = attr.split_once('=').unwrap_or((attr, ""));
        match k.trim().to_ascii_lowercase().as_str() {
            "secure" => c.secure = true,
            "httponly" => c.http_only = true,
            "samesite" => c.same_site = Some(val.trim().to_ascii_lowercase()),
            _ => {}
        }
    }
    c
}

/// Cookies set by load balancers, CDNs and WAFs (stickiness, bot management) rather than by the application,
/// with the platform that sets them.
const INFRA_COOKIES: &[(&str, &str)] = &[
    ("awsalb", "aws-elb"),
    ("awselb", "aws-elb"),
    ("bigipserver", "f5"),
    ("ts01", "f5"),
    ("nsc_", "netscaler"),
    ("citrix_ns_id", "netscaler"),
    ("fortiwafsid", "fortiweb"),
    ("cookiesession1", "fortiweb"),
    ("__cf_bm", "cloudflare"),
    ("cf_clearance", "cloudflare"),
    ("__cflb", "cloudflare"),
    ("_cfuvid", "cloudflare"),
    ("incap_ses_", "imperva"),
    ("visid_incap_", "imperva"),
    ("nlbi_", "imperva"),
    ("ak_bmsc", "akamai"),
    ("bm_s", "akamai"),
    ("bm_mi", "akamai"),
    ("akaalb_", "akamai"),
    ("akaas_", "akamai"),
    ("_abck", "akamai"),
];

fn infra_platform(name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    INFRA_COOKIES
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .map(|(_, platform)| *platform)
}
/// Distinct names of the cookies matching `pred`, in order.
fn flagged_names<'a>(cookies: &'a [Cookie], pred: &dyn Fn(&Cookie) -> bool) -> Vec<&'a str> {
    let mut names: Vec<&str> = Vec::new();
    for c in cookies.iter().filter(|c| pred(c)) {
        if !names.contains(&c.name.as_str()) {
            names.push(&c.name);
        }
    }
    names
}

/// `a, b +3` — keeps one-line reasons short enough that the important part (e.g. who sets a cookie) is never cut.
fn short_list(names: &[&str]) -> String {
    let mut unique: Vec<&str> = Vec::new();
    for n in names {
        if !unique.contains(n) {
            unique.push(n);
        }
    }
    let shown: Vec<String> = unique
        .iter()
        .take(2)
        .map(|n| {
            if n.chars().count() > 18 {
                format!("{}…", n.chars().take(17).collect::<String>())
            } else {
                (*n).to_string()
            }
        })
        .collect();
    let rest = unique.len().saturating_sub(2);
    if rest > 0 {
        format!("{} +{rest}", shown.join(", "))
    } else {
        shown.join(", ")
    }
}
/// `name (flags)` per cookie — never the value.
fn cookie_detail(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|c| {
            let mut attrs = Vec::new();
            if c.secure {
                attrs.push("Secure".to_string());
            }
            if c.http_only {
                attrs.push("HttpOnly".to_string());
            }
            if let Some(s) = &c.same_site {
                attrs.push(format!("SameSite={s}"));
            }
            if attrs.is_empty() {
                attrs.push("no flags".to_string());
            }
            if c.on_redirect {
                attrs.push("on redirect".to_string());
            }
            // `name (flags)`, not `name: flags` — a `TOKEN: …` shape would be taken for a secret by redaction.
            format!("{} ({})", c.name, attrs.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Guidance goes where the flagged cookies come from: a load balancer / CDN cookie is configured in that service,
/// never in the app. Returns the hint, who to name in the reason (`3 imperva cookies` or the cookie names) and,
/// for infrastructure cookies, the suffix naming where to fix it.
fn cookie_guidance(
    cookies: &[Cookie],
    pred: &dyn Fn(&Cookie) -> bool,
) -> (LayerHint, String, String) {
    let owners: Vec<Option<&'static str>> = cookies
        .iter()
        .filter(|c| pred(c))
        .map(|c| infra_platform(&c.name))
        .collect();
    if !owners.is_empty() && owners.iter().all(Option::is_some) {
        let mut only: Vec<&'static str> = owners.into_iter().flatten().collect();
        only.sort_unstable();
        only.dedup();
        let count = flagged_names(cookies, pred).len();
        let owner = only.join(" / ");
        let who = format!(
            "{count} {owner} cookie{}",
            if count == 1 { "" } else { "s" }
        );
        let note = " (fix it there)".to_string();
        (
            LayerHint {
                prefer: vec![Layer::Cdn],
                skip: vec![
                    Layer::Host,
                    Layer::Server,
                    Layer::Framework,
                    Layer::Frontend,
                ],
                only,
                sources: vec![],
            },
            who,
            note,
        )
    } else {
        (
            LayerHint {
                prefer: vec![Layer::Framework],
                ..LayerHint::default()
            },
            short_list(&flagged_names(cookies, pred)),
            String::new(),
        )
    }
}

/// A session-style cookie (`HttpOnly`, set by the site itself on this page) on a response that `Cache-Control` lets a
/// shared cache store (`public` / `s-maxage`, without `private` / `no-store`): one visitor's cookie could be served to
/// others. Always REVIEW: whether a cache keeps a Set-Cookie response is up to that cache, and even a cache HIT
/// (`Age` > 0, a cache status of HIT) does not prove it — edges often add their own cookie after the lookup (seen live
/// on a large CDN-fronted site). A HIT is named in the reason because it makes the question more pressing.
fn cached_session_cookies(
    http: &HttpEvidence,
    cookies: &[Cookie],
    detail: &str,
) -> Option<Outcome> {
    let cc = http.values("cache-control").join(", ").to_ascii_lowercase();
    let directives: Vec<&str> = cc.split(',').map(str::trim).collect();
    let shared = directives
        .iter()
        .any(|d| *d == "public" || d.starts_with("s-maxage"));
    let personal = directives
        .iter()
        .any(|d| d.starts_with("private") || *d == "no-store");
    if !shared || personal {
        return None;
    }
    let pred = |c: &Cookie| c.http_only && !c.on_redirect && infra_platform(&c.name).is_none();
    let names = flagged_names(cookies, &pred);
    if names.is_empty() {
        return None;
    }
    let hit = http
        .values("age")
        .iter()
        .any(|a| a.parse::<u64>().is_ok_and(|n| n > 0))
        || http
            .values("cf-cache-status")
            .iter()
            .any(|v| v.eq_ignore_ascii_case("hit"))
        || http
            .values("x-cache")
            .iter()
            .any(|v| v.to_ascii_lowercase().contains("hit"));
    let who = short_list(&names);
    let detail = format!(
        "{detail}; cache-control: {}",
        http.values("cache-control").join(", ")
    );
    let layers = LayerHint {
        prefer: vec![Layer::Framework],
        ..LayerHint::default()
    };
    let reason = if hit {
        format!("{who} on a cached (HIT) response may reach other visitors")
    } else {
        format!("{who} on a publicly cacheable response may reach other visitors")
    };
    Some(
        Outcome::review(detail, reason)
            .with_question(
                "Is this response ever cached for other visitors? If so, send Cache-Control: private.",
            )
            .with_layers(layers),
    )
}

fn cookies(http: &HttpEvidence) -> Outcome {
    let mut cookies: Vec<Cookie> = http
        .values("set-cookie")
        .iter()
        .map(|v| parse_cookie(v))
        .collect();
    // A cookie set again by the final page is judged by that last version, as the browser keeps it.
    for v in &http.redirect_cookies {
        let mut c = parse_cookie(v);
        if !cookies.iter().any(|k| k.name == c.name) {
            c.on_redirect = true;
            cookies.push(c);
        }
    }
    if cookies.is_empty() {
        return Outcome::not_applicable(
            "(no Set-Cookie on this response)".into(),
            "this page sets no cookies; scan a page that does (e.g. login) to check them".into(),
        );
    }
    let detail = cookie_detail(&cookies);
    let none_insecure_pred = |c: &Cookie| c.same_site.as_deref() == Some("none") && !c.secure;
    let n = flagged_names(&cookies, &none_insecure_pred).len();
    if n > 0 {
        let (hint, who, note) = cookie_guidance(&cookies, &none_insecure_pred);
        let them = if n == 1 { "it" } else { "them" };
        return Outcome::fail(
            detail,
            format!("SameSite=None without Secure on {who}, so browsers reject {them}{note}"),
        )
        .with_layers(hint);
    }
    let not_secure_pred = |c: &Cookie| !c.secure;
    let n = flagged_names(&cookies, &not_secure_pred).len();
    if http.https && n > 0 {
        let (hint, who, note) = cookie_guidance(&cookies, &not_secure_pred);
        let they_are = if n == 1 { "it is" } else { "they are" };
        return Outcome::fail(
            detail,
            format!("Secure missing on {who}, so {they_are} also sent over http://{note}"),
        )
        .with_layers(hint);
    }
    if let Some(outcome) = cached_session_cookies(http, &cookies, &detail) {
        return outcome;
    }
    let readable_pred = |c: &Cookie| {
        !c.http_only && !SCRIPT_READABLE_COOKIES.contains(&c.name.to_ascii_lowercase().as_str())
    };
    let n = flagged_names(&cookies, &readable_pred).len();
    if n > 0 {
        let (hint, who, note) = cookie_guidance(&cookies, &readable_pred);
        let them = if n == 1 { "it" } else { "them" };
        return Outcome::review(
            detail,
            format!("HttpOnly missing on {who}, so page scripts can read {them}{note}"),
        )
        .with_layers(hint);
    }
    Outcome::pass(detail)
}

const TECH_HEADERS: [&str; 6] = [
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-backend-server",
];

/// Last labels that only appear on private networks.
const INTERNAL_SUFFIXES: [&str; 9] = [
    "internal",
    "local",
    "localdomain",
    "lan",
    "intra",
    "corp",
    "private",
    "svc",
    "cluster",
];

/// Host names or IPv4 addresses inside a `Server-Timing` value. Strict, so CDN metrics (`cfL4;desc="?proto=TCP…"`,
/// `cache;desc=hit`, `dur=1.5`) never match: an IPv4 address, a name ending in a private-network label, or a name with
/// at least three labels.
fn timing_hosts(value: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for token in value.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        let token = token.trim_matches('.');
        let labels: Vec<&str> = token.split('.').collect();
        if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
            continue;
        }
        let ipv4 = labels.len() == 4 && labels.iter().all(|l| l.parse::<u8>().is_ok());
        let last = labels
            .last()
            .map_or(String::new(), |l| l.to_ascii_lowercase());
        let named = last.bytes().any(|b| b.is_ascii_alphabetic())
            && (labels.len() >= 3 || INTERNAL_SUFFIXES.contains(&last.as_str()));
        if (ipv4 || named) && !hosts.iter().any(|h: &String| h == token) {
            hosts.push(token.chars().take(60).collect());
        }
    }
    hosts
}

/// Platform a `<meta name="generator">` names (`WordPress 6.5` → wordpress): the software that writes the tag.
fn generator_platform(content: &str) -> Option<&'static str> {
    let lower = content.trim().to_ascii_lowercase();
    PLATFORMS
        .iter()
        .find(|p| lower.starts_with(p.id))
        .map(|p| p.id)
}

fn has_version(server: &str) -> bool {
    server
        .split('/')
        .skip(1)
        .any(|rest| rest.trim_start().starts_with(|c: char| c.is_ascii_digit()))
}

/// True when the value carries a version: a word that starts with a digit (`6.5.2`, `11`, `PHP/8.1` → `8.1`,
/// `tool-0.0.65` → `0.0.65`) or with `v` and a digit. A digit inside a product name (`TYPO3 CMS`) is not a version.
fn has_version_token(value: &str) -> bool {
    value
        .split(|c: char| c.is_whitespace() || matches!(c, '/' | '(' | ')' | ';' | ',' | '_' | '-'))
        .any(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(d) if d.is_ascii_digit() => true,
                Some('v' | 'V') => c.next().is_some_and(|d| d.is_ascii_digit()),
                _ => false,
            }
        })
}

/// A value blanked out by a load balancer or proxy (`XXXXXXXX`, `****`): the header is still sent but names nothing.
fn is_masked(value: &str) -> bool {
    value
        .trim()
        .chars()
        .all(|c| matches!(c, 'X' | 'x' | '*' | '#' | '-' | ' '))
}

/// The software that emits each leaked value (`ARR/3.0` → IIS, `WordPress 6.5` → wordpress), in order, once each.
fn leak_sources(leaks: &[(&str, &str)]) -> Vec<&'static str> {
    let mut sources: Vec<&'static str> = Vec::new();
    for (h, v) in leaks {
        let ids = if *h == "meta generator" {
            generator_platform(v).into_iter().collect()
        } else {
            platforms_named_by(h, v)
        };
        for id in ids {
            if !sources.contains(&id) {
                sources.push(id);
            }
        }
    }
    sources
}

/// REVIEW when `Server-Timing` carries what looks like an internal host name (see `timing_hosts`).
fn timing_review(http: &HttpEvidence) -> Option<Outcome> {
    let timing = http.values("server-timing");
    let hosts: Vec<String> = timing.iter().flat_map(|v| timing_hosts(v)).collect();
    let host = hosts.first()?;
    Some(
        Outcome::review(
            shown("server-timing", &timing),
            format!("server-timing names {host}, which may be an internal server"),
        )
        .with_question(
            "Is this an internal host or server name? If so, remove it from Server-Timing.",
        )
        .with_layers(LayerHint {
            prefer: vec![Layer::Framework],
            skip: vec![Layer::Frontend],
            ..LayerHint::default()
        }),
    )
}

fn info_disclosure(http: &HttpEvidence) -> Outcome {
    let mut leaks: Vec<(&str, &str)> = http
        .values("server")
        .into_iter()
        .filter(|v| has_version(v))
        .map(|v| ("server", v))
        .collect();
    let mut masked: Vec<&str> = Vec::new();
    for h in TECH_HEADERS {
        for v in http.values(h) {
            if is_masked(v) {
                if !masked.contains(&h) {
                    masked.push(h);
                }
            } else {
                leaks.push((h, v));
            }
        }
    }
    let generator = http
        .html_generator
        .as_deref()
        .filter(|g| has_version_token(g));
    if let Some(g) = generator {
        leaks.push(("meta generator", g));
    }
    if leaks.is_empty() {
        if let Some(review) = timing_review(http) {
            return review;
        }
        return Outcome::pass(if masked.is_empty() {
            "no version or technology headers".into()
        } else {
            format!(
                "no version or technology headers ({} masked)",
                masked.join(", ")
            )
        });
    }
    let names: Vec<&str> = leaks.iter().fold(Vec::new(), |mut acc, (n, _)| {
        if !acc.contains(n) {
            acc.push(n);
        }
        acc
    });
    // A `Server` version is set by the web server (or its host panel) — the app and the CDN guides cannot remove it;
    // app headers such as `X-Powered-By` are best removed in the app, though a proxy or CDN in front can also strip them.
    // Each leaked value that names its software (`ARR/3.0` → IIS) points at a place that must be fixed too.
    let server_leak = names.contains(&"server");
    let app_leak = names.iter().any(|n| *n != "server");
    let sources = leak_sources(&leaks);
    let layers = match (server_leak, app_leak) {
        (true, false) => LayerHint {
            prefer: vec![Layer::Server, Layer::Host],
            skip: vec![Layer::Cdn, Layer::Framework, Layer::Frontend],
            only: vec![],
            sources,
        },
        (false, _) => LayerHint {
            prefer: vec![Layer::Framework],
            skip: vec![Layer::Frontend],
            only: vec![],
            sources,
        },
        (true, true) => LayerHint {
            prefer: vec![Layer::Server, Layer::Host, Layer::Framework],
            skip: vec![Layer::Frontend],
            only: vec![],
            sources,
        },
    };
    let versioned = leaks
        .iter()
        .any(|(h, v)| *h != "x-backend-server" && has_version_token(v));
    let shown_leaks: Vec<String> = leaks.iter().map(|(h, v)| format!("{h}: {v}")).collect();
    let reason = if names == ["x-backend-server"] {
        "x-backend-server reveals the name of an internal server".to_string()
    } else {
        let what = if versioned {
            "which software and version runs here"
        } else {
            "which software runs here"
        };
        format!(
            "{} {} attackers {what}",
            short_list(&names),
            if names.len() == 1 { "tells" } else { "tell" }
        )
    };
    Outcome::fail(shown_leaks.join("; "), reason).with_layers(layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::RedirectHop;
    use crate::finding::Status;

    fn ev(headers: &[(&str, &str)]) -> HttpEvidence {
        HttpEvidence {
            source: "GET https://example.com/".into(),
            status: 200,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
            https: true,
            insecure_probe: None,
            redirect_cookies: vec![],
            html_generator: None,
        }
    }

    #[test]
    fn hsts_rules() {
        assert_eq!(hsts(&ev(&[])).status, Status::Fail);
        assert!(hsts(&ev(&[])).missing);
        let ok = ev(&[(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )]);
        assert_eq!(hsts(&ok).status, Status::Pass);
        let short = hsts(&ev(&[("Strict-Transport-Security", "max-age=86400")]));
        assert_eq!(
            short.reason.as_deref(),
            Some("max-age=86400 (1 days) is shorter than 180 days")
        );
        assert_eq!(
            hsts(&ev(&[("Strict-Transport-Security", "max-age=0")])).status,
            Status::Fail
        );
        assert_eq!(
            hsts(&ev(&[("Strict-Transport-Security", "max-age=abc")])).status,
            Status::Fail
        );
        // Browsers use the first header only.
        let first_wins = ev(&[
            ("Strict-Transport-Security", "max-age=60"),
            ("Strict-Transport-Security", "max-age=31536000"),
        ]);
        assert_eq!(hsts(&first_wins).status, Status::Fail);
        let mut plain = ok.clone();
        plain.https = false;
        assert_eq!(hsts(&plain).status, Status::Fail);
    }

    /// Script strength only; `base-uri` is set where a nonce is trusted (that case is covered on its own below).
    #[test]
    fn csp_strength() {
        let st = |v: &str| csp(&ev(&[("Content-Security-Policy", v)])).status;
        assert_eq!(st("default-src 'self'"), Status::Pass);
        assert_eq!(
            st("script-src 'self' 'nonce-abc' 'unsafe-inline'; base-uri 'self'"),
            Status::Pass
        );
        assert_eq!(
            st("script-src 'nonce-abc' 'strict-dynamic' https:; base-uri 'none'"),
            Status::Pass
        );
        assert_eq!(st("script-src 'self' 'unsafe-inline'"), Status::Fail);
        assert_eq!(st("script-src *"), Status::Fail);
        assert_eq!(st("script-src https:"), Status::Fail);
        assert_eq!(st("frame-ancestors 'none'"), Status::Fail);
        assert_eq!(st("script-src 'self' 'unsafe-eval'"), Status::NeedsReview);
        // Two enforced policies: the strict one blocks inline scripts.
        assert_eq!(
            csp(&ev(&[
                ("Content-Security-Policy", "script-src * 'unsafe-inline'"),
                ("Content-Security-Policy", "script-src 'self'"),
            ]))
            .status,
            Status::Pass
        );
        let ro = csp(&ev(&[(
            "Content-Security-Policy-Report-Only",
            "default-src 'self'",
        )]));
        assert_eq!(ro.status, Status::Fail);
        assert!(!ro.missing);
        assert!(csp(&ev(&[])).missing);
    }

    #[test]
    fn csp_follows_the_effective_directive_for_elements_and_handlers() {
        let st = |p: &str| csp(&ev(&[("Content-Security-Policy", p)]));
        let n = "'nonce-abc'";
        // script-src-elem overrides script-src for <script> elements.
        let elem = st(&format!(
            "script-src 'self' {n}; script-src-elem 'self' 'unsafe-inline'"
        ));
        assert_eq!(elem.status, Status::Fail);
        assert!(elem
            .reason
            .as_deref()
            .unwrap_or("")
            .starts_with("script-src-elem allows 'unsafe-inline'"));
        assert_eq!(
            elem.example.as_deref(),
            Some(
                "change only script-src-elem: script-src-elem 'self' 'nonce-<random-per-request>'"
            )
        );
        // A strong script-src-elem does not hide a weak script-src for event handlers.
        let handlers = st(&format!(
            "script-src-elem 'self' {n}; script-src 'self' 'unsafe-inline'"
        ));
        assert_eq!(handlers.status, Status::Fail);
        assert!(
            handlers
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("event handlers"),
            "{:?}",
            handlers.reason
        );
        assert_eq!(
            handlers.example.as_deref(),
            Some("add (keep the rest): script-src-attr 'none'")
        );
        let attr = st(&format!(
            "script-src 'self' {n}; script-src-attr 'unsafe-inline'"
        ));
        assert_eq!(attr.status, Status::Fail);
        assert_eq!(
            attr.example.as_deref(),
            Some("change only script-src-attr: script-src-attr 'none'")
        );
        // Strong everywhere: nonce makes 'unsafe-inline' ignored, and handlers fall back to that script-src.
        assert_eq!(
            st(&format!(
                "script-src 'self' {n} 'unsafe-inline'; base-uri 'self'"
            ))
            .status,
            Status::Pass
        );
        assert_eq!(
            st(&format!(
                "script-src {n} 'strict-dynamic'; script-src-attr 'none'; base-uri 'self'"
            ))
            .status,
            Status::Pass
        );
        // eval() is governed by script-src even when script-src-elem is strong.
        let eval = st(&format!("default-src 'self'; script-src-elem 'self' 'strict-dynamic' {n}; script-src 'self' blob: 'unsafe-eval' {n}"));
        assert_eq!(eval.status, Status::NeedsReview);
        assert_eq!(
            eval.reason.as_deref(),
            Some("script-src allows 'unsafe-eval'")
        );
        // Two policies: the stricter one blocks, as browsers enforce both.
        assert_eq!(
            st(&format!(
                "script-src 'unsafe-inline', script-src 'self' {n}; base-uri 'self'"
            ))
            .status,
            Status::Pass
        );
    }

    /// A nonce trusts any URL, so an injected `<base>` can move the page's own scripts to another site: REVIEW when no
    /// policy sets `base-uri`. Hashes and host lists are not open to that, so a missing `base-uri` is only advice.
    #[test]
    fn csp_base_uri_by_risk() {
        let st = |p: &[&str]| {
            let headers: Vec<(&str, &str)> =
                p.iter().map(|v| ("Content-Security-Policy", *v)).collect();
            csp(&ev(&headers))
        };
        let nonce = st(&["script-src 'self' 'nonce-abc'"]);
        assert_eq!(nonce.status, Status::NeedsReview);
        assert_eq!(
            nonce.reason.as_deref(),
            Some("CSP trusts nonces but has no base-uri, so an injected <base> tag can redirect its scripts")
        );
        assert_eq!(
            nonce.question.as_deref(),
            Some("Does any page need a <base> tag to another site? If not, add base-uri 'self'.")
        );
        assert_eq!(
            nonce.example.as_deref(),
            Some("add (keep the rest): base-uri 'self'; object-src 'none'")
        );
        let dynamic = st(&["default-src 'self'; script-src 'strict-dynamic' 'sha256-abc'"]);
        assert_eq!(dynamic.status, Status::NeedsReview);
        assert_eq!(
            dynamic.example.as_deref(),
            Some("add (keep the rest): base-uri 'self'")
        );
        let closed = st(&["script-src 'self' 'nonce-abc'; base-uri 'self'; object-src 'none'"]);
        assert_eq!((closed.status, closed.advice), (Status::Pass, None));
        let other_policy = st(&["script-src 'self' 'nonce-abc'", "base-uri 'none'"]);
        assert_eq!(other_policy.status, Status::Pass);
        assert_eq!(
            other_policy.advice.as_deref(),
            Some("add object-src 'none' to close less common injection paths")
        );
        for (policies, why) in [
            (&["default-src 'self'"][..], "host list"),
            (
                &["script-src 'sha256-abc'; object-src 'none'"][..],
                "hash only",
            ),
            (
                &["script-src 'nonce-abc'", "script-src 'self'"][..],
                "a host-list policy also applies",
            ),
        ] {
            let o = st(policies);
            assert_eq!(o.status, Status::Pass, "{why}");
            assert!(
                o.advice
                    .as_deref()
                    .unwrap_or("")
                    .contains("base-uri 'self'"),
                "{why}: {:?}",
                o.advice
            );
            assert!(o.question.is_none(), "{why}");
        }
        let eval = st(&["script-src 'self' 'unsafe-eval'"]);
        assert_eq!(eval.status, Status::NeedsReview);
        assert_eq!(
            eval.reason.as_deref(),
            Some("script-src allows 'unsafe-eval'")
        );
        assert_eq!(
            eval.advice.as_deref(),
            Some("add base-uri 'self' and object-src 'none' to close less common injection paths")
        );
    }

    #[test]
    fn hsts_advice_never_changes_the_status() {
        let h = |v: &str| hsts(&ev(&[("Strict-Transport-Security", v)]));
        let no_sub = h("max-age=31536000");
        assert_eq!(no_sub.status, Status::Pass);
        assert_eq!(
            no_sub.advice.as_deref(),
            Some("add includeSubDomains once every subdomain serves HTTPS, so subdomains are protected too")
        );
        assert_eq!(
            no_sub.example.as_deref(),
            Some("Strict-Transport-Security: max-age=31536000; includeSubDomains")
        );
        let no_preload = h("max-age=63072000; includeSubDomains");
        assert_eq!(no_preload.status, Status::Pass);
        assert!(no_preload
            .advice
            .as_deref()
            .unwrap_or("")
            .starts_with("optional: preload"));
        assert_eq!(
            no_preload.example.as_deref(),
            Some("Strict-Transport-Security: max-age=63072000; includeSubDomains; preload")
        );
        assert_eq!(h("max-age=15552000; includeSubDomains").advice, None);
        assert_eq!(
            h("max-age=31536000; includeSubDomains; preload").advice,
            None
        );
        let short = h("max-age=86400");
        assert_eq!((short.status, short.advice), (Status::Fail, None));
    }

    /// Browsers enforce every CSP policy: one restrictive `frame-ancestors` is enough.
    #[test]
    fn clickjacking_reads_every_policy() {
        let c = |p: &[&str]| {
            let headers: Vec<(&str, &str)> =
                p.iter().map(|v| ("Content-Security-Policy", *v)).collect();
            clickjacking(&ev(&headers))
        };
        let both = c(&["frame-ancestors *", "frame-ancestors 'none'"]);
        assert_eq!(both.status, Status::Pass);
        assert_eq!(both.detail, "frame-ancestors 'none'");
        assert_eq!(c(&["frame-ancestors 'none'"]).status, Status::Pass);
        assert_eq!(c(&["frame-ancestors *"]).status, Status::Fail);
        let open = c(&["frame-ancestors https:", "frame-ancestors *"]);
        assert_eq!(open.status, Status::Fail);
        assert_eq!(
            open.reason.as_deref(),
            Some("frame-ancestors allows https:, so any site can frame this page")
        );
    }

    #[test]
    fn deprecated_headers_are_advice() {
        let x = header_syntax(&ev(&[
            ("X-Content-Type-Options", "nosniff"),
            ("X-XSS-Protection", "1; mode=block"),
        ]));
        assert_eq!(x.status, Status::Pass);
        assert_eq!(
            x.advice.as_deref(),
            Some(
                "remove x-xss-protection: current browsers ignore it (or send X-XSS-Protection: 0)"
            )
        );
        let off = header_syntax(&ev(&[("X-XSS-Protection", "0")]));
        assert_eq!((off.status, off.advice), (Status::Pass, None));
        let only = header_syntax(&ev(&[("Expect-CT", "max-age=0")]));
        assert_eq!(only.status, Status::Pass);
        assert_eq!(
            only.advice.as_deref(),
            Some("remove expect-ct: current browsers ignore it")
        );
        let two = header_syntax(&ev(&[
            ("Feature-Policy", "camera 'none'"),
            ("Public-Key-Pins", "pin-sha256=\"x\"; max-age=1"),
        ]));
        assert_eq!(
            two.advice.as_deref(),
            Some("remove feature-policy, public-key-pins: current browsers ignore them")
        );
        let dup = header_syntax(&ev(&[
            ("X-Frame-Options", "DENY"),
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Expect-CT", "max-age=0"),
        ]));
        assert_eq!(dup.status, Status::Fail);
        assert!(dup.advice.is_some());
        assert_eq!(header_syntax(&ev(&[])).status, Status::NotApplicable);
    }

    #[test]
    fn session_cookie_on_a_shared_cacheable_response() {
        let c = |extra: &[(&str, &str)]| {
            let mut h = vec![("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")];
            h.extend_from_slice(extra);
            cookies(&ev(&h))
        };
        let review = c(&[("Cache-Control", "public, s-maxage=86400")]);
        assert_eq!(review.status, Status::NeedsReview);
        assert_eq!(
            review.reason.as_deref(),
            Some("sid on a publicly cacheable response may reach other visitors")
        );
        assert_eq!(
            review.question.as_deref(),
            Some("Is this response ever cached for other visitors? If so, send Cache-Control: private.")
        );
        assert!(review
            .detail
            .contains("cache-control: public, s-maxage=86400"));
        assert!(!review.detail.contains("sid=1"));
        for hit in [
            ("Age", "120"),
            ("cf-cache-status", "HIT"),
            ("X-Cache", "Hit from cloudfront"),
        ] {
            let o = c(&[("Cache-Control", "public, max-age=600"), hit]);
            assert_eq!(o.status, Status::NeedsReview, "{hit:?}");
            assert_eq!(
                o.reason.as_deref(),
                Some("sid on a cached (HIT) response may reach other visitors")
            );
        }
        let long = cookies(&ev(&[
            ("Set-Cookie", "app_session=1; Secure; HttpOnly"),
            (
                "Set-Cookie",
                "Xy7rQ2mN8pL4kV9sT1wZ3bC6dF0gH5jK=1; Secure; HttpOnly",
            ),
            (
                "Set-Cookie",
                "third_session_cookie_name=1; Secure; HttpOnly",
            ),
            ("Cache-Control", "public, s-maxage=86400"),
            ("Age", "3"),
        ]));
        assert!(
            long.reason.as_deref().unwrap_or("").chars().count() <= 100,
            "{:?}",
            long.reason
        );
        for cc in [
            "private, max-age=0",
            "public, no-store",
            "max-age=600",
            "no-cache",
        ] {
            assert_eq!(c(&[("Cache-Control", cc)]).status, Status::Pass, "{cc}");
        }
        assert_eq!(
            c(&[("Cache-Control", "public"), ("Age", "0")]).status,
            Status::NeedsReview
        );
        let infra = cookies(&ev(&[
            ("Set-Cookie", "__cf_bm=x; Secure; HttpOnly; SameSite=None"),
            ("Cache-Control", "public, max-age=600"),
        ]));
        assert_eq!(infra.status, Status::Pass);
        let insecure = cookies(&ev(&[
            ("Set-Cookie", "sid=1; HttpOnly"),
            ("Cache-Control", "public"),
        ]));
        assert_eq!(insecure.status, Status::Fail);
        assert!(insecure
            .reason
            .as_deref()
            .unwrap_or("")
            .starts_with("Secure missing"));
        let mut hop = ev(&[("Cache-Control", "public")]);
        hop.redirect_cookies = vec!["sid=1; Secure; HttpOnly".into()];
        assert_eq!(cookies(&hop).status, Status::Pass);
    }

    #[test]
    fn disclosure_reads_meta_generator_backend_and_server_timing() {
        let with_gen = |g: &str| {
            let mut e = ev(&[]);
            e.html_generator = Some(g.into());
            info_disclosure(&e)
        };
        let wp = with_gen("WordPress 6.5.2");
        assert_eq!(wp.status, Status::Fail);
        assert_eq!(wp.detail, "meta generator: WordPress 6.5.2");
        assert_eq!(
            wp.reason.as_deref(),
            Some("meta generator tells attackers which software and version runs here")
        );
        assert_eq!(wp.layers.map(|l| l.sources), Some(vec!["wordpress"]));
        assert_eq!(with_gen("WordPress").status, Status::Pass);
        assert_eq!(with_gen("TYPO3 CMS").status, Status::Pass);
        assert_eq!(
            with_gen("Drupal 11 (https://www.drupal.org)").status,
            Status::Fail
        );
        assert_eq!(with_gen("WordPress 7.2-alpha-64347").status, Status::Fail);
        assert_eq!(with_gen("Hugo v0.120.4").status, Status::Fail);
        assert_eq!(with_gen("sitegen-0.0.65").status, Status::Fail);
        assert_eq!(
            info_disclosure(&ev(&[("X-Powered-By", "TYPO3")]))
                .reason
                .as_deref(),
            Some("x-powered-by tells attackers which software runs here")
        );
        let backend = info_disclosure(&ev(&[("X-Backend-Server", "web-03")]));
        assert_eq!(backend.status, Status::Fail);
        assert_eq!(
            backend.reason.as_deref(),
            Some("x-backend-server reveals the name of an internal server")
        );
        assert_eq!(
            info_disclosure(&ev(&[("X-Backend-Server", "XXXXXX")])).status,
            Status::Pass
        );
        for benign in [
            "cfL4;desc=\"?proto=TCP&rtt=1234&min_rtt=1000&rtt_var=50\"",
            "cdn-cache;desc=HIT, edge;dur=1.5",
            "chlray;desc=\"0123456789abcdef\"",
            "cache;desc=cache.hit",
            "app;dur=12.25",
        ] {
            assert_eq!(
                info_disclosure(&ev(&[("Server-Timing", benign)])).status,
                Status::Pass,
                "{benign}"
            );
        }
        let internal = info_disclosure(&ev(&[(
            "Server-Timing",
            "origin;desc=\"web-03.prod.internal\";dur=20",
        )]));
        assert_eq!(internal.status, Status::NeedsReview);
        assert_eq!(
            internal.reason.as_deref(),
            Some("server-timing names web-03.prod.internal, which may be an internal server")
        );
        assert_eq!(
            internal.question.as_deref(),
            Some("Is this an internal host or server name? If so, remove it from Server-Timing.")
        );
        assert_eq!(
            info_disclosure(&ev(&[("Server-Timing", "db;desc=10.0.3.7")])).status,
            Status::NeedsReview
        );
        let both = info_disclosure(&ev(&[
            ("X-Powered-By", "PHP/8.2.1"),
            ("Server-Timing", "origin;desc=\"web-03.prod.internal\""),
        ]));
        assert_eq!(both.status, Status::Fail);
        for cdn in [("Via", "1.1 varnish"), ("X-Served-By", "cache-xyz1234-ABC")] {
            assert_eq!(info_disclosure(&ev(&[cdn])).status, Status::Pass, "{cdn:?}");
        }
    }

    #[test]
    fn csp_example_keeps_the_sites_own_hosts() {
        let o = csp(&ev(&[(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://challenges.cloudflare.com; img-src *",
        )]));
        assert_eq!(
            o.example.as_deref(),
            Some("change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com https://challenges.cloudflare.com")
        );
        let d = csp(&ev(&[(
            "Content-Security-Policy",
            "default-src * 'unsafe-inline'",
        )]));
        assert_eq!(
            d.example.as_deref(),
            Some(
                "add script-src (keep default-src): script-src 'self' 'nonce-<random-per-request>'"
            )
        );
        let hosts = (0..40)
            .map(|i| format!("https://h{i}.example.com"))
            .collect::<Vec<_>>()
            .join(" ");
        let long = csp(&ev(&[(
            "Content-Security-Policy",
            format!("script-src 'unsafe-inline' {hosts}").as_str(),
        )]));
        let ex = long.example.unwrap();
        assert!(ex.chars().count() <= MAX_EXAMPLE_CHARS, "{ex}");
        assert!(ex.ends_with("…keep your other sources"));
        assert!(ex.contains(NONCE_PLACEHOLDER));
    }

    #[test]
    fn referrer_uses_last_known_token() {
        let st = |v: &str| referrer_policy(&ev(&[("Referrer-Policy", v)])).status;
        assert_eq!(st("strict-origin-when-cross-origin"), Status::Pass);
        assert_eq!(
            st("no-referrer, strict-origin-when-cross-origin"),
            Status::Pass
        );
        assert_eq!(st("strict-origin, unsafe-url"), Status::Fail);
        assert_eq!(st("strict-origin, made-up"), Status::Pass);
        assert_eq!(st("made-up"), Status::Fail);
    }

    #[test]
    fn clickjacking_rules() {
        let st = |h: &[(&str, &str)]| clickjacking(&ev(h)).status;
        assert_eq!(st(&[("X-Frame-Options", "DENY")]), Status::Pass);
        assert_eq!(st(&[("X-Frame-Options", "sameorigin")]), Status::Pass);
        assert_eq!(
            st(&[("X-Frame-Options", "ALLOW-FROM https://a.example")]),
            Status::Fail
        );
        assert_eq!(
            st(&[
                ("X-Frame-Options", "DENY"),
                ("X-Frame-Options", "SAMEORIGIN")
            ]),
            Status::Fail
        );
        assert_eq!(
            st(&[("Content-Security-Policy", "frame-ancestors 'self'")]),
            Status::Pass
        );
        // frame-ancestors overrides X-Frame-Options.
        assert_eq!(
            st(&[
                ("Content-Security-Policy", "frame-ancestors *"),
                ("X-Frame-Options", "DENY")
            ]),
            Status::Fail
        );
        assert!(clickjacking(&ev(&[])).missing);
    }

    fn probe(hops: &[(u16, &str)], final_url: &str) -> HttpEvidence {
        let mut e = ev(&[]);
        e.insecure_probe = Some(InsecureProbe::Responded {
            chain: hops
                .iter()
                .map(|(s, u)| RedirectHop {
                    url: (*u).into(),
                    status: *s,
                    location: None,
                })
                .collect(),
            final_url: final_url.into(),
        });
        e
    }

    #[test]
    fn https_redirect_distinguishes_permanent_temporary_and_none() {
        let ok = https_redirect(&probe(
            &[(301, "http://a.example/"), (200, "https://a.example/")],
            "https://a.example/",
        ));
        assert_eq!(ok.status, Status::Pass);
        assert_eq!(
            ok.detail,
            "GET http://a.example/ → 301 → https://a.example/ 200"
        );
        let temp = https_redirect(&probe(
            &[(302, "http://a.example/"), (200, "https://a.example/")],
            "https://a.example/",
        ));
        assert_eq!(temp.status, Status::NeedsReview);
        let none = https_redirect(&probe(&[(200, "http://a.example/")], "http://a.example/"));
        assert_eq!(none.status, Status::Fail);
        assert!(none
            .reason
            .unwrap()
            .contains("traffic can be read or changed"));
        let stays = https_redirect(&probe(
            &[(301, "http://a.example/"), (200, "http://b.example/")],
            "http://b.example/",
        ));
        assert_eq!(stays.status, Status::Fail);
        let mut closed = ev(&[]);
        closed.insecure_probe = Some(InsecureProbe::Unreachable("connection refused".into()));
        assert_eq!(https_redirect(&closed).status, Status::Pass);
        assert_eq!(https_redirect(&ev(&[])).status, Status::Unknown);
    }

    #[test]
    fn header_syntax_is_na_without_headers_and_catches_conflicts() {
        assert_eq!(
            header_syntax(&ev(&[("Server", "x")])).status,
            Status::NotApplicable
        );
        assert_eq!(
            header_syntax(&ev(&[("X-Content-Type-Options", "nosniff")])).status,
            Status::Pass
        );
        for bad in [
            vec![
                ("Strict-Transport-Security", "max-age=1"),
                ("Strict-Transport-Security", "max-age=2"),
            ],
            vec![("Strict-Transport-Security", "max-age=1; max-age=2")],
            vec![("Content-Security-Policy", "script-src 'self'; script-src *")],
            vec![("Permissions-Policy", "camera 'none'")],
        ] {
            assert_eq!(header_syntax(&ev(&bad)).status, Status::Fail, "{bad:?}");
        }
        assert_eq!(
            header_syntax(&ev(&[(
                "Permissions-Policy",
                "camera=(), geolocation=(self)"
            )]))
            .status,
            Status::Pass
        );
    }

    #[test]
    fn cookies_never_show_values() {
        let x = cookies(&ev(&[(
            "Set-Cookie",
            "XSRF-TOKEN=abc; Secure; SameSite=Lax",
        )]));
        let shown = crate::redact::redact(&x.detail);
        assert_eq!(
            shown, "XSRF-TOKEN (Secure, SameSite=lax)",
            "flags survive redaction"
        );
        let na = cookies(&ev(&[]));
        assert_eq!(na.status, Status::NotApplicable);
        let o = cookies(&ev(&[(
            "Set-Cookie",
            "sid=SECRETVALUE123; Path=/; HttpOnly",
        )]));
        assert_eq!(o.status, Status::Fail);
        assert!(!o.detail.contains("SECRETVALUE123"), "{}", o.detail);
        assert!(o.detail.contains("sid (HttpOnly)"));
        let ok = cookies(&ev(&[(
            "Set-Cookie",
            "sid=x; Secure; HttpOnly; SameSite=Lax",
        )]));
        assert_eq!(ok.status, Status::Pass);
        let js = cookies(&ev(&[("Set-Cookie", "theme=dark; Secure")]));
        assert_eq!(js.status, Status::NeedsReview);
        let none = cookies(&ev(&[("Set-Cookie", "a=1; SameSite=None; HttpOnly")]));
        assert!(none
            .reason
            .unwrap()
            .starts_with("SameSite=None without Secure on a, so browsers reject it"));
    }

    #[test]
    fn framework_csrf_cookies_may_be_script_readable() {
        let laravel = cookies(&ev(&[
            ("Set-Cookie", "XSRF-TOKEN=a; path=/; secure; samesite=lax"),
            (
                "Set-Cookie",
                "app_session=b; path=/; secure; httponly; samesite=lax",
            ),
        ]));
        assert_eq!(laravel.status, Status::Pass, "{:?}", laravel.reason);
        let django = cookies(&ev(&[("Set-Cookie", "csrftoken=a; Secure; SameSite=Lax")]));
        assert_eq!(django.status, Status::Pass);
        // Express csurf keeps its secret in `_csrf`: still flagged, and Secure is still required.
        let csurf = cookies(&ev(&[("Set-Cookie", "_csrf=a; Secure")]));
        assert_eq!(csurf.status, Status::NeedsReview);
        let insecure = cookies(&ev(&[("Set-Cookie", "XSRF-TOKEN=a; path=/")]));
        assert_eq!(insecure.status, Status::Fail);
    }

    #[test]
    fn cookies_from_redirects_are_checked_unless_the_page_sets_them_again() {
        let mut e = ev(&[("Set-Cookie", "sid=1; Secure; HttpOnly")]);
        e.redirect_cookies = vec!["tracker=x; Path=/".into(), "sid=0; Path=/".into()];
        let o = cookies(&e);
        assert_eq!(o.status, Status::Fail);
        assert!(
            o.reason.as_deref().unwrap_or("").contains("tracker"),
            "{:?}",
            o.reason
        );
        assert!(
            !o.reason.as_deref().unwrap_or("").contains("sid"),
            "{:?}",
            o.reason
        );
        assert!(
            o.detail.contains("tracker (no flags, on redirect)"),
            "{}",
            o.detail
        );
        let mut only_hops = ev(&[]);
        only_hops.redirect_cookies = vec!["t=1; Secure; HttpOnly; SameSite=Lax".into()];
        assert_eq!(cookies(&only_hops).status, Status::Pass);
    }

    #[test]
    fn reasons_stay_short_and_keep_the_owner_note() {
        let many = ev(&[
            (
                "Set-Cookie",
                "visid_incap_1832240_extra_long_name=a; Path=/",
            ),
            ("Set-Cookie", "incap_ses_373_1832240=b; Path=/"),
            ("Set-Cookie", "nlbi_1832240=c; Path=/"),
        ]);
        let why = cookies(&many).reason.unwrap();
        assert!(why.chars().count() <= 100, "{why}");
        assert_eq!(
            why,
            "Secure missing on 3 imperva cookies, so they are also sent over http:// (fix it there)"
        );
        let leak = info_disclosure(&ev(&[
            ("X-Powered-By", "ASP.NET"),
            ("X-AspNet-Version", "4.0.30319"),
            ("X-AspNetMvc-Version", "5.2"),
        ]))
        .reason
        .unwrap();
        assert!(leak.chars().count() <= 100, "{leak}");
        assert_eq!(super::infra_platform("akaalb_0001_www"), Some("akamai"));
        assert_eq!(super::infra_platform("bm_so"), Some("akamai"));
        // A cookie named like a token must not turn the reason into `NAME: …` (redaction would hide it).
        let token = crate::redact::redact(
            &cookies(&ev(&[("Set-Cookie", "API-TOKEN=abc; Secure")]))
                .reason
                .unwrap(),
        )
        .into_owned();
        assert_eq!(
            token,
            "HttpOnly missing on API-TOKEN, so page scripts can read it"
        );
    }

    #[test]
    fn disclosure_reason_mentions_a_version_only_when_one_is_shown() {
        let name_only = info_disclosure(&ev(&[("X-Powered-By", "Next.js")]));
        assert_eq!(
            name_only.reason.as_deref(),
            Some("x-powered-by tells attackers which software runs here")
        );
        let versioned = info_disclosure(&ev(&[("Server", "nginx/1.24.0")]));
        assert_eq!(
            versioned.reason.as_deref(),
            Some("server tells attackers which software and version runs here")
        );
    }

    #[test]
    fn info_disclosure_collects_every_value() {
        assert_eq!(
            info_disclosure(&ev(&[("Server", "cloudflare")])).status,
            Status::Pass
        );
        assert_eq!(
            info_disclosure(&ev(&[("Server", "nginx")])).status,
            Status::Pass
        );
        let o = info_disclosure(&ev(&[
            ("Server", "Microsoft-IIS/10.0"),
            ("X-Powered-By", "ASP.NET"),
            ("X-Powered-By", "ARR/3.0"),
        ]));
        assert_eq!(o.status, Status::Fail);
        assert_eq!(
            o.detail,
            "server: Microsoft-IIS/10.0; x-powered-by: ASP.NET; x-powered-by: ARR/3.0"
        );
        assert!(o
            .reason
            .unwrap()
            .starts_with("server, x-powered-by tell attackers which software and version"));
    }
}
