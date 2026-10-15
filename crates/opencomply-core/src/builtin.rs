//! Built-in header checks selected by name from the closed `Builtin` list. Pure: evidence in → outcome out.
//! Browser behaviour they follow: first HSTS header wins; every enforced CSP must allow a script, so the strongest
//! policy decides; nonces / hashes make 'unsafe-inline' ignored; frame-ancestors overrides X-Frame-Options.
//! Cookie evidence shows names and attributes only — never cookie values.

use std::collections::BTreeMap;

use crate::evaluate::{directive_value, shown, HttpEvidence, InsecureProbe, Outcome};
use crate::platform::Layer;
use crate::render::MAX_EXAMPLE_CHARS;
use crate::rules::{Builtin, LayerHint};

/// 180 days: shorter policies expire between visits of occasional users.
pub const HSTS_MIN_MAX_AGE: u64 = 15_552_000;

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
        Some(Ok(_)) => Outcome::pass(detail),
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
    let mut review = None;
    let mut weak = None;
    for p in &policies {
        match script_control(p) {
            ScriptControl::Strong => return Outcome::pass(detail),
            ScriptControl::Review(r) => review = review.or(Some(r)),
            ScriptControl::Weak(r) => weak = weak.or(Some((r, p))),
        }
    }
    if let Some(r) = review {
        return Outcome::review(detail, r);
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

fn clickjacking(http: &HttpEvidence) -> Outcome {
    let csp = http.values("content-security-policy");
    for p in parse_policies(&csp) {
        if let Some(fa) = p.get("frame-ancestors") {
            let detail = format!("frame-ancestors {}", fa.join(" "));
            return match fa.iter().find(|s| is_wildcard_source(s)) {
                Some(w) => Outcome::fail(
                    detail,
                    format!("frame-ancestors allows {w}, so any site can frame this page"),
                ),
                None => Outcome::pass(detail),
            };
        }
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

fn header_syntax(http: &HttpEvidence) -> Outcome {
    let present: Vec<&str> = SECURITY_HEADERS
        .iter()
        .copied()
        .filter(|h| !http.values(h).is_empty())
        .collect();
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
            },
            who,
            note,
        )
    } else {
        (
            LayerHint {
                prefer: vec![Layer::Framework],
                skip: vec![],
                only: vec![],
            },
            short_list(&flagged_names(cookies, pred)),
            String::new(),
        )
    }
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

const TECH_HEADERS: [&str; 5] = [
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
];

fn has_version(server: &str) -> bool {
    server
        .split('/')
        .skip(1)
        .any(|rest| rest.trim_start().starts_with(|c: char| c.is_ascii_digit()))
}

fn info_disclosure(http: &HttpEvidence) -> Outcome {
    let mut leaks: Vec<String> = http
        .values("server")
        .into_iter()
        .filter(|v| has_version(v))
        .map(|v| format!("server: {v}"))
        .collect();
    for h in TECH_HEADERS {
        leaks.extend(http.values(h).into_iter().map(|v| format!("{h}: {v}")));
    }
    if leaks.is_empty() {
        return Outcome::pass("no version or technology headers".into());
    }
    let names: Vec<&str> =
        leaks
            .iter()
            .filter_map(|l| l.split(':').next())
            .fold(Vec::new(), |mut acc, n| {
                if !acc.contains(&n) {
                    acc.push(n);
                }
                acc
            });
    // A `Server` version is set by the web server (or its host panel) — the app and the CDN guides cannot remove it;
    // app headers such as `X-Powered-By` are best removed in the app, though a proxy or CDN in front can also strip them.
    let server_leak = names.contains(&"server");
    let app_leak = names.iter().any(|n| *n != "server");
    let layers = match (server_leak, app_leak) {
        (true, false) => LayerHint {
            prefer: vec![Layer::Server, Layer::Host],
            skip: vec![Layer::Cdn, Layer::Framework, Layer::Frontend],
            only: vec![],
        },
        (false, _) => LayerHint {
            prefer: vec![Layer::Framework],
            skip: vec![Layer::Frontend],
            only: vec![],
        },
        (true, true) => LayerHint {
            prefer: vec![Layer::Server, Layer::Host, Layer::Framework],
            skip: vec![Layer::Frontend],
            only: vec![],
        },
    };
    // Say "version" only when a value carries one: `x-powered-by: Next.js` names the software, nothing more.
    let what = if leaks.iter().any(|l| {
        l.split_once(':')
            .is_some_and(|(_, v)| v.bytes().any(|b| b.is_ascii_digit()))
    }) {
        "which software and version runs here"
    } else {
        "which software runs here"
    };
    Outcome::fail(
        leaks.join("; "),
        format!(
            "{} {} attackers {what}",
            short_list(&names),
            if names.len() == 1 { "tells" } else { "tell" }
        ),
    )
    .with_layers(layers)
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

    #[test]
    fn csp_strength() {
        let st = |v: &str| csp(&ev(&[("Content-Security-Policy", v)])).status;
        assert_eq!(st("default-src 'self'"), Status::Pass);
        assert_eq!(
            st("script-src 'self' 'nonce-abc' 'unsafe-inline'"),
            Status::Pass
        );
        assert_eq!(
            st("script-src 'nonce-abc' 'strict-dynamic' https:"),
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
            st(&format!("script-src 'self' {n} 'unsafe-inline'")).status,
            Status::Pass
        );
        assert_eq!(
            st(&format!(
                "script-src {n} 'strict-dynamic'; script-src-attr 'none'"
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
                "script-src 'unsafe-inline', script-src 'self' {n}"
            ))
            .status,
            Status::Pass
        );
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
