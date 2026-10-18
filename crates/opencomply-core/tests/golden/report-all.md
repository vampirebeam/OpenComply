# OpenComply report — headers

| | |
|---|---|
| Target | `https://example.com/` |
| Verdict | **FAIL** — fix 2, decide 3 · advice 1 (optional) |
| Grade | **D** (58/100) |
| Results | 5 passed · 2 failed · 0 unknown · 3 needs review · 0 no evidence · 0 not applicable · 1 with advice |
| Scanner | 0.0.0-golden · report schema 1 |
| Rule packs | opencomply-headers 1.2.0 (signed by opencomply-2026, sha256 `b709d5939032…`) |
| Platform | Cloudflare (CDN / WAF, from `CF-Ray: 0123456789abcdef-BKK`) · nginx (web server, from `Server: nginx/1.24.0`) · PHP (framework / CMS, from `X-Powered-By: PHP/8.2.1`) · WordPress (framework / CMS, from `HTML contains "/wp-content/"`) — detected from response headers, used only for fix guidance |

## How to raise the grade

The grade weighs every check by severity; a grade reached here does not mean every check passes (the verdict lists what is still open).

| Target | Check | Points | Required | Impact of passing it |
|---|---|---|---|---|
| C (→ B 83) | HDR-002 | +25 | yes | Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes |
| A+ (→ A+ 95) | HDR-002 | +25 | yes | Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes |
| A+ (→ A+ 95) | HDR-007 | +7 | yes | All http:// links and bookmarks are moved to https://; mixed http:// resources on the pages must be fixed |
| A+ (→ A+ 95) | HDR-010 | +5 | yes | None for users; only hides version details |

## Needs action

| Rule | Version | Severity | Effort | Finding | Why | Evidence | Fix | Example | Where to fix |
|---|---|---|---|---|---|---|---|---|---|
| HDR-002 | 1.1.0 | high | involved | Content-Security-Policy | script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run | GET `https://example.com/` `content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com` | CSP limits which scripts can run, which reduces what injected code (XSS) can do. Generate a new random nonce per response and put it on every &lt;script&gt;, or use hashes for fixed inline scripts. With nonces, also set base-uri 'self' so an injected &lt;base&gt; tag cannot send the page's own scripts to another site. The example is a starting point, not a drop-in policy: review the whole existing CSP, check third-party scripts and framework hydration, roll out with Content-Security-Policy-Report-Only, fix what it reports, then enforce. | `change only script-src: script-src 'self' 'nonce-<random-per-request>' https://cdn.example.com` | **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Set static: Content-Security-Policy — ⚠ A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker · **nginx:** add_header Content-Security-Policy "..." always; nonces: set them in the app, or sub_filter with $request_id |
| HDR-010 | 1.1.0 | low | quick | Technology disclosure | server, x-powered-by +1 tell attackers which software and version runs here | GET `https://example.com/` `server: nginx/1.24.0; x-powered-by: PHP/8.2.1; meta generator: WordPress 6.5.2` | Version headers let attackers look up known vulnerabilities for your exact software without probing. Removing them is not a fix for outdated software, but it stops free reconnaissance. Keep the software updated as well. The same applies to a &lt;meta name="generator"&gt; tag with a version, and to internal server names in X-Backend-Server or Server-Timing. |  | **nginx, preferred:** server_tokens off; PHP: fastcgi_hide_header X-Powered-By; proxy: proxy_hide_header X-Powered-By; · **php, preferred:** php.ini: expose_php = Off · **wordpress, preferred:** php.ini expose_php = Off, and hide the server version on the web server — ⚠ meta generator: remove_action('wp_head', 'wp_generator') in the theme's functions.php |

## Needs your review

### HDR-007 · HTTPS enforcement

- **Status:** REVIEW · severity high · rule version 1.1.0
- **Effort:** moderate
- **Why:** http:// moves to https:// with a temporary redirect (302), which browsers do not remember
- **Evidence (verified):** GET `https://example.com/` — `GET http://example.com/ → 302 → https://example.com/ 200`
- **Decide:** Is the temporary redirect intentional? If not, make it 301 or 308.
- **Example:** `http://example.com/ → 301 → https://example.com/`
- **How (cloudflare):** SSL/TLS &gt; Edge Certificates &gt; Always Use HTTPS: On
- **How (nginx):** server { listen 80; server_name example.com; return 301 https://$host$request_uri; }
- **Guidance:** If http:// still serves the page, anyone on the network (public Wi-Fi, ISP) can read or change it. Redirect all http:// requests to the same path on https:// with a permanent redirect (301 or 308), then add HSTS (HDR-001).

### HDR-009 · Cookie security

- **Status:** REVIEW · severity medium · rule version 1.1.0
- **Effort:** moderate
- **Why:** HttpOnly missing on theme, so page scripts can read it
- **Evidence (verified):** GET `https://example.com/` — `sid (Secure, HttpOnly); theme (Secure, SameSite=lax)`
- **Decide:** Does page JavaScript need to read these cookies? If not, add HttpOnly.
- **Example:** `Set-Cookie: session=<value>; Path=/; Secure; HttpOnly; SameSite=Lax`
- **How (php, preferred):** php.ini: session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax
- **How (wordpress, preferred):** Core login cookies are HttpOnly; set FORCE_SSL_ADMIN true in wp-config.php and check plugin cookies
- **Guidance:** Secure keeps cookies off http://, HttpOnly hides them from scripts (so injected scripts cannot read them), SameSite=Lax limits cross-site requests (CSRF). Set them where the cookie is created: framework session settings or app code. A response that sets a session cookie should send Cache-Control: private (or no-store), so a shared cache never stores it and hands it to other visitors.

### HDR-005 · Permissions-Policy

- **Status:** REVIEW · severity low · rule version 1.2.0
- **Effort:** quick
- **Why:** camera=* lets every embedded site use it
- **Evidence (verified):** GET `https://example.com/` — `permissions-policy: camera=*, geolocation=()`
- **Decide:** Do embedded sites need these features? If not, use =() or =(self).
- **Example:** `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
- **How (cloudflare):** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Set static: Permissions-Policy
- **How (nginx):** add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
- **Guidance:** Permissions-Policy turns off browser features (camera, microphone, location, payment) the site does not use, so injected or embedded code cannot use them. List only features the site needs with (self).

## Advice (optional — already passed)

| Rule | Check | Advice | Example |
|---|---|---|---|
| HDR-001 | Strict-Transport-Security | add includeSubDomains once every subdomain serves HTTPS, so subdomains are protected too | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |

## Passed and not applicable

| Status | Rule | Version | Check | Evidence |
|---|---|---|---|---|
| PASS | HDR-001 | 1.1.0 | Strict-Transport-Security | GET `https://example.com/` `strict-transport-security: max-age=31536000` |
| PASS | HDR-003 | 1.2.0 | X-Content-Type-Options | GET `https://example.com/` `x-content-type-options: nosniff` |
| PASS | HDR-006 | 1.1.0 | Clickjacking protection | GET `https://example.com/` `x-frame-options: SAMEORIGIN` |
| PASS | HDR-008 | 1.1.0 | Security header syntax | GET `https://example.com/` `checked: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy, permissions-policy` |
| PASS | HDR-004 | 1.1.0 | Referrer-Policy | GET `https://example.com/` `referrer-policy: strict-origin-when-cross-origin` |
