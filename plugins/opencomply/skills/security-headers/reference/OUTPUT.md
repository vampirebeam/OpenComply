# Reading OpenComply output

## Summary (default)

```
headers https://example.com/ verdict=fail grade=D score=63 pass=6 fail=3 … platform=cloudflare+nextjs
to C: HDR-002 +26 required → B 89
to A+: HDR-002 +26 required · HDR-005 +6 required → A+ 95
  impact (HDR-002): Nonces need each response rendered per request …
FAIL HDR-002 high Content-Security-Policy
  why: script-src allows 'unsafe-inline', so an injected <script> still runs
  fix: enforce a CSP whose script-src allows no inline or wildcard scripts
  example: change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
  how (nextjs, preferred): middleware (proxy): create a nonce per request …
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Set static: Content-Security-Policy
  note (cloudflare): A static Transform Rule cannot add a per-request nonce …
next: fix 3 · evidence: --format markdown
```

| Line | Meaning |
|---|---|
| first line | module, target, `verdict`, grade and score, count per status, detected platforms |
| `grade capped:` | why the grade is lower than the score alone would give |
| `to X: … → Y n` | fixes needed to reach grade X, points each adds, `required` = cannot be skipped; `→` the actual result after them (can exceed X) |
| `impact (ID):` | what passing that rule changes or costs; `impact of …: --all` = more impact lines with `--all` |
| `FAIL` / `REVIEW` / `UNKNOWN` | status, rule ID, severity, finding |
| `why:` | the observed problem |
| `fix:` | the action |
| `example:` | a starting point built from the site's own values — adapt it, replace `<...>` |
| `how (platform)` | where to fix it on that platform; `preferred` = fix it here rather than at the other listed place |
| `note (platform)` | a caveat for that platform |
| `decide:` | the question the user must answer (REVIEW / UNKNOWN only) |
| `next:` | what remains |

## Statuses

| Status | Meaning | Treat as |
|---|---|---|
| PASS | meets the rule | passed |
| FAIL | does not meet the rule | must fix |
| REVIEW | needs a user decision (e.g. a temporary redirect, a cookie JavaScript may need) | not passed — ask |
| UNKNOWN | could not be checked | not passed — re-run or check manually |
| N/A | rule does not apply (no cookies, a JSON API) | excluded from the score |

`verdict`: `fail` (any FAIL) → `incomplete` (any UNKNOWN) → `review` (any REVIEW) → `pass`.

## Grade

- Score = weight of passing rules ÷ weight of applicable rules (REVIEW counts half). A+ 95–100 · A 90–94 · B 80–89 ·
  C 70–79 · D 50–69 · F 0–49.
- A failing mandatory rule (HSTS HDR-001, CSP HDR-002, clickjacking HDR-006, HTTPS enforcement HDR-007) caps the grade
  at C; a failing high / critical rule caps it at B; A+ needs every mandatory rule passed; a mandatory UNKNOWN gives no
  grade (`N/A`).

## Rules

| ID | Checks |
|---|---|
| HDR-001 | Strict-Transport-Security (max-age ≥ 180 days, served over HTTPS) |
| HDR-002 | Content-Security-Policy enforced, no inline / wildcard scripts |
| HDR-003 | X-Content-Type-Options: nosniff |
| HDR-004 | Referrer-Policy not leaking full URLs |
| HDR-005 | Permissions-Policy present |
| HDR-006 | Clickjacking protection (frame-ancestors or X-Frame-Options) |
| HDR-007 | `http://` moves to `https://` with a permanent redirect |
| HDR-008 | Security headers sent once, with valid syntax |
| HDR-009 | Cookies: Secure, HttpOnly, SameSite (N/A when the page sets none — scan a page that does) |
| HDR-010 | No version / technology disclosure (Server version, X-Powered-By …) |

## JSON

One line: `schema_version`, `scanner_version`, `module`, `target`, `rule_packs`, `platforms`, `verdict`, `grade`
(`grade`, `score`, `capped_by`, `upgrades[]` with `to`, `steps[]`, `result`, `result_score`), `summary`, `findings[]`
(`rule_id`, `rule_version`, `title`, `status`, `severity`, `evidence[]`, `reason`, `fix_hint`, `example_fix`,
`platform_fixes[]` with `platform`, `how`, `note`, `preferred`, `review_question`, `remediation`).
Full schema: `opencomply schema report`.
Evidence `class`: `verified` = read from the response and used to decide; `inferred` = platform detection, guidance only.
