# Reading OpenComply output

## Summary (default)

```
headers https://example.com/ verdict=fail grade=D score=63 pass=6 fail=3 … platform=cloudflare+nextjs
to C: HDR-002 +26 required → B 89
to A+: HDR-002 +26 required · HDR-005 +6 required → A+ 95
  impact (HDR-002): Nonces need each response rendered per request …
FAIL HDR-002 high Content-Security-Policy · involved
  why: script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run
  fix: enforce a CSP whose script-src allows no inline or wildcard scripts
  example: change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
  how (nextjs, preferred): middleware (proxy): create a nonce per request …
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Set static: Content-Security-Policy
  note (cloudflare): A static Transform Rule cannot add a per-request nonce …
next: fix 3 · evidence: --format markdown
```

| Line | Meaning |
|---|---|
| first line | module, target, `verdict`, grade and score, count per status, `advice=N` when there is advice, detected platforms |
| `grade capped:` | why the grade is lower than the score alone would give |
| `note:` | grade A / A+ while checks are still open — the grade weighs checks; report the open ones, never "everything passed" |
| `to X: … → Y n` | fixes needed to reach grade X, points each adds, `required` = cannot be skipped; `→` the actual result after them (can exceed X) |
| `impact (ID):` | what passing that rule changes or costs; `impact of …: --all` = more impact lines with `--all` |
| `FAIL` / `REVIEW` / `UNKNOWN` | status, rule ID, severity, finding, then the usual effort: `quick` · `moderate` · `involved` |
| `after:` | fix these rules first (e.g. HSTS after the http:// redirect); the list is already in that order |
| `why:` | the observed problem |
| `fix:` | the action |
| `example:` | a starting point built from the site's own values — adapt it, replace `<...>` |
| `how (platform)` | where to fix it on that platform; `preferred` = fix it here rather than at the other listed place |
| `note (platform)` | a caveat for that platform |
| `decide:` | the question the user must answer (REVIEW / UNKNOWN only) |
| `PASS` + `advice:` | already passed; an optional improvement (with its own `example:`) — never changes verdict or grade |
| `together (group):` | rules set in the same place, so one change covers them |
| `next:` | what remains, plus how many optional advice items |

## Statuses

| Status | Meaning | Treat as |
|---|---|---|
| PASS | meets the rule | passed |
| FAIL | does not meet the rule | must fix |
| REVIEW | needs a user decision (e.g. a temporary redirect, a cookie JavaScript may need) | not passed — ask |
| UNKNOWN | could not be checked | not passed — re-run or check manually |
| N/A | rule does not apply (no cookies, a JSON API) | excluded from the score |

`verdict`: `fail` (any FAIL) → `incomplete` (any UNKNOWN) → `review` (any REVIEW) → `pass`.
Advice is not a status: it sits on a result (usually PASS) and is optional.

## Grade

- Score = weight of passing rules ÷ weight of applicable rules (REVIEW counts half). A+ 95–100 · A 90–94 · B 80–89 ·
  C 70–79 · D 50–69 · F 0–49.
- A failing mandatory rule (HSTS HDR-001, CSP HDR-002, clickjacking HDR-006, HTTPS enforcement HDR-007) caps the grade
  at C; a failing high / critical rule caps it at B; A+ needs every mandatory rule passed; a mandatory UNKNOWN gives no
  grade (`N/A`).

## Rules

| ID | Checks |
|---|---|
| HDR-001 | Strict-Transport-Security (max-age ≥ 180 days, served over HTTPS); advice: includeSubDomains, then preload |
| HDR-002 | Content-Security-Policy enforced, no inline / wildcard scripts; REVIEW when nonces are trusted without base-uri |
| HDR-003 | X-Content-Type-Options: nosniff |
| HDR-004 | Referrer-Policy not leaking full URLs |
| HDR-005 | Permissions-Policy present |
| HDR-006 | Clickjacking protection (frame-ancestors in any policy, or X-Frame-Options) |
| HDR-007 | `http://` moves to `https://` with a permanent redirect |
| HDR-008 | Security headers sent once, with valid syntax; advice: remove headers browsers no longer use |
| HDR-009 | Cookies: Secure, HttpOnly, SameSite, and session cookies not on a publicly cacheable response (N/A when the page sets none — scan a page that does) |
| HDR-010 | No version / technology disclosure (Server version, X-Powered-By, versioned `<meta name="generator">`, X-Backend-Server); REVIEW for an internal-looking host in Server-Timing |

## JSON

One line: `schema_version`, `scanner_version`, `module`, `target`, `rule_packs`, `platforms`, `verdict`, `grade`
(`grade`, `score`, `capped_by`, `upgrades[]` with `to`, `steps[]`, `result`, `result_score`), `summary` (count per
status plus `advice`), `findings[]` (`rule_id`, `rule_version`, `title`, `status`, `severity`, `evidence[]`, `reason`,
`fix_hint`, `example_fix`, `platform_fixes[]` with `platform`, `how`, `note`, `preferred`, `review_question`,
`remediation`, `advice`, `effort`, `depends_on[]`, `group`). Findings come in the order to work on them.
`--format json --compact` leaves out `remediation` and the evidence of passed checks.
Evidence `detail` is redacted, then cut to 4,096 characters in JSON and 300 in the summary / Markdown;
`truncated: true` = the shown value is not whole (the check itself used the whole value).
Full schema: `opencomply schema report`.
This describes `schema_version` 1. New fields are always optional, so the same version keeps the same meanings; a
higher `schema_version` means compatibility is not confirmed: show only the target, scanner version and number of
findings, do not state a grade, verdict, PASS or FAIL, and tell the user to update the OpenComply plugin.
Evidence `class`: `verified` = read from the response and used to decide (including the page's own
`<meta name="generator">`); `inferred` = platform detection, guidance only.
