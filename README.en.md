<p align="center"><img src="docs/assets/opencomply-hero.svg" alt="OpenComply — security and compliance scanner" width="960" /></p>

<p align="center"><a href="README.md">🇹🇭 ภาษาไทย</a> &nbsp;|&nbsp; <strong>🇬🇧 English</strong></p>

<h3 align="center">Website security checks<br/>that tell you what's missing, how to fix it and where, in a form developers and AI agents can build on.</h3>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.3-f59e0b?style=flat-square" alt="Version 0.2.3" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-22c55e?style=flat-square" alt="Apache-2.0 License" /></a>
  <img src="https://img.shields.io/badge/rust-1.90-0891b2?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.90" />
  <img src="https://img.shields.io/badge/works_with-Claude_Code_%7C_Codex_%7C_Cursor_%7C_Gemini_CLI-7C3AED?style=flat-square" alt="Works with Claude Code, Codex, Cursor and Gemini CLI" />
</p>

## Overview

OpenComply is **a single CLI engine** that checks targets against versioned, signed rules and returns structured output. Pass and fail come only from the engine; you or your AI agent call it and act on the results.

| Module | Checks | Result |
|---|---|---|
| **HTTP Security Headers** | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking, HTTPS enforcement, cookies, information disclosure | Grade A+ – F with a 0–100 score |

## Install

### With an AI agent

**Claude Code** — install the plugin:

```text
/plugin marketplace add vampirebeam/OpenComply
/plugin install opencomply@opencomply
```

Then just ask, e.g. *"Check the security headers of https://example.com"*, or run `/opencomply:security-headers`. On first use the agent asks before installing the CLI for you (the same way as the command below).

**Other agents that support Agent Skills** (e.g. Codex, Cursor, Gemini CLI) — use the skill folder [`plugins/opencomply/skills/security-headers`](plugins/opencomply/skills/security-headers) with that agent's skill install method.

### Install the CLI with one command

```bash
# Linux x86_64 / macOS Apple Silicon
curl -fsSL https://github.com/vampirebeam/OpenComply/releases/latest/download/install.sh | sh
```

```powershell
# Windows x86_64 (PowerShell)
irm https://github.com/vampirebeam/OpenComply/releases/latest/download/install.ps1 | iex
```

Then open a new terminal and run `opencomply`. The installer downloads the release for your operating system, checks its SHA-256 before installing, and needs no admin rights (Windows: `%LOCALAPPDATA%\opencomply\bin` on the user PATH · Linux / macOS: `~/.local/bin/opencomply`).

The SHA-256 check confirms the download matches the checksum published with the release; on its own it does not prove who published it. To read the installer before it runs, download it first: `curl -fsSLO …/install.sh` → read → `sh install.sh` · PowerShell: `irm …/install.ps1 -OutFile install.ps1` → read → `& ([scriptblock]::Create((Get-Content install.ps1 -Raw)))`.

Uninstall: `curl -fsSL …/install.sh | sh -s -- --uninstall` or `& ([scriptblock]::Create((irm …/install.ps1))) -Uninstall`

<details>
<summary>Download manually</summary>

Download a file from [Releases](https://github.com/vampirebeam/OpenComply/releases) and check it against the attached `.sha256`.

```bash
# Linux x86_64 / macOS Apple Silicon
sha256sum -c opencomply-v<version>-<target>.tar.gz.sha256      # macOS: shasum -a 256 -c …
tar -xzf opencomply-v<version>-<target>.tar.gz
./opencomply-v<version>-<target>/opencomply --version
```

```powershell
# Windows x86_64
Get-FileHash opencomply-v<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256   # compare with the .sha256 file
Expand-Archive opencomply-v<version>-x86_64-pc-windows-msvc.zip -DestinationPath .
.\opencomply-v<version>-x86_64-pc-windows-msvc\opencomply.exe --version
```

The binaries are not signed by Apple or Microsoft, so the operating system may show a warning on first run.

</details>

## Usage

```bash
opencomply scan headers https://example.com      # HTTP security headers
opencomply standards                             # supported standards, scanner and report schema versions
opencomply schema report                         # JSON Schema of the report
```

A headers check fetches 2 URLs: the page you give, and the `http://` version of the same URL to check HTTPS enforcement, following at most 5 redirects each. Every request is a GET with the User-Agent `OpenComply/<version>` and sends no cookies and no request body.

### Output formats and options

OpenComply supports several output formats, for developers and AI agents.

| Option | Description |
|---|---|
| *(none)* | Short summary that is easy to read, concise and uses few tokens |
| `--format json` | Export the results as JSON data for further processing |
| `--format markdown` | Markdown report with details and evidence |
| `--all` | Show every check, including those that passed |
| `--fail-on review` | Make items that still need review (`REVIEW`) fail the command too |
| `--allow-private` | Allow internal systems you are authorized to scan, such as staging (private IPs are refused by default; cloud metadata is always refused) |

**Examples**

Check security headers and show a summary:

```bash
opencomply scan headers https://example.com
```

Export the results as JSON:

```bash
opencomply scan headers https://example.com --format json
```

## Integrations

| Method | Use |
|---|---|
| **CLI** | Run `opencomply` from a terminal or script |
| **AI agent** | A Claude Code plugin or Agent Skill (Codex, Cursor, Gemini CLI) that teaches the agent to install the CLI, call it and explain the results by the same rules (see [Install](#install)) |

OpenComply is a CLI that AI agents can call, **not an AI model**, and no AI takes part in deciding results. OpenComply checks and reports; it never modifies source code. Whether recommendations are applied to code depends on the user and on the permissions of the connected AI agent.

An example of how an AI agent may summarize the same results shown below:

> **You:** Check the security headers of example.com.
>
> **AI:** **Grade D (63)**: 3 items to fix, 6 checks passed. The site runs **Next.js** behind **Cloudflare**.
>
> 🔴 **1. CSP allows inline scripts** · HDR-002 · high. Fixing only this raises the score to 89 (B), and A+ requires it.<br/>
> The recommended place is Next.js middleware, which creates a new nonce per request; a static Cloudflare Transform Rule cannot add a per-request nonce. Change only `script-src` and keep the existing hosts:
> ```
> script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
> ```
> This is a starting point, not a drop-in policy. Review the whole existing CSP, including third-party scripts and Next.js hydration, and test with `Content-Security-Policy-Report-Only` before enforcing.
>
> 🟠 **2. Permissions-Policy is missing** · HDR-005 · low. Fixing 1 and 2 gives **A+ (95)**.
>
> 🟠 **3. `X-Powered-By: Next.js`** · HDR-010 · low. Set `poweredByHeader: false` in `next.config.js`.

## Dynamic behavior: guidance for the actual environment

OpenComply reads evidence from the response and picks guidance that matches the detected stack.

| Detected | Effect on guidance |
|---|---|
| Platform from headers, cookies and HTML (53 platforms, e.g. Cloudflare, Vercel, nginx, IIS, WordPress, Laravel, Next.js) | Platform-specific fix (`how (…)`) and caveats (`note (…)`), up to 2 places |
| Several layers can fix it, e.g. Cloudflare + Next.js | Marks the place to fix first (`preferred`), e.g. nonces belong in the app, not the CDN |
| Current header values, e.g. the existing CSP | Builds `example:` from the site's own values: keeps existing hosts, removes only the unsafe parts, names the directive to change |
| Content-Type is not HTML (e.g. a JSON API) | Browser-only rules (CSP, Permissions-Policy, clickjacking) become `N/A` |
| `http://` behavior | Separates no redirect, temporary redirect (302/307) and permanent redirect (301/308) |

**Observed vs inferred:** header values that decide a result are `verified`; platforms are `inferred` and only select guidance — **they never change PASS / FAIL**.

## Example output

All three formats below are generated by the real renderer from one synthetic data set (example.com) — illustrative data, not a real scan of example.com.

<details>
<summary><strong>Summary</strong> (default)</summary>

```console
$ opencomply scan headers https://example.com/

headers https://example.com/ verdict=fail grade=D score=63 pass=6 fail=3 unknown=0 review=0 no_evidence=0 n/a=1 platform=cloudflare+nextjs
to C: HDR-002 +26 required → B 89
to A+: HDR-002 +26 required · HDR-005 +6 required → A+ 95
  impact (HDR-002): Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes
  impact of HDR-005: --all
FAIL HDR-002 high Content-Security-Policy
  why: script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run
  fix: enforce a CSP whose script-src allows no inline or wildcard scripts
  example: change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
  how (nextjs, preferred): middleware (proxy): create a nonce per request, set the CSP header and read it with headers() in the layout
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Set static: Content-Security-Policy
  note (cloudflare): A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker
FAIL HDR-005 low Permissions-Policy missing
  why: response has no permissions-policy header
  fix: send a Permissions-Policy that turns off features the site does not use
  example: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Set static: Permissions-Policy
  how (nextjs): next.config.js headers(): { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" }
FAIL HDR-010 low Technology disclosure
  why: x-powered-by tells attackers which software runs here
  fix: remove X-Powered-By and version numbers from Server and similar headers
  how (nextjs, preferred): next.config.js: poweredByHeader: false
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Remove: X-Powered-By
next: fix 3 · evidence: --format markdown
```

| Line | Meaning |
|---|---|
| First line | module · target · `verdict` · grade and score · count per status · detected platforms |
| `to …:` | Rules to fix for the target grade, points each adds (`required` = cannot be skipped), and `→` the actual result after fixing |
| `impact` | What fixing that rule changes (`--all` shows every step) |
| `FAIL` / `REVIEW` / `UNKNOWN` | Status · rule ID · severity · finding, most important first |
| `why:` · `fix:` · `example:` | Reason · action · example setting (replace anything in `<...>` and adapt it to your system) |
| `how (…)` / `note (…)` | Where to fix it on that platform, and caveats · `preferred` = recommended place |
| `decide:` | A decision for the user (only on `REVIEW` / `UNKNOWN`) |
| `next:` | What to do next |

</details>

<details>
<summary><strong>Evidence-based Assessment Report</strong> (<code>--format markdown</code>)</summary>

```markdown

# OpenComply report — headers

| | |
|---|---|
| Target | `https://example.com/` |
| Verdict | **FAIL** — fix 3 |
| Grade | **D** (63/100) |
| Results | 6 passed · 3 failed · 0 unknown · 0 needs review · 0 no evidence · 1 not applicable |
| Scanner | 0.2.3 · report schema 1 |
| Rule packs | opencomply-headers 1.0.0 (signed by opencomply-2026, sha256 `b256d2d6244f…`) |
| Platform | Cloudflare (CDN / WAF, from `cf-ray: 8f1c2a3b4d5e6f70-BKK`) · Next.js (framework / CMS, from `x-powered-by: Next.js`) — detected from response headers, used only for fix guidance |

## How to raise the grade

| Target | Check | Points | Required | Impact of passing it |
|---|---|---|---|---|
| C (→ B 89) | HDR-002 | +26 | yes | Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes |
| A+ (→ A+ 95) | HDR-002 | +26 | yes | Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes |
| A+ (→ A+ 95) | HDR-005 | +6 | yes | Features not listed (camera, location, payment) stop working, including in embedded frames |

## Needs action

| Rule | Version | Severity | Finding | Why | Evidence | Fix | Example | Where to fix |
|---|---|---|---|---|---|---|---|---|
| HDR-002 | 1.0.0 | high | Content-Security-Policy | script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run | GET https://example.com/ `content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; frame-ancestors 'self'` | CSP limits which scripts can run, so injected code (XSS) is blocked. Generate a new random nonce per response and put it on every &lt;script&gt;, or use hashes for fixed inline scripts. The example is a starting point, not a drop-in policy: review the whole existing CSP, check third-party scripts and framework hydration, roll out with Content-Security-Policy-Report-Only, fix what it reports, then enforce. | `change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com` | **nextjs, preferred:** middleware (proxy): create a nonce per request, set the CSP header and read it with headers() in the layout · **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Set static: Content-Security-Policy — ⚠ A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker |
| HDR-005 | 1.0.0 | low | Permissions-Policy missing | response has no permissions-policy header | GET https://example.com/ `(header not present)` | Permissions-Policy turns off browser features (camera, microphone, location, payment) the site does not use, so injected or embedded code cannot use them. List only features the site needs with (self). | `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` | **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Set static: Permissions-Policy · **nextjs:** next.config.js headers(): { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" } |
| HDR-010 | 1.0.0 | low | Technology disclosure | x-powered-by tells attackers which software runs here | GET https://example.com/ `x-powered-by: Next.js` | Version headers let attackers look up known vulnerabilities for your exact software without probing. Removing them is not a fix for outdated software, but it stops free reconnaissance. Keep the software updated as well. |  | **nextjs, preferred:** next.config.js: poweredByHeader: false · **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Remove: X-Powered-By |
```

</details>

<details>
<summary><strong>JSON</strong> (<code>--format json</code>)</summary>

A single line with `verdict`, `grade` and `summary` before `findings`. By default only items that need action are listed (`--all` lists everything).

```json

{"schema_version":1,"scanner_version":"0.2.3","module":"headers","target":"https://example.com/","rule_packs":[{"id":"opencomply-headers","version":"1.0.0","sha256":"b256d2d6244f568acd376cc1cd747b9a0728402d21e31836b0ee2c04bf9af605","signed_by":"opencomply-2026"}],"platforms":[{"id":"cloudflare","name":"Cloudflare","layer":"cdn","evidence":{"class":"inferred","source":"GET https://example.com/","detail":"cf-ray: 8f1c2a3b4d5e6f70-BKK"}},{"id":"nextjs","name":"Next.js","layer":"framework","evidence":{"class":"inferred","source":"GET https://example.com/","detail":"x-powered-by: Next.js"}}],"verdict":"fail","grade":{"grade":"D","score":63,"upgrades":[{"to":"C","steps":[{"rule_id":"HDR-002","points":26,"required":true,"impact":"Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes"}],"result":"B","result_score":89},{"to":"A+","steps":[{"rule_id":"HDR-002","points":26,"required":true,"impact":"Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes"},{"rule_id":"HDR-005","points":6,"required":true,"impact":"Features not listed (camera, location, payment) stop working, including in embedded frames"}],"result":"A+","result_score":95}]},"summary":{"pass":6,"fail":3,"unknown":0,"not_applicable":1,"needs_review":0,"insufficient_evidence":0},"findings":[{"rule_id":"HDR-002","rule_version":"1.0.0","title":"Content-Security-Policy","status":"fail","severity":"high","evidence":[{"class":"verified","source":"GET https://example.com/","detail":"content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; frame-ancestors 'self'"}],"reason":"script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run","fix_hint":"enforce a CSP whose script-src allows no inline or wildcard scripts","example_fix":"change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com","platform_fixes":[{"platform":"nextjs","how":"middleware (proxy): create a nonce per request, set the CSP header and read it with headers() in the layout","preferred":true},{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Set static: Content-Security-Policy","note":"A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker"}],"remediation":"CSP limits which scripts can run, so injected code (XSS) is blocked. Generate a new random nonce per response and put it on every <script>, or use hashes for fixed inline scripts. The example is a starting point, not a drop-in policy: review the whole existing CSP, check third-party scripts and framework hydration, roll out with Content-Security-Policy-Report-Only, fix what it reports, then enforce."},{"rule_id":"HDR-005","rule_version":"1.0.0","title":"Permissions-Policy missing","status":"fail","severity":"low","evidence":[{"class":"verified","source":"GET https://example.com/","detail":"(header not present)"}],"reason":"response has no permissions-policy header","fix_hint":"send a Permissions-Policy that turns off features the site does not use","example_fix":"Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()","platform_fixes":[{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Set static: Permissions-Policy"},{"platform":"nextjs","how":"next.config.js headers(): { key: \"Permissions-Policy\", value: \"camera=(), microphone=(), geolocation=()\" }"}],"remediation":"Permissions-Policy turns off browser features (camera, microphone, location, payment) the site does not use, so injected or embedded code cannot use them. List only features the site needs with (self)."},{"rule_id":"HDR-010","rule_version":"1.0.0","title":"Technology disclosure","status":"fail","severity":"low","evidence":[{"class":"verified","source":"GET https://example.com/","detail":"x-powered-by: Next.js"}],"reason":"x-powered-by tells attackers which software runs here","fix_hint":"remove X-Powered-By and version numbers from Server and similar headers","platform_fixes":[{"platform":"nextjs","how":"next.config.js: poweredByHeader: false","preferred":true},{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Remove: X-Powered-By"}],"remediation":"Version headers let attackers look up known vulnerabilities for your exact software without probing. Removing them is not a fix for outdated software, but it stops free reconnaissance. Keep the software updated as well."}]}
```

</details>

## Output contract

### Result statuses

| Summary | JSON `status` | Meaning | Counts as |
|---|---|---|---|
| `PASS` | `pass` | Meets the criterion | Pass |
| `FAIL` | `fail` | Does not meet the criterion; fix it | Fail |
| `REVIEW` | `needs_review` | Needs a user decision, e.g. a temporary redirect or a cookie JavaScript may need to read | Not passed |
| `UNKNOWN` | `unknown` | Could not be checked (e.g. an unreadable value) — **never treated as a pass** | Incomplete |
| `NO-EVIDENCE` | `insufficient_evidence` | Not enough evidence to conclude (does not occur in HTTP Security Headers) | Not passed |
| `N/A` | `not_applicable` | The rule does not apply to this target, e.g. no cookies or a JSON API | Excluded from the score |

`verdict` combines them into one word: `fail` (any FAIL) → `incomplete` (any UNKNOWN) → `review` (any REVIEW / NO-EVIDENCE) → `pass`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `pass` or `review` — `review` is **not** a pass, and returns 1 with `--fail-on review` |
| 1 | `fail` |
| 2 | Invalid usage, or a target that is not allowed (e.g. a private IP) |
| 3 | `incomplete`, or the check did not finish in time |
| 4 | Error, e.g. the target could not be reached |

Exit code 0 does not mean every rule passed: `review` also returns 0. If a program acts on the result, use `--fail-on review` or read `verdict` in the JSON report.

### JSON Schema and compatibility

- Report schema: `opencomply schema report` (or [`schemas/report.schema.json`](schemas/report.schema.json))
- `schema_version` increases on any change that is not backward compatible. New optional fields may be added without changing `schema_version`; consumers should ignore unknown fields.
- Before v1.0 the structure may still change, but every incompatible change bumps `schema_version`.

### Traceability

Every finding carries `rule_id`, `rule_version` and evidence (`evidence`: `source` + `detail`). The report carries `scanner_version` and the rule packs used (`id`, `version`, `sha256`, `signed_by`), so results from the same target and rule pack are reproducible and traceable.

## Scoring and grades

- **Score (0–100)** = weight of passing rules ÷ total weight of applicable rules (`PASS` counts fully, `REVIEW` half, `N/A` is excluded). Each rule's weight is defined in the rule pack. `REVIEW` counts half so an open decision weighs less than a failure — it is still not a pass.
- **Grade from score:** A+ 95–100 · A 90–94 · B 80–89 · C 70–79 · D 50–69 · F 0–49
- **Grade caps** (a high score cannot make up for a serious weakness):

| Condition | Effect |
|---|---|
| A mandatory rule fails (HSTS, CSP, clickjacking, HTTPS enforcement) | At most C |
| A high / critical rule fails | At most B |
| A mandatory rule is REVIEW, or a high / critical rule is undecided | No A+ |
| A mandatory rule is UNKNOWN | No grade (`N/A`) |

- **Path to a higher grade** (`to …:`) lists only the rules needed, largest gain first, and shows the actual result after fixing (`→`), which can exceed the target. In the example, fixing HDR-002 alone gives 89 (B); A+ needs HDR-002 and HDR-005 for 95, and HDR-010 is not needed for A+.

## Trust model

| Evidence class | Meaning |
|---|---|
| `verified` | A value read from the response and used to decide a result |
| `inferred` | Inferred information, e.g. the platform; only selects guidance and never decides a result |
| `manual_review` | Needs a person or expert to judge |

- Results come from comparing evidence with rules directly — no AI and no randomness — so the same evidence and rule pack give the same result (live results can differ if the site's responses change).
- Values that cannot be read or checked become `UNKNOWN`, and matters that need judgement become `REVIEW`; neither counts as `PASS`.
- Official rule packs are checked with an Ed25519 signature before loading; a modified file is not used.
- Known kinds of secrets in output (cookie values, tokens, passwords, keys) are redacted in every format.

## Extending OpenComply

Extensions to OpenComply are **data, not code**. No plugin that executes code is loaded into the scanner, which keeps results reproducible and reduces the plugin-related attack surface.

| Capability | Details |
|---|---|
| Rule pack format (TOML) and JSON Schema | `opencomply schema rule-pack` |
| Rule pack validation (schema, semantics, conflicts between packs, signature) | `opencomply rules validate <files…>` |
| Operators | An allowlist plus named built-in checks; no expressions or scripts |
| Rule pack used by `scan` | The official pack embedded in the binary, signature-checked before every use |
| New checks | Contributed to the main source code, see [CONTRIBUTING](CONTRIBUTING.md) |

## Privacy and security

| | |
|---|---|
| **No telemetry** | No usage data is collected, and no source code or results are sent back to the OpenComply developers |
| **Network** | Sends GET requests to the URL you give and to the `http://` version of the same URL, and follows redirects one hop at a time (plus DNS). Refuses private IPs and loopback on every hop (unless `--allow-private`) and cloud metadata always, guards against DNS rebinding, and bounds time and size on every request |
| **AI agents** | Output an AI agent reads is sent to that agent's model provider under the provider's policy, not to OpenComply |
| **Least privilege** | Runs with normal user rights; never modifies local files or code. Scans are real network requests (GET only); a badly designed site can still act on a GET, so only scan systems you are authorized to assess |

## Standards and criteria

OpenComply evaluates against its own versioned criteria, based on current browser behavior and security practice. Results and grades are OpenComply's own: they are not a certification against any standard, and they are not affiliated with, or equivalent to, any third-party rating service.

## Contributing

- [Contribution guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy and vulnerability reporting](SECURITY.md)

## Disclaimer and license

OpenComply is an independent assessment tool, **not a certification body**. Results are not a certification of compliance and do not guarantee security. Only scan systems you are authorized to assess.

Copyright 2026 vampirebeam · [Apache License 2.0](LICENSE) · [NOTICE](NOTICE)
