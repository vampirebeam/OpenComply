<p align="center"><img src="docs/assets/opencomply-hero.svg" alt="OpenComply — security and compliance scanner" width="960" /></p>

<p align="center"><a href="README.md">🇹🇭 ภาษาไทย</a> &nbsp;|&nbsp; <strong>🇬🇧 English</strong></p>

<h3 align="center">Security and compliance-readiness checks for your websites and code.<br/>OpenComply tells you what's missing, how to fix it and where, in a form both people and AI can read.</h3>

<p align="center">
  <img src="https://img.shields.io/badge/status-early_development-f59e0b?style=flat-square" alt="Status: early development" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-22c55e?style=flat-square" alt="Apache-2.0 License" /></a>
  <img src="https://img.shields.io/badge/rust-1.90-0891b2?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.90" />
  <img src="https://img.shields.io/badge/designed_for-Claude_Code_%7C_Codex_%7C_Cursor_%7C_Gemini_CLI-7C3AED?style=flat-square" alt="Designed for Claude Code, Codex, Cursor and Gemini CLI" />
</p>

> [!NOTE]
> OpenComply is in early development and has no release yet. The commands and output below show what it will ship with.

## What it checks

| Module | Checks | Result |
|---|---|---|
| **HTTP Security Headers** | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking protection, HTTPS enforcement, cookies, information disclosure | Grade A+ – F |
| **SSL/TLS** | Certificate, TLS 1.2/1.3, legacy protocols, cipher suites, key exchange, forward secrecy | Grade A+ – F |
| **ISO/IEC 27001:2022** | Repository evidence against ISMS requirements and controls | Readiness level 0–4 |
| **ISO/IEC 42001:2023** | Repository evidence against AI management system requirements and controls | Readiness level 0–4 |

Every result carries evidence, a rule ID and a rule version, so it can be traced back. OpenComply also identifies the platforms and technologies behind the system (for example Cloudflare, Vercel, nginx, WordPress and Next.js) so it can tell you **where** each fix belongs.

## Using it with an AI agent

Ask in plain language. The AI agent runs OpenComply and summarizes the results like this:

> **You:** Check the security headers of example.com.
>
> **AI:** Done. **Not passing yet: 2 items to fix and 1 decision for you.** The other 6 checks passed. The site is served through **Cloudflare**.
>
> 🟠 **1. Permissions-Policy is missing** · HDR-005 · low. *This is the easiest fix, so start here.*<br/>
> Set it in Cloudflare under **Rules → Transform Rules → Modify Response Header**:
> ```
> Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
> ```
>
> 🔴 **2. CSP allows inline scripts** · HDR-002 · medium<br/>
> If the site has an XSS flaw, injected scripts would run immediately. Use a nonce instead of `'unsafe-inline'`. **This must be fixed in the application, not in Cloudflare**: Cloudflare can only set static values, and a nonce must be new for every response.
> ```
> script-src 'self' 'nonce-<per-response-random>'
> ```
> This is an example. Changing this one value does not make the CSP secure on its own: review the other directives too, and test with `Content-Security-Policy-Report-Only` before enforcing to confirm the application still works. Would you like me to review the code and draft the change?
>
> 🟡 **For your decision: the `Server: cloudflare` header** · HDR-010<br/>
> Cloudflare sets this header and it shows no version, so the risk is generally low. Is this acceptable?

The AI states the overall result first, explains it in clear and simple language, says where each fix belongs, cites the rule ID and **asks you** about anything that needs a decision. Pass and fail always come from OpenComply, and the AI changes code only with your approval.

<details>
<summary><strong>Raw output the AI reads</strong> (<code>opencomply scan headers …</code>)</summary>

```console
$ opencomply scan headers https://example.com
headers https://example.com verdict=fail pass=6 fail=2 unknown=0 review=1 no_evidence=0 n/a=1 platform=cloudflare
FAIL HDR-002 medium CSP allows inline scripts
  why: script-src contains 'unsafe-inline', so any injected inline script runs
  fix: replace 'unsafe-inline' in script-src with a per-response nonce
  example: script-src 'self' 'nonce-<per-response-random>'
  how (cloudflare): set the CSP in the application (origin), not in Cloudflare
  note (cloudflare): Transform Rules only set static values; per-request nonces need the app or a Worker
FAIL HDR-005 low Permissions-Policy missing
  why: response has no Permissions-Policy header
  fix: add a Permissions-Policy that disables unused features
  example: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Set static header
REVIEW HDR-010 info Hosting platform disclosed
  why: header is set by the hosting platform, not by the site
  decide: is revealing the hosting platform acceptable for this site?
next: fix 2, decide 1 · evidence: --format markdown
```

| Line | Meaning |
|---|---|
| First line | Overall result (`verdict`: `pass` · `review` · `incomplete` · `fail`), the count for each status, and the detected platforms |
| `FAIL` / `REVIEW` | Rule ID · severity · what was found, most important first |
| `why:` | What is missing, or why this result was given |
| `fix:` | What to do |
| `example:` | An **example** setting. Adapt it to your system before use, and always replace anything in `<...>` |
| `how (…)` / `note (…)` | Where to fix it on that platform, and any caveats |
| `decide:` | A question **you** need to decide |
| `next:` | Next steps |

</details>

<details>
<summary><strong>Audit report</strong> (<code>--format markdown</code>)</summary>

```markdown
# OpenComply report — headers

| | |
|---|---|
| Target | `https://example.com` |
| Verdict | **FAIL** — fix 2, decide 1 |
| Results | 6 passed · 2 failed · 0 unknown · 1 needs review · 0 no evidence · 1 not applicable |
| Scanner | 0.1.0 · report schema 1 |
| Platform | Cloudflare (CDN / WAF, from `CF-RAY: 8f1c2a3b4d5e6f70-BKK`) — detected from response headers, used only for fix guidance |

## Needs action

| Rule | Version | Severity | Finding | Why | Evidence | Fix | Example | Where to fix |
|---|---|---|---|---|---|---|---|---|
| HDR-002 | 1.0.0 | medium | CSP allows inline scripts | script-src contains 'unsafe-inline', so any injected inline script runs | GET https://example.com `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'` | Generate a new random nonce for every response, add it to script-src and to each inline script, then remove 'unsafe-inline'. Review the other directives and test in Content-Security-Policy-Report-Only mode before enforcing. | `script-src 'self' 'nonce-<per-response-random>'` | **cloudflare:** set the CSP in the application (origin), not in Cloudflare — ⚠ Transform Rules only set static values; per-request nonces need the app or a Worker |
| HDR-005 | 1.0.0 | low | Permissions-Policy missing | response has no Permissions-Policy header | GET https://example.com `(header not present)` | Disable every browser feature the site does not use; keep (self) only for features it needs. | `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()` | **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Set static header |

## Needs your review

### HDR-010 · Hosting platform disclosed

- **Status:** REVIEW · severity info · rule version 1.0.0
- **Why:** header is set by the hosting platform, not by the site
- **Evidence (verified):** GET https://example.com — `Server: cloudflare`
- **Decide:** is revealing the hosting platform acceptable for this site?
- **Guidance:** Usually low risk when no version is shown. Accept and document it.
```

</details>

<details>
<summary><strong>JSON for AI agents and CI</strong> (<code>--format json</code>)</summary>

A single line with the summary before the findings, so an agent can read the result from the start of the output. By default only items that need action are listed (here: 2 failures and 1 review item); add `--all` to include passing checks. The full structure is defined by the JSON Schema.

```json
{"schema_version":1,"scanner_version":"0.1.0","module":"headers","target":"https://example.com","platforms":[{"id":"cloudflare","name":"Cloudflare","layer":"cdn","evidence":{"class":"inferred","source":"GET https://example.com","detail":"CF-RAY: 8f1c2a3b4d5e6f70-BKK"}}],"verdict":"fail","summary":{"pass":6,"fail":2,"unknown":0,"not_applicable":1,"needs_review":1,"insufficient_evidence":0},"findings":[{"rule_id":"HDR-002","rule_version":"1.0.0","title":"CSP allows inline scripts","status":"fail","severity":"medium","evidence":[{"class":"verified","source":"GET https://example.com","detail":"Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'"}],"reason":"script-src contains 'unsafe-inline', so any injected inline script runs","fix_hint":"replace 'unsafe-inline' in script-src with a per-response nonce","example_fix":"script-src 'self' 'nonce-<per-response-random>'","platform_fixes":[{"platform":"cloudflare","how":"set the CSP in the application (origin), not in Cloudflare","note":"Transform Rules only set static values; per-request nonces need the app or a Worker"}],"remediation":"Generate a new random nonce for every response, add it to script-src and to each inline script, then remove 'unsafe-inline'. Review the other directives and test in Content-Security-Policy-Report-Only mode before enforcing."},{"rule_id":"HDR-005","rule_version":"1.0.0","title":"Permissions-Policy missing","status":"fail","severity":"low","evidence":[{"class":"verified","source":"GET https://example.com","detail":"(header not present)"}],"reason":"response has no Permissions-Policy header","fix_hint":"add a Permissions-Policy that disables unused features","example_fix":"Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()","platform_fixes":[{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Set static header"}],"remediation":"Disable every browser feature the site does not use; keep (self) only for features it needs."},{"rule_id":"HDR-010","rule_version":"1.0.0","title":"Hosting platform disclosed","status":"needs_review","severity":"info","evidence":[{"class":"verified","source":"GET https://example.com","detail":"Server: cloudflare"}],"reason":"header is set by the hosting platform, not by the site","review_question":"is revealing the hosting platform acceptable for this site?","remediation":"Usually low risk when no version is shown. Accept and document it."}]}
```

</details>

## Get started

```bash
opencomply scan headers https://example.com      # HTTP security headers
opencomply scan tls https://example.com          # SSL/TLS
opencomply scan iso27001 ./my-repo               # ISO/IEC 27001 readiness
opencomply scan iso42001 ./my-repo               # ISO/IEC 42001 readiness
opencomply standards                             # supported standards and versions
```

| Option | Use |
|---|---|
| *(none)* | Short summary that is easy to read and uses few tokens |
| `--format json` | For AI agents, CI and other tools |
| `--format markdown` | Audit report with evidence |
| `--all` | Also show checks that passed |
| `--fail-on review` | For CI: treat undecided items as failures |

> [!IMPORTANT]
> **CI usage:** if every item must be decided before a merge or deploy, you **must use `--fail-on review`**. By default the exit code is 0 when only items for review remain.
>
> ```bash
> opencomply scan headers https://example.com --format json --fail-on review
> ```

<details>
<summary><strong>Exit codes</strong></summary>

| Code | Meaning |
|---|---|
| 0 | Passed, or only items for review remain (`verdict=review`), which is **not** a pass. With `--fail-on review` this case returns 1 instead |
| 1 | Items need fixing |
| 2 | Invalid usage |
| 3 | Assessment incomplete |
| 4 | Error |

</details>

## Privacy and security

| | |
|---|---|
| **No telemetry** | No usage data is collected, and no source code or results are sent back to the OpenComply developers |
| **Network** | Website and TLS checks connect only to the target you specify (plus DNS). Repository checks use no network |
| **AI agents** | Output an AI agent reads is sent to that agent's model provider under the provider's policy, not to OpenComply |
| **Least privilege** | Runs with normal user rights, reads only, and treats rules as data that can never execute code |

## Standards and criteria

OpenComply evaluates against internationally recognized standards and current security practice, consolidated into its own versioned criteria.

- **Technical checks:** grades come from weighted checks. Critical weaknesses cap the highest grade, and an incomplete assessment cannot receive the top grade.
- **ISO readiness:** evidence is assessed against requirements and controls. Technical and organizational evidence are kept separate, and items that need expert judgement are identified.

Grades and readiness levels are OpenComply's own criteria. They are not affiliated with, or equivalent to, any third-party rating service.

### Limits of ISO assessment

Scanning a repository alone **cannot prove that an information security management system (ISMS) or an AI management system (AIMS) is complete**. Many requirements depend on policy documents, processes, interviews and evidence of real operation. OpenComply marks these items as needing expert review or as having insufficient evidence instead of concluding on them, and its results are for readiness preparation only.

## Contributing

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy and vulnerability reporting](SECURITY.md)
- Contribution guidelines (CONTRIBUTING) will be published with the first release

## Disclaimer and license

OpenComply is an independent assessment tool, **not an ISO certification body**. Results are not a certification of compliance and do not guarantee security. Only scan systems you are authorized to assess.

Copyright 2026 vampirebeam · [Apache License 2.0](LICENSE) · [NOTICE](NOTICE)
