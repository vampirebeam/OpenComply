<p align="center"><img src="docs/assets/opencomply-hero.svg" alt="OpenComply — security and compliance scanner" width="960" /></p>

<p align="center"><strong>🇹🇭 ภาษาไทย</strong> &nbsp;|&nbsp; <a href="README.en.md">🇬🇧 English</a></p>

<h3 align="center">เครื่องมือตรวจสอบความปลอดภัยของเว็บไซต์<br/>ระบุสิ่งที่ขาด วิธีแก้ไข และตำแหน่งที่ต้องแก้ไข ในรูปแบบที่ทั้งนักพัฒนาและ AI agent นำไปใช้ต่อได้</h3>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.0-f59e0b?style=flat-square" alt="Version 0.3.0" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-22c55e?style=flat-square" alt="Apache-2.0 License" /></a>
  <img src="https://img.shields.io/badge/rust-1.90-0891b2?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.90" />
  <img src="https://img.shields.io/badge/works_with-Claude_Code_%7C_Codex_%7C_Cursor_%7C_Gemini_CLI-7C3AED?style=flat-square" alt="Works with Claude Code, Codex, Cursor and Gemini CLI" />
</p>

## ภาพรวม

OpenComply เป็น **CLI engine ตัวเดียว** ที่ตรวจสอบตาม rule ที่กำหนดเวอร์ชันและมีลายเซ็นกำกับ แล้วส่งผลเป็น output ที่มีโครงสร้างชัดเจน ผลผ่านหรือไม่ผ่านมาจาก engine เท่านั้น ส่วนผู้ใช้หรือ AI agent เป็นผู้เรียกใช้และนำผลไปดำเนินการต่อ

| Module | รายการที่ตรวจสอบ | ผลลัพธ์ |
|---|---|---|
| **HTTP Security Headers** | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking, HTTPS enforcement, cookie และการเปิดเผยข้อมูลระบบ | เกรด A+ – F พร้อมคะแนน 0–100 |

## การติดตั้ง

### ใช้กับ AI agent

**Claude Code** — ติดตั้ง plugin:

```text
/plugin marketplace add vampirebeam/OpenComply
/plugin install opencomply@opencomply
```

จากนั้นสั่งได้ทันที เช่น *"ตรวจ security headers ของ https://example.com"* หรือเรียก `/opencomply:security-headers` ครั้งแรกที่ใช้ agent จะขออนุญาตติดตั้ง CLI ให้ (แบบเดียวกับคำสั่งด้านล่าง)

**Agent อื่นที่รองรับ Agent Skills** (เช่น Codex, Cursor, Gemini CLI) — ใช้โฟลเดอร์ skill [`plugins/opencomply/skills/security-headers`](plugins/opencomply/skills/security-headers) ตามวิธีติดตั้ง skill ของ agent นั้น

### ติดตั้ง CLI ด้วยคำสั่งเดียว

```bash
# Linux x86_64 / macOS Apple Silicon
curl -fsSL https://github.com/vampirebeam/OpenComply/releases/latest/download/install.sh | sh
```

```powershell
# Windows x86_64 (PowerShell)
irm https://github.com/vampirebeam/OpenComply/releases/latest/download/install.ps1 | iex
```

จากนั้นเปิด terminal ใหม่ แล้วใช้ `opencomply` ได้เลย ตัวติดตั้งดาวน์โหลด release ที่ตรงกับระบบปฏิบัติการ ตรวจ SHA-256 ก่อนติดตั้ง และไม่ต้องใช้สิทธิ์ admin (Windows: `%LOCALAPPDATA%\opencomply\bin` ใน PATH ของผู้ใช้ · Linux / macOS: `~/.local/bin/opencomply`)

การตรวจ SHA-256 ยืนยันว่าไฟล์ที่ดาวน์โหลดตรงกับ checksum ที่เผยแพร่พร้อม release แต่ลำพังตัวเองไม่ได้ยืนยันว่าใครเป็นผู้เผยแพร่ หากต้องการอ่านตัวติดตั้งก่อนรัน ให้ดาวน์โหลดก่อน: `curl -fsSLO …/install.sh` → อ่าน → `sh install.sh` · PowerShell: `irm …/install.ps1 -OutFile install.ps1` → อ่าน → `& ([scriptblock]::Create((Get-Content install.ps1 -Raw)))`

ถอนการติดตั้ง: `curl -fsSL …/install.sh | sh -s -- --uninstall` หรือ `& ([scriptblock]::Create((irm …/install.ps1))) -Uninstall`

<details>
<summary>ดาวน์โหลดเอง</summary>

ดาวน์โหลดไฟล์จาก [Releases](https://github.com/vampirebeam/OpenComply/releases) และตรวจกับไฟล์ `.sha256` ที่แนบมา

```bash
# Linux x86_64 / macOS Apple Silicon
sha256sum -c opencomply-v<version>-<target>.tar.gz.sha256      # macOS: shasum -a 256 -c …
tar -xzf opencomply-v<version>-<target>.tar.gz
./opencomply-v<version>-<target>/opencomply --version
```

```powershell
# Windows x86_64
Get-FileHash opencomply-v<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256   # เทียบกับไฟล์ .sha256
Expand-Archive opencomply-v<version>-x86_64-pc-windows-msvc.zip -DestinationPath .
.\opencomply-v<version>-x86_64-pc-windows-msvc\opencomply.exe --version
```

Binary ไม่มีการลงนามของ Apple / Microsoft ระบบปฏิบัติการอาจแสดงคำเตือนเมื่อเปิดครั้งแรก

</details>

## การใช้งาน

```bash
opencomply scan headers https://example.com      # ตรวจสอบ HTTP security headers
opencomply standards                             # มาตรฐานที่รองรับ เวอร์ชันของ scanner และ report schema
opencomply schema report                         # JSON Schema ของ report
```

การตรวจ HTTP Security Headers ขอข้อมูลจาก 2 URL คือหน้าเว็บที่ระบุ และ `http://` ของ URL เดียวกันเพื่อตรวจ HTTPS enforcement โดยตาม redirect ได้ไม่เกิน 5 ครั้งต่อ URL ทุกคำขอใช้ GET ระบุ User-Agent `OpenComply/<version>` และไม่ส่ง cookie หรือ request body

### รูปแบบการแสดงผลและตัวเลือก

OpenComply รองรับการแสดงผลหลายรูปแบบ เพื่อให้เหมาะกับการใช้งานทั้งโดยนักพัฒนาและ AI agent

| Option | คำอธิบาย |
|---|---|
| *(ไม่ระบุ)* | แสดงผลสรุปแบบอ่านง่าย กระชับ และประหยัด Token |
| `--format json` | ส่งออกผลการตรวจสอบเป็นข้อมูล JSON สำหรับนำไปประมวลผลต่อ |
| `--format markdown` | สร้างรายงาน Markdown พร้อมรายละเอียดและหลักฐานการตรวจสอบ |
| `--all` | แสดงผลการตรวจสอบทั้งหมด รวมถึงรายการที่ผ่านเกณฑ์ |
| `--compact` | ใช้กับ `--format json`: ตัดคำอธิบายยาวและหลักฐานของรายการที่ผ่านออก (ประหยัด Token) |
| `--fail-on review` | กำหนดให้รายการที่ต้องตรวจสอบเพิ่มเติม (`REVIEW`) ส่งผลให้คำสั่งไม่สำเร็จด้วย |
| `--allow-private` | อนุญาตให้ตรวจระบบภายในที่ได้รับอนุญาต เช่น staging (ค่าเริ่มต้นปฏิเสธ IP ภายใน ส่วน cloud metadata ปฏิเสธเสมอ) |

**ตัวอย่างการใช้งาน**

ตรวจสอบ Security Headers และแสดงผลสรุป:

```bash
opencomply scan headers https://example.com
```

ส่งออกผลการตรวจสอบเป็น JSON:

```bash
opencomply scan headers https://example.com --format json
```

## การเชื่อมต่อ (Integrations)

| วิธี | การใช้งาน |
|---|---|
| **CLI** | เรียก `opencomply` จาก terminal หรือ script โดยตรง |
| **AI agent** | Claude Code plugin หรือ Agent Skill (Codex, Cursor, Gemini CLI) ที่สอนให้ agent ติดตั้ง เรียก CLI และอธิบายผลตามกฎเดียวกัน (ดู[การติดตั้ง](#การติดตั้ง)) |

OpenComply เป็น CLI ที่ AI agent เรียกใช้ได้ **ไม่ใช่ AI model** และไม่มี AI อยู่ในการตัดสินผล OpenComply ทำหน้าที่ตรวจสอบและรายงานผล โดยไม่แก้ไข Source Code อัตโนมัติ การนำคำแนะนำไปแก้ไขโค้ดขึ้นอยู่กับผู้ใช้และการกำหนดสิทธิ์ของ AI Agent ที่เชื่อมต่อ

ตัวอย่างการสรุปผลของ AI agent จากผลลัพธ์ชุดเดียวกับตัวอย่างด้านล่าง:

> **ผู้ใช้:** ช่วยตรวจสอบ security headers ของ example.com
>
> **AI:** ได้**เกรด D (63 คะแนน)** ต้องแก้ไข 3 รายการ อีก 6 รายการผ่านเกณฑ์ เว็บไซต์ใช้ **Next.js** ผ่าน **Cloudflare**
>
> 🔴 **1. CSP อนุญาต inline script** · HDR-002 · high — แก้ข้อนี้ข้อเดียวคะแนนจะเป็น 89 (เกรด B) และเป็นเงื่อนไขบังคับของ A+<br/>
> ตำแหน่งที่แนะนำคือ Next.js middleware ซึ่งสร้าง nonce ใหม่ทุก request เพราะ Transform Rule แบบค่าคงที่ของ Cloudflare ใส่ nonce ต่อ request ไม่ได้ แก้เฉพาะ `script-src` และคง host เดิมไว้:
> ```
> script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
> ```
> ค่านี้เป็นจุดเริ่มต้น ไม่ใช่ policy ที่นำไปวางแล้วปลอดภัยทันที ต้องตรวจ CSP เดิมทั้งชุด รวมถึง third-party script และ hydration ของ Next.js และทดสอบด้วย `Content-Security-Policy-Report-Only` ก่อนบังคับใช้
>
> 🟠 **2. ไม่พบ Permissions-Policy** · HDR-005 · low — แก้ข้อ 1 และข้อนี้แล้วจะได้ **A+ (95)**
>
> 🟠 **3. `X-Powered-By: Next.js`** · HDR-010 · low — กำหนด `poweredByHeader: false` ใน `next.config.js`

## Dynamic behavior: คำแนะนำตาม environment จริง

OpenComply อ่านหลักฐานจาก response แล้วเลือกคำแนะนำให้ตรงกับระบบที่ตรวจพบ

| สิ่งที่ตรวจพบ | ผลต่อคำแนะนำ |
|---|---|
| Platform จาก header, cookie และ HTML (54 ระบบ เช่น Cloudflare, Vercel, nginx, IIS, WordPress, Laravel, Next.js) | แสดงวิธีแก้เฉพาะ platform นั้น (`how (…)`) และข้อจำกัด (`note (…)`) ปกติสูงสุด 2 ตำแหน่ง ถ้าข้อมูลที่รั่วมาจากหลายซอฟต์แวร์ ทุกตัวจะได้วิธีแก้ของตัวเอง |
| หลายชั้นแก้ได้ เช่น Cloudflare + Next.js | ระบุตำแหน่งที่ควรแก้ก่อน (`preferred`) เช่น nonce ต้องสร้างที่ app ไม่ใช่ CDN |
| ค่าปัจจุบันของ header เช่น CSP เดิม | สร้าง `example:` จากค่าจริงของเว็บ คง host เดิม ลบเฉพาะส่วนที่ไม่ปลอดภัย และระบุ directive ที่ต้องเปลี่ยน |
| Content-Type ไม่ใช่ HTML (เช่น JSON API) | rule ที่ใช้เฉพาะ browser (CSP, Permissions-Policy, clickjacking) เป็น `N/A` |
| พฤติกรรมของ `http://` | แยกกรณีไม่ redirect, redirect ชั่วคราว (302/307) และ redirect ถาวร (301/308) |
| การแก้ที่ต้องทำตามลำดับ หรือตั้งค่าที่เดียวกัน | เรียงตามลำดับที่ต้องทำ (`after:`) ระบุแรงที่มักต้องใช้ (`quick` · `moderate` · `involved`) และจัดกลุ่มไว้ด้วยกัน (`together`) |

**แยกสิ่งที่ตรวจพบจริงออกจากสิ่งที่อนุมาน:** ค่าของ header ที่ใช้ตัดสินผลเป็น `verified` ส่วน platform เป็น `inferred` และใช้เพื่อเลือกคำแนะนำเท่านั้น **ไม่มีผลต่อ PASS / FAIL**

## ตัวอย่างผลลัพธ์

ตัวอย่างทั้ง 3 รูปแบบสร้างจาก renderer จริงด้วยข้อมูลสมมติชุดเดียวกัน (example.com) — เป็นข้อมูลตัวอย่าง ไม่ใช่ผลสแกน example.com จริง

<details>
<summary><strong>Summary</strong> (ค่าเริ่มต้น)</summary>

```console
$ opencomply scan headers https://example.com/

headers https://example.com/ verdict=fail grade=D score=63 pass=6 fail=3 unknown=0 review=0 no_evidence=0 n/a=1 advice=1 platform=cloudflare+nextjs
to C: HDR-002 +26 required → B 89
to A+: HDR-002 +26 required · HDR-005 +6 required → A+ 95
  impact (HDR-002): Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes
  impact of HDR-005: --all
FAIL HDR-002 high Content-Security-Policy · involved
  why: script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run
  fix: enforce a CSP whose script-src allows no inline or wildcard scripts
  example: change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
  how (nextjs, preferred): middleware (proxy): create a nonce per request, set the CSP header and read it with headers() in the layout
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Set static: Content-Security-Policy
  note (cloudflare): A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker
FAIL HDR-005 low Permissions-Policy missing · quick
  why: response has no permissions-policy header
  fix: send a Permissions-Policy that turns off features the site does not use
  example: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Set static: Permissions-Policy
  how (nextjs): next.config.js headers(): { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" }
FAIL HDR-010 low Technology disclosure · quick
  why: x-powered-by tells attackers which software runs here
  fix: remove X-Powered-By, version numbers and internal host names from headers and meta generator
  how (nextjs, preferred): next.config.js: poweredByHeader: false
  how (cloudflare): Rules > Transform Rules > Modify Response Header > Remove: X-Powered-By
PASS HDR-001 high Strict-Transport-Security
  advice: add includeSubDomains once every subdomain serves HTTPS, so subdomains are protected too
  example: Strict-Transport-Security: max-age=31536000; includeSubDomains
next: fix 3 · advice 1 (optional) · evidence: --format markdown
```

| บรรทัด | ความหมาย |
|---|---|
| บรรทัดแรก | module · target · `verdict` · เกรดและคะแนน · จำนวนในแต่ละสถานะ · `advice=N` เมื่อมีคำแนะนำเพิ่มเติม · platform ที่ตรวจพบ |
| `to …:` | rule ที่ต้องแก้เพื่อให้ได้เกรดเป้าหมาย คะแนนที่เพิ่ม (`required` = ขาดไม่ได้) และ `→` ผลที่จะได้จริงหลังแก้ |
| `impact` | ผลกระทบของการแก้ rule นั้น (`--all` แสดงครบทุกขั้น) |
| `FAIL` / `REVIEW` / `UNKNOWN` | สถานะ · rule ID · severity · สิ่งที่ตรวจพบ · แรงที่มักต้องใช้ เรียงตามลำดับที่ควรทำ |
| `after:` | ต้องแก้ rule เหล่านี้ก่อน เช่น HSTS หลังตั้ง redirect จาก `http://` |
| `why:` · `fix:` · `example:` | เหตุผล · สิ่งที่ต้องทำ · ตัวอย่างการตั้งค่า (ต้องแทนค่าใน `<...>` และปรับให้เข้ากับระบบจริง) |
| `how (…)` / `note (…)` | ตำแหน่งที่แก้ไขบน platform นั้น และข้อจำกัด · `preferred` = ตำแหน่งที่แนะนำ |
| `decide:` | ประเด็นที่ผู้ใช้ต้องตัดสินใจ (เฉพาะ `REVIEW` / `UNKNOWN`) |
| `PASS` + `advice:` | ผ่านแล้ว เป็นคำแนะนำเพิ่มเติมที่ไม่บังคับ ไม่มีผลต่อ verdict และเกรด |
| `together (…)` | rule ที่ตั้งค่าที่เดียวกัน แก้ครั้งเดียวได้ทั้งกลุ่ม |
| `next:` | สรุปสิ่งที่ต้องทำต่อ |

</details>

<details>
<summary><strong>รายงานผลการตรวจสอบพร้อมหลักฐาน</strong> (<code>--format markdown</code>)</summary>

```markdown

# OpenComply report — headers

| | |
|---|---|
| Target | `https://example.com/` |
| Verdict | **FAIL** — fix 3 · advice 1 (optional) |
| Grade | **D** (63/100) |
| Results | 6 passed · 3 failed · 0 unknown · 0 needs review · 0 no evidence · 1 not applicable · 1 with advice |
| Scanner | 0.3.0 · report schema 1 |
| Rule packs | opencomply-headers 1.1.0 (signed by opencomply-2026, sha256 `321106287793…`) |
| Platform | Cloudflare (CDN / WAF, from `cf-ray: 8f1c2a3b4d5e6f70-BKK`) · Next.js (framework / CMS, from `x-powered-by: Next.js`) — detected from response headers, used only for fix guidance |

## How to raise the grade

| Target | Check | Points | Required | Impact of passing it |
|---|---|---|---|---|
| C (→ B 89) | HDR-002 | +26 | yes | Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes |
| A+ (→ A+ 95) | HDR-002 | +26 | yes | Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes |
| A+ (→ A+ 95) | HDR-005 | +6 | yes | Features not listed (camera, location, payment) stop working, including in embedded frames |

## Needs action

| Rule | Version | Severity | Effort | Finding | Why | Evidence | Fix | Example | Where to fix |
|---|---|---|---|---|---|---|---|---|---|
| HDR-002 | 1.1.0 | high | involved | Content-Security-Policy | script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run | GET https://example.com/ `content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; frame-ancestors 'self'` | CSP limits which scripts can run, which reduces what injected code (XSS) can do. Generate a new random nonce per response and put it on every &lt;script&gt;, or use hashes for fixed inline scripts. With nonces, also set base-uri 'self' so an injected &lt;base&gt; tag cannot send the page's own scripts to another site. The example is a starting point, not a drop-in policy: review the whole existing CSP, check third-party scripts and framework hydration, roll out with Content-Security-Policy-Report-Only, fix what it reports, then enforce. | `change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com` | **nextjs, preferred:** middleware (proxy): create a nonce per request, set the CSP header and read it with headers() in the layout · **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Set static: Content-Security-Policy — ⚠ A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker |
| HDR-005 | 1.1.0 | low | quick | Permissions-Policy missing | response has no permissions-policy header | GET https://example.com/ `(header not present)` | Permissions-Policy turns off browser features (camera, microphone, location, payment) the site does not use, so injected or embedded code cannot use them. List only features the site needs with (self). | `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` | **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Set static: Permissions-Policy · **nextjs:** next.config.js headers(): { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" } |
| HDR-010 | 1.1.0 | low | quick | Technology disclosure | x-powered-by tells attackers which software runs here | GET https://example.com/ `x-powered-by: Next.js` | Version headers let attackers look up known vulnerabilities for your exact software without probing. Removing them is not a fix for outdated software, but it stops free reconnaissance. Keep the software updated as well. The same applies to a &lt;meta name="generator"&gt; tag with a version, and to internal server names in X-Backend-Server or Server-Timing. |  | **nextjs, preferred:** next.config.js: poweredByHeader: false · **cloudflare:** Rules &gt; Transform Rules &gt; Modify Response Header &gt; Remove: X-Powered-By |

## Advice (optional — already passed)

| Rule | Check | Advice | Example |
|---|---|---|---|
| HDR-001 | Strict-Transport-Security | add includeSubDomains once every subdomain serves HTTPS, so subdomains are protected too | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
```

</details>

<details>
<summary><strong>JSON</strong> (<code>--format json</code>)</summary>

ข้อมูลอยู่ในบรรทัดเดียว เรียง `verdict`, `grade` และ `summary` ไว้ก่อน `findings` ค่าเริ่มต้นแสดงเฉพาะรายการที่ต้องดำเนินการ (`--all` แสดงทั้งหมด)

```json

{"schema_version":1,"scanner_version":"0.3.0","module":"headers","target":"https://example.com/","rule_packs":[{"id":"opencomply-headers","version":"1.1.0","sha256":"321106287793747f7f1909f0fb58a8f536d0796a7d455e75cb008fcd8f17107c","signed_by":"opencomply-2026"}],"platforms":[{"id":"cloudflare","name":"Cloudflare","layer":"cdn","evidence":{"class":"inferred","source":"GET https://example.com/","detail":"cf-ray: 8f1c2a3b4d5e6f70-BKK"}},{"id":"nextjs","name":"Next.js","layer":"framework","evidence":{"class":"inferred","source":"GET https://example.com/","detail":"x-powered-by: Next.js"}}],"verdict":"fail","grade":{"grade":"D","score":63,"upgrades":[{"to":"C","steps":[{"rule_id":"HDR-002","points":26,"required":true,"impact":"Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes"}],"result":"B","result_score":89},{"to":"A+","steps":[{"rule_id":"HDR-002","points":26,"required":true,"impact":"Nonces need each response rendered per request (server or edge); fully static pages must use hashes, and inline or third-party scripts may need changes"},{"rule_id":"HDR-005","points":6,"required":true,"impact":"Features not listed (camera, location, payment) stop working, including in embedded frames"}],"result":"A+","result_score":95}]},"summary":{"pass":6,"fail":3,"unknown":0,"not_applicable":1,"needs_review":0,"insufficient_evidence":0,"advice":1},"findings":[{"rule_id":"HDR-002","rule_version":"1.1.0","title":"Content-Security-Policy","status":"fail","severity":"high","evidence":[{"class":"verified","source":"GET https://example.com/","detail":"content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; frame-ancestors 'self'"}],"reason":"script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run","fix_hint":"enforce a CSP whose script-src allows no inline or wildcard scripts","example_fix":"change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com","platform_fixes":[{"platform":"nextjs","how":"middleware (proxy): create a nonce per request, set the CSP header and read it with headers() in the layout","preferred":true},{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Set static: Content-Security-Policy","note":"A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker"}],"remediation":"CSP limits which scripts can run, which reduces what injected code (XSS) can do. Generate a new random nonce per response and put it on every <script>, or use hashes for fixed inline scripts. With nonces, also set base-uri 'self' so an injected <base> tag cannot send the page's own scripts to another site. The example is a starting point, not a drop-in policy: review the whole existing CSP, check third-party scripts and framework hydration, roll out with Content-Security-Policy-Report-Only, fix what it reports, then enforce.","effort":"involved"},{"rule_id":"HDR-005","rule_version":"1.1.0","title":"Permissions-Policy missing","status":"fail","severity":"low","evidence":[{"class":"verified","source":"GET https://example.com/","detail":"(header not present)"}],"reason":"response has no permissions-policy header","fix_hint":"send a Permissions-Policy that turns off features the site does not use","example_fix":"Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()","platform_fixes":[{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Set static: Permissions-Policy"},{"platform":"nextjs","how":"next.config.js headers(): { key: \"Permissions-Policy\", value: \"camera=(), microphone=(), geolocation=()\" }"}],"remediation":"Permissions-Policy turns off browser features (camera, microphone, location, payment) the site does not use, so injected or embedded code cannot use them. List only features the site needs with (self).","effort":"quick","group":"response-headers"},{"rule_id":"HDR-010","rule_version":"1.1.0","title":"Technology disclosure","status":"fail","severity":"low","evidence":[{"class":"verified","source":"GET https://example.com/","detail":"x-powered-by: Next.js"}],"reason":"x-powered-by tells attackers which software runs here","fix_hint":"remove X-Powered-By, version numbers and internal host names from headers and meta generator","platform_fixes":[{"platform":"nextjs","how":"next.config.js: poweredByHeader: false","preferred":true},{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Remove: X-Powered-By"}],"remediation":"Version headers let attackers look up known vulnerabilities for your exact software without probing. Removing them is not a fix for outdated software, but it stops free reconnaissance. Keep the software updated as well. The same applies to a <meta name=\"generator\"> tag with a version, and to internal server names in X-Backend-Server or Server-Timing.","effort":"quick"},{"rule_id":"HDR-001","rule_version":"1.1.0","title":"Strict-Transport-Security","status":"pass","severity":"high","evidence":[{"class":"verified","source":"GET https://example.com/","detail":"strict-transport-security: max-age=31536000"}],"example_fix":"Strict-Transport-Security: max-age=31536000; includeSubDomains","advice":"add includeSubDomains once every subdomain serves HTTPS, so subdomains are protected too"}]}
```

</details>

## Output contract

### สถานะของผลการตรวจสอบ

| Summary | JSON `status` | ความหมาย | นับเป็น |
|---|---|---|---|
| `PASS` | `pass` | ผ่านเกณฑ์ | ผ่าน |
| `FAIL` | `fail` | ไม่ผ่านเกณฑ์ ต้องแก้ไข | ไม่ผ่าน |
| `REVIEW` | `needs_review` | ต้องให้ผู้ใช้ตัดสินใจ เช่น redirect ชั่วคราว หรือ cookie ที่ JavaScript อาจต้องอ่าน | ยังไม่ผ่าน |
| `UNKNOWN` | `unknown` | ตรวจสอบไม่ได้ (เช่น ค่าอ่านไม่ออก) — **ไม่ถือว่าผ่าน** | ตรวจไม่ครบ |
| `NO-EVIDENCE` | `insufficient_evidence` | หลักฐานไม่เพียงพอที่จะสรุปผล (ไม่เกิดขึ้นใน HTTP Security Headers) | ยังไม่ผ่าน |
| `N/A` | `not_applicable` | rule ไม่เกี่ยวข้องกับเป้าหมายนี้ เช่น ไม่มี cookie หรือเป็น JSON API | ไม่นำมาคิดคะแนน |

`verdict` รวมผลเป็นคำเดียว: `fail` (มี FAIL) → `incomplete` (มี UNKNOWN) → `review` (มี REVIEW / NO-EVIDENCE) → `pass`

คำแนะนำเพิ่มเติม (`advice:` · JSON `advice` นับรวมใน `summary.advice`) ไม่ใช่สถานะ แต่เป็นข้อปรับปรุงที่ไม่บังคับซึ่งแนบมากับผล (ส่วนใหญ่เป็น `PASS`) และไม่มีผลต่อ `verdict`, exit code หรือเกรด

### Exit codes

| Code | ความหมาย |
|---|---|
| 0 | `pass` หรือ `review` — `review` **ไม่ถือว่าผ่าน** และจะคืนค่า 1 เมื่อใช้ `--fail-on review` |
| 1 | `fail` |
| 2 | ใช้คำสั่งไม่ถูกต้อง หรือเป้าหมายไม่ได้รับอนุญาต (เช่น IP ภายใน) |
| 3 | `incomplete` หรือตรวจสอบไม่เสร็จภายในเวลาที่กำหนด |
| 4 | เกิดข้อผิดพลาด เช่น เชื่อมต่อเป้าหมายไม่ได้ |

Exit code 0 ไม่ได้แปลว่าผ่านทุก rule: `review` ก็คืนค่า 0 เช่นกัน หากมีโปรแกรมนำผลไปใช้ต่อ ให้ใช้ `--fail-on review` หรืออ่าน `verdict` ใน JSON report

### JSON Schema และความเข้ากันได้

- Schema ของ report: `opencomply schema report` (หรือ [`schemas/report.schema.json`](schemas/report.schema.json))
- `schema_version` จะเพิ่มขึ้นเมื่อมีการเปลี่ยนแปลงที่ไม่เข้ากันกับเวอร์ชันก่อน field ใหม่ที่เป็น optional อาจเพิ่มได้โดยไม่เปลี่ยน `schema_version` ผู้ใช้ข้อมูลควรข้าม field ที่ไม่รู้จัก
- ก่อน v1.0 โครงสร้างยังอาจเปลี่ยนได้ แต่การเปลี่ยนแปลงที่ไม่เข้ากันจะเปลี่ยน `schema_version` ทุกครั้ง

### การตรวจสอบย้อนกลับ

ทุก finding มี `rule_id`, `rule_version` และหลักฐาน (`evidence`: `source` + `detail`) ส่วน report มี `scanner_version` และ rule pack ที่ใช้ (`id`, `version`, `sha256`, `signed_by`) ผลจากเป้าหมายและ rule pack เดียวกันจึงทำซ้ำได้และตรวจย้อนได้

## วิธีคิดคะแนนและเกรด

- **คะแนน (0–100)** = น้ำหนักของ rule ที่ผ่าน ÷ น้ำหนักรวมของ rule ที่เกี่ยวข้อง (`PASS` ได้เต็ม, `REVIEW` ได้ครึ่ง, `N/A` ไม่นำมาคิด, คำแนะนำเพิ่มเติมไม่นำมาคิด) น้ำหนักของแต่ละ rule กำหนดใน rule pack — `REVIEW` ได้ครึ่งเพื่อให้เรื่องที่ยังรอตัดสินใจถูกหักน้อยกว่า FAIL แต่ยัง**ไม่ถือว่าผ่าน**
- **เกรดจากคะแนน:** A+ 95–100 · A 90–94 · B 80–89 · C 70–79 · D 50–69 · F 0–49
- **เพดานเกรด** (คะแนนสูงไม่สามารถชดเชยจุดอ่อนร้ายแรงได้):

| เงื่อนไข | ผล |
|---|---|
| rule บังคับไม่ผ่าน (HSTS, CSP, clickjacking, HTTPS enforcement) | สูงสุด C |
| rule ระดับ high / critical ไม่ผ่าน | สูงสุด B |
| rule บังคับเป็น REVIEW หรือ rule ระดับ high / critical ยังไม่ได้ตัดสินใจ | ไม่ได้ A+ |
| rule บังคับเป็น UNKNOWN | ไม่ให้เกรด (`N/A`) |

- **เส้นทางสู่เกรดที่สูงขึ้น** (`to …:`) แสดงเฉพาะ rule ที่จำเป็น เรียงตามผลที่ได้มากที่สุด และแสดงผลจริงหลังแก้ (`→`) ซึ่งอาจสูงกว่าเกรดเป้าหมาย ในตัวอย่าง แก้ HDR-002 ข้อเดียวได้ 89 (B) ส่วน A+ ต้องแก้ HDR-002 และ HDR-005 ได้ 95 ขณะที่ HDR-010 ไม่จำเป็นต่อ A+

## ความน่าเชื่อถือของผล

| ประเภทหลักฐาน | ความหมาย |
|---|---|
| `verified` | ค่าที่อ่านได้จริงจาก response และใช้ตัดสินผล |
| `inferred` | ข้อมูลที่อนุมาน เช่น platform ใช้เลือกคำแนะนำเท่านั้น ไม่มีผลต่อการตัดสิน |
| `manual_review` | ต้องให้ผู้ใช้หรือผู้เชี่ยวชาญพิจารณา |

- การตัดสินผลเป็นการเทียบหลักฐานกับ rule โดยตรง ไม่มี AI และไม่มีการสุ่ม หลักฐานและ rule pack ชุดเดียวกันจึงให้ผลเดิม (ผลจากเว็บจริงอาจต่างกันได้หาก response ของเว็บเปลี่ยน)
- ค่าที่อ่านไม่ออกหรือตรวจไม่ได้จะเป็น `UNKNOWN` และเรื่องที่ต้องใช้วิจารณญาณจะเป็น `REVIEW` ทั้งสองกรณีไม่ถูกนับเป็น `PASS`
- rule pack ทางการตรวจลายเซ็น Ed25519 ก่อนโหลด หากไฟล์ถูกแก้ไขจะไม่ถูกนำมาใช้
- ข้อมูลลับชนิดที่รู้จัก เช่น ค่า cookie, token, รหัสผ่าน และ key จะถูกปิดบังใน output ทุกรูปแบบ

## การขยายความสามารถ

ส่วนขยายของ OpenComply เป็น**ข้อมูล ไม่ใช่โค้ด** ไม่มีการโหลด plugin ที่รันโค้ดเข้ามาใน scanner ทั้งนี้เพื่อให้ผลทำซ้ำได้และลดช่องทางโจมตีที่เกี่ยวกับ plugin

| ความสามารถ | รายละเอียด |
|---|---|
| รูปแบบ rule pack (TOML) และ JSON Schema | `opencomply schema rule-pack` |
| ตรวจ rule pack (schema, semantic, ความขัดแย้งระหว่าง pack, ลายเซ็น) | `opencomply rules validate <files…>` |
| Operator | allowlist และ built-in checks ตามชื่อที่กำหนด ไม่มี expression หรือ script |
| Rule pack ที่ `scan` ใช้ | rule pack ทางการที่ฝังใน binary และตรวจลายเซ็นก่อนใช้ทุกครั้ง |
| เพิ่มความสามารถการตรวจ | ผ่านการร่วมพัฒนาในซอร์สโค้ดหลัก ดู [CONTRIBUTING](CONTRIBUTING.md) |

## ความเป็นส่วนตัวและความปลอดภัย

| | |
|---|---|
| **ไม่มี telemetry** | ไม่เก็บข้อมูลการใช้งาน และไม่ส่งซอร์สโค้ดหรือผลการตรวจสอบกลับไปยังผู้พัฒนา OpenComply |
| **การเชื่อมต่อเครือข่าย** | ส่งคำขอ GET ไปยัง URL ที่ระบุและ `http://` ของ URL เดียวกัน แล้วตาม redirect ทีละ hop (และ DNS) ปฏิเสธ IP ภายในและ loopback ทุก hop (เว้นแต่ใช้ `--allow-private`) และปฏิเสธ cloud metadata เสมอ ป้องกัน DNS rebinding และจำกัดเวลาและขนาดข้อมูลทุกคำขอ |
| **AI agent** | ผลลัพธ์ที่ AI agent อ่านจะถูกส่งไปยังผู้ให้บริการโมเดลของ agent นั้น ตามนโยบายของผู้ให้บริการ ไม่ใช่ OpenComply |
| **สิทธิ์ขั้นต่ำ** | ทำงานด้วยสิทธิ์ผู้ใช้ทั่วไป ไม่แก้ไขไฟล์หรือโค้ดในเครื่อง การสแกนเป็นคำขอเครือข่ายจริง (GET เท่านั้น) เว็บที่ออกแบบไม่ดีอาจยังทำงานบางอย่างเมื่อได้รับ GET จึงควรสแกนเฉพาะระบบที่ได้รับอนุญาต |

## มาตรฐานและหลักเกณฑ์

OpenComply ประเมินตามเกณฑ์ของ OpenComply เองที่มีการกำหนดเวอร์ชัน โดยอิงพฤติกรรมของเบราว์เซอร์และแนวปฏิบัติด้านความปลอดภัยในปัจจุบัน ผลและเกรดเป็นของ OpenComply ไม่ใช่การรับรองตามมาตรฐานใด และไม่มีความเกี่ยวข้องหรือเทียบเท่ากับบริการให้คะแนนของบุคคลที่สาม

## การมีส่วนร่วม

- [แนวทางการร่วมพัฒนา (Contributing)](CONTRIBUTING.md)
- [แนวทางปฏิบัติของชุมชน (Code of Conduct)](CODE_OF_CONDUCT.md)
- [นโยบายความปลอดภัยและการแจ้งช่องโหว่](SECURITY.md)

## ข้อจำกัดความรับผิดชอบและสัญญาอนุญาต

OpenComply เป็นเครื่องมือประเมินที่เป็นอิสระ **ไม่ใช่หน่วยงานรับรองมาตรฐาน** ผลการประเมินไม่ใช่การรับรองความสอดคล้องและไม่ใช่การรับประกันความปลอดภัย ผู้ใช้ควรตรวจสอบเฉพาะระบบที่ได้รับอนุญาตเท่านั้น

Copyright 2026 vampirebeam · [Apache License 2.0](LICENSE) · [NOTICE](NOTICE)
