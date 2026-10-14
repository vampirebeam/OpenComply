<p align="center"><img src="docs/assets/opencomply-hero.svg" alt="OpenComply — security and compliance scanner" width="960" /></p>

<p align="center"><strong>🇹🇭 ภาษาไทย</strong> &nbsp;|&nbsp; <a href="README.en.md">🇬🇧 English</a></p>

<h3 align="center">เครื่องมือตรวจสอบความปลอดภัยและความพร้อมด้าน Compliance ของเว็บไซต์และซอร์สโค้ด<br/>ระบุสิ่งที่ขาด วิธีแก้ไข และตำแหน่งที่ต้องแก้ไข ในรูปแบบที่ทั้งผู้ใช้และ AI เข้าใจได้</h3>

<p align="center">
  <img src="https://img.shields.io/badge/status-early_development-f59e0b?style=flat-square" alt="Status: early development" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-22c55e?style=flat-square" alt="Apache-2.0 License" /></a>
  <img src="https://img.shields.io/badge/rust-1.90-0891b2?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.90" />
  <img src="https://img.shields.io/badge/designed_for-Claude_Code_%7C_Codex_%7C_Cursor_%7C_Gemini_CLI-7C3AED?style=flat-square" alt="Designed for Claude Code, Codex, Cursor and Gemini CLI" />
</p>

> [!NOTE]
> โครงการอยู่ระหว่างการพัฒนาและยังไม่มีการเผยแพร่เวอร์ชันใช้งาน คำสั่งและผลลัพธ์ด้านล่างเป็นรูปแบบที่จะใช้เมื่อเปิดตัว

## ขอบเขตการตรวจสอบ

| Module | รายการที่ตรวจสอบ | ผลลัพธ์ |
|---|---|---|
| **HTTP Security Headers** | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, การป้องกัน clickjacking, การบังคับใช้ HTTPS, cookie และการเปิดเผยข้อมูลระบบ | เกรด A+ – F |
| **SSL/TLS** | ใบรับรอง (certificate), TLS 1.2/1.3, protocol รุ่นเก่า, cipher suites, key exchange และ forward secrecy | เกรด A+ – F |
| **ISO/IEC 27001:2022** | หลักฐานใน repository เทียบกับข้อกำหนดของระบบบริหารความมั่นคงปลอดภัยสารสนเทศ (ISMS) และ controls | ระดับความพร้อม 0–4 |
| **ISO/IEC 42001:2023** | หลักฐานใน repository เทียบกับข้อกำหนดของระบบบริหารจัดการ AI และ controls | ระดับความพร้อม 0–4 |

ผลการตรวจสอบทุกรายการมีหลักฐาน รหัสกฎ (rule ID) และเวอร์ชันของกฎกำกับ จึงตรวจสอบย้อนกลับได้ นอกจากนี้ OpenComply จะระบุผู้ให้บริการและเทคโนโลยีที่ระบบใช้งาน (เช่น Cloudflare, Vercel, nginx, WordPress, Next.js) เพื่อแนะนำ**ตำแหน่งที่ต้องแก้ไข**ได้ถูกต้อง

## การใช้งานร่วมกับ AI agent

ผู้ใช้สามารถสั่งงานด้วยภาษาทั่วไป AI agent จะเรียกใช้ OpenComply และสรุปผลในลักษณะต่อไปนี้

> **ผู้ใช้:** ช่วยตรวจสอบ security headers ของ example.com
>
> **AI:** ตรวจสอบเรียบร้อยแล้ว **ผลยังไม่ผ่าน: ต้องแก้ไข 2 รายการ และต้องให้คุณพิจารณาตัดสินใจ 1 รายการ** ส่วนอีก 6 รายการผ่านเกณฑ์ (เว็บไซต์ใช้งานผ่าน **Cloudflare**)
>
> 🟠 **1. ไม่พบ Permissions-Policy** · HDR-005 · ความรุนแรงต่ำ — *แก้ไขได้ง่ายที่สุด แนะนำให้ดำเนินการก่อน*<br/>
> สามารถตั้งค่าที่ Cloudflare ได้ที่ **Rules → Transform Rules → Modify Response Header** โดยกำหนดค่าดังนี้
> ```
> Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
> ```
>
> 🔴 **2. CSP อนุญาตให้รัน inline script** · HDR-002 · ความรุนแรงปานกลาง<br/>
> หากเว็บไซต์มีช่องโหว่ XSS สคริปต์ที่ถูกแทรกเข้ามาจะทำงานได้ทันที ควรใช้ nonce แทน `'unsafe-inline'` ทั้งนี้**ต้องแก้ไขที่แอปพลิเคชัน ไม่ใช่ที่ Cloudflare** เนื่องจาก Cloudflare กำหนดได้เฉพาะค่าคงที่ ขณะที่ nonce ต้องสร้างใหม่ทุกครั้งที่ตอบกลับ
> ```
> script-src 'self' 'nonce-<per-response-random>'
> ```
> ค่าข้างต้นเป็นตัวอย่าง การเปลี่ยนค่านี้เพียงค่าเดียวไม่ได้ทำให้ CSP ปลอดภัยโดยสมบูรณ์ ควรตรวจสอบ directive อื่นร่วมด้วย และทดสอบด้วย `Content-Security-Policy-Report-Only` ก่อนบังคับใช้ เพื่อยืนยันว่าแอปพลิเคชันยังทำงานได้ตามปกติ ต้องการให้ตรวจสอบโค้ดและร่างการแก้ไขให้หรือไม่
>
> 🟡 **รายการที่ต้องพิจารณา — header `Server: cloudflare`** · HDR-010<br/>
> header นี้ Cloudflare เป็นผู้กำหนดและไม่ระบุเวอร์ชัน โดยทั่วไปจึงมีความเสี่ยงต่ำ ยอมรับความเสี่ยงนี้ได้หรือไม่

AI จะแจ้งผลโดยรวมก่อน อธิบายด้วยภาษาที่เข้าใจง่าย ระบุตำแหน่งที่ต้องแก้ไขและรหัสกฎทุกรายการ และ**สอบถามผู้ใช้**ในรายการที่ต้องตัดสินใจ ผลผ่านหรือไม่ผ่านมาจาก OpenComply เสมอ และ AI จะแก้ไขโค้ดเมื่อได้รับอนุมัติจากผู้ใช้เท่านั้น

<details>
<summary><strong>ผลลัพธ์ต้นฉบับที่ AI อ่าน</strong> (<code>opencomply scan headers …</code>)</summary>

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

| บรรทัด | ความหมาย |
|---|---|
| บรรทัดแรก | ผลโดยรวม (`verdict`: `pass` ผ่าน · `review` ต้องพิจารณา · `incomplete` ตรวจสอบไม่ครบ · `fail` ไม่ผ่าน) จำนวนในแต่ละสถานะ และผู้ให้บริการที่ตรวจพบ |
| `FAIL` / `REVIEW` | รหัสกฎ · ระดับความรุนแรง · สิ่งที่ตรวจพบ เรียงจากรายการสำคัญที่สุด |
| `why:` | สิ่งที่ขาด หรือเหตุผลของผลการตรวจสอบ |
| `fix:` | สิ่งที่ต้องดำเนินการ |
| `example:` | **ตัวอย่าง**การตั้งค่า ต้องปรับให้เข้ากับระบบจริงก่อนใช้งาน และต้องแทนที่ค่าใน `<...>` ทุกครั้ง |
| `how (…)` / `note (…)` | ตำแหน่งที่ต้องแก้ไขบนผู้ให้บริการนั้น และข้อควรระวัง |
| `decide:` | ประเด็นที่**ผู้ใช้**ต้องพิจารณาตัดสินใจ |
| `next:` | ขั้นตอนถัดไป |

</details>

<details>
<summary><strong>รายงานสำหรับการตรวจประเมิน (audit)</strong> (<code>--format markdown</code>)</summary>

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
<summary><strong>ข้อมูล JSON สำหรับ AI และ CI</strong> (<code>--format json</code>)</summary>

ข้อมูลอยู่ในบรรทัดเดียว โดยสรุปผลอยู่ก่อนรายการผลการตรวจสอบ AI จึงทราบผลได้จากส่วนต้นของข้อมูล ค่าเริ่มต้นแสดงเฉพาะรายการที่ต้องดำเนินการ (ในตัวอย่างคือ fail 2 รายการ และ review 1 รายการ) หากต้องการรายการที่ผ่านด้วยให้เพิ่ม `--all` โครงสร้างข้อมูลทั้งหมดอธิบายไว้ใน JSON Schema

```json
{"schema_version":1,"scanner_version":"0.1.0","module":"headers","target":"https://example.com","platforms":[{"id":"cloudflare","name":"Cloudflare","layer":"cdn","evidence":{"class":"inferred","source":"GET https://example.com","detail":"CF-RAY: 8f1c2a3b4d5e6f70-BKK"}}],"verdict":"fail","summary":{"pass":6,"fail":2,"unknown":0,"not_applicable":1,"needs_review":1,"insufficient_evidence":0},"findings":[{"rule_id":"HDR-002","rule_version":"1.0.0","title":"CSP allows inline scripts","status":"fail","severity":"medium","evidence":[{"class":"verified","source":"GET https://example.com","detail":"Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'"}],"reason":"script-src contains 'unsafe-inline', so any injected inline script runs","fix_hint":"replace 'unsafe-inline' in script-src with a per-response nonce","example_fix":"script-src 'self' 'nonce-<per-response-random>'","platform_fixes":[{"platform":"cloudflare","how":"set the CSP in the application (origin), not in Cloudflare","note":"Transform Rules only set static values; per-request nonces need the app or a Worker"}],"remediation":"Generate a new random nonce for every response, add it to script-src and to each inline script, then remove 'unsafe-inline'. Review the other directives and test in Content-Security-Policy-Report-Only mode before enforcing."},{"rule_id":"HDR-005","rule_version":"1.0.0","title":"Permissions-Policy missing","status":"fail","severity":"low","evidence":[{"class":"verified","source":"GET https://example.com","detail":"(header not present)"}],"reason":"response has no Permissions-Policy header","fix_hint":"add a Permissions-Policy that disables unused features","example_fix":"Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()","platform_fixes":[{"platform":"cloudflare","how":"Rules > Transform Rules > Modify Response Header > Set static header"}],"remediation":"Disable every browser feature the site does not use; keep (self) only for features it needs."},{"rule_id":"HDR-010","rule_version":"1.0.0","title":"Hosting platform disclosed","status":"needs_review","severity":"info","evidence":[{"class":"verified","source":"GET https://example.com","detail":"Server: cloudflare"}],"reason":"header is set by the hosting platform, not by the site","review_question":"is revealing the hosting platform acceptable for this site?","remediation":"Usually low risk when no version is shown. Accept and document it."}]}
```

</details>

## การเริ่มต้นใช้งาน

```bash
opencomply scan headers https://example.com      # ตรวจสอบ HTTP security headers
opencomply scan tls https://example.com          # ตรวจสอบ SSL/TLS
opencomply scan iso27001 ./my-repo               # ประเมินความพร้อม ISO/IEC 27001
opencomply scan iso42001 ./my-repo               # ประเมินความพร้อม ISO/IEC 42001
opencomply standards                             # แสดงมาตรฐานที่รองรับและเวอร์ชัน
```

| Option | การใช้งาน |
|---|---|
| *(ไม่ระบุ)* | แสดงผลแบบสรุป อ่านง่าย และใช้ token น้อย |
| `--format json` | สำหรับ AI agent, CI หรือเครื่องมืออื่น |
| `--format markdown` | จัดทำรายงานสำหรับการตรวจประเมินพร้อมหลักฐาน |
| `--all` | แสดงรายการที่ผ่านเกณฑ์ด้วย |
| `--fail-on review` | สำหรับ CI — ถือว่ารายการที่ยังไม่ได้ตัดสินใจไม่ผ่านเกณฑ์ |

> [!IMPORTANT]
> **การใช้งานใน CI:** หากต้องการให้ทุกประเด็นได้รับการตัดสินก่อน merge หรือ deploy **ต้องใช้ `--fail-on review`** เนื่องจากค่าเริ่มต้นจะคืนค่า exit code 0 เมื่อเหลือเพียงรายการที่ต้องพิจารณา
>
> ```bash
> opencomply scan headers https://example.com --format json --fail-on review
> ```

<details>
<summary><strong>Exit codes</strong></summary>

| Code | ความหมาย |
|---|---|
| 0 | ผ่าน หรือเหลือเพียงรายการที่ต้องพิจารณา (`verdict=review`) ซึ่ง**ไม่ถือว่าผ่าน** — เมื่อใช้ `--fail-on review` กรณีนี้จะคืนค่า 1 แทน |
| 1 | พบรายการที่ต้องแก้ไข |
| 2 | ใช้คำสั่งไม่ถูกต้อง |
| 3 | ตรวจสอบไม่ครบถ้วน |
| 4 | เกิดข้อผิดพลาด |

</details>

## ความเป็นส่วนตัวและความปลอดภัย

| | |
|---|---|
| **ไม่มี telemetry** | ไม่เก็บข้อมูลการใช้งาน และไม่ส่งซอร์สโค้ดหรือผลการตรวจสอบกลับไปยังผู้พัฒนา OpenComply |
| **การเชื่อมต่อเครือข่าย** | การตรวจสอบเว็บไซต์และ TLS เชื่อมต่อเฉพาะเป้าหมายที่ผู้ใช้ระบุ (และ DNS) ส่วนการตรวจสอบ repository ไม่มีการเชื่อมต่อเครือข่าย |
| **AI agent** | ผลลัพธ์ที่ AI agent อ่านจะถูกส่งไปยังผู้ให้บริการโมเดลของ agent นั้น ตามนโยบายของผู้ให้บริการ ไม่ใช่ OpenComply |
| **สิทธิ์ขั้นต่ำ** | ทำงานด้วยสิทธิ์ผู้ใช้ทั่วไป อ่านข้อมูลอย่างเดียว และกฎเป็นข้อมูลที่ไม่สามารถรันโค้ดได้ |

## มาตรฐานและหลักเกณฑ์

OpenComply ประเมินตามมาตรฐานที่ได้รับการยอมรับในระดับสากลและแนวปฏิบัติด้านความปลอดภัยในปัจจุบัน โดยรวบรวมเป็นเกณฑ์ของ OpenComply ที่มีการกำหนดเวอร์ชัน

- **การตรวจสอบเชิงเทคนิค** — ให้เกรดจากการตรวจสอบแบบถ่วงน้ำหนัก จุดอ่อนที่ร้ายแรงจะจำกัดเกรดสูงสุด และการตรวจสอบที่ไม่ครบถ้วนจะไม่ได้รับเกรดสูงสุด
- **ความพร้อมด้าน ISO** — ประเมินหลักฐานเทียบกับข้อกำหนดและ controls โดยแยกหลักฐานเชิงเทคนิคออกจากหลักฐานเชิงองค์กร และระบุรายการที่ต้องให้ผู้เชี่ยวชาญพิจารณา

เกรดและระดับความพร้อมเป็นเกณฑ์ของ OpenComply ไม่มีความเกี่ยวข้องและไม่เทียบเท่ากับบริการให้คะแนนของบุคคลที่สาม

### ข้อจำกัดของการประเมินด้าน ISO

การตรวจสอบ repository เพียงอย่างเดียว**ไม่สามารถพิสูจน์ความครบถ้วนของระบบบริหารความมั่นคงปลอดภัยสารสนเทศ (ISMS) หรือระบบบริหารจัดการ AI (AIMS) ได้** ข้อกำหนดจำนวนมากต้องอาศัยเอกสารนโยบาย กระบวนการ การสัมภาษณ์ผู้เกี่ยวข้อง และหลักฐานการดำเนินงานจริง OpenComply จึงระบุรายการเหล่านี้เป็น "ต้องให้ผู้เชี่ยวชาญพิจารณา" หรือ "หลักฐานไม่เพียงพอ" แทนการสรุปผล และผลการประเมินใช้เพื่อเตรียมความพร้อมเท่านั้น

## การมีส่วนร่วม

- [แนวทางปฏิบัติของชุมชน (Code of Conduct)](CODE_OF_CONDUCT.md)
- [นโยบายความปลอดภัยและการแจ้งช่องโหว่](SECURITY.md)
- แนวทางการร่วมพัฒนา (CONTRIBUTING) จะเผยแพร่พร้อมเวอร์ชันแรก

## ข้อจำกัดความรับผิดชอบและสัญญาอนุญาต

OpenComply เป็นเครื่องมือประเมินที่เป็นอิสระ **ไม่ใช่หน่วยงานรับรอง ISO** ผลการประเมินไม่ใช่การรับรองความสอดคล้องและไม่ใช่การรับประกันความปลอดภัย ผู้ใช้ควรตรวจสอบเฉพาะระบบที่ได้รับอนุญาตเท่านั้น

Copyright 2026 vampirebeam · [Apache License 2.0](LICENSE) · [NOTICE](NOTICE)
