<p align="center"><img src="docs/assets/opencomply-hero.svg" alt="OpenComply — security and compliance scanner" width="960" /></p>

<p align="center"><strong>🇹🇭 ภาษาไทย</strong> &nbsp;|&nbsp; <a href="README.en.md">🇬🇧 English</a></p>

<h3 align="center">เครื่องมือตรวจสอบความปลอดภัยของเว็บไซต์<br/>ระบุสิ่งที่ขาด วิธีแก้ไข และตำแหน่งที่ต้องแก้ไข ในรูปแบบที่ทั้งนักพัฒนาและ AI agent นำไปใช้ต่อได้</h3>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.3-f59e0b?style=flat-square" alt="Version 0.3.3" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-22c55e?style=flat-square" alt="Apache-2.0 License" /></a>
  <img src="https://img.shields.io/badge/rust-1.90-0891b2?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.90" />
  <img src="https://img.shields.io/badge/agent_skill-Agent_Skills_format-7C3AED?style=flat-square" alt="Agent skill in the Agent Skills format" />
</p>


## ภาพรวม

OpenComply เป็น **CLI engine ตัวเดียว** ที่ตรวจเว็บไซต์ตาม rule ที่กำหนดเวอร์ชันและมีลายเซ็นกำกับ แล้วบอกว่าขาดอะไร แก้อย่างไร และแก้ที่ไหน ผลผ่านหรือไม่ผ่านมาจาก engine เท่านั้น ไม่มี AI ตัดสินผล ผู้ใช้หรือ AI agent เป็นผู้เรียกใช้และนำผลไปดำเนินการต่อ

| Module | รายการที่ตรวจสอบ | ผลลัพธ์ |
|---|---|---|
| **HTTP Security Headers** | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking, HTTPS enforcement, cookie และการเปิดเผยข้อมูลระบบ | เกรด A+ – F พร้อมคะแนน 0–100 |

## เริ่มใช้งาน

**Claude Code** — ติดตั้ง plugin:

```text
/plugin marketplace add vampirebeam/OpenComply
/plugin install opencomply@opencomply
```

จากนั้นสั่งเป็นภาษาของคุณได้ทันที เช่น *"ตรวจ https://example.com ให้หน่อย"* หรือ *"เว็บฉันปลอดภัยไหม"* หรือเรียก `/opencomply <URL>` ครั้งแรกที่ใช้ agent จะขออนุญาตติดตั้ง CLI ให้ ระบุ URL เต็มก็พอ ไม่ต้องให้รหัสผ่านหรือ cookie

**ใช้เฉพาะ CLI:**

```bash
# Linux x86_64 / macOS Apple Silicon
curl -fsSL https://github.com/vampirebeam/OpenComply/releases/latest/download/install.sh | sh
```

```powershell
# Windows x86_64 (PowerShell)
irm https://github.com/vampirebeam/OpenComply/releases/latest/download/install.ps1 | iex
```

ตัวติดตั้งตรวจ SHA-256 ของไฟล์ที่ดาวน์โหลด และไม่ต้องใช้สิทธิ์ admin ส่วน agent อื่น การอ่านตัวติดตั้งก่อนรัน การถอนการติดตั้ง และการดาวน์โหลดเอง ดูที่ [Getting started](docs/GETTING_STARTED.md)

## การใช้งาน

```bash
opencomply scan headers https://example.com                    # ผลสรุป
opencomply scan headers https://example.com --format markdown  # รายงานพร้อมหลักฐาน
opencomply scan headers https://example.com --format json      # ข้อมูลสำหรับโปรแกรมอื่น
```

`--all` แสดงรายการที่ผ่านด้วย · `--allow-private` ตรวจระบบภายในที่คุณได้รับอนุญาต · ตัวเลือกทั้งหมด: [Getting started](docs/GETTING_STARTED.md#usage)

## ตัวอย่างผลลัพธ์

ตัดมาบางส่วน (`…` คือบรรทัดที่ตัดออก) สร้างจาก renderer จริงด้วยข้อมูลสมมติ (example.com) ไม่ใช่ผลสแกนจริง:

```console
$ opencomply scan headers https://example.com/
headers https://example.com/ verdict=fail grade=D score=63 pass=6 fail=3 unknown=0 review=0 no_evidence=0 n/a=1 advice=1 platform=cloudflare+nextjs
to C: HDR-002 +26 required → B 89
to A+: HDR-002 +26 required · HDR-005 +6 required → A+ 95
FAIL HDR-002 high Content-Security-Policy · involved
  why: script-src allows 'unsafe-inline' without a nonce or hash, so injected inline scripts can run
  fix: enforce a CSP whose script-src allows no inline or wildcard scripts
  example: change only script-src: script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
  how (nextjs, preferred): middleware (proxy): create a nonce per request, set the CSP header and read it with headers() in the layout
  note (cloudflare): A static Transform Rule cannot add a per-request nonce; set the CSP in the app, use hashes, or a Worker
…
next: fix 3 · advice 1 (optional) · evidence: --format markdown
```

ผลลัพธ์ฉบับเต็ม วิธีอ่านแต่ละบรรทัด รายงานพร้อมหลักฐาน JSON เกรด และ exit code: [Reports](docs/REPORTS.md)

## สิ่งที่คุณได้

- **หลักฐานของทุกผล** — ค่า header ที่ใช้ตัดสิน รหัส rule และเวอร์ชันของ rule pack ทุกผลจึงตรวจย้อนได้
- **วิธีแก้ตาม platform ของคุณ** — OpenComply ตรวจว่าเว็บใช้ระบบอะไร (เช่น Cloudflare, nginx, WordPress, Next.js) แล้วบอกว่าต้องแก้แต่ละข้อที่ไหน โดยสร้างตัวอย่างจากค่าปัจจุบันของเว็บ การตรวจ platform ใช้เลือกคำแนะนำเท่านั้น ไม่มีผลต่อ PASS / FAIL
- **เส้นทางสู่เกรดที่สูงขึ้น** — แก้ข้อไหนแล้วเกรดขึ้นเท่าไร และแต่ละข้อมีต้นทุนอะไร
- **ผลตามจริง** — สิ่งที่ตรวจไม่ได้เป็น `UNKNOWN` และเรื่องที่ต้องให้คุณตัดสินใจเป็น `REVIEW` ทั้งสองไม่นับว่าผ่าน

## ความปลอดภัยและความเป็นส่วนตัว

- **ไม่มี telemetry** ไม่ต้องมีบัญชีหรือ API key CLI ไม่เก็บข้อมูลใดๆ และไม่แก้ไขไฟล์ของคุณ
- การสแกนส่งเฉพาะคำขอ GET ไปยัง URL ที่ระบุและ `http://` ของ URL เดียวกัน ปฏิเสธที่อยู่ภายในเว้นแต่คุณอนุญาต และปฏิเสธ cloud metadata เสมอ
- เมื่อใช้ AI agent สิ่งที่ agent อ่านจะถูกส่งไปยังผู้ให้บริการโมเดลของ agent นั้น agent skill ทดสอบและตรวจผลโดย vampirebeam โดยใช้ Claude Code เป็น agent แต่พฤติกรรมของ AI อาจต่างกันในแต่ละครั้ง การป้องกันของ CLI เองจึงไม่ขึ้นกับ AI

[Security and privacy](docs/SECURITY_AND_PRIVACY.md) · [นโยบายความปลอดภัย](SECURITY.md)

## เอกสาร

| คู่มือ (ภาษาอังกฤษ) | เนื้อหา |
|---|---|
| [Getting started](docs/GETTING_STARTED.md) | ติดตั้ง (agent และ CLI) ถอนการติดตั้ง ตัวเลือก |
| [Reports](docs/REPORTS.md) | รูปแบบผลลัพธ์ สถานะ เกรด exit code JSON schema |
| [Security and privacy](docs/SECURITY_AND_PRIVACY.md) | ข้อมูล เครือข่าย AI agent สิ่งที่ป้องกันและไม่ได้ป้องกัน ข้อจำกัด |

## การมีส่วนร่วม

[แนวทางการร่วมพัฒนา](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [นโยบายความปลอดภัย](SECURITY.md)

## ข้อจำกัดความรับผิดชอบและสัญญาอนุญาต

OpenComply เป็นเครื่องมือประเมินที่เป็นอิสระ **ไม่ใช่หน่วยงานรับรองมาตรฐาน** ผลการประเมินไม่ใช่การรับรองความสอดคล้องและไม่ใช่การรับประกันความปลอดภัย เกรดเป็นของ OpenComply เองและไม่เกี่ยวข้องกับบริการให้คะแนนของบุคคลที่สาม ผู้ใช้ควรตรวจสอบเฉพาะระบบที่ได้รับอนุญาตเท่านั้น

Copyright 2026 vampirebeam · [Apache License 2.0](LICENSE) · [NOTICE](NOTICE) หากนำ OpenComply ไปใช้หรือพัฒนาต่อ โปรดคงไฟล์ NOTICE และให้เครดิตโปรเจกต์
