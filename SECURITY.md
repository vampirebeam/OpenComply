# Security Policy

**ภาษาไทย** · [English](#english)

## การแจ้งช่องโหว่

หากพบช่องโหว่ใน OpenComply **กรุณาอย่าเปิด issue สาธารณะ** ให้แจ้งแบบส่วนตัวผ่าน [GitHub Security Advisories](https://github.com/vampirebeam/OpenComply/security/advisories/new)

กรุณาแนบ:

- เวอร์ชันของ OpenComply (`opencomply --version`) และระบบปฏิบัติการ
- ขั้นตอนทำซ้ำ หรือ input ที่ทำให้เกิดปัญหา
- ผลกระทบที่คาดว่าจะเกิด

| ขั้นตอน | ระยะเวลา |
|---|---|
| ตอบรับการแจ้ง | ภายใน 7 วัน |
| ประเมินและแจ้งแผนแก้ไข | ภายใน 30 วัน |
| เผยแพร่การแก้ไข | ตามความรุนแรง — ช่องโหว่ร้ายแรงจะได้รับความสำคัญสูงสุด |

เราจะให้เครดิตผู้แจ้งในประกาศแก้ไข เว้นแต่ผู้แจ้งต้องการไม่เปิดเผยชื่อ

## ขอบเขต

อยู่ในขอบเขต — ช่องโหว่ของตัว OpenComply เช่น:

- ทำให้ scanner เข้าถึงเครือข่ายภายในหรือไฟล์นอกขอบเขตที่สแกนได้
- ทำให้ scanner ค้าง ใช้ทรัพยากรเกินกำหนด หรือ crash จาก input ที่ถูกสร้างขึ้น
- รันโค้ดหรือคำสั่งผ่าน rule pack หรือเนื้อหาที่ถูกสแกน
- ข้อมูลลับหลุดลงในรายงาน
- รายงานถูกแทรกเนื้อหาจนทำให้ผู้อ่านหรือ AI agent เข้าใจผิด

ไม่อยู่ในขอบเขต:

- ช่องโหว่ของเว็บไซต์หรือ repository ที่คุณสแกน — กรุณาแจ้งเจ้าของระบบนั้นโดยตรง
- ผลประเมินที่คุณไม่เห็นด้วย — เปิด issue ปกติได้

## เวอร์ชันที่รองรับ

ก่อน v1.0.0 จะแก้ไขเฉพาะเวอร์ชันล่าสุดเท่านั้น

---

<a id="english"></a>

[ภาษาไทย](#security-policy) · **English**

## Reporting a vulnerability

If you find a vulnerability in OpenComply, **please do not open a public issue.** Report it privately through [GitHub Security Advisories](https://github.com/vampirebeam/OpenComply/security/advisories/new).

Please include:

- The OpenComply version (`opencomply --version`) and your operating system
- Steps or input that reproduce the problem
- The expected impact

| Step | Timeline |
|---|---|
| Acknowledge the report | Within 7 days |
| Assess and share a fix plan | Within 30 days |
| Release the fix | By severity; critical issues get top priority |

We credit reporters in the fix announcement unless they prefer to stay anonymous.

## Scope

In scope: vulnerabilities in OpenComply itself, for example:

- Making the scanner reach internal networks or files outside the scanned target
- Making the scanner hang, exceed its resource limits or crash on crafted input
- Executing code or commands through a rule pack or scanned content
- Secrets leaking into reports
- Injecting report content that misleads a reader or an AI agent

Out of scope:

- Vulnerabilities in the website or repository you scanned. Please report those to that system's owner.
- Assessment results you disagree with. Open a regular issue for those.

## Supported versions

Before v1.0.0, only the latest release receives fixes.
