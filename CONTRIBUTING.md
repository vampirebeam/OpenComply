# Contributing to OpenComply

**ภาษาไทย** · [English](#english)

ขอบคุณที่สนใจช่วยพัฒนา OpenComply

## ก่อนเริ่ม

- ช่องโหว่ด้านความปลอดภัย → แจ้งแบบส่วนตัวตาม [SECURITY.md](SECURITY.md) ห้ามเปิด issue สาธารณะ
- งานใหญ่หรือ rule ใหม่ → เปิด issue คุยกันก่อนเขียนโค้ด
- โปรเจกต์อยู่ระหว่างพัฒนา โครงสร้างอาจเปลี่ยนได้ก่อน v1.0.0

## ตั้งค่าเครื่อง

ต้องมี [Rust](https://rustup.rs/) — `rust-toolchain.toml` จะเลือกเวอร์ชันที่ถูกต้องให้อัตโนมัติ

```bash
cargo build
cargo test --workspace
```

## ก่อนส่ง Pull Request

ทุกข้อต้องผ่าน:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check
```

## หลักการเขียนโค้ด

- **ห้ามใช้ `unsafe`** และห้าม `unwrap` / `expect` / `panic` ในโค้ดที่ไม่ใช่ test
- **ทุก I/O ต้องมี timeout และขีดจำกัด** — ขนาด, จำนวน, ความลึก, เวลา; ถึงขีดจำกัดต้องจบอย่างปลอดภัย ไม่ค้าง
- **Scanner อ่านอย่างเดียว** ไม่แก้ไขระบบที่สแกน และทำงานได้ด้วยสิทธิ์ผู้ใช้ปกติ
- **Rule เป็นข้อมูลเท่านั้น** ห้ามเพิ่มกลไกที่ทำให้ rule รันโค้ดได้
- **ทุก finding ต้องมีหลักฐาน** พร้อม rule ID และ rule version
- **ไม่อ้างการรับรอง** — ห้าม output ที่สื่อว่าผ่านการรับรองมาตรฐานหรือรับประกันความปลอดภัย
- Comment เฉพาะที่จำเป็น วางไว้ต้นไฟล์หรือเหนือ function / struct
- Dependency ใหม่ต้องผ่าน `cargo deny check` (license ต้องเข้ากันได้กับ Apache-2.0)

## Rule ใหม่หรือแก้ rule

Rule อยู่ใน `rules/opencomply-headers.toml` เป็นข้อมูลล้วน รูปแบบเต็มอยู่ใน `schemas/rule-pack.schema.json`

- **คุยก่อน:** เปิด issue บอกว่าตรวจอะไร หลักฐานคืออะไร และควรได้ผลอย่างไรเมื่อหลักฐานไม่พอ
- **Rule ID และ version:** ตามรูปแบบของ module เช่น `HDR-011`; version แบบ `MAJOR.MINOR.PATCH` — แก้ rule เดิมให้ขึ้น version ของ rule และของ `[pack]`
- **การตรวจ (`check`):** ใช้ operator ที่อนุญาตเท่านั้น — `header_present`, `header_absent`, `header_equals`, `header_contains`, `header_one_of`, `header_directive_at_least` หรือ `builtin` (ชื่อจากรายการปิดใน engine) การตรวจที่ต้อง parse จริงต้องเพิ่มเป็น builtin ในโค้ด Rust พร้อม test ไม่ใช่ใน rule
- **คะแนน:** `weight` ของทุก rule ใน pack รวมกันต้องเท่ากับ 100; `mandatory = true` จำกัดเกรดเมื่อ rule นั้นไม่ผ่าน
- **คำแนะนำ:** `fix_hint` สั้นๆ, `remediation` ที่ทำตามได้จริง, `review_question` ไม่เกิน 100 ตัวอักษร, `upgrade_impact` เมื่อการแก้มีผลข้างเคียง, `effort` / `depends_on` / `group` เพื่อเรียงลำดับการแก้
- **ตัวอย่าง:** `example_fix` เป็นตัวอย่างเท่านั้น — ค่าที่ต้องสร้างเองหรือเป็นความลับ (เช่น nonce, token) ต้องเขียนเป็น `<...>` เพื่อไม่ให้ copy ไปใช้ตรงๆ ได้
- **Platform:** `platforms.<id>` บอกว่าแก้ที่ไหนบนผู้ให้บริการนั้น (`how`) พร้อม `note` เมื่อมีข้อจำกัด และ `prefer = true` เมื่อควรแก้ที่ชั้นนั้น ใช้ id เดียวกับ rule ที่มีอยู่
- **Test:** ครบทั้ง ผ่าน, ไม่ผ่าน และหลักฐานไม่พอ — ใช้ข้อมูลสมมติ (`example.com`) ห้ามใช้ค่าจากเว็บจริง
- **ตรวจ pack:** `cargo run -q -p opencomply-cli -- rules validate rules/opencomply-headers.toml`

### ลายเซ็นของ pack

Pack ทางการเซ็นโดยผู้ดูแลโปรเจกต์ และ binary จะปฏิเสธ pack ที่ถูกแก้หลังเซ็น เมื่อแก้ `.toml` แล้ว ให้ย้าย `rules/opencomply-headers.toml.sig` ออกไปชั่วคราวระหว่างทดสอบในเครื่อง (build จะถือว่า pack ยังไม่เซ็นและเตือน "not signed") ห้าม commit การลบหรือแก้ `.sig` — ผู้ดูแลจะตรวจและเซ็นใหม่ก่อน merge ระหว่างนั้น test ที่โหลด pack ใน PR อาจไม่ผ่าน ซึ่งเป็นเรื่องปกติ

## Commit และ Pull Request

- Commit message แบบ [Conventional Commits](https://www.conventionalcommits.org/) เช่น `feat(headers): ...`, `fix(core): ...`
- 1 PR = 1 เรื่อง พร้อม test
- ห้ามใส่ข้อมูลลับ, ข้อมูลส่วนตัว หรือผลสแกนของระบบจริงใน commit

## License

การส่ง contribution ถือว่าคุณยินยอมให้เผยแพร่ภายใต้ [Apache License 2.0](LICENSE)

---

<a id="english"></a>

[ภาษาไทย](#contributing-to-opencomply) · **English**

Thank you for your interest in improving OpenComply.

## Before you start

- **Security vulnerabilities:** report them privately as described in [SECURITY.md](SECURITY.md). Do not open a public issue.
- **Large changes or new rules:** open an issue to discuss before writing code.
- **Project stage:** OpenComply is in early development, and its structure may change before v1.0.0.

## Setup

Install [Rust](https://rustup.rs/). `rust-toolchain.toml` selects the right version automatically.

```bash
cargo build
cargo test --workspace
```

## Before opening a pull request

All of these must pass:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check
```

## Code principles

- **No `unsafe`**, and no `unwrap` / `expect` / `panic` outside tests.
- **Every I/O operation has timeouts and limits** on size, count, depth and time. Hitting a limit must end the scan safely, never hang it.
- **Scanners are read-only.** They never change the scanned system and run with normal user privileges.
- **Rules are data only.** Never add a mechanism that lets a rule execute code.
- **Every finding carries evidence**, a rule ID and a rule version.
- **No certification claims.** No output may imply certification against a standard or guaranteed security.
- **Comments only where necessary**, placed at the top of a file or above a function or struct.
- **New dependencies** must pass `cargo deny check`, with licenses compatible with Apache-2.0.

## New or changed rules

Rules live in `rules/opencomply-headers.toml` and are data only. The full format is in `schemas/rule-pack.schema.json`.

- **Discuss first:** open an issue that says what the rule checks, what evidence it uses and what it should report when the evidence is not enough.
- **Rule IDs and versions:** follow the module's ID pattern, such as `HDR-011`, and use a `MAJOR.MINOR.PATCH` version. When you change a rule, bump its version and the `[pack]` version.
- **Checks (`check`):** use only the allowed operators: `header_present`, `header_absent`, `header_equals`, `header_contains`, `header_one_of`, `header_directive_at_least`, or `builtin` (a name from the engine's closed list). A check that needs real parsing is added as a builtin in Rust, with tests, not in the rule.
- **Scoring:** the `weight` of all rules in a pack must add up to 100. `mandatory = true` caps the grade when that rule fails.
- **Guidance:** a short `fix_hint`, an actionable `remediation`, a `review_question` of at most 100 characters, an `upgrade_impact` when the fix has side effects, and `effort` / `depends_on` / `group` to order the fixes.
- **Examples:** `example_fix` is only an example. Write values that must be generated or kept secret (nonces, tokens) as `<...>` so they can't be copied verbatim.
- **Platform guidance:** `platforms.<id>` says where to fix it on that provider (`how`), with a `note` for any limitation and `prefer = true` when that layer is the better place to fix it. Use the same ids as the existing rules.
- **Tests:** cover the pass, fail and insufficient-evidence cases, with made-up data (`example.com`), never values from real sites.
- **Validation:** `cargo run -q -p opencomply-cli -- rules validate rules/opencomply-headers.toml`

### Pack signature

The official pack is signed by the maintainer, and the binary refuses a pack that changed after signing. After editing the `.toml`, move `rules/opencomply-headers.toml.sig` aside while you test locally (the build then treats the pack as unsigned and warns "not signed"). Do not commit a deleted or changed `.sig`: the maintainer reviews and re-signs the pack before merging. Until then, tests that load the pack may fail on your pull request; that is expected.

## Commits and pull requests

- **Commit messages:** use [Conventional Commits](https://www.conventionalcommits.org/), for example `feat(headers): ...` or `fix(core): ...`.
- **Pull requests:** one topic per PR, with tests.
- **Sensitive content:** never commit secrets, personal data or scan results from real systems.

## License

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
