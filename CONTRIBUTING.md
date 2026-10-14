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

## Rule ใหม่

- Rule ID ตามรูปแบบของ module เช่น `HDR-011`; version แบบ `MAJOR.MINOR.PATCH`
- ต้องมี test ครบ: ผ่าน, ไม่ผ่าน, และหลักฐานไม่พอ
- ต้องมี `fix_hint` สั้นๆ และ `remediation` ที่ทำตามได้จริง
- `example_fix` เป็นตัวอย่างเท่านั้น — ค่าที่ต้องสร้างเองหรือเป็นความลับ (เช่น nonce, token) ต้องเขียนเป็น `<...>` เพื่อไม่ให้ copy ไปใช้ตรงๆ ได้
- `platforms.<id>` บอกว่าแก้ที่ไหนบนผู้ให้บริการนั้น พร้อม `note` เมื่อมีข้อจำกัด
- ตรวจด้วย `opencomply rules validate <file>`

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

## New rules

- **Rule IDs and versions:** follow the module's ID pattern, such as `HDR-011`, and use a `MAJOR.MINOR.PATCH` version.
- **Tests:** cover the pass, fail and insufficient-evidence cases.
- **Fix guidance:** include a short `fix_hint` and an actionable `remediation`.
- **Examples:** `example_fix` is only an example. Write values that must be generated or kept secret (nonces, tokens) as `<...>` so they can't be copied verbatim.
- **Platform guidance:** `platforms.<id>` says where to fix it on that provider, with a `note` for any limitation.
- **Validation:** check the pack with `opencomply rules validate <file>`.

## Commits and pull requests

- **Commit messages:** use [Conventional Commits](https://www.conventionalcommits.org/), for example `feat(headers): ...` or `fix(core): ...`.
- **Pull requests:** one topic per PR, with tests.
- **Sensitive content:** never commit secrets, personal data or scan results from real systems.

## License

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
