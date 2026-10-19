# Getting started

[← README](../README.en.md) · [Reports](REPORTS.md) · [Security and privacy](SECURITY_AND_PRIVACY.md)

## With an AI agent

### Claude Code

```text
/plugin marketplace add vampirebeam/OpenComply
/plugin install opencomply@opencomply
```

Then ask in your own words, e.g. *"Check https://example.com"* or *"Is my site secure?"*, or run `/opencomply <URL>`. On first use the agent asks before installing the CLI for you (the same way as the command below).

**For the best results:** give the full URL of the page to check (a login page also shows the cookie checks), say when an internal site is yours, and ask for *the evidence report* when you need the details. Nothing else is needed — never passwords or cookies.

An example of how an agent may summarize a result:

> **You:** Check the security headers of example.com.
>
> **AI:** **Grade D (63)**: 3 items to fix, 6 checks passed. The site runs **Next.js** behind **Cloudflare**.
>
> 🔴 **1. CSP allows inline scripts** · HDR-002 · high. Fixing only this raises the score to 89 (B), and A+ requires it. The recommended place is Next.js middleware, which creates a new nonce per request:
> ```
> script-src 'self' 'nonce-<random-per-request>' https://www.googletagmanager.com
> ```
> This is a starting point, not a drop-in policy. Test with `Content-Security-Policy-Report-Only` before enforcing.
>
> 🟠 **2. Permissions-Policy is missing** · HDR-005 · low. Fixing 1 and 2 gives **A+ (95)**.
>
> 🟠 **3. `X-Powered-By: Next.js`** · HDR-010 · low. Set `poweredByHeader: false` in `next.config.js`.

The skill instructs the agent to explain findings and ask for approval before making changes. Review any proposed change before applying it.

### Other agents that support Agent Skills

The skill folder [`plugins/opencomply/skills/opencomply`](../plugins/opencomply/skills/opencomply) follows the Agent Skills format (e.g. Codex, Cursor, Gemini CLI) and can be installed with that agent's skill install method. It works without the Claude Code plugin's confirmation step. The skill is tested and reviewed by vampirebeam, with Claude Code as the agent.

## Install the CLI

```bash
# Linux x86_64 / macOS Apple Silicon
curl -fsSL https://github.com/vampirebeam/OpenComply/releases/latest/download/install.sh | sh
```

```powershell
# Windows x86_64 (PowerShell)
irm https://github.com/vampirebeam/OpenComply/releases/latest/download/install.ps1 | iex
```

Then open a new terminal and run `opencomply`. The installer downloads the release for your operating system, checks its SHA-256 before installing, and needs no admin rights (Windows: `%LOCALAPPDATA%\opencomply\bin` on the user PATH · Linux / macOS: `~/.local/bin/opencomply`).

### Read the installer before it runs

```bash
curl -fsSLO https://github.com/vampirebeam/OpenComply/releases/latest/download/install.sh
# read install.sh, then:
sh install.sh
```

```powershell
irm https://github.com/vampirebeam/OpenComply/releases/latest/download/install.ps1 -OutFile install.ps1
# read install.ps1, then:
& ([scriptblock]::Create((Get-Content install.ps1 -Raw)))
```

The SHA-256 check confirms the download matches the checksum published with the release; on its own it does not prove who published it.

### Uninstall

```bash
curl -fsSL https://github.com/vampirebeam/OpenComply/releases/latest/download/install.sh | sh -s -- --uninstall
```

```powershell
& ([scriptblock]::Create((irm https://github.com/vampirebeam/OpenComply/releases/latest/download/install.ps1))) -Uninstall
```

### Download manually

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

## Usage

```bash
opencomply scan headers https://example.com      # HTTP security headers
opencomply scan headers example.com              # no scheme = https://
opencomply standards                             # what OpenComply checks, scanner and report schema versions
opencomply standards --format json               # the same as JSON, for agents and other programs
opencomply schema report                         # JSON Schema of the report
```

| Option | Description |
|---|---|
| *(none)* | Short summary that is easy to read and uses few tokens |
| `--format markdown` | Report with details and evidence |
| `--format json` | Structured data for other programs |
| `--compact` | With `--format json`: leave out long guidance and the evidence of passed checks |
| `--all` | Show every check, including those that passed |
| `--fail-on review` | Items that still need a decision (`REVIEW`) also fail the command |
| `--allow-private` | Allow internal systems you are authorized to scan, such as staging (private addresses are refused by default; cloud metadata is always refused) |

How to read the output, the grade and the exit codes: [Reports](REPORTS.md).

---

OpenComply · Copyright 2026 vampirebeam · [Apache License 2.0](../LICENSE) · [NOTICE](../NOTICE)
