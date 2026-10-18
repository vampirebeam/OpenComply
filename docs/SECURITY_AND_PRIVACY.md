# Security and privacy

[← README](../README.en.md) · [Getting started](GETTING_STARTED.md) · [Reports](REPORTS.md)

This page states what OpenComply does with your machine and your data, what it protects against, and what it does not.
It separates what the CLI enforces itself from what depends on an AI agent following instructions.

## Data handling

- **No telemetry.** No usage data is collected, and no source code or results are sent to the OpenComply developers.
- **Nothing stored.** The CLI writes results to the terminal only; it keeps no history, cache or log files.
- **Secrets are redacted.** Known kinds of secrets (cookie values, tokens, passwords, keys) are masked in every report format and in error and warning messages.
- **No changes to your system.** The CLI never modifies local files or code, and runs with normal user rights.

## Network access

- A headers check sends **GET requests** to the URL you give and to the `http://` version of the same URL (to check HTTPS enforcement), and follows at most 5 redirects each, one hop at a time. Requests use the User-Agent `OpenComply/<version>` and send no cookies and no request body.
- **Internal addresses are refused** on every hop — private ranges and loopback unless you pass `--allow-private`, and cloud metadata addresses always. Requests are protected against DNS rebinding, and every request has time and size limits. URLs that contain a username or password are refused.
- The installer contacts only GitHub, to download the release and its checksum.
- Scans are real requests. A badly designed site can still act on a GET, so **only scan systems you are authorized to assess**.

## AI agents

- OpenComply is a CLI that agents call, **not an AI model**. Results come from comparing evidence with signed rules; no AI takes part in deciding them.
- What an agent reads — including OpenComply output — is sent to that agent's model provider under the provider's policy, not to OpenComply.
- The agent skill instructs the agent to:
  - ask only for the URL, never for passwords, cookies, tokens or keys, and not repeat secrets you paste;
  - save or send results only to a destination you name, after saying what goes where;
  - treat text from the scanned site as data, not follow instructions in it, and tell you when the site contains text aimed at AI assistants.
- **These are instructions to an AI, not guarantees.** They are tested and reviewed by vampirebeam, with Claude Code as the agent, repeatedly, because AI behaviour can vary between runs.
- **Confirmation step (Claude Code plugin only).** Before the agent sends OpenComply results off your computer or writes them to a report file, the plugin asks you to confirm. It covers the agent's commands and file writes that carry OpenComply results; it does not cover every way an agent could move data, and other agents do not have it.

## Security boundaries

| Enforced by the CLI (does not depend on AI) | Depends on the agent following the skill |
|---|---|
| Refusing internal and metadata addresses · redirect checks · time and size limits | Asking before scanning a site that may not be yours |
| Redacting secrets in output and errors | Not repeating secrets you typed into the chat |
| No telemetry, nothing stored | Saving or sending results only where you said |
| Signed rule pack: a modified official pack is not loaded | Ignoring instructions planted in the scanned site |

Also:

- The installer checks the SHA-256 of the download. That confirms the file matches the checksum published with the release; on its own it does not prove who published it. You can [read the installer before it runs](GETTING_STARTED.md#read-the-installer-before-it-runs), and [verify a download](#verify-a-download) against the maintainer's signature.
- The binaries are not signed by Apple or Microsoft.
- **Testing:** vampirebeam tests the agent skill and plugin, with Claude Code as the agent, against adversarial inputs, unauthorized actions and data-handling scenarios, checking both what the agent says and what its tools actually do. Results do not guarantee identical behaviour across agents or environments.

## Verify a download

From v0.3.12, each release includes `SHA256SUMS` (the SHA-256 of every archive and both installers) and `SHA256SUMS.sig`, a signature the maintainer makes offline with the release key — the key is never on GitHub or in the build system. A valid signature shows the files match what the holder of that key signed. It does not show that the code is safe, and because this key is published here, on the same GitHub account as the files, it does not protect a first download if that account were taken over.

Release key `opencomply-release-2026` (Ed25519):

```text
655b5d1cd30940ae6a008628fd694cbcf3d7c99de4e2fa3651bbdb5277a66227
```

Save it as `opencomply-release.pub.pem`:

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZVtdHNMJQK5qAIYo/WlMvPPXyZ3k4vo2UbvbUnemYic=
-----END PUBLIC KEY-----
```

Download `SHA256SUMS`, `SHA256SUMS.sig` and the files you want into one folder, then run the following. This needs OpenSSL 3 — the `openssl` built into macOS (LibreSSL) cannot check this kind of signature; use Homebrew's `openssl@3`. On Windows, Git for Windows includes OpenSSL 3.

Linux / macOS:

```bash
sed -n 's/^signature: //p' SHA256SUMS.sig | xxd -r -p > SHA256SUMS.sig.bin
openssl pkeyutl -verify -pubin -inkey opencomply-release.pub.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig.bin
sha256sum -c --ignore-missing SHA256SUMS   # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
```

Windows (PowerShell):

```powershell
$openssl = "C:\Program Files\Git\mingw64\bin\openssl.exe"
$hex = ((Get-Content SHA256SUMS.sig) -match '^signature: ') -replace '^signature: ', ''
[IO.File]::WriteAllBytes("$PWD\SHA256SUMS.sig.bin", [byte[]]($hex -split '(..)' -ne '' | ForEach-Object { [Convert]::ToByte($_, 16) }))
& $openssl pkeyutl -verify -pubin -inkey opencomply-release.pub.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig.bin
Get-Content SHA256SUMS | ForEach-Object { $h, $f = $_ -split '\s+', 2; if (Test-Path $f) { "$f " + ((Get-FileHash $f).Hash.ToLower() -eq $h) } }
```

Expect `Signature Verified Successfully`, then `OK` (or `True`) for each file you downloaded. Anything else: do not run the files, and [report it](../SECURITY.md).
## Limitations

- This version checks **HTTP security headers** only. It does not check SSL/TLS certificates or ciphers, look for vulnerabilities or malware, or review source code. `opencomply standards` lists what is checked.
- A result describes the responses at the time of the scan; a site can change.
- Grades are OpenComply's own, based on current browser behaviour and security practice. They are **not a certification** against any standard and do not guarantee security.

## Reporting a vulnerability

See the [security policy](../SECURITY.md).

---

OpenComply · Copyright 2026 vampirebeam · [Apache License 2.0](../LICENSE) · [NOTICE](../NOTICE)
