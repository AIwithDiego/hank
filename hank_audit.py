#!/usr/bin/env python3
"""
Hank: AI-security audit for your Claude Code agentic OS.

Hank statically scans a Claude Code setup (CLAUDE.md, skills, .mcp.json,
settings.json, hooks, .env) and reports security findings mapped to the
OWASP LLM Top 10 (2025) plus agentic-specific risks (MCP tool poisoning,
rug-pulls, excessive agency, secret leaks).

No dependencies. Python 3.8+. It never modifies the files it scans; the only
files it writes are the reports you ask for.

The scanned tree is treated as untrusted input: it cannot supply config to
Hank (memes, suppressions) unless the operator opts in, its text is
sanitised before it reaches a terminal or a report, and secrets are masked.

Usage:
    python3 hank_audit.py [TARGET_DIR] [--json] [--min-severity low] [--no-color]

    TARGET_DIR                directory to scan (default: current directory)
    --json                    emit findings as JSON instead of the report
    --min-severity            critical|high|medium|low|info (default: info)
    --no-color                disable ANSI colors
    -o, --output              also write a markdown report to this path
    --html [PATH]             write the HTML report card
    --gifs                    let the HTML card load reaction GIFs from Giphy
    --memes FILE              meme config for the HTML card (default: Hank's own)
    --ignore-file FILE        operator-supplied ignore globs (always applied)
    --allow-repo-suppressions honour the scanned repo's .hankignore and
                              inline hank:ignore markers
    --show-secrets            print secrets unmasked (local debugging only)
"""

import argparse
import fnmatch
import hashlib
import html as htmllib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))

# Resource bounds (LLM10). A hostile repo must not be able to hang a CI gate.
MAX_FILE_BYTES = 2 * 1024 * 1024   # read at most this much of any file
MAX_SEGMENT = 4096                 # long lines are matched in windows this wide
SEGMENT_OVERLAP = 512              # windows overlap so a match on a seam is kept

# Set by --show-secrets. Off by default: every output format masks secrets.
SHOW_SECRETS = False

# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}
SEVERITY_COLOR = {
    "critical": "\033[97;41m",  # white on red
    "high": "\033[91m",          # red
    "medium": "\033[93m",        # yellow
    "low": "\033[96m",           # cyan
    "info": "\033[90m",          # grey
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
BLUE = "\033[94m"
GREEN = "\033[92m"


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str
    owasp: str
    why: str
    fix: str

    def sort_key(self):
        return (SEVERITY_ORDER[self.severity], self.file, self.line)


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}

# Files Hank knows how to reason about, by role.
CONFIG_NAMES = {".mcp.json", "settings.json", "settings.local.json", "mcp.json", "hooks.json"}
DOC_NAMES = {"claude.md"}
SKILL_NAME = "skill.md"
# Subagent and slash-command definitions: *.md under agents/ or commands/ that
# sit in a .claude/ dir or at a plugin root (a dir holding .claude-plugin/).
AGENT_DIRS = {"agents", "commands"}


@dataclass
class Target:
    config_files: List[str] = field(default_factory=list)
    doc_files: List[str] = field(default_factory=list)
    skill_files: List[str] = field(default_factory=list)
    env_files: List[str] = field(default_factory=list)
    agent_files: List[str] = field(default_factory=list)
    # symlinks that resolve outside the scan root: listed, never read
    outside_links: List[str] = field(default_factory=list)


# Inline suppression: a line containing this marker drops findings on that line
# (only with --allow-repo-suppressions, and never for critical findings).
IGNORE_MARKER = re.compile(r"hank[:\-]ignore")


def parse_ignore_lines(lines: List[str]) -> List[str]:
    globs = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            globs.append(line.rstrip("/"))
    return globs


def load_ignore_globs(root: str) -> List[str]:
    """Read the scanned repo's own .hankignore (globs relative to root)."""
    path = os.path.join(root, ".hankignore")
    if os.path.isfile(path) and not os.path.islink(path):
        return parse_ignore_lines(read_lines(path))
    return []


def load_ignore_file(path: str) -> List[str]:
    """Read an operator-supplied ignore file (--ignore-file)."""
    return parse_ignore_lines(read_lines(path))


def is_ignored(relpath: str, globs: List[str]) -> bool:
    for g in globs:
        if fnmatch.fnmatch(relpath, g) or fnmatch.fnmatch(relpath, g + "/*") or relpath.startswith(g.rstrip("*").rstrip("/") + "/"):
            return True
    return False


def is_within(path: str, root: str) -> bool:
    """True if `path` is `root` or inside it. Both must already be realpaths."""
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def file_role(dirpath: str, fn: str) -> Optional[str]:
    low = fn.lower()
    if low in CONFIG_NAMES:
        return "config_files"
    if low in DOC_NAMES:
        return "doc_files"
    if low == SKILL_NAME:
        return "skill_files"
    if low == ".env" or low.startswith(".env."):
        return "env_files"
    if low.endswith(".md") and os.path.basename(dirpath) in AGENT_DIRS:
        parent = os.path.dirname(dirpath)
        if os.path.basename(parent) == ".claude" or os.path.isdir(os.path.join(parent, ".claude-plugin")):
            return "agent_files"
    return None


def collect(root: str) -> Target:
    """List the files Hank scans. Suppression is applied later, per finding, so
    that every report can say how many findings were suppressed and by what.
    os.walk does not descend into symlinked dirs; symlinked files are kept only
    when they resolve inside the scan root."""
    t = Target()
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            role = file_role(dirpath, fn)
            if role is None:
                continue
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) and not is_within(os.path.realpath(full), real_root):
                t.outside_links.append(full)
                continue
            getattr(t, role).append(full)
    return t


def ignored_linenos(lines: List[str]) -> Set[int]:
    return {i for i, line in enumerate(lines, 1) if IGNORE_MARKER.search(line)}


def read_text(path: str) -> Tuple[List[str], str]:
    """Read a file safely. Returns (lines, status); status is 'ok', 'oversize'
    (only the first MAX_FILE_BYTES were read), 'not-regular' (FIFO, device,
    directory: never read, so it cannot block) or 'error'."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return [], "error"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return [], "not-regular"
        with os.fdopen(fd, "rb") as f:
            fd = -1  # the file object owns it now
            data = f.read(MAX_FILE_BYTES + 1)
    except OSError:
        return [], "error"
    finally:
        if fd >= 0:
            os.close(fd)
    status = "oversize" if len(data) > MAX_FILE_BYTES else "ok"
    text = data[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    return text.splitlines(), status


def read_lines(path: str) -> List[str]:
    return read_text(path)[0]


def iter_segments(lines: List[str]):
    """Yield (lineno, segment, line). Normal lines are one segment. A very long
    line is matched in overlapping windows, so regex cost stays linear in the
    file size and a payload far along the line is still seen."""
    step = MAX_SEGMENT - SEGMENT_OVERLAP
    for i, line in enumerate(lines, 1):
        if len(line) <= MAX_SEGMENT:
            yield i, line, line
            continue
        for start in range(0, len(line), step):
            yield i, line[start:start + MAX_SEGMENT], line
            if start + MAX_SEGMENT >= len(line):
                break


def rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


# C0/C1 control characters, DEL, and the invisible zero-width / bidi / BOM
# characters. Any of these in scanned text could rewrite the user's terminal
# (ANSI/OSC escapes) or hide text from a reviewer, so they are shown escaped.
UNSAFE_CHARS = re.compile(
    r"[\x00-\x1f\x7f-\x9f"
    r"\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"
    r"|[\U000e0000-\U000e007f]"
)


def clean(text: str) -> str:
    """Make scanned text inert for a terminal or report: every control or
    invisible character becomes a visible \\xNN / \\uNNNN escape."""
    def _esc(m):
        c = ord(m.group(0))
        if c <= 0xFF:
            return "\\x%02x" % c
        if c <= 0xFFFF:
            return "\\u%04x" % c
        return "\\U%08x" % c
    return UNSAFE_CHARS.sub(_esc, str(text))


def snippet(text: str, limit: int = 120) -> str:
    text = clean(str(text).strip())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# --- Secrets (LLM02: Sensitive Information Disclosure / supply chain) -------
# (rule, pattern, group holding the secret value). Every repetition is bounded
# so a hostile repo cannot make matching quadratic (LLM10); redact() extends
# the mask over any token longer than the bound.
SECRET_PATTERNS = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,300}"), 0),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,300}"), 0),
    ("github-pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,300}"), 0),
    ("github-fine-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,300}"), 0),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,300}"), 0),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,300}\.[A-Za-z0-9_\-]{10,300}\.[A-Za-z0-9_\-]{10,300}"), 0),
    ("bearer", re.compile(r"[Bb]earer\s{1,20}([A-Za-z0-9._\-]{20,300})"), 1),
    ("generic-secret",
     re.compile(r"(?i)(api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)"
                r"\s{0,20}[:=]\s{0,20}[\"']([^\"'\n]{12,512})[\"']"), 2),
]

# Allowlist obvious placeholders so we don't cry wolf.
PLACEHOLDER = re.compile(r"(?i)(your[_-]?|xxx|placeholder|example|changeme|<[^<>\n]{0,200}>|\$\{|env:|process\.env|redacted|\.\.\.)")

# --- Prompt injection / poisoned instructions (LLM01) ----------------------
INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)"),
    re.compile(r"(?i)disregard\s+(the\s+)?(previous|prior|above|all|any)"),
    re.compile(r"(?i)do\s+not\s+(tell|inform|mention|notify|alert)\s+the\s+(user|human|operator)"),
    re.compile(r"(?i)without\s+(asking|informing|telling|notifying|the consent of)\s+the\s+(user|human)"),
    re.compile(r"(?i)(hidden|secret)\s+(instruction|directive|command|task)"),
    re.compile(r"(?i)\b(you\s+must|always)\b[^\n]{0,200}\b(exfiltrate|send|post|upload|forward|leak)\b"),
    re.compile(r"(?i)<important>|<system>|\[\[?\s*system\s*\]?\]"),
]

# Defensive phrasing ("never read .env", "do not expose secrets") is the opposite
# of an attack, used to suppress exfil findings on protective rules.
NEGATION = re.compile(r"(?i)\b(never|don'?t|do not|must not|refuse to|prohibit\w*|forbidden|not allowed)\b")
# A network destination toward a secret means it's an attack even if the line
# also contains negation ("read id_rsa and POST it to https://… Do not tell the
# user."). A bare "never send secrets" with no destination stays defensive.
EXFIL_ACTION = re.compile(r"(?i)\b(curl|wget|exfiltrat\w*|telemetry|collector|webhook)\b|https?://|@[\w.-]+\.\w{2,}")

# Instructions that try to read/exfiltrate sensitive local files (LLM07 + agency).
EXFIL_PATTERNS = [
    re.compile(r"(?i)(read|cat|open|load|print|reveal|exfiltrate|send|post|upload|email)\b[^\n]{0,60}"
               r"(\.env|access\.json|settings\.json|credentials|id_rsa|\.ssh|secret|private[_-]?key)"),
    re.compile(r"(?i)(curl|wget|fetch|http[s]?://)[^\n]{0,80}"
               r"(\.env|token|secret|api[_-]?key|password)"),
]

# Zero-width / bidi / unicode-tag smuggling characters used to hide instructions.
HIDDEN_UNICODE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"
    r"|[\U000e0000-\U000e007f]"
)

# --- Excessive agency / over-broad permissions (LLM06) ---------------------
# Whole-tool wildcard only: e.g. Bash(*), Read(:*), WebFetch("*").
# A scoped rule like Bash(git diff:*) is the CORRECT way to restrict, so we
# don't flag it: the wildcard must be the entire argument.
BROAD_PERMISSION = re.compile(r"(?i)\b(Bash|Read|Write|Edit|WebFetch|Execute|Glob|Grep)\s*\(\s*[\"']?:?\*[\"']?\s*\)")
DANGEROUS_BASH = re.compile(r"(?i)Bash\(\s*[\"']?(rm\s|sudo|curl|wget|chmod\s+777|:\(\)|dd\s|mkfs|eval)")
BYPASS_PERMISSIONS = re.compile(r"(?i)(bypassPermissions|dangerouslySkipPermissions|dangerously-skip-permissions|--yes\b|autoApprove\s*[:=]\s*true|acceptEdits)")

# --- Dangerous hook commands (LLM06 / RCE) ---------------------------------
PIPE_TO_SHELL = re.compile(r"(?i)(curl|wget|fetch)[^\n|]{0,300}\|\s{0,20}(sh|bash|zsh|python3?|node)\b")
# Cheap single-pass prefilters: the gap regexes below only run on text that
# contains their required tail, so a line full of "curl curl curl" stays fast.
PIPE_TAIL = re.compile(r"\|")
NETWORK_TAIL = re.compile(r"(?i)-X\s{0,20}POST|--data|-d\s|https?://")
HOOK_NETWORK_EXFIL = re.compile(r"(?i)(curl|wget|nc|netcat)\s[^\n]{0,300}\b(-X\s{0,20}POST|--data|-d\s|http[s]?://)")

# --- Supply chain: unpinned / untrusted MCP servers (LLM03) ----------------
HTTP_INLINE_TOKEN = re.compile(
    r"(?i)[\"']?(authorization|x-api-key|\b[a-z_]{0,40}(?:token|api[_-]?key|secret))[\"']?"
    r"\s{0,20}[:=]\s{0,20}[\"']([^\"'\n]{8,512})[\"']")


# ---------------------------------------------------------------------------
# Evidence: secrets masked, control characters escaped
# ---------------------------------------------------------------------------

AUTH_SCHEME = re.compile(r"(?i)(bearer|basic|token)\s{1,20}")
TOKEN_CHARS = re.compile(r"[A-Za-z0-9._\-+/=]{0,4096}")


def mask_value(value: str) -> str:
    """Show only a short prefix and the length of a secret."""
    return f"{value[:4]}[REDACTED {len(value)} chars]"


def redact(text: str) -> str:
    """Mask every secret-looking value in `text` (all output formats go
    through this). --show-secrets turns it off for local debugging."""
    if SHOW_SECRETS:
        return text
    spans = []
    for _rule, pat, grp in SECRET_PATTERNS:
        for m in pat.finditer(text):
            spans.append(m.span(grp))
    for m in HTTP_INLINE_TOKEN.finditer(text):
        s, e = m.span(2)
        scheme = AUTH_SCHEME.match(text, s)  # keep "Bearer " readable, mask the token
        spans.append((scheme.end() if scheme else s, e))
    if not spans:
        return text
    # extend each span over the rest of the token, then merge overlaps
    merged: List[List[int]] = []
    for s, e in sorted(spans):
        e = TOKEN_CHARS.match(text, e).end()
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, last = [], 0
    for s, e in merged:
        value = text[s:e]
        out.append(text[last:s])
        # ${VAR} / env: references are not secrets; leave them readable
        out.append(value if value.startswith(("${", "$", "env:", "process.env")) else mask_value(value))
        last = e
    out.append(text[last:])
    return "".join(out)


def ev(line: str, limit: int = 120, as_repr: bool = False) -> str:
    """Evidence for a finding: first `limit` chars of the line, secrets masked,
    control and invisible characters escaped. Redaction runs on a window wide
    enough to hold any secret that starts inside the displayed part."""
    text = redact(line.strip()[:limit + 1024])
    if as_repr:
        text = repr(text)
    return snippet(text, limit)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_secrets(path: str, lines: List[str], root: str) -> List[Finding]:
    out = []
    for i, seg, line in iter_segments(lines):
        for rule, pat, grp in SECRET_PATTERNS:
            for m in pat.finditer(seg):
                value = m.group(grp)
                if PLACEHOLDER.search(value):
                    continue
                out.append(Finding(
                    rule_id=f"SECRET-{rule}",
                    severity="critical",
                    title=f"Hard-coded secret in config ({rule})",
                    file=rel(path, root), line=i,
                    evidence=ev(line),
                    owasp="LLM02:2025 Sensitive Information Disclosure",
                    why="A live credential committed to a Claude Code config leaks via disk, "
                        "git history, the /mcp UI, and the model's own context. Anyone with the "
                        "repo (or the agent) can read and use it.",
                    fix="Move the secret to an environment variable or OS keychain. For MCP "
                        "servers, prefer hosted OAuth over inline tokens. Rotate the exposed key now.",
                ))
                break  # one finding per rule per segment is enough
    return out


def detect_injection(path: str, lines: List[str], root: str, kind: str) -> List[Finding]:
    out = []
    for i, line, full in iter_segments(lines):
        for pat in INJECTION_PATTERNS:
            if pat.search(line):
                out.append(Finding(
                    rule_id="INJ-instruction-override",
                    severity="high" if kind == "config" else "medium",
                    title="Prompt-injection / instruction-override phrasing",
                    file=rel(path, root), line=i,
                    evidence=ev(full),
                    owasp="LLM01:2025 Prompt Injection",
                    why="Override phrasing inside a tool description, skill, or doc is the classic "
                        "agentic injection vector: the agent treats it as a trusted instruction and "
                        "can be steered against the user.",
                    fix="Remove the override phrasing. Tool/skill text should describe capability, "
                        "never instruct the agent to ignore rules or hide actions from the user.",
                ))
                break
        for pat in EXFIL_PATTERNS:
            if pat.search(line):
                if NEGATION.search(line) and not EXFIL_ACTION.search(line):
                    break  # protective rule ("never read .env"), not an attack
                out.append(Finding(
                    rule_id="INJ-exfil-instruction",
                    severity="critical",
                    title="Instruction to read or exfiltrate sensitive files",
                    file=rel(path, root), line=i,
                    evidence=ev(full),
                    owasp="LLM01:2025 Prompt Injection / LLM06 Excessive Agency",
                    why="Text directing the agent to read .env / credentials / SSH keys and send "
                        "them anywhere is a data-exfiltration payload. In an MCP tool description "
                        "this is a textbook tool-poisoning attack.",
                    fix="Delete the instruction. If the tool legitimately needs a secret, pass it "
                        "via environment, never by having the agent read a secrets file.",
                ))
                break
        if HIDDEN_UNICODE.search(line):
            out.append(Finding(
                rule_id="INJ-hidden-unicode",
                severity="high",
                title="Hidden / bidirectional Unicode characters",
                file=rel(path, root), line=i,
                evidence=ev(full, as_repr=True),
                owasp="LLM01:2025 Prompt Injection",
                why="Zero-width, bidi-override, or Unicode-tag characters can smuggle instructions "
                    "the human reviewer can't see but the model still reads.",
                fix="Strip non-printing Unicode from instructions, tool descriptions, and configs.",
            ))
    return out


def detect_permissions(path: str, lines: List[str], root: str) -> List[Finding]:
    out = []
    for i, line, full in iter_segments(lines):
        if DANGEROUS_BASH.search(line):
            out.append(Finding(
                rule_id="AGENCY-dangerous-bash-allow",
                severity="high",
                title="Dangerous shell command pre-approved in permissions",
                file=rel(path, root), line=i, evidence=ev(full),
                owasp="LLM06:2025 Excessive Agency",
                why="Pre-allowing rm/sudo/curl/eval means the agent can run destructive or "
                    "exfiltrating commands with no human gate; a single bad instruction becomes RCE.",
                fix="Scope allow-rules to specific safe commands. Never wildcard-allow shells that "
                    "can delete, escalate, or reach the network.",
            ))
        elif BROAD_PERMISSION.search(line):
            out.append(Finding(
                rule_id="AGENCY-wildcard-permission",
                severity="high",
                title="Wildcard tool permission",
                file=rel(path, root), line=i, evidence=ev(full),
                owasp="LLM06:2025 Excessive Agency",
                why="A wildcard allow (e.g. Bash(*)) grants the agent unbounded use of a powerful "
                    "tool. Excessive agency is the amplifier that turns a prompt injection into impact.",
                fix="Replace wildcards with an explicit allowlist of the exact commands you need.",
            ))
        if BYPASS_PERMISSIONS.search(line):
            out.append(Finding(
                rule_id="AGENCY-bypass-permissions",
                severity="critical",
                title="Permission prompts disabled / auto-approved",
                file=rel(path, root), line=i, evidence=ev(full),
                owasp="LLM06:2025 Excessive Agency",
                why="Bypassing or auto-approving permissions removes the human-in-the-loop entirely. "
                    "Any injected instruction executes silently.",
                fix="Keep permission prompts on for anything that writes, deletes, or reaches the "
                    "network. Reserve bypass mode for sandboxed, throwaway environments only.",
            ))
    return out


def detect_hooks(path: str, lines: List[str], root: str) -> List[Finding]:
    out = []
    for i, line, full in iter_segments(lines):
        if PIPE_TAIL.search(line) and PIPE_TO_SHELL.search(line):
            out.append(Finding(
                rule_id="HOOK-pipe-to-shell",
                severity="critical",
                title="Hook pipes a network download straight into a shell",
                file=rel(path, root), line=i, evidence=ev(full),
                owasp="LLM03:2025 Supply Chain / LLM06 Excessive Agency",
                why="`curl … | sh` in a hook runs whatever the remote server returns, every session. "
                    "A compromised or swapped URL is instant remote code execution on your machine.",
                fix="Vendor the script locally, pin it, and review it. Never pipe a live download "
                    "into an interpreter from a hook.",
            ))
        elif NETWORK_TAIL.search(line) and HOOK_NETWORK_EXFIL.search(line):
            out.append(Finding(
                rule_id="HOOK-network-exfil",
                severity="high",
                title="Hook sends data to an external endpoint",
                file=rel(path, root), line=i, evidence=ev(full),
                owasp="LLM06:2025 Excessive Agency / data exfiltration",
                why="A hook that POSTs to a URL can quietly ship your prompts, files, or secrets "
                    "off-box on every trigger.",
                fix="Confirm the endpoint is yours and the payload carries no sensitive data. Prefer "
                    "local logging; if you must send, redact and pin the destination.",
            ))
    return out


RUNNERS = {"npx", "uvx", "bunx", "dlx", "pnpm"}


def find_line(lines: List[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 1


def parse_json(lines: List[str]):
    """Parse a config as JSON; None if it isn't (or is pathologically nested)."""
    try:
        return json.loads("\n".join(lines))
    except (ValueError, TypeError, RecursionError):
        return None


def json_strings(data, limit: int = 20000):
    """Every string (keys and values) in parsed JSON, iteratively."""
    stack, n = [data], 0
    while stack and n < limit:
        node = stack.pop()
        if isinstance(node, str):
            n += 1
            yield node
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append(k)
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)


def detect_json_escaped(path: str, lines: List[str], root: str, data) -> List[Finding]:
    """Run the injection and hidden-Unicode detectors on decoded JSON strings.
    Raw-text matching misses payloads written as JSON escapes
    (\\u200b, \\u0069gnore previous instructions ...), which is exactly how a
    poisoned MCP tool description would hide them."""
    raw = "\n".join(lines)
    out = []
    for s in json_strings(data):
        encoded = json.dumps(s, ensure_ascii=False)[1:-1]
        if encoded in raw:
            continue  # written plainly: the raw-text scan already covered it
        # best-effort line: where the string's first plain run appears
        probe = re.match(r"[A-Za-z0-9 _.,:;!?'-]{6,}", s)
        lineno = find_line(lines, probe.group(0)) if probe else 1
        for f in detect_injection(path, s.splitlines() or [s], root, kind="config"):
            f.line = lineno
            f.evidence = ev(s, as_repr=f.rule_id == "INJ-hidden-unicode")
            f.title += " (JSON-escaped)"
            out.append(f)
    return out


def detect_supply_chain(path: str, lines: List[str], root: str, data=None) -> List[Finding]:
    out = []

    # Inline tokens: line-based so it covers any config shape (skip placeholders).
    for i, line, full in iter_segments(lines):
        m = HTTP_INLINE_TOKEN.search(line)
        if m and not PLACEHOLDER.search(m.group(2)):
            out.append(Finding(
                rule_id="SUPPLY-inline-mcp-token",
                severity="high",
                title="Inline auth token in MCP server config",
                file=rel(path, root), line=i, evidence=ev(full),
                owasp="LLM02:2025 Sensitive Information Disclosure",
                why="A PAT or API key inlined in .mcp.json leaks via disk, the process list, and "
                    "Claude's own /mcp UI. Hosted OAuth keeps the token in the OS keychain instead.",
                fix="Switch the server to hosted OAuth, or load the token from the environment. "
                    "Never commit it to the config.",
            ))

    # Unpinned MCP packages: JSON-aware so a version pin on the args line counts.
    if data is None:
        data = parse_json(lines)
    if not isinstance(data, dict):
        return out
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    if not isinstance(servers, dict):
        return out
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", ""))
        arglist = cfg.get("args", []) or []
        if not isinstance(arglist, list):
            arglist = [arglist]
        tokens = [cmd] + [str(a) for a in arglist]
        runner = os.path.basename(cmd) in RUNNERS or any(t in RUNNERS for t in tokens)
        if not runner:
            continue
        pinned = any(re.search(r"@\d", t) for t in tokens) or \
            any(t.startswith((".", "/", "~")) for t in tokens)
        if not pinned:
            out.append(Finding(
                rule_id="SUPPLY-unpinned-mcp",
                severity="medium",
                title=f"MCP server '{snippet(name, 60)}' runs an unpinned package",
                file=rel(path, root), line=find_line(lines, '"' + name + '"'),
                evidence=ev(" ".join(tokens)),
                owasp="LLM03:2025 Supply Chain",
                why="Pulling an MCP server via npx/uvx with no version pin means you run whatever the "
                    "registry serves today, which is the rug-pull vector: a benign tool ships a malicious "
                    "update and your agent trusts it.",
                fix="Pin the exact version (e.g. package@1.2.3) and bump deliberately after review.",
            ))
    return out


def check_hygiene(target: Target, root: str) -> List[Finding]:
    """Positive/negative posture checks across the whole setup."""
    out = []
    # .env committed alongside the project is a leak risk if present at all.
    for env in target.env_files:
        out.append(Finding(
            rule_id="HYGIENE-env-present",
            severity="medium",
            title=".env file present in the scanned tree",
            file=rel(env, root), line=1, evidence=os.path.basename(env),
            owasp="LLM02:2025 Sensitive Information Disclosure",
            why="A readable .env in the project tree can be picked up by the agent, a skill, or a "
                "mis-scoped Read permission, and accidentally committed.",
            fix="Confirm .env is git-ignored, never referenced by a skill/hook for output, and not "
                "readable by broad Read() permissions.",
        ))
    # Does any CLAUDE.md establish a 'never expose secrets / never commit .env' rule?
    has_secret_rule = False
    for doc in target.doc_files:
        text = "\n".join(read_lines(doc)).lower()
        if re.search(r"(?i)(never|don'?t|do not|must not)\b[^\n]{0,60}"
                     r"(\.env|secret|credential|token|api[_-]?key|password)", text):
            has_secret_rule = True
            break
    if target.doc_files and not has_secret_rule:
        out.append(Finding(
            rule_id="HYGIENE-no-secret-rule",
            severity="low",
            title="No explicit secret-handling rule in CLAUDE.md",
            file=rel(target.doc_files[0], root), line=1, evidence="CLAUDE.md",
            owasp="LLM02:2025 Sensitive Information Disclosure",
            why="CLAUDE.md sets the agent's standing rules. Without an explicit 'never expose/commit "
                "secrets' instruction, nothing reminds the agent to refuse those requests.",
            fix="Add a hard rule: never read, print, or commit .env / credentials / settings secrets.",
        ))
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def scan_integrity_finding(rule: str, severity: str, title: str, path: str, root: str,
                           why: str, fix: str) -> Finding:
    return Finding(
        rule_id=rule, severity=severity, title=title,
        file=rel(path, root), line=1, evidence=snippet(os.path.basename(path)),
        owasp="Scanner integrity", why=why, fix=fix)


@dataclass
class Suppression:
    """What was (or would have been) suppressed, and by what. Every report
    states this so a clean result can never hide a suppression."""
    allowed: bool = False          # --allow-repo-suppressions given
    operator: int = 0              # dropped by --ignore-file (always applied)
    repo_ignore: int = 0           # matched the scanned repo's .hankignore
    inline: int = 0                # on a line carrying hank:ignore
    inline_critical_kept: int = 0  # criticals an inline marker could not drop

    @property
    def applied(self) -> int:
        return self.operator + (self.repo_ignore + self.inline if self.allowed else 0)

    @property
    def requested_by_repo(self) -> int:
        return self.repo_ignore + self.inline

    def summary(self) -> str:
        parts = []
        if self.operator:
            parts.append(f"{self.operator} by --ignore-file")
        if self.allowed:
            if self.repo_ignore:
                parts.append(f"{self.repo_ignore} by the repo's .hankignore")
            if self.inline:
                parts.append(f"{self.inline} by inline hank:ignore")
        text = f"{self.applied} finding{'' if self.applied == 1 else 's'} suppressed"
        text += (" (" + ", ".join(parts) + ")") if parts else ""
        if not self.allowed and self.requested_by_repo:
            text += (f". The scanned repo asked to suppress {self.requested_by_repo} more "
                     f"(.hankignore {self.repo_ignore}, inline {self.inline}); not applied "
                     "without --allow-repo-suppressions")
        if self.inline_critical_kept:
            text += (f". {self.inline_critical_kept} critical finding"
                     f"{'' if self.inline_critical_kept == 1 else 's'} kept: inline markers "
                     "never suppress criticals")
        return text + "."


def run_audit_detailed(root: str, allow_repo_suppressions: bool = False,
                       ignore_file: Optional[str] = None):
    """Scan `root`. Returns (findings, target, suppression).

    Suppression sources, in order:
      1. --ignore-file globs (operator-supplied): always applied.
      2. the scanned repo's .hankignore and inline hank:ignore markers: only
         with allow_repo_suppressions, because the repo under review must not
         be able to mark itself clean. Inline markers never drop criticals.
    """
    target = collect(root)
    findings: List[Finding] = []
    marked: Dict[str, Set[int]] = {}  # rel-path -> lines carrying hank:ignore

    def scan(path: str, kind: str):
        lines, status = read_text(path)
        if status == "not-regular":
            findings.append(scan_integrity_finding(
                "SCAN-not-regular-file", "medium", "Agent config is not a regular file",
                path, root,
                why="A FIFO, device or other special file where a config should be. Hank does not "
                    "read it (it could block or never end), so its content is unchecked.",
                fix="Replace it with a regular file, or review what the agent would load from it."))
            return
        if status == "oversize":
            findings.append(scan_integrity_finding(
                "SCAN-file-too-large", "high", "Agent config too large to scan fully",
                path, root,
                why=f"Only the first {MAX_FILE_BYTES // (1024 * 1024)} MB were scanned. Padding a "
                    "config past the limit is a way to hide a payload from a scanner.",
                fix="Configs this size are not normal. Review the file by hand and trim it."))
        marked[rel(path, root)] = ignored_linenos(lines)
        findings.extend(detect_secrets(path, lines, root))
        findings.extend(detect_injection(path, lines, root, kind=kind))
        findings.extend(detect_permissions(path, lines, root))
        findings.extend(detect_hooks(path, lines, root))
        if kind == "config":
            data = parse_json(lines)
            findings.extend(detect_supply_chain(path, lines, root, data))
            if data is not None:
                findings.extend(detect_json_escaped(path, lines, root, data))

    for path in target.config_files:
        scan(path, "config")
    for path in target.doc_files + target.skill_files + target.agent_files:
        scan(path, "doc")

    for link in target.outside_links:
        findings.append(scan_integrity_finding(
            "SCAN-symlink-outside-target", "medium", "Agent file is a symlink out of the scanned tree",
            link, root,
            why="The file resolves outside the directory being audited, so Hank does not read it "
                "(it could expose files you never meant to scan). The agent would still load it.",
            fix="Replace the symlink with the real file, or audit the link target separately."))

    findings += check_hygiene(target, root)

    # de-dup identical (rule,file,line)
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    # suppression, counted per source so reports can say exactly what happened
    sup = Suppression(allowed=allow_repo_suppressions)
    operator_globs = load_ignore_file(ignore_file) if ignore_file else []
    repo_globs = load_ignore_globs(root)
    kept = []
    for f in unique:
        if operator_globs and is_ignored(f.file, operator_globs):
            sup.operator += 1
            continue
        if repo_globs and is_ignored(f.file, repo_globs):
            sup.repo_ignore += 1
            if allow_repo_suppressions:
                continue
        elif f.line in marked.get(f.file, set()):
            if f.severity == "critical":
                sup.inline_critical_kept += 1
            else:
                sup.inline += 1
                if allow_repo_suppressions:
                    continue
        kept.append(f)
    kept.sort(key=lambda f: f.sort_key())
    return kept, target, sup


def run_audit(root: str, allow_repo_suppressions: bool = False,
              ignore_file: Optional[str] = None) -> List[Finding]:
    return run_audit_detailed(root, allow_repo_suppressions, ignore_file)[0]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
# Everything that came from the scanned tree (file names, evidence, server
# names inside titles, the target path) is untrusted. Terminal output runs it
# through clean(); markdown through md_text()/md_code(); HTML through
# html.escape(). Evidence is already masked by ev().

def color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def scanned_summary(scanned: Target) -> str:
    text = (f"{len(scanned.doc_files)} CLAUDE.md · {len(scanned.skill_files)} skills · "
            f"{len(scanned.config_files)} configs · {len(scanned.env_files)} env files")
    if scanned.agent_files:
        text += f" · {len(scanned.agent_files)} agents/commands"
    return text


def print_report(findings: List[Finding], root: str, scanned: Target, use_color: bool,
                 suppression: Optional[Suppression] = None):
    suppression = suppression or Suppression()
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1

    print()
    print(color("  ╭───────────────────────────────────────────────╮", DIM, use_color))
    print(color("  │  👮 HANK · AI-security audit for Claude Code   │", BOLD, use_color))
    print(color("  ╰───────────────────────────────────────────────╯", DIM, use_color))
    print(f"  Target: {clean(root)}")
    print(f"  Scanned: {scanned_summary(scanned)}")
    print(f"  Suppressed: {suppression.summary()}")
    print()

    if not findings:
        msg = "  ✓ No security findings. Clean setup."
        if suppression.applied:
            msg = f"  ✓ No findings left after suppression ({suppression.applied} suppressed)."
        print(color(msg, GREEN, use_color))
        print()
        return

    # severity summary line
    summary = "  ".join(
        color(f"{SEVERITY_LABEL[s]} {counts[s]}", SEVERITY_COLOR[s], use_color)
        for s in SEVERITY_ORDER if counts[s]
    )
    print("  " + summary)
    print()

    for idx, f in enumerate(findings, 1):
        badge = color(f" {SEVERITY_LABEL[f.severity]} ", SEVERITY_COLOR[f.severity], use_color)
        print(f"  {badge} {color(clean(f.title), BOLD, use_color)}")
        location = clean(f.file) + ":" + str(int(f.line))
        print(f"       {color(location, BLUE, use_color)}   "
              f"{color('[' + clean(f.rule_id) + ']', DIM, use_color)}")
        print(f"       {color('└', DIM, use_color)} {color(snippet(f.evidence, 100), DIM, use_color)}")
        print(f"       {color('OWASP:', DIM, use_color)} {clean(f.owasp)}")
        print(f"       {color('Why:', DIM, use_color)}   {clean(f.why)}")
        print(f"       {color('Fix:', DIM, use_color)}   {clean(f.fix)}")
        print()

    worst = min((SEVERITY_ORDER[f.severity] for f in findings), default=4)
    verdict = {
        0: ("✗ CRITICAL issues: do not run this setup until fixed.", SEVERITY_COLOR["critical"]),
        1: ("✗ HIGH-risk issues found: fix before trusting this agent.", SEVERITY_COLOR["high"]),
        2: ("⚠ MEDIUM-risk issues: review and tighten.", SEVERITY_COLOR["medium"]),
        3: ("⚠ LOW-risk hygiene items.", SEVERITY_COLOR["low"]),
        4: ("ℹ Informational only.", SEVERITY_COLOR["info"]),
    }[worst]
    print("  " + color(verdict[0], verdict[1], use_color))
    print()


# Inline markdown syntax. Block syntax (#, -, >) only matters at the start of a
# line, and untrusted text never starts one in these reports.
MD_SPECIAL = re.compile(r"([\\`*_\[\]|~])")


def md_text(text: str) -> str:
    """Untrusted text for markdown prose: HTML-escaped (so raw tags are inert
    where a renderer allows HTML) and markdown punctuation backslash-escaped
    (so it cannot open links, images or code spans)."""
    return MD_SPECIAL.sub(r"\\\1", htmllib.escape(clean(text), quote=False))


def md_code(text: str) -> str:
    """Untrusted text as an inline code span. Code spans are literal in
    markdown (no HTML, no links); the fence is longer than any backtick run
    inside, so the text cannot close it early."""
    text = clean(text).replace("\n", " ")
    longest = max((len(r) for r in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def markdown_report(findings: List[Finding], root: str, scanned: Target,
                    suppression: Optional[Suppression] = None) -> str:
    suppression = suppression or Suppression()
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    lines = [
        "# Hank: AI-Security Audit Report",
        "",
        f"**Target:** {md_code(os.path.basename(root) or root)}  ",
        f"**Scanned:** {scanned_summary(scanned)}  ",
        f"**Findings:** " + ", ".join(f"{SEVERITY_LABEL[s]} {counts[s]}"
                                      for s in SEVERITY_ORDER if counts[s]) + "  ",
        f"**Suppressed:** {md_text(suppression.summary())}  ",
        "",
        "Mapped to the OWASP LLM Top 10 (2025). Generated by [Hank](https://github.com/aiwithdiego/hank).",
        "",
        "---",
        "",
    ]
    if not findings:
        if suppression.applied:
            lines.append(f"**No findings left after suppression ({suppression.applied} suppressed).**")
        else:
            lines.append("✅ **No security findings. Clean setup.**")
        return "\n".join(lines)
    for i, f in enumerate(findings, 1):
        lines += [
            f"## {i}. {SEVERITY_LABEL[f.severity]}: {md_text(f.title)}",
            "",
            f"- **Location:** {md_code(f.file + ':' + str(int(f.line)))}",
            f"- **Rule:** {md_code(f.rule_id)}",
            f"- **OWASP:** {md_text(f.owasp)}",
            f"- **Evidence:** {md_code(snippet(f.evidence, 160))}",
            "",
            f"**Why it matters.** {f.why}",
            "",
            f"**Fix.** {f.fix}",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fun mode: the meme-powered HTML "security report card"
# ---------------------------------------------------------------------------

# How many points each finding costs. Score starts at 100.
SCORE_WEIGHTS = {"critical": 28, "high": 13, "medium": 5, "low": 2, "info": 0}

# Severity → reaction memes. Each severity has a POOL of GIFs; Hank picks one
# per finding (deterministically: the same finding always gets the same GIF, but
# different cards vary). GIFs are off unless --gifs is passed (opening a card
# would otherwise make requests to Giphy). Swappable via Hank's own memes.json
# or --memes FILE; never read from the scanned repo. A broken/empty GIF falls
# back to the emoji, so a card never looks broken.
DEFAULT_MEMES = {
    "critical": {
        "emoji": "🔥", "caption": "THIS IS FINE.",
        "gifs": [
            "https://media.giphy.com/media/NTur7XlVDUdqM/giphy.gif",
            "https://media.giphy.com/media/QMHoU66sBXqqLqYvGO/giphy.gif",
            "https://media.giphy.com/media/1rNWZu4QQqCUaq434T/giphy.gif",
            "https://media.giphy.com/media/Z9P7Kbj8pjVxuFh9UT/giphy.gif",
            "https://media.giphy.com/media/8zyppUPi4lIcplZxcI/giphy.gif",
            "https://media.giphy.com/media/3o7TKL9JE2dDb7pj0I/giphy.gif",
            "https://media.giphy.com/media/l2QEgWxqxI2WJCXpC/giphy.gif",
            "https://media.giphy.com/media/KZy3dUmfAkku9YS3sk/giphy.gif",
        ],
    },
    "high": {
        "emoji": "😰", "caption": "Big, big yikes.",
        "gifs": [
            "https://media.giphy.com/media/HUkOv6BNWc1HO/giphy.gif",
            "https://media.giphy.com/media/h7VZeudL5u0N6onoI7/giphy.gif",
            "https://media.giphy.com/media/FoThOBFT1zCub4WsvP/giphy.gif",
            "https://media.giphy.com/media/5lNqZ6xXiyQBwGaCoK/giphy.gif",
            "https://media.giphy.com/media/SiibX1NXc4JhL7JVS7/giphy.gif",
            "https://media.giphy.com/media/3oEdv0Kle09oH9GqxW/giphy.gif",
            "https://media.giphy.com/media/R0RaI63M3g7qdaLnmB/giphy.gif",
            "https://media.giphy.com/media/jcbsThcVP2yFa/giphy.gif",
        ],
    },
    "medium": {
        "emoji": "👀", "caption": "...we need to talk.",
        "gifs": [
            "https://media.giphy.com/media/NO37xAoHt2jvhxqBcD/giphy.gif",
            "https://media.giphy.com/media/BJVJxagR3GG4w/giphy.gif",
            "https://media.giphy.com/media/yyq0WXMv720OcpZvmA/giphy.gif",
            "https://media.giphy.com/media/WRuBiZKB6xgsS9DrFA/giphy.gif",
            "https://media.giphy.com/media/38vz5MBF9gF4Q/giphy.gif",
            "https://media.giphy.com/media/26BkO5fkr0Kh7RhHG/giphy.gif",
            "https://media.giphy.com/media/s0PwOijk682OPn3rwy/giphy.gif",
            "https://media.giphy.com/media/JaNtIG4UnKzD2/giphy.gif",
        ],
    },
    "low": {
        "emoji": "🤷", "caption": "Eh. Noted.",
        "gifs": [
            "https://media.giphy.com/media/SAHGcjT1jNvDB6oxI8/giphy.gif",
            "https://media.giphy.com/media/vqKlNf8jpBB7O/giphy.gif",
            "https://media.giphy.com/media/w0mylo7p4OXUQ/giphy.gif",
            "https://media.giphy.com/media/12wQni7Ylp8mek/giphy.gif",
            "https://media.giphy.com/media/iA8jqAN2GXSTe/giphy.gif",
            "https://media.giphy.com/media/LlE3uMF20U7Ys/giphy.gif",
            "https://media.giphy.com/media/jEirVKZl0JytW/giphy.gif",
            "https://media.giphy.com/media/xUPGclwjEhqp5zi0bm/giphy.gif",
        ],
    },
    "info": {
        "emoji": "ℹ️", "caption": "Just so you know.",
        "gifs": [
            "https://media.giphy.com/media/3o752kakMLKVv5Jzpu/giphy.gif",
            "https://media.giphy.com/media/5TD4dseytpaIhYbyWq/giphy.gif",
            "https://media.giphy.com/media/VjLYJ3KwrRe6xZ1BwN/giphy.gif",
            "https://media.giphy.com/media/EYUNo9AHh1qvx87fH1/giphy.gif",
            "https://media.giphy.com/media/JwkxjWXEZeqRz5Y4QO/giphy.gif",
            "https://media.giphy.com/media/vaCubgL0e8nSoTfCD2/giphy.gif",
        ],
    },
}

# Per-rule one-liner roast. Substance stays in `why`/`fix`; this is the spice.
ROASTS = {
    "SECRET-anthropic-key": "A live API key. In plain text. In the repo. Chef's kiss. 💋",
    "SECRET-openai-key": "A live API key, committed for all to enjoy. Generous.",
    "SECRET-github-pat": "Your GitHub PAT, right there in the config. The internet thanks you.",
    "SECRET-github-fine-pat": "Fine-grained token, finely leaked.",
    "SECRET-aws-access-key": "An AWS key in the open. Hope you like surprise bills.",
    "SECRET-slack-token": "Slack token in the clear. Someone's about to /giphy your channel.",
    "SECRET-google-api-key": "Google key, hardcoded. Bold.",
    "SECRET-jwt": "A JWT just sitting there. Tasty.",
    "SECRET-bearer": "A bearer token glued into the config. It will leak. It always leaks.",
    "SECRET-generic-secret": "That sure looks like a secret pretending to be a config value.",
    "INJ-exfil-instruction": "Your config politely asks the agent to mail your secrets to strangers.",
    "INJ-instruction-override": "'Ignore previous instructions': the four words behind every agent horror story.",
    "INJ-hidden-unicode": "Invisible characters. Your reviewer can't see them. The model can. Spooky. 👻",
    "AGENCY-bypass-permissions": "Permissions: OFF. Vibes: ON. What could possibly go wrong.",
    "AGENCY-wildcard-permission": "Bash(*): you handed the agent the keys, the car, AND your blessing.",
    "AGENCY-dangerous-bash-allow": "rm -rf, pre-approved. Living dangerously. I respect it. (I do not.)",
    "HOOK-pipe-to-shell": "curl | sh on startup. Trusting a stranger's server with your whole laptop.",
    "HOOK-network-exfil": "Every prompt you type, shipped off-box. Hope that endpoint is yours!",
    "SUPPLY-inline-mcp-token": "Token welded into the config. See also: every breach ever.",
    "SUPPLY-unpinned-mcp": "Unpinned package = you run whatever the internet feels like serving today.",
    "HYGIENE-env-present": "A .env, just vibing in the tree. One Read() away from a bad day.",
    "HYGIENE-no-secret-rule": "No 'don't leak secrets' rule. The agent's on the honor system. Cute.",
}
DEFAULT_ROAST = "Hank flagged this. Hank is rarely wrong."


def pick_gif(meme: dict, finding: "Finding") -> str:
    """Deterministically pick one GIF from the severity's pool for this finding.
    Same finding → same GIF (reproducible reports); different findings spread
    across the pool for variety. Back-compat: honors a single 'gif' string."""
    gifs = meme.get("gifs")
    if not gifs:
        single = meme.get("gif")
        gifs = [single] if single else []
    gifs = [g for g in gifs if g]
    if not gifs:
        return ""
    key = f"{finding.rule_id}:{finding.file}:{finding.line}".encode("utf-8")
    idx = int(hashlib.md5(key).hexdigest(), 16) % len(gifs)
    return gifs[idx]


def load_academy() -> Optional[dict]:
    """Read Hank Academy progress (written by hank_quiz.py) if the user has any.
    Returns None when the Academy has never been run; the report card simply
    omits the strip. Kept as a plain JSON read so the scanner stays standalone."""
    home = os.environ.get("HANK_HOME") or os.path.join(os.path.expanduser("~"), ".hank")
    path = os.path.join(home, "academy.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except (ValueError, OSError):
        return None
    if not state.get("totals", {}).get("asked"):
        return None
    return state


GIF_URL = re.compile(r"^https://media[0-9]?\.giphy\.com/[A-Za-z0-9/_.\-]{1,200}$")
MEME_TEXT_MAX = 80


def sanitize_meme(cfg: dict, base: dict) -> dict:
    """Keep only well-typed fields: short text, and GIF URLs on the Giphy
    allowlist. Output is still HTML-escaped at render time."""
    out = dict(base)
    for key in ("emoji", "caption"):
        val = cfg.get(key)
        if isinstance(val, str):
            out[key] = val[:MEME_TEXT_MAX]
    gifs = cfg.get("gifs")
    if gifs is None and isinstance(cfg.get("gif"), str):
        gifs = [cfg["gif"]]
    if isinstance(gifs, list):
        out["gifs"] = [g for g in gifs if isinstance(g, str) and GIF_URL.match(g)]
        out.pop("gif", None)
    return out


def load_memes(path: Optional[str] = None) -> dict:
    """Load meme config from Hank's own install dir (default) or an explicit
    operator-supplied file (--memes). Never from the scanned repo: that would
    let the repo under review write into its own report. `path` may be a file
    or a directory holding memes.json."""
    memes = {k: dict(v) for k, v in DEFAULT_MEMES.items()}
    if path is None:
        path = TOOL_DIR
    if os.path.isdir(path):
        path = os.path.join(path, "memes.json")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                override = json.load(f)
        except (ValueError, OSError, RecursionError):
            override = {}
        if isinstance(override, dict):
            for sev, cfg in override.items():
                if sev in memes and isinstance(cfg, dict):
                    memes[sev] = sanitize_meme(cfg, memes[sev])
    return memes


def score_and_verdict(findings: List[Finding]):
    score = max(0, 100 - sum(SCORE_WEIGHTS[f.severity] for f in findings))
    if score >= 90:
        grade, tier, emoji, line = "A", "FORTRESS", "🛡️", "Nothing to see here. Hank is impressed. (Rare.)"
    elif score >= 80:
        grade, tier, emoji, line = "B", "SOLID", "😎", "A couple of gremlins, nothing that'll ruin your week."
    elif score >= 60:
        grade, tier, emoji, line = "C", "SHAKY", "😬", "It runs. I wouldn't brag about it yet."
    elif score >= 40:
        grade, tier, emoji, line = "D", "ROUGH", "🫠", "Patch this before anyone else reads it."
    else:
        grade, tier, emoji, line = "F", "THIS IS FINE", "🔥", "(Narrator: it was not, in fact, fine.)"
    return score, grade, tier, emoji, line


GRADE_COLOR = {"A": "#34d399", "B": "#a3e635", "C": "#fbbf24", "D": "#fb923c", "F": "#f87171"}

BOTTOM_LINE = {
    "A": "basically clean, nice work.",
    "B": "solid; just clean up the stragglers.",
    "C": "it runs, but tighten the highs and mediums before you trust it.",
    "D": "patch the criticals before this goes anywhere near production.",
    "F": "do not run this setup until the criticals are gone.",
}


def summary_paragraph(findings: List[Finding], scanned: Target, root: str) -> str:
    """One-paragraph executive brief, in Hank's voice, built from the findings."""
    esc = htmllib.escape
    target = esc(os.path.basename(root) or root)
    nfiles = len(scanned.doc_files) + len(scanned.skill_files) + len(scanned.config_files)
    filebit = f"{nfiles} file" + ("" if nfiles == 1 else "s")

    if not findings:
        return (f"<b>Hank</b> swept <code>{target}</code> ({filebit}) and found "
                "<b>nothing to flag</b>: no leaked secrets, no prompt-injection vectors, "
                "no over-broad permissions, no risky hooks. Your agent's house is in order. "
                "(Hank's almost disappointed.)")

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    total = len(findings)
    breakdown = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s])

    # up to three distinct headline issues (findings are pre-sorted by severity)
    seen, tops = set(), []
    for f in findings:
        key = f.title.lower()
        if key not in seen:
            seen.add(key)
            tops.append(f.title)
        if len(tops) == 3:
            break
    lc = [esc(t[0].lower() + t[1:] if t else t) for t in tops]
    if len(lc) == 1:
        topstr = lc[0]
    elif len(lc) == 2:
        topstr = " and ".join(lc)
    else:
        topstr = ", ".join(lc[:-1]) + ", and " + lc[-1]

    _, grade, _, _, _ = score_and_verdict(findings)
    return (f"<b>Hank</b> audited <code>{target}</code> ({filebit}) and turned up "
            f"<b>{total} issue{'' if total == 1 else 's'}</b>: {breakdown}. "
            f"Top of the pile: {topstr}. That's a grade <b>{grade}</b>: {BOTTOM_LINE[grade]} "
            "Each card below has the exact <code>file:line</code> and the one-line fix; "
            "start at the top and work down.")

HTML_CSS = """
:root{--bg:#0b0e14;--card:#141925;--card2:#1b2230;--ink:#e6e9ef;--mut:#8b94a7;--line:#222a3a}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#16203a 0%,var(--bg) 55%);
  color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;padding:48px 16px 80px}
.wrap{max-width:880px;margin:0 auto}
.brand{display:flex;align-items:center;gap:12px;justify-content:center;margin-bottom:6px}
.brand .badge{font-size:34px}
.brand h1{font-size:30px;margin:0;letter-spacing:-.5px}
.sub{text-align:center;color:var(--mut);margin:0 0 4px}
.meta{text-align:center;color:var(--mut);font-size:13px;margin-bottom:30px}
.scorecard{display:flex;gap:24px;align-items:center;background:linear-gradient(180deg,var(--card),var(--card2));
  border:1px solid var(--line);border-radius:20px;padding:26px 28px;margin-bottom:18px;flex-wrap:wrap;
  box-shadow:0 20px 50px -30px #000}
.ring{--v:0;--c:#34d399;width:128px;height:128px;border-radius:50%;flex:0 0 auto;
  background:conic-gradient(var(--c) calc(var(--v)*1%),#26303f 0);display:grid;place-items:center;position:relative}
.ring::before{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--card)}
.ring .n{position:relative;font-size:40px;font-weight:800}
.ring .n small{font-size:15px;font-weight:600;color:var(--mut)}
.verdict{flex:1;min-width:240px}
.verdict .tier{font-size:26px;font-weight:800;margin:0 0 2px;display:flex;gap:10px;align-items:center}
.verdict .grade{font-size:15px;color:var(--mut)}
.verdict .line{margin:8px 0 0;color:var(--ink)}
.summary{background:var(--card);border:1px solid var(--line);border-left:4px solid #9ae4ff;
  border-radius:12px;padding:15px 18px;margin:0 0 18px;color:#cdd4e2;font-size:15px;line-height:1.62}
.summary b{color:var(--ink)}
.summary code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#9ae4ff}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 30px}
.pill{font-size:13px;font-weight:700;padding:6px 12px;border-radius:999px;border:1px solid var(--line)}
.pill.crit{background:#3b0d0d;color:#ff9a9a;border-color:#5a1414}
.pill.high{background:#3a1f06;color:#ffc48a}
.pill.med{background:#3a3206;color:#ffe79a}
.pill.low{background:#06303a;color:#9ae4ff}
.pill.zero{opacity:.4}
.card{display:flex;gap:0;background:var(--card);border:1px solid var(--line);border-radius:16px;
  overflow:hidden;margin-bottom:16px;box-shadow:0 16px 40px -32px #000}
.stage{flex:0 0 200px;background:#0d1119;position:relative;display:grid;place-items:center;min-height:170px;border-right:1px solid var(--line)}
.stage .emoji{font-size:74px;filter:drop-shadow(0 6px 14px #000)}
.stage img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.stage .cap{position:absolute;left:0;right:0;bottom:0;background:linear-gradient(180deg,transparent,#000c);
  color:#fff;font-family:Impact,"Arial Black",sans-serif;text-transform:uppercase;letter-spacing:.5px;
  text-align:center;padding:18px 8px 8px;font-size:15px;text-shadow:1px 1px 2px #000}
.body{flex:1;padding:18px 20px}
.tag{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.6px;padding:3px 9px;border-radius:6px;text-transform:uppercase}
.t-crit{background:#ff5a5a;color:#1a0000}.t-high{background:#ff9d3c;color:#1a0e00}
.t-med{background:#ffd23c;color:#1a1600}.t-low{background:#46c8ff;color:#001520}.t-info{background:#7a8699;color:#0b0e14}
.body h3{margin:10px 0 4px;font-size:18px}
.roast{color:#cdd4e2;font-style:italic;margin:0 0 12px}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#9ae4ff;
  background:#0d1119;border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:0 0 10px;word-break:break-all}
.kv{font-size:13.5px;margin:6px 0;color:var(--mut)}
.kv b{color:var(--ink)}
.owasp{font-size:11.5px;color:var(--mut);margin-top:10px}
.academy{display:flex;gap:14px;align-items:center;flex-wrap:wrap;background:var(--card);
  border:1px solid var(--line);border-left:4px solid #fbbf24;border-radius:12px;
  padding:12px 18px;margin:0 0 18px;font-size:14px}
.academy .rk{font-weight:800;font-size:15px}
.academy .xp{color:var(--mut)}
.academy .stk{color:#ffc48a;font-weight:700}
.academy .shelf{font-size:18px;letter-spacing:3px}
.academy .cta{color:var(--mut);font-size:12.5px;margin-left:auto}
.clean{text-align:center;padding:50px 20px}
.clean .big{font-size:90px}
.clean h2{font-size:26px;margin:6px 0}
.foot{text-align:center;color:var(--mut);font-size:12.5px;margin-top:34px;line-height:1.8}
.foot a{color:#9ae4ff;text-decoration:none}
"""


def academy_strip(academy: Optional[dict]) -> str:
    """The Hank Academy badge strip for the report card. Empty string when the
    user has never trained; the card renders exactly as before."""
    if not academy:
        return ""
    esc = htmllib.escape
    rank = academy.get("rank") or {}
    remoji, rname = str(rank.get("emoji", "🎓")), str(rank.get("name", "Cadet"))
    def as_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    xp = as_int(academy.get("xp", 0))
    streak = as_int(academy.get("streak", 0))
    badges = [b for b in academy.get("badges", []) if isinstance(b, dict)]
    shelf = "".join(
        f"<span title='{esc(str(b.get('name', '')))}: {esc(str(b.get('desc', '')))}'>{esc(str(b.get('emoji', '')))}</span>"
        for b in badges)
    streak_bit = (f"<span class='stk'>🔥 {streak}-day streak</span>" if streak else "")
    return ("<div class='academy'>"
            f"<span class='rk'>{esc(remoji)} {esc(rname)}</span>"
            f"<span class='xp'>{xp} XP · Hank Academy</span>"
            f"{streak_bit}"
            f"<span class='shelf'>{shelf}</span>"
            "<span class='cta'>train: <code>hank_quiz.py --daily</code></span>"
            "</div>")


def html_report(findings: List[Finding], root: str, scanned: Target, memes: dict,
                academy: Optional[dict] = None, gifs: bool = False,
                suppression: Optional[Suppression] = None) -> str:
    """The HTML report card. No scripts, no inline event handlers, and a CSP
    that forbids scripts outright; every scanned-tree value is escaped. Images
    load only when gifs=True, and only from Giphy."""
    esc = htmllib.escape
    suppression = suppression or Suppression()
    img_src = ("data: https://media.giphy.com https://media0.giphy.com https://media1.giphy.com "
               "https://media2.giphy.com https://media3.giphy.com https://media4.giphy.com"
               if gifs else "data:")
    csp = (f"default-src 'none'; img-src {img_src}; style-src 'unsafe-inline'; "
           "base-uri 'none'; form-action 'none'")
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    score, grade, tier, vemoji, vline = score_and_verdict(findings)
    ring_color = GRADE_COLOR[grade]

    tag_cls = {"critical": "t-crit", "high": "t-high", "medium": "t-med", "low": "t-low", "info": "t-info"}
    stage_cap_cls = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}

    head = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<meta http-equiv='Content-Security-Policy' content=\"{csp}\">",
        "<meta name='referrer' content='no-referrer'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Hank: Security Report Card</title><style>", HTML_CSS, "</style></head><body><div class='wrap'>",
        "<div class='brand'><span class='badge'>👮</span><h1>HANK</h1></div>",
        "<p class='sub'>AI-Security Report Card for your Claude Code agentic OS</p>",
        f"<p class='meta'>Target: <code>{esc(os.path.basename(root) or root)}</code> · "
        f"{esc(scanned_summary(scanned))}<br>Suppressed: {esc(suppression.summary())}</p>",
        "<div class='scorecard'>",
        f"<div class='ring' style='--v:{int(score)};--c:{esc(ring_color)}'><div class='n'>{int(score)}<small>/100</small></div></div>",
        "<div class='verdict'>",
        f"<p class='tier'>{esc(vemoji)} {esc(tier)}</p>",
        f"<p class='grade'>Security grade: <b style='color:{esc(ring_color)}'>{esc(grade)}</b></p>",
        f"<p class='line'>{esc(vline)}</p>",
        "</div></div>",
        academy_strip(academy),
        f"<div class='summary'>{summary_paragraph(findings, scanned, root)}</div>",
    ]

    pill = lambda cls, label, n: (
        f"<span class='pill {cls}{'' if n else ' zero'}'>{label} {n}</span>")
    head.append("<div class='pills'>"
                + pill("crit", "CRITICAL", counts["critical"])
                + pill("high", "HIGH", counts["high"])
                + pill("med", "MEDIUM", counts["medium"])
                + pill("low", "LOW", counts["low"]) + "</div>")

    if not findings and suppression.applied:
        head.append("<div class='card'><div class='body clean'>"
                     "<div class='big'>🙈</div><h2>Clean after suppression</h2>"
                     f"<p class='roast'>Nothing left to roast, but {int(suppression.applied)} "
                     "finding(s) were suppressed. Check that each one was meant to be.</p></div></div>")
    elif not findings:
        head.append("<div class='card'><div class='body clean'>"
                     "<div class='big'>🛡️😎👏</div><h2>Certified Agent-Safe™</h2>"
                     "<p class='roast'>Hank scanned the whole setup and found nothing to roast. "
                     "Honestly? A little disappointed. Great job.</p></div></div>")
    else:
        cards = []
        for f in findings:
            m = memes.get(f.severity, memes["info"])
            gif = pick_gif(m, f) if gifs else ""
            if gif and not GIF_URL.match(gif):
                gif = ""
            # no onerror handler: a failed GIF is simply transparent over the emoji
            img = f"<img src='{esc(gif)}' alt='' loading='lazy'>" if gif else ""
            roast = ROASTS.get(f.rule_id, DEFAULT_ROAST)
            cards.append(
                "<div class='card'>"
                f"<div class='stage'><span class='emoji'>{esc(str(m.get('emoji', '')))}</span>{img}"
                f"<div class='cap'>{esc(str(m.get('caption', '')))}</div></div>"
                "<div class='body'>"
                f"<span class='tag {tag_cls[f.severity]}'>{esc(SEVERITY_LABEL[f.severity])}</span>"
                f"<h3>{esc(f.title)}</h3>"
                f"<p class='roast'>{esc(roast)}</p>"
                f"<div class='loc'>{esc(clean(f.file))}:{int(f.line)} &nbsp;·&nbsp; {esc(clean(f.evidence))}</div>"
                f"<p class='kv'><b>Why it matters.</b> {esc(f.why)}</p>"
                f"<p class='kv'><b>The fix.</b> {esc(f.fix)}</p>"
                f"<p class='owasp'>{esc(f.owasp)} &nbsp;·&nbsp; rule <code>{esc(f.rule_id)}</code></p>"
                "</div></div>")
        head.append("".join(cards))

    head.append(
        "<p class='foot'>Generated by <b>Hank</b> 👮 · AI-security audit for Claude Code · "
        "mapped to the OWASP LLM Top 10 (2025)<br>"
        "Never modifies scanned files. Memes swappable in Hank's <code>memes.json</code>. "
        "<a href='https://github.com/aiwithdiego/hank'>Fork it &amp; harden your agents.</a></p>")
    head.append("</div></body></html>")
    return "".join(head)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    global SHOW_SECRETS
    p = argparse.ArgumentParser(description="Hank: AI-security audit for your Claude Code setup.")
    p.add_argument("target", nargs="?", default=".", help="directory to scan (default: .)")
    p.add_argument("--json", action="store_true", help="emit findings as JSON")
    p.add_argument("--min-severity", default="info",
                   choices=list(SEVERITY_ORDER.keys()), help="minimum severity to report")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("-o", "--output", help="also write a markdown report to this path")
    p.add_argument("--html", nargs="?", const="hank-report.html", default=None,
                   help="write the HTML report card (default path: hank-report.html)")
    p.add_argument("--gifs", action="store_true",
                   help="let the HTML card load reaction GIFs from Giphy (off by default)")
    p.add_argument("--memes", metavar="FILE",
                   help="meme config for the HTML card (default: memes.json next to hank_audit.py)")
    p.add_argument("--ignore-file", metavar="FILE",
                   help="operator-supplied ignore globs; keep it outside the tree under review")
    p.add_argument("--allow-repo-suppressions", action="store_true",
                   help="honour the scanned repo's own .hankignore and inline hank:ignore markers "
                        "(off by default: a repo under review must not mark itself clean)")
    p.add_argument("--show-secrets", action="store_true",
                   help="print secrets unmasked in every output (local debugging only)")
    args = p.parse_args(argv)
    SHOW_SECRETS = bool(args.show_secrets)

    root = os.path.abspath(args.target)
    if not os.path.isdir(root):
        print(f"hank: not a directory: {clean(root)}", file=sys.stderr)
        return 2

    try:
        findings, scanned, sup = run_audit_detailed(
            root, allow_repo_suppressions=args.allow_repo_suppressions,
            ignore_file=args.ignore_file)
        threshold = SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= threshold]

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(markdown_report(findings, root, scanned, sup))

        if args.html:
            memes = load_memes(args.memes)  # Hank's own file unless --memes; never the target's
            with open(args.html, "w", encoding="utf-8") as f:
                f.write(html_report(findings, root, scanned, memes, academy=load_academy(),
                                    gifs=args.gifs, suppression=sup))

        if args.json:
            print(json.dumps({
                "findings": [asdict(f) for f in findings],
                "suppressed": {
                    "total": sup.applied,
                    "repo_suppressions_allowed": sup.allowed,
                    "by_ignore_file": sup.operator,
                    "by_repo_hankignore": sup.repo_ignore if sup.allowed else 0,
                    "by_inline_marker": sup.inline if sup.allowed else 0,
                    "requested_by_repo_not_applied": 0 if sup.allowed else sup.requested_by_repo,
                    "critical_kept_despite_inline_marker": sup.inline_critical_kept,
                    "summary": sup.summary(),
                },
            }, indent=2))
        else:
            use_color = sys.stdout.isatty() and not args.no_color
            print_report(findings, root, scanned, use_color, sup)
            if args.html:
                print(f"  📋 Report card written to {clean(args.html)}. Open it in a browser.\n")
    finally:
        SHOW_SECRETS = False

    # exit code: 1 if any high+ findings, else 0 (CI-friendly)
    worst = min((SEVERITY_ORDER[f.severity] for f in findings), default=4)
    return 1 if worst <= SEVERITY_ORDER["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
