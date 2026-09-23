# Hank

**A security scanner and training quiz for Claude Code setups, mapped to the OWASP Top 10 for LLM Applications (2025).**

Hank reads the files a Claude Code agent runs on (`CLAUDE.md`, skills, `.mcp.json`, `settings.json`, hooks, `.env`) and reports what an attacker would use. It ships as a Claude Code plugin, a standalone Python scanner and a CI gate. A companion quiz, Hank Academy, trains you on the categories the scanner flags.

| Insecure demo setup: grade F | Hardened setup: grade A |
|---|---|
| ![HTML report card for the insecure demo: score 0, 19 findings](docs/screenshots/report-card-vulnerable.png) | ![HTML report card for the hardened example: score 100, no findings](docs/screenshots/report-card-clean.png) |

## Why I built it

Agent setups are configuration, and configuration doesn't get code review. A single line in `.mcp.json` or `settings.json` can pre-approve `rm -rf`, pull an unpinned server from a registry, or hand the agent a tool description that tells it to send your SSH key somewhere. Secret scanners and linters don't look for that. I wanted a tool I could run on my own setups and in CI, and a way to make the lessons stick, so the same mistakes stop coming back.

## What it finds

The agent-specific problems that general linters and secret scanners miss:

- **Prompt injection and tool poisoning.** Override phrasing and exfiltration instructions hidden in MCP tool descriptions, skills and docs the agent trusts.
- **Leaked secrets.** API keys, GitHub tokens and bearer tokens written inline in configs.
- **Unpinned MCP servers.** `npx` or `uvx` servers with no version, which run whatever the registry serves that day.
- **Excessive agency.** Wildcard permissions such as `Bash(*)`, `bypassPermissions`, pre-approved `rm -rf`.
- **Dangerous hooks.** `curl ... | sh` on session start, hooks that POST prompts to an external URL.
- **Hidden Unicode.** Zero-width and bidi characters that hide instructions from a human reviewer.

The scanner is one Python file with no dependencies. It never modifies the project it scans, and it treats that project as untrusted input (see [Security](#security)).

## Install

### As a Claude Code plugin

Inside Claude Code:

```text
/plugin marketplace add aiwithdiego/hank
/plugin install hank@hank-security
```

Or from a shell: `claude plugin marketplace add aiwithdiego/hank`, then `claude plugin install hank@hank-security`.

Then ask for it in plain language:

> "Hank, audit my setup."
> "Check my MCP servers for tool poisoning."
> "Quiz me on security."

The plugin runs the scanner, reads the flagged files and adds the judgment a static rule cannot: cross-server shadowing, permissions that are safe alone but dangerous together, and paths from untrusted input to a privileged action. It reports severity, `file:line`, the OWASP category, why the issue matters in that setup, and the fix. It only applies fixes when you ask.

### As a standalone scanner

Requires Python 3.8 or later. Nothing to install.

```bash
git clone https://github.com/aiwithdiego/hank && cd hank

python3 hank_audit.py /path/to/project                  # terminal report
python3 hank_audit.py /path/to/project --html           # HTML report card, writes hank-report.html
python3 hank_audit.py /path/to/project --html --gifs    # same, with reaction GIFs from Giphy
python3 hank_audit.py /path/to/project -o report.md     # markdown report
python3 hank_audit.py /path/to/project --json           # structured findings plus a suppression summary
python3 hank_audit.py /path/to/project --min-severity high
```

`--json` prints an object: `findings` (the list) and `suppressed` (counts by source). Secrets are masked in every format; `--show-secrets` turns that off for local debugging only.

### As a CI gate

The scanner exits with code `1` when it finds anything rated high or critical, so a pull request that adds a leaked key or a `curl | sh` hook fails the build.

Run Hank from its own checkout, not from a copy inside the repo under review, and leave the defaults alone: the scanned repo's `.hankignore` and inline `hank:ignore` markers are not honoured unless you pass `--allow-repo-suppressions`, so a pull request cannot mark itself clean. Do not pass that flag in CI.

```yaml
# .github/workflows/hank.yml
name: hank
on: [pull_request]
permissions:
  contents: read
jobs:
  hank:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          path: target
          persist-credentials: false
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          repository: aiwithdiego/hank
          path: hank
          persist-credentials: false
          # pin `ref:` to a release commit of Hank
      - run: python3 hank/hank_audit.py target --min-severity high
```

To baseline accepted findings in CI, pass `--ignore-file` with a file the pull request cannot change (for example one kept in a separate, protected repo). Every report states how many findings were suppressed and by what.

## Architecture

```mermaid
flowchart LR
  Target[("Scanned repo<br/>untrusted input")] --> Walk["File walker<br/>fixed file set, no symlink escape,<br/>2 MB cap, regular files only"]
  Walk --> Rules["Detectors<br/>regex tables + JSON-aware<br/>MCP checks, bounded patterns"]
  Rules --> Supp["Suppression<br/>operator --ignore-file always;<br/>repo .hankignore only if allowed"]
  Supp --> Out["Reporters<br/>terminal, markdown, JSON, HTML card<br/>escaped, secrets masked"]
  Out --> Gate{"exit 1 on<br/>high or critical"}
  Rules -. "findings by category" .-> Quiz["Hank Academy<br/>hank_quiz.py --target"]
  Plugin["Claude Code plugin<br/>skills/hank/SKILL.md"] --> Walk
  Plugin -. "reads flagged files as evidence,<br/>adds judgment" .-> Out
```

- `hank_audit.py` is one file, standard library only: the walker, detector tables, scoring and four report formats.
- `hank_quiz.py` and `questions.json` are the Academy: 48 questions, missed ones coming back later, and progress in `~/.hank/academy.json`.
- `skills/hank/SKILL.md` turns the scanner into a Claude Code plugin. Claude runs the scan, reads the flagged files and adds the judgment static rules can't, such as cross-server shadowing or permissions that are safe alone but dangerous together.

## Sample output

The repo includes a deliberately insecure Claude Code setup in `demo/` with one realistic problem per category, and a hardened version of the same project in `examples/secure-setup/`.

```bash
python3 hank_audit.py demo --html
python3 hank_audit.py examples/secure-setup
```

The demo produces 19 findings (6 critical, 8 high, 4 medium, 1 low). The secure setup produces none. Pre-rendered output:

- [`sample-report.md`](sample-report.md): the markdown report for `demo/`
- [`samples/report-card-vulnerable.html`](samples/report-card-vulnerable.html): the HTML report card for `demo/` (score 0, grade F)
- [`samples/report-card-clean.html`](samples/report-card-clean.html): the HTML report card for the secure setup (score 100, grade A)

The HTML report card gives a score out of 100, a letter grade, a short summary, and one card per finding with the location, OWASP mapping and fix. Each card also carries a reaction emoji and a one-line roast, because people read a report they enjoy. With `--gifs` the card also loads a reaction GIF from Giphy (the sample cards were made this way); without it the card makes no network requests. Memes come from Hank's own [`memes.json`](memes.json), or a file you pass with `--memes`, and never from the scanned project.

The fixtures in `demo/` are attack examples. Do not open `demo/` as a Claude Code project: its settings and hooks are written to be unsafe. The domains in it use the reserved `.example` TLD and the keys are fake.

## OWASP LLM Top 10 (2025) coverage

| ID | Risk | Coverage | What Hank checks |
|---|---|---|---|
| LLM01 | Prompt Injection | Yes | Override phrasing, exfiltration instructions, hidden Unicode in configs, skills and `CLAUDE.md` |
| LLM02 | Sensitive Information Disclosure | Yes | Hard-coded keys and tokens, inline MCP auth headers, a `.env` in the tree, no secret-handling rule in `CLAUDE.md` |
| LLM03 | Supply Chain | Yes | MCP servers launched through `npx`, `uvx`, `bunx` or `pnpm` without a version pin, hooks that pipe a download into a shell |
| LLM04 | Data and Model Poisoning | No | Out of scope for a config scanner |
| LLM05 | Improper Output Handling | No | Out of scope for a config scanner |
| LLM06 | Excessive Agency | Yes | Wildcard permissions, `bypassPermissions` and auto-approve modes, dangerous shell allow-rules, hooks that send data off the machine |
| LLM07 | System Prompt Leakage | Partial | Instructions to read or reveal config and secret files (reported under LLM01 and LLM06) |
| LLM08 | Vector and Embedding Weaknesses | No | Out of scope |
| LLM09 | Misinformation | No | Out of scope |
| LLM10 | Unbounded Consumption | No | Out of scope |

Severity guide: **critical** means do not run the setup until it is fixed (leaked key, exfiltration instruction, permission bypass, `curl | sh`). **High** means fix it before trusting the agent. **Medium** means review and tighten. **Low** covers hygiene.

## Hank Academy

A scanner tells you what is wrong today. The Academy is a short quiz so the same mistakes stop coming back.

```bash
python3 hank_quiz.py                  # 10-question round
python3 hank_quiz.py --daily          # daily question with a streak
python3 hank_quiz.py --daily-goal 3   # 1 to 5 questions per day
python3 hank_quiz.py --target .       # bias questions toward what the audit flags in this project
python3 hank_quiz.py --stats          # rank, streak, badges, accuracy by category
```

- 48 questions across the six categories the scanner detects: secrets, injection, agency, hooks, supply chain and hygiene. Each answer comes with an explanation and its OWASP mapping. Missed questions come back later.
- `--target <dir>` runs the scanner first and weights the questions toward what it found.
- XP, seven ranks, 13 badges and a daily streak. A missed day resets the streak.
- Once you have trained, your rank, streak and badges appear on the next HTML report card.

Progress is stored in `~/.hank/academy.json`. Set `$HANK_HOME` to change the location.

## Suppressing findings

- `--ignore-file FILE`: gitignore-style globs, relative to the scan root, supplied by you. Always applied. Keep the file outside the tree under review.
- A `.hankignore` at the scan root and `hank:ignore` on a line are written by the repo being scanned, so they are only honoured with `--allow-repo-suppressions`. Inline markers never suppress a critical finding.
- Without the flag, the report still says how many findings the repo asked to suppress, so you can see the attempt.

Every report (terminal, markdown, HTML and JSON) states how many findings were suppressed and by which source. A card with suppressed findings reads "Clean after suppression", never "Certified Agent-Safe".

To self-scan this repo, which documents attacks in its own skill file: `python3 hank_audit.py . --allow-repo-suppressions`.

## Security

A security scanner is itself an attack surface: it reads hostile files by design, writes reports people open in a browser, and gates CI. Hank is meant to run on repos you do not trust yet, so the scanned tree never gets to configure Hank or reach your terminal:

- **No config from the target.** Memes load only from Hank's install dir or `--memes`. Suppressions from the target are opt-in (above).
- **Inert output.** Every value taken from the scanned tree is HTML-escaped in the report card, placed in code spans or escaped in markdown, and stripped of control characters (ANSI and OSC escapes, bidi and zero-width characters) before it reaches the terminal. The report card carries a Content-Security-Policy that blocks all scripts, and has no inline event handlers.
- **Secrets masked.** Evidence shows a secret's first four characters and its length, never the value, in every output format.
- **Stays inside the target.** Symlinked files that resolve outside the scan root are not read and are reported as a finding. FIFOs and devices are not read.
- **Bounded work.** Files are read up to 2 MB (a larger agent config is itself a high finding), and long lines are matched in fixed-size windows with bounded patterns, so a 1 MB line scans in about a second.
- **No execution, no network.** No `eval`, `exec`, `pickle`, subprocess or network calls in the scanner, and JSON is parsed with `json.loads`. The only network use is the opt-in GIFs in the HTML card.
- **The plugin skill** tells Claude that scanned content is evidence and never instructions, forbids network calls and edits during an audit, and limits the skill to `Read`, `Grep`, `Glob` and Hank's two scripts.

- **CI** runs both test suites on Python 3.9 and 3.13, runs Hank on its own hardened example (expects zero findings) and on the insecure demo (expects the gate to fail), and scans the full git history with gitleaks. Actions are pinned to commit SHAs with read-only permissions, and Dependabot keeps them current. The gitleaks config allowlists exactly one value: the fake token in `demo/.mcp.json`.

Found a way around any of this? See [SECURITY.md](SECURITY.md).

## Limitations

- **Static and pattern-based.** Detection uses regular expressions and a JSON-aware check for MCP servers. It will miss attacks phrased in ways the rules do not cover, and it can flag text that only discusses an attack. The plugin's judgment step reduces both, but does not remove them.
- **Fixed file set.** It scans `CLAUDE.md`, `SKILL.md`, `.mcp.json`, `mcp.json`, `settings.json`, `settings.local.json`, `hooks.json`, `.env*`, and subagent and command files (`*.md` under `agents/` or `commands/` in `.claude/` or a plugin root) under the target directory. It does not follow hook scripts to their source, and it does not read `~/.claude` or `~/.claude.json` unless you point it there.
- **No data-flow analysis.** It does not trace untrusted input through to a privileged tool. Combined risks are left to the plugin's judgment step.
- **Secret detection is format-based.** It recognises common key formats and skips obvious placeholders. It does not verify whether a key is live.
- **GIFs are opt-in.** With `--gifs`, opening the HTML report card loads images from Giphy, which sees your IP address. Without it the card is fully offline.

## What I learned

Before publishing, I put Hank through an independent security review that treated it as the target instead of the tool. It found real problems. All are fixed in 1.2.0 and covered by `tests/test_security.py`.

- **A scanner must not take its config from the thing it scans.** Early versions loaded `memes.json` and honoured `.hankignore` and inline `hank:ignore` markers from the scanned repo. A hostile repo could inject script into the HTML report, or add one line and mark itself clean in CI. Config now comes from the operator only, and every report says what was suppressed.
- **Escaping tests have to cover every output channel.** I had tested HTML escaping of the finding fields, but not the meme fields or the terminal. The fix was one hostile fixture that fills every input with `<script>`, ANSI escapes and a very long line, then checks all four output formats.
- **Unbounded regex gaps on untrusted lines go quadratic.** Patterns like `.*` inside an unanchored search took over 20 seconds on a single 140 KB line, enough to hang a CI gate. Bounded gaps, line windows and a file-size cap brought a 1 MB line down to about a second, and a timing test keeps it there.
- **A security tool shouldn't print the secrets it finds.** Evidence lines used to include full keys, which then land in CI logs. Every format now masks them.
- **An agent that reads attack payloads needs to be told they're evidence.** The plugin asks Claude to read the flagged files, which are by definition the ones carrying injection text. The skill now says up front that scanned content is never instructions, and limits the tools it can use.

## Tests

```bash
python3 -m pytest               # both suites
python3 tests/test_hank.py      # 81 functional checks, printed one by one
python3 tests/test_security.py  # 24 security regression tests
```

Standard library only (pytest is optional). The functional checks cover every detector against the demo, zero findings on the secure setup, precision cases for defensive phrasing and scoped permissions, report scoring and HTML escaping, and the Academy's sessions, streaks, badges and audit-to-quiz loop. The security tests cover Hank's own integrity against a hostile repo: a malicious `memes.json`, `*` in `.hankignore`, inline markers, symlink escape, FIFOs, oversize files, 1 MB lines, ANSI and OSC escapes, secret masking, JSON-escaped payloads, and the skill's guardrails.

## Extending

Detection rules are regex tables near the top of `hank_audit.py`. Add a pattern, add a check to `tests/test_hank.py`, and run the suite.

## Roadmap

- `--fix` mode that proposes a diff for each finding
- Data-flow tracking from untrusted input to privileged tools
- Rule packs for specific MCP servers (GitHub, Supabase, filesystem)

## License

[MIT](LICENSE) © 2026 Diego Bauer
