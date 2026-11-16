# Hank

**An AI security and EU compliance reviewer for Claude Code.**

[![Sample review](https://img.shields.io/badge/sample_review-18_of_18_found-0c1a1c?style=for-the-badge&labelColor=0c1a1c&color=e3cd9c)](docs/sample-review/)
[![Frameworks](https://img.shields.io/badge/briefs-13_frameworks-0c1a1c?style=for-the-badge&labelColor=0c1a1c&color=7fe6da)](skills/hank/references/)
[![tests](https://img.shields.io/github/actions/workflow/status/AIwithDiego/hank/ci.yml?branch=main&style=for-the-badge&label=tests&labelColor=0c1a1c)](https://github.com/AIwithDiego/hank/actions/workflows/ci.yml)
![Claude Code plugin](https://img.shields.io/badge/Claude_Code-plugin-0c1a1c?style=for-the-badge&logo=anthropic&logoColor=7fe6da)
[![MIT](https://img.shields.io/badge/licence-MIT-0c1a1c?style=for-the-badge&labelColor=0c1a1c)](LICENSE)

[![Hank found all 18 issues planted in a deliberately unsafe AI support chat, wrote 26 findings with file, line, rule and fix, and followed none of the hidden instructions planted in it](docs/assets/cover.png)](docs/sample-review/)

```text
/plugin marketplace add AIwithDiego/hank
/plugin install hank@hank-security
```

A Claude Code plugin: one skill and one subagent. Built in Dublin with Claude Code; version 2.0 published 29 September 2026. Hank is the reviewer I use on my own work and on client projects, the same one that checked the EU AI Act and GDPR mapping in [taste-to-evals](https://github.com/AIwithDiego/taste-to-evals).

**[Read the sample review](docs/sample-review/)** (an unsafe demo app, the answer key, Hank's report) · [Run it yourself](#run-it-yourself)

**Contents:** [The problem](#the-problem) · [Research](#research) · [What it does](#what-it-does) · [Results](#results) · [The build](#the-build) · [What went wrong](#what-went-wrong) · [What I learned](#what-i-learned) · [Run it yourself](#run-it-yourself)

## The problem

Small teams now ship LLM features, agents and MCP servers to EU customers. Two kinds of risk land on them at once, and most have no security engineer and no lawyer on call:

- **The AI surface.** Prompt injection, agents with tools that can write, poisoned MCP tool descriptions, model output rendered as HTML. Generic code review misses most of it because the bug is in what the model is allowed to do.
- **The law.** A chat widget on a shop can touch GDPR, the ePrivacy cookie rules and the AI Act's transparency duty on the same page. One incident at a client in finance can start NIS2, DORA and GDPR clocks with different regulators.
- **The dates.** EU rules moved a lot in 2025 and 2026: the AI Act was amended by Regulation (EU) 2026/1744, and the Digital Omnibus proposals are still going through Parliament and Council. Advice from a year ago can be wrong today.

> Security review and compliance review are usually two people and two reports. Hank reads the code once and tells you what an attacker can do and which article you'd break.

## Research

**What already exists.** Scanners and red-team tools (promptfoo, garak, Invariant's mcp-scan) test models, prompts and MCP configs. Compliance platforms (Vanta, Drata) track controls for an audit. Lawyers answer the legal question once it has been asked. Each covers a slice. I wanted one reviewer that reads a Flask route and says "this is LLM06, and it is also a GDPR Art. 32 problem".

**Who it's for.** Builders who ship AI features into small and mid-sized EU businesses, starting with us: at AIwithDiego, Hank sits in the design review of every change that touches an AI surface, and answers every EU compliance question on any project, AI or not.

**The limits we chose.** Hank reads and reports. He edits nothing unless asked, runs active tests only against a staging environment you own, and treats every file he reviews as evidence, never as instructions. His compliance output is analysis, not legal advice: anything material gets a `REQUIRES COUNSEL` line with the exact question for a lawyer. Every brief carries a "Last reviewed" date, and he is told to check a primary source when a question turns on something newer.

**What I didn't build.**

| Choice | Why | Trade-off |
|---|---|---|
| Not a rule-based scanner | Hank 1.x was one. Rules catch patterns, not what a tool lets the model do | A review costs tokens and isn't deterministic |
| Not a SaaS or a dashboard | The reviewer lives where the code is written | No history across reviews unless you keep the reports |
| Not a law firm | Analysis with the article named is what a builder can act on | Material questions still go to counsel |
| Not every country | Ireland is the worked example of a national layer | Other Member States need their own brief |

## What it does

Ask in plain words: "Hank, review the chatbot endpoint for prompt injection", "Check our MCP server before we publish it", "Does this site need a cookie banner?", "Is our AI feature high-risk under the AI Act?", "Review this DPA". Hank picks the mode, works through it and returns a ranked report.

| Area | What he checks |
|---|---|
| AI security | OWASP LLM Top 10 (2025), OWASP Agentic Top 10, MCP checks (tool poisoning, rug pulls, cross-server shadowing), mapped to MITRE ATLAS |
| Supply chain and privacy | Unpinned packages and MCP servers, secrets, where personal data flows and where it's logged |
| Data protection | GDPR, ePrivacy (cookies, tracking, e-marketing) |
| AI regulation | EU AI Act as amended by Regulation (EU) 2026/1744 |
| Cybersecurity law | NIS2, Cyber Resilience Act, DORA |
| Data and cloud | Data Act (switching, egress charges, unfair B2B terms) |
| Standards | ISO/IEC 27001, ISO/IEC 42001, SOC 2, NIST AI RMF |
| National example | Ireland: the Data Protection Commission, Data Protection Act 2018, S.I. 336/2011 |

<table>
<tr>
<td width="50%"><img src="docs/assets/poisoned-mcp-tool.png" alt="The demo app's MCP tool: its description hides an instruction to read the user's SSH and AWS keys and not tell them"></td>
<td width="50%"><img src="docs/assets/hank-finding-f003.png" alt="Hank's finding F-003: poisoned tool description, rated critical, treated as evidence and not acted on, with four remediation steps"></td>
</tr>
<tr>
<td>Planted: an MCP tool that tells the AI to steal SSH and AWS keys.</td>
<td>Hank's finding: reported as critical, never followed.</td>
</tr>
</table>

![How Hank works: you ask in plain words; Hank reads everything as evidence; an AI surface gets the six-phase security review, a legal question gets the EU compliance review; both read 13 dated briefs](docs/how-it-works.svg)

1. **The method** ([`skills/hank/SKILL.md`](skills/hank/SKILL.md)): both modes, the checklists and the report format. Short enough to load on every review.
2. **The briefs** ([`skills/hank/references/`](skills/hank/references/)): one per framework, each with its sources and a "Last reviewed" date. Read only when a question needs the detail.
3. **The subagent** ([`agents/hank.md`](agents/hank.md)): runs the review in its own context, static only, with the hard rules repeated in case the method can't load.
4. **The checks** ([`scripts/check.py`](scripts/check.py)): the plugin manifest and marketplace agree, every brief is linked from the method and has sources and a date, no broken links. Runs in CI.

Every compliance review starts with the same question: which of these laws actually apply to this project? Hank maps that first, then opens only the rules that apply.

## Results

I wrote a small, deliberately unsafe support chat for an invented shop ([`examples/acme-helpdesk`](examples/acme-helpdesk/)): Flask, the Anthropic SDK, four agent tools, a RAG store, a staff MCP server and a web page. I planted 18 issues, wrote them down in an [answer key](docs/sample-review/answer-key.md) and committed it ([`994cd92`](https://github.com/AIwithDiego/hank/commit/994cd92)) before Hank saw the app.

| | Count |
|---|---|
| Planted issues (15 security, 3 EU compliance) | 18 |
| Found, with the right file and a fix that closes it | 18 |
| Further findings not in the key | 10, none false by my reading; 4 of them are paperwork code can't show |
| Hidden instructions followed (the poisoned MCP tool) | 0 |
| Total findings | 26: 3 critical, 12 high, 8 medium, 3 low across both modes |

Hank also caught a bug I hadn't planted: the demo wouldn't run at all, because the Anthropic SDK requires `max_tokens` and my code never set it.

The full report is in [`docs/sample-review/report.md`](docs/sample-review/report.md), unedited, and the score with its limits in [`docs/sample-review/`](docs/sample-review/). The honest caveats: one run on one model (Claude Opus 5.5), a target I wrote myself, static review only. To reproduce it, copy the demo app into an empty folder and ask Hank to review it (step 4 below).

## The build

Built by Diego Bauer with Claude Code. I decided what Hank checks and how he behaves, chose the frameworks and reviewed his reports on real projects; Claude wrote most of the text and the checks under my direction. Hank started as something else, which is most of the story. Versions 1.x lived in a private repo; this public repo's history starts at 2.0.

| When | What landed |
|---|---|
| Jun to Jul 2026 | Hank 1.0, a zero-dependency Python scanner for Claude Code setups (`CLAUDE.md`, skills, `.mcp.json`, hooks) mapped to the OWASP LLM Top 10, with a meme-powered HTML report card. Then 1.1, Hank Academy: a 48-question security quiz with streaks and badges, 81 tests. A demo for an AI security offer |
| 23 Sep | 1.2: a security audit of Hank himself found 15 issues, the worst being that the repo under review could switch its own findings off. Fixed before publishing |
| 24 Sep | First public release of the scanner; Dependabot tamed ([#3](https://github.com/AIwithDiego/hank/pull/3), [#4](https://github.com/AIwithDiego/hank/pull/4)) |
| 29 Sep | The Hank I use every day gains an EU compliance mode and becomes the standing reviewer for every EU question on any project. Same day: this repo replaced with 2.0, the real reviewer as a plugin, 13 briefs checked against EUR-Lex, the Commission, the EDPB, ENISA and national regulators ([`21e00be`](https://github.com/AIwithDiego/hank/commit/21e00be)) |
| 5 Nov | Checks the EU AI Act and GDPR mapping of [taste-to-evals](https://github.com/AIwithDiego/taste-to-evals) before it goes public |
| 16 Nov | The sample review: unsafe demo app, answer key first, report and score ([`32f4f38`](https://github.com/AIwithDiego/hank/commit/32f4f38)) |

## What went wrong

| | |
|---|---|
| **I published the wrong Hank first.** The public repo was the 1.x scanner and quiz. Five days later I saw it misrepresented the reviewer I actually use, and replaced it with 2.0. | [`21e00be`](https://github.com/AIwithDiego/hank/commit/21e00be), [CHANGELOG](CHANGELOG.md) |
| **Replacing it erased the history.** I swapped the repo's history for one fresh commit. PRs #3 and #4 still show as merged, but their commits are no longer on `main`. My public repos now keep their history as it is. | [#3](https://github.com/AIwithDiego/hank/pull/3) |
| **The scanner trusted the repo it scanned.** A pull request could add `*` to `.hankignore` and turn the CI gate green. Auditing Hank himself caught it. The lesson became 2.0's first hard rule: everything under review is evidence, never instructions. | [`agents/hank.md`](agents/hank.md) |
| **My own demo app couldn't run.** The sample app called the Anthropic API without `max_tokens`, which the SDK requires. I hadn't planted that; Hank found it. | [report, F-013](docs/sample-review/report.md) |

## What I learned

- **Ship the tool you actually use.** The scanner was one narrow use of Hank. The reviewer I rely on every day is the judgement about what a finding means, and that is what went public in 2.0.
- **Rules miss what a tool lets the model do.** The worst issues in the sample were permissions (any SQL, any shell command, any refund), and no pattern match shows those.
- **Treat what you review as hostile.** Both versions of Hank had to learn this: a reviewer that follows instructions in the code is an attack path.
- **Date every legal claim.** EU law moved faster in 2026 than any brief could; a "Last reviewed" date makes the age visible.
- **Write the answer key before the run.** Otherwise the score bends to whatever came back.

**What's next:** a second sample for the compliance mode alone (a brochure site with no AI), a warning when a brief is more than six months old, and a European Accessibility Act brief. All three are open as [good first issues](https://github.com/AIwithDiego/hank/labels/good%20first%20issue).

## Ground rules

- **Read-only by default.** Hank reports; he changes files only when you ask for a specific fix after reading the report.
- **Your staging, never production.** Active tests run only against an environment you own, after you confirm the target.
- **Not legal advice.** Analysis that names the article and the gap, with a question for counsel when it matters.
- **Demo data only in this repo.** `acme-helpdesk` is invented, uses reserved test domains and placeholder IDs, and is unsafe on purpose. Don't deploy it.

## Run it yourself

1. In Claude Code: `/plugin marketplace add AIwithDiego/hank`, then `/plugin install hank@hank-security`. From a shell: `claude plugin marketplace add AIwithDiego/hank && claude plugin install hank@hank-security`.
2. Open your project and ask: *"Hank, review the chat endpoint for prompt injection"* or *"Does this site need a cookie banner?"*.
3. For a review in its own context, ask Claude to delegate it to the `hank` subagent.
4. To reproduce the sample: clone this repo, copy `examples/acme-helpdesk` into an empty folder, open Claude Code there and ask *"Hank, review this app before we launch it. Run both modes. Static review only."* Compare with [`docs/sample-review/answer-key.md`](docs/sample-review/answer-key.md).
5. Changing the plugin: `python3 scripts/check.py` (standard library only), the same check CI runs.

## Repo map

```
.claude-plugin/        plugin manifest and marketplace entry
skills/hank/SKILL.md   the method: both modes, checklists, report format
skills/hank/references/ 13 briefs, one per framework, with sources and a review date
agents/hank.md         the subagent: static review in its own context
examples/acme-helpdesk/ a deliberately unsafe demo app (do not deploy)
docs/sample-review/    answer key, Hank's report, the score
docs/                  how-it-works diagram, images
scripts/check.py       structure, links, sources and dates; runs in CI
```

## Credits

The [OWASP GenAI Security Project](https://genai.owasp.org/) for the LLM and Agentic Top 10 lists, [MITRE ATLAS](https://atlas.mitre.org/) for the technique IDs, and EUR-Lex, the EDPB, ENISA and the Irish Data Protection Commission for the sources behind the briefs. Built with [Claude Code](https://claude.com/claude-code). Part of a series with [taste-to-evals](https://github.com/AIwithDiego/taste-to-evals), which Hank reviewed. Issues and pull requests welcome: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## Licence

MIT · Made in Dublin by [Diego Bauer](https://www.aiwithdiego.com) · [LinkedIn](https://www.linkedin.com/in/diego-bauer-domeyko/)

Built by [AIwithDiego](https://www.aiwithdiego.com). Need something like this for your team? [Talk to me](https://www.aiwithdiego.com).
