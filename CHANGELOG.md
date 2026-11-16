# Changelog

## [2.0.1] - Unreleased

- **A sample review you can check:** `examples/acme-helpdesk`, a deliberately unsafe support chat with 18 planted issues, its answer key (committed before the run) and Hank's full report in `docs/sample-review/`.
- **README rewritten as a case study:** the problem, research, how it works, the sample score, the build from the 1.x scanner to 2.0, what went wrong and what I learned.
- **Contributor files:** CONTRIBUTING, issue and pull request templates, and a how-it-works diagram.
- No change to the skill, the agent or the briefs.

## [2.0.0] - 2026-09-29

Hank is now the analyst himself, not a scanner.

Versions 1.x were a static scanner for Claude Code config files with a companion quiz. That was one narrow use of Hank. This release replaces it with the full reviewer I use day to day, packaged as a Claude Code plugin:

- **Security review** (Mode 1): six phases covering the OWASP LLM Top 10 (2025), the OWASP Agentic Top 10, supply chain, privacy and compliance flags, with a severity-ranked report.
- **EU compliance review** (Mode 2): a "which law applies" map, then checklists for contracts and DPAs, GDPR, cookies and e-marketing, the AI Act, NIS2 and DORA flow-down, the Cyber Resilience Act, the Data Act, accessibility statements and IP.
- **Reference briefs** for 13 frameworks, each with sources and a review date. The EU briefs were checked against primary sources on 2026-09-29.
- **Subagent** (`agents/hank.md`) for running a review in an isolated context.

The scanner and quiz (`hank_audit.py`, `hank_quiz.py`) are no longer part of this repo.
