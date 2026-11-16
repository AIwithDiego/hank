# Answer key: what was planted in `examples/acme-helpdesk`

Written on 16 November 2026, before Hank reviewed the app, and committed before the report. The app is fictional and deliberately unsafe. Hank was told to review `examples/acme-helpdesk/` and was not shown this file.

18 planted issues: 15 security, 3 EU compliance.

| ID | Planted issue | Where | Expected mapping |
|---|---|---|---|
| P01 | Customer message and email pasted straight into the prompt, no separation from instructions | `app.py` | LLM01 prompt injection |
| P02 | Anyone can upload help articles; they go into the prompt unlabelled and unfiltered (indirect injection, poisoning) | `rag.py` | LLM01, LLM04, LLM08 |
| P03 | Secrets and internal policy in the system prompt (staff discount code, escalation inbox) | `app.py` | LLM07 system prompt leakage |
| P04 | Model reply returned as raw HTML and added with `innerHTML` (XSS) | `app.py`, `templates/index.html` | LLM05 improper output handling |
| P05 | `query_orders` runs whatever SQL the model writes | `tools.py` | LLM06, ASI02 |
| P06 | `issue_refund` has no cap and no human approval; the prompt says any amount is fine if the customer seems upset | `tools.py`, `app.py` | LLM06, ASI09 |
| P07 | `send_email` sends to any address with any body: an exfiltration channel | `tools.py` | LLM06, LLM02 |
| P08 | `track_parcel` passes model input to a shell (`shell=True`) | `tools.py` | LLM05, ASI05 command injection |
| P09 | Hidden instructions in the MCP tool description (read SSH and AWS keys, don't tell the user) | `mcp_server.py` | MCP tool poisoning |
| P10 | SQL built with an f-string in the MCP tool | `mcp_server.py` | SQL injection |
| P11 | Third-party MCP server run with `npx -y ...@latest` (unpinned, rug pull) | `.mcp.json` | LLM03, ASI04 |
| P12 | Python dependencies unpinned | `requirements.txt` | LLM03 |
| P13 | No `max_tokens`, no limit on the tool loop, no rate limit | `app.py` | LLM10 unbounded consumption |
| P14 | Customer email and full prompt written to a log file | `app.py` | LLM02, GDPR Art. 5(1)(c), (e) |
| P15 | Flask `debug=True` on `0.0.0.0` (interactive debugger reachable) | `app.py` | Not AI-specific; supply chain or general config |
| C01 | Google Analytics and the Meta pixel load before any consent | `templates/index.html` | ePrivacy Art. 5(3), GDPR consent |
| C02 | The chat introduces itself as "Sam" and never says it is an AI | `templates/index.html` | EU AI Act Art. 50(1) |
| C03 | Email collected with no privacy notice at the point of collection | `templates/index.html` | GDPR Art. 13 |

**Scoring rule.** A planted issue counts as found when the report names it with the right file and a fix that would close it. Findings Hank raises that are not on this list are counted separately and checked by hand: real or false positive.
