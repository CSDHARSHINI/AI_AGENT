# Toolkit Readiness Research Agent

Research pipeline for the *AI Product Ops Intern* take-home: for each of 100 apps, find **auth method, access gate (self-serve vs gated), MCP availability and a buildability verdict**, with evidence, then surface patterns instead of a raw table.

- **Case study page:** `index.html` (single file, no dependencies, deploy to any static host)
- **Agent:** `research_agent.py` (no API key needed)
- **Input:** `apps.csv` (the 100 apps and docs hints from the brief)

## Quick start

```bash
pip install httpx
python research_agent.py --limit 5     # smoke test on 5 apps
python research_agent.py               # all 100 apps (reads apps.csv next to the script)
```

Requires Python 3.9+. Works on Windows, macOS and Linux. No API key is needed by default.

### Outputs

| File | Contents |
|---|---|
| `results.jsonl` | One JSON row per app: auth, gate, MCP, verdict, flags, verbatim evidence snippets, OpenAPI probe result |
| `results.csv` | Summary table (opens in Excel) |
| `review_queue.csv` | Only the rows a human must check, with the reason flags |

### Codes used on the page

- **Auth:** O = OAuth2, K = API key, T = token, B = Basic, X = none/unknown
- **Gate:** S = self-serve, P = paid plan, A = approval/review, C = contact sales / partner
- **MCP:** Y = vendor-hosted, C = community, N = none found
- **Verdict:** G = build now, Y = build with a caveat, R = needs outreach

## How the agent works

1. **Fetch** the docs page, `/openapi.json` and `/llms.txt` per app (cached on disk in `.cache/`, bounded concurrency).
2. **Deterministic probes (zero tokens):** read auth from OpenAPI `securitySchemes`; look the app up in the official MCP registry (best effort).
3. **Trim** each page to windows around auth / pricing / approval keywords, so text per app is constant-size.
4. **Rule extractor:** keyword rules produce auth, gate and MCP, each with a snippet copied from the page as evidence.
5. **Cross-checks produce flags:** docs vs OpenAPI auth, MCP mentioned but not in registry, weak gate evidence, auth not found, no docs fetched.
6. **Human queue:** any flagged row goes to `review_queue.csv`.

Optional second opinion, still without an Anthropic key: `LLM_BACKEND=ollama python research_agent.py` (needs a local Ollama; set `OLLAMA_MODEL`, default `llama3.1`). Its answers are compared with the rules and disagreements are flagged. `LLM_BACKEND=anthropic` also works if you have `ANTHROPIC_API_KEY`.

### Efficiency

| Concern | Approach |
|---|---|
| Time | N apps, at most 4 fetches each, `CONC=12` in flight, so wall time is about N / 12 x latency; O(N) total work |
| Tokens / text | Keyword-window trimming keeps per-app text constant (about 12k chars max) |
| Space | Results stream to JSONL, O(N) memory; page cache on disk |
| Reruns | Cache keyed by URL hash makes reruns idempotent; failed fetches are never cached |
| Robustness | One failing app is caught and queued for review, never kills the batch |

## Where a human is needed

- Every row in `review_queue.csv`.
- Apps with only a homepage as docs hint, or no public docs (e.g. fanbasis, Paygent Connect, iPayX, Waterfall.io, Consensus).
- Gate classification, which is the roughest field (keyword heuristics). Paid / approval / contact-sales signals are easy to misread.
- Every MCP cell, since availability changes quickly.

## Verification

Protocol:

1. **Loop 1, automatic:** OpenAPI and registry cross-checks, evidence-strength flags (optional second model).
2. **Loop 2, re-check flagged rows** against the live docs in a browser.
3. **Loop 3, human sample:** at least 2 apps per category, over-sampling amber and red rows. Record each field as right or wrong.

Results (fill in after your run; do not report numbers you did not measure):

| Field | First pass correct | After loops correct | Notes |
|---|---|---|---|
| Auth | _/_ | _/_ | |
| Gate | _/_ | _/_ | |
| MCP | _/_ | _/_ | |
| Verdict | _/_ | _/_ | |

Checked so far: **Otter AI** (OAuth, vendor-hosted MCP at `mcp.otter.ai/mcp`, REST API beta and Enterprise-only) matched the table.

## Known limitations (honest)

- Rules are keyword heuristics, not understanding. They are good for auth and rough for gate, so expect many flagged rows.
- Docs hints that are homepages return thin results; give real docs URLs in `apps.csv` where you can.
- MCP registry lookup is best effort; a failed lookup is reported as `unknown`, not guessed.
- Composio's SDK/MCP is not wired in. It would slot in as the fetch / search layer (replace `get()`), and Composio toolkit pages are a useful extra evidence source for MCP and auth.

## Repo layout

```
index.html          case-study page (deployable as-is)
research_agent.py   research pipeline
apps.csv            the 100 apps
README.md           this file
```

## Deploy the page

Drag the folder containing `index.html` into Netlify Drop, or enable GitHub Pages (Settings, Pages, deploy from `main` / root), or run `npx vercel`. Set `var REPO=""` in the page's script to your repository URL.
