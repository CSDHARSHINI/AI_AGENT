"""
Evidence-first research agent for the 100-app toolkit study.  NO API KEY NEEDED (default backend = rules).

Setup:   pip install httpx
Run:     python research_agent.py                 (reads apps.csv next to this script)
         python research_agent.py --limit 5      (smoke test)
Outputs: results.jsonl (rows + verbatim evidence), results.csv (summary), review_queue.csv (rows a human must check)

Pipeline per app (all free):
  1 fetch docs + /openapi.json + /llms.txt                (cached on disk, bounded concurrency)
  2 deterministic probe: OpenAPI securitySchemes -> auth   (0 tokens)
  3 deterministic probe: official MCP registry lookup      (best effort)
  4 keyword-window trim -> rule extractor (auth / gate / mcp) with verbatim evidence snippets
  5 cross-checks (docs vs OpenAPI, docs vs MCP registry, evidence strength) -> flags -> human queue
Optional second opinion (still no Anthropic key):  set LLM_BACKEND=ollama  (needs local Ollama; OLLAMA_MODEL=llama3.1)
Optional:                                          set LLM_BACKEND=anthropic (needs ANTHROPIC_API_KEY)

Cost: O(N*K) fetches (K<=4/app), constant text per app, O(N) memory, wall time ~ N/CONC * latency.
Honest limit: rules are keyword heuristics - good for auth, rough for gate. Every weak/conflicting row is flagged.
"""
import asyncio, csv, hashlib, json, os, re, sys, pathlib, argparse
from urllib.parse import urlparse, quote
import httpx

CONC, PAGE_CHARS = 12, 12000
CACHE = pathlib.Path(".cache"); CACHE.mkdir(exist_ok=True)
BACKEND = os.getenv("LLM_BACKEND", "rules").lower()                 # rules | ollama | anthropic
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
UA = {"User-Agent": "Mozilla/5.0 (compatible; toolkit-research-agent/1.0)"}
AUTH_CODE = {"oauth2": "O", "api_key": "K", "basic": "B", "token": "T", "other": "X"}

KW = re.compile(r"oauth|api[ -]?key|bearer|access token|authenticat|authoriz|rate limit|pricing|enterprise|approval|"
                r"app review|partner|contact sales|mcp|model context protocol|sandbox|free trial|paid plan", re.I)
AUTH_PAT = {"oauth2": r"oauth\s*2?(?:\.0)?|authorization code|client credentials",
            "api_key": r"api[ _-]?key|x-api-key",
            "basic": r"basic auth(?:entication)?|http basic",
            "token": r"bearer token|access token|api token|personal access token|auth token"}
GATE_PAT = [  # (label, regex, min_hits) - first class reaching min_hits wins, else self_serve if any hit
    ("contact_sales", r"contact (?:our )?sales|talk to sales|book a demo|request (?:api )?access|apply for (?:api )?access|partner(?:ship)? program|become a partner|by invitation", 2),
    ("approval", r"app review|review process|approval|approved by|verification|developer token|production access|submit .{0,30}for review", 2),
    ("paid", r"enterprise (?:plan|customers|edition|only)|paid plans?|available (?:on|for|with) .{0,40}(?:plans?|tiers?)|requires? (?:a )?(?:pro|premium|business|enterprise)|upgrade", 2),
    ("self_serve", r"free (?:tier|plan|trial|account|developer)|sandbox|sign up|create (?:an? )?(?:app|account|api key)|generate (?:an? )?(?:api )?(?:key|token)|get (?:your )?api key|developer (?:account|portal|dashboard)", 1)]

# ---------- input ----------
def load_rows(path, limit=None):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        norm = lambda h: re.sub(r"[^a-z]", "", (h or "").lower())
        hdr = {norm(h): h for h in (rd.fieldnames or [])}
        n = next((hdr[k] for k in hdr if k in {"name", "app", "appname"}), None)
        u = next((hdr[k] for k in hdr if k in {"docsurl", "url", "website", "websitehint", "hint", "docs"}), None)
        if not n or not u: sys.exit(f"Need a name column and a docs-url column. Found headers: {rd.fieldnames}")
        rows = []
        for r in rd:
            name, url = (r.get(n) or "").strip(), (r.get(u) or "").strip()
            if not name: continue
            url = url.split()[0] if url else ""
            if url and not url.startswith("http"): url = "https://" + url
            rows.append({"name": name, "docs_url": url})
    return rows[:limit] if limit else rows

# ---------- fetch (cached, bounded) ----------
async def get(client, sem, url):
    if not url: return ""
    f = CACHE / hashlib.sha1(url.encode()).hexdigest()
    if f.exists(): return f.read_text(encoding="utf-8", errors="ignore")
    async with sem:
        try:
            r = await client.get(url)
            text = r.text if r.status_code == 200 else ""
        except Exception:
            text = ""
    if text: f.write_text(text, encoding="utf-8")
    return text

def strip_html(t):
    t = re.sub(r"(?is)<(script|style|noscript).*?</\1>", " ", t)
    return re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", t))

def trim(text, budget=PAGE_CHARS):
    """+-window around auth/pricing keywords: constant size regardless of page length."""
    text, spans, last = strip_html(text), [], -1
    for m in KW.finditer(text):
        if m.start() < last: continue
        spans.append(text[max(0, m.start() - 200): m.end() + 300]); last = m.end() + 300
    return " ... ".join(spans)[:budget]

# ---------- deterministic probes (zero tokens) ----------
def probe_openapi(spec_text):
    try: j = json.loads(spec_text)
    except Exception: return None
    schemes = (j.get("components", {}) or {}).get("securitySchemes") or j.get("securityDefinitions") or {}
    codes = set()
    for v in schemes.values():
        t, s = str(v.get("type", "")).lower(), str(v.get("scheme", "")).lower()
        codes.add("O" if t in ("oauth2", "openidconnect") else "K" if t == "apikey" else "B" if s == "basic" else "T" if s == "bearer" else "X")
    return {"auth": sorted(codes), "endpoints": sum(len(p) for p in (j.get("paths") or {}).values() if isinstance(p, dict))}

async def probe_mcp_registry(client, sem, name):
    """Best-effort lookup in the official MCP registry. Returns official|community|none|unknown."""
    key = re.sub(r"[^a-z0-9]", "", name.lower().split("(")[0].split()[0])
    txt = await get(client, sem, f"https://registry.modelcontextprotocol.io/v0/servers?search={quote(name.split('(')[0].strip())}&limit=20")
    try: items = json.loads(txt).get("servers", [])
    except Exception: return "unknown"
    best = "none"
    for it in items:
        s = it.get("server", it)
        nm = str(s.get("name", "")).lower()
        if key and key in re.sub(r"[^a-z0-9/.]", "", nm + str(s.get("title", "")).lower()):
            ns = nm.split("/")[0]
            if key in ns and "github" not in ns: return "official"
            best = "community"
    return best

# ---------- rule extractor (verbatim evidence from the page) ----------
def snippet(text, m, w=110): return text[max(0, m.start() - w): m.end() + w].strip()

def extract_rules(page):
    auth, quotes, hits = [], {}, {}
    for label, pat in AUTH_PAT.items():
        ms = list(re.finditer(pat, page, re.I))
        if ms: hits[label] = len(ms)
    auth = [k for k, _ in sorted(hits.items(), key=lambda kv: -kv[1])][:3]
    if auth: quotes["auth"] = snippet(page, next(re.finditer(AUTH_PAT[auth[0]], page, re.I)))
    gate, gate_hits = "unknown", 0
    for label, pat, need in GATE_PAT:
        ms = list(re.finditer(pat, page, re.I))
        if len(ms) >= need:
            gate, gate_hits = label, len(ms); quotes["gate"] = snippet(page, ms[0]); break
    mcp = "unknown"
    mm = re.search(r"model context protocol|\bmcp\b", page, re.I)
    if mm: mcp = "mentioned"; quotes["mcp"] = snippet(page, mm)
    return {"auth": auth, "gate": gate, "mcp": mcp, "blocker": "", "quotes": quotes, "gate_hits": gate_hits}

# ---------- optional LLM second opinion (no Anthropic key needed for ollama) ----------
SCHEMA = '{"auth": ["oauth2|api_key|basic|token|other"], "gate": "self_serve|paid|approval|contact_sales|unknown", "mcp": "official|community|none|unknown", "blocker": "", "quotes": {"auth": "verbatim or null", "gate": "verbatim or null"}}'
_llm_sem = asyncio.Semaphore(2)
async def llm_extract(client, name, page):
    prompt = f"App: {name}\nUsing ONLY this documentation excerpt, answer JSON matching {SCHEMA}\nQuotes must be verbatim. JSON only.\n\nEXCERPT:\n{page[:6000]}"
    async with _llm_sem:
        if BACKEND == "ollama":
            r = await client.post(OLLAMA_URL + "/api/generate", timeout=300,
                                  json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"})
            txt = r.json().get("response", "")
        else:
            import anthropic
            r = await anthropic.AsyncAnthropic().messages.create(model=ANTHROPIC_MODEL, max_tokens=600, messages=[{"role": "user", "content": prompt}])
            txt = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
    m = re.search(r"\{.*\}", txt, re.S)
    try: ans = json.loads(m.group()) if m else {}
    except Exception: ans = {}
    ans["auth"] = [a for a in (ans.get("auth") or []) if isinstance(a, str)]
    ans["quotes"] = ans.get("quotes") or {}
    return ans

def grounded(ans, page):
    flat = re.sub(r"\s+", " ", page).lower()
    qs = [q for q in (ans.get("quotes") or {}).values() if isinstance(q, str) and q.strip()]
    return all(re.sub(r"\s+", " ", q).lower() in flat for q in qs)

def verdict(o):
    if o["gate"] in ("contact_sales", "unknown") and not o["auth"]: return "R"
    if o["gate"] == "contact_sales": return "R"
    if o["gate"] == "self_serve" and o["auth"]: return "G"
    return "Y"

# ---------- per-app pipeline ----------
async def research(client, sem, row):
    name, url = row["name"], row["docs_url"]
    p = urlparse(url) if url else None
    origin = f"{p.scheme}://{p.netloc}" if p and p.netloc else ""
    pages, mcp_reg = await asyncio.gather(
        asyncio.gather(get(client, sem, url), get(client, sem, origin + "/openapi.json" if origin else ""), get(client, sem, origin + "/llms.txt" if origin else "")),
        probe_mcp_registry(client, sem, name))
    spec = probe_openapi(pages[1]) if pages[1] else None
    page = trim("\n".join([pages[0], pages[2]]))
    out = {"app": name, "docs": url, "spec": spec, "mcp_registry": mcp_reg, "flags": []}
    if not page:
        out.update(auth=[], gate="unknown", mcp=mcp_reg, blocker="no docs fetched", quotes={}, flags=["no_docs_fetched"], needs_human=True, verdict="R")
        return out
    a, flags = extract_rules(page), []
    if mcp_reg in ("official", "community"): a["mcp"] = mcp_reg                 # registry beats docs mention
    elif a["mcp"] == "mentioned": a["mcp"] = "unknown"; flags.append("mcp_mentioned_not_in_registry")
    else: a["mcp"] = mcp_reg
    if not a["auth"]: flags.append("auth_not_found")
    if a["gate"] == "unknown" or a["gate_hits"] < 2: flags.append("weak_gate_evidence")
    if spec and spec["auth"] and a["auth"] and not ({AUTH_CODE[x] for x in a["auth"]} & set(spec["auth"])): flags.append("auth_vs_openapi")
    if BACKEND in ("ollama", "anthropic"):
        try:
            b = await llm_extract(client, name, page); out["second_opinion"] = b
            if b.get("gate") != a["gate"]: flags.append("gate_disagree")
            if set(b.get("auth", [])) != set(a["auth"]): flags.append("auth_disagree")
            if not grounded(b, page): flags.append("llm_quote_not_in_page")
        except Exception as e: flags.append("llm_error:" + type(e).__name__)
    out.update(**a, flags=flags, needs_human=bool(flags)); out["verdict"] = verdict(out)
    return out

async def safe(client, sem, row):
    try: return await research(client, sem, row)
    except Exception as e:
        return {"app": row["name"], "docs": row["docs_url"], "error": repr(e), "flags": ["exception"], "needs_human": True, "verdict": "R"}

async def main(path, limit):
    rows, sem = load_rows(path, limit), asyncio.Semaphore(CONC)
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=UA) as client:
        res = await asyncio.gather(*[safe(client, sem, r) for r in rows])
    with open("results.jsonl", "w", encoding="utf-8") as f:
        for o in res: f.write(json.dumps(o, ensure_ascii=False) + "\n")
    cols = ["app", "docs", "auth", "gate", "mcp", "verdict", "blocker", "flags", "needs_human"]
    with open("results.csv", "w", newline="", encoding="utf-8-sig") as f, open("review_queue.csv", "w", newline="", encoding="utf-8-sig") as g:
        w, q = csv.writer(f), csv.writer(g); w.writerow(cols); q.writerow(cols)
        for o in res:
            line = [";".join(o[c]) if isinstance(o.get(c), list) else o.get(c, "") for c in cols]
            w.writerow(line)
            if o.get("needs_human"): q.writerow(line)
    print(f"[{BACKEND}] {len(res)} apps done, {sum(1 for o in res if o.get('needs_human'))} queued for human review -> review_queue.csv")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Research agent for the 100-app toolkit study (no API key needed)")
    ap.add_argument("csv", nargs="?", default="apps.csv"); ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args(); path = pathlib.Path(a.csv)
    if not path.is_absolute() and not path.exists(): path = pathlib.Path(__file__).resolve().parent / a.csv
    if not path.exists(): sys.exit(f"Input file not found: {a.csv}")
    asyncio.run(main(str(path), a.limit))