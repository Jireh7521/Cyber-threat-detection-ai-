# Cyber Threat Detection AI

Paste network traffic logs (firewall/IDS alerts, PCAP summaries, NetFlow, SSH/auth logs…) and get an
AI-written threat report, an IOC list with MITRE ATT&CK mapping, or a plain-English explanation.
You can ask follow-up questions about the findings.

> For defensive and educational use. The AI's output is a starting point for an analyst, not a verdict.

## How it works

```
Browser (static/)  ──►  FastAPI server (app/)  ──►  Anthropic API
  index.html, app.js      holds the API key           streams the analysis
        ◄── Server-Sent Events (streamed text + structured summary) ──
```

- The **API key stays on the server** (`.env`); the browser never sees it.
- The model ends each report with a hidden `<summary>` JSON tag; the server strips it from the stream and
  sends it as a separate event, so the stats cards (threats / risk / confidence) are real data, not regex guesses.
- Logs are wrapped in `<traffic_log>` tags and the prompt tells the model to treat them as **untrusted data**
  (defence against prompt injection hidden in logs).
- Limits: max input size and a per-IP rate limit (configurable).

## Run it

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env                                    # then put your ANTHROPIC_API_KEY in .env
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 and click a sample dataset, then **Analyze Traffic**.

Get an API key at https://console.anthropic.com.

## Test

```bash
pytest
```

Tests use a fake Anthropic client, so they need no key and no network.

## Project layout

```
app/
  main.py          routes, SSE streaming, input validation, error mapping
  prompts.py       system prompts for the 3 modes + injection guard + summary tag
  streamfilter.py  hides/parses the trailing <summary> tag while streaming
  ratelimit.py     in-memory per-IP rate limiter
  config.py        settings from environment variables
static/            index.html, app.js, samples.js (the UI)
tests/             pytest suite
prototype/         the original single-file version (kept for reference)
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Required. |
| `ANTHROPIC_MODEL` | `claude-sonnet-5-5` | Model used for analysis. |
| `MAX_OUTPUT_TOKENS` | `4096` | Max length of a report. |
| `MAX_INPUT_CHARS` | `100000` | Max pasted log size. |
| `RATE_LIMIT_REQUESTS` / `RATE_LIMIT_WINDOW_SECONDS` | `20` / `60` | Per-IP limit. |

## Known limits / next steps

- **Detection is LLM-only.** There are no log parsers or rule-based detectors yet, so very large or
  binary captures aren't supported. A good next step: parse logs into events, flag port scans /
  brute force / beaconing with thresholds, then have the AI explain those findings.
- No login, no saved history, no file upload yet.
- The rate limiter is per-process and uses the direct client IP; behind a reverse proxy, put the limit
  at the proxy or configure it to read the forwarded address.
- Not yet containerised. Add a `Dockerfile` (`uvicorn app.main:app --host 0.0.0.0`) when you deploy.
