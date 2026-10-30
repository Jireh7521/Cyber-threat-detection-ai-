"""Cyber Threat Detection AI — FastAPI backend.

The browser never sees the Anthropic API key: it talks to this server, and this
server talks to Anthropic. Responses are streamed back as Server-Sent Events:

    data: {"type": "text", "text": "..."}                         (repeated)
    data: {"type": "summary", "threat_count": 3, "risk": "High", "confidence": 90}
    data: {"type": "done"}
    data: {"type": "error", "message": "..."}                     (on failure)
"""
import json
import logging
from pathlib import Path
from typing import Literal

import anthropic
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import settings
from .prompts import build_followup_system, build_system, wrap_traffic
from .ratelimit import RateLimiter
from .streamfilter import SummaryFilter

log = logging.getLogger("threat-ai")

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Cyber Threat Detection AI", docs_url=None, redoc_url=None)
limiter = RateLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds)

_client: anthropic.AsyncAnthropic | None = None


def get_client() -> anthropic.AsyncAnthropic:
    """Create the Anthropic client once. Tests replace this function."""
    global _client
    if _client is None:
        _client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    return _client


# ── Request models ───────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    traffic: str
    mode: Literal["a", "i", "e"] = "a"


class QA(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class FollowUpRequest(BaseModel):
    traffic: str          # original log text (server re-wraps it, client can't forge the wrapper)
    report: str           # the report the AI already produced
    previous_qa: list[QA] = []
    question: str


# ── Guards ───────────────────────────────────────────────────────────────────
def _guard(request: Request) -> None:
    if not settings.anthropic_api_key:
        raise HTTPException(503, "Server is not configured: ANTHROPIC_API_KEY is missing.")
    ip = request.client.host if request.client else "unknown"
    if not limiter.allow(ip):
        raise HTTPException(429, "Too many requests. Please wait a moment and try again.")


def _check_traffic(text: str) -> str:
    text = text.strip()
    if not text:
        raise HTTPException(400, "Please paste some network traffic data first.")
    if len(text) > settings.max_input_chars:
        raise HTTPException(
            413, f"Input too large ({len(text):,} chars). Limit is {settings.max_input_chars:,}."
        )
    return text


# ── Streaming ────────────────────────────────────────────────────────────────
def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _friendly_error(exc: Exception) -> str:
    """Map provider errors to safe messages (never leak keys or internals)."""
    if isinstance(exc, anthropic.AuthenticationError):
        return "The server's Anthropic API key was rejected. Check ANTHROPIC_API_KEY."
    if isinstance(exc, anthropic.RateLimitError):
        return "The AI provider is rate limiting requests. Try again in a minute."
    if isinstance(exc, anthropic.APIConnectionError):
        return "Could not reach the AI provider. Check the server's network connection."
    if isinstance(exc, anthropic.APIStatusError):
        return f"The AI provider returned an error (HTTP {exc.status_code})."
    return "Unexpected server error while analyzing."


async def _stream_response(system: str, messages: list[dict], with_summary: bool):
    filt = SummaryFilter() if with_summary else None
    try:
        async with get_client().messages.stream(
            model=settings.model,
            max_tokens=settings.max_output_tokens,
            system=system,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                safe = filt.feed(text) if filt else text
                if safe:
                    yield _sse({"type": "text", "text": safe})

        if filt:
            leftover, summary = filt.finish()
            if leftover:
                yield _sse({"type": "text", "text": leftover})
            if summary:
                yield _sse({"type": "summary", **summary})
        yield _sse({"type": "done"})
    except Exception as exc:  # noqa: BLE001 — report any failure to the client as an event
        log.exception("Streaming failed")
        yield _sse({"type": "error", "message": _friendly_error(exc)})


def _sse_response(gen) -> StreamingResponse:
    return StreamingResponse(
        gen,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Routes ───────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "api_key_configured": bool(settings.anthropic_api_key),
        "model": settings.model,
    }


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    _guard(request)
    traffic = _check_traffic(req.traffic)
    messages = [{"role": "user", "content": wrap_traffic(traffic)}]
    return _sse_response(_stream_response(build_system(req.mode), messages, with_summary=True))


@app.post("/api/followup")
async def followup(req: FollowUpRequest, request: Request):
    _guard(request)
    traffic = _check_traffic(req.traffic)

    question = req.question.strip()
    if not question:
        raise HTTPException(400, "Question is empty.")
    if len(question) > settings.max_followup_chars:
        raise HTTPException(413, f"Question too long (limit {settings.max_followup_chars} chars).")
    if len(req.report) > 60_000:
        raise HTTPException(413, "Report too large.")

    qa = req.previous_qa
    if len(qa) > settings.max_history_messages:
        raise HTTPException(413, "Conversation too long. Run a new analysis.")
    # Prior Q&A must strictly alternate user → assistant.
    for i, m in enumerate(qa):
        expected = "user" if i % 2 == 0 else "assistant"
        if m.role != expected or len(m.content) > 60_000:
            raise HTTPException(400, "Invalid conversation history.")
    if len(qa) % 2 != 0:
        raise HTTPException(400, "Invalid conversation history.")

    messages = [
        {"role": "user", "content": wrap_traffic(traffic)},
        {"role": "assistant", "content": req.report},
        *({"role": m.role, "content": m.content} for m in qa),
        {"role": "user", "content": question},
    ]
    return _sse_response(_stream_response(build_followup_system(), messages, with_summary=False))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
