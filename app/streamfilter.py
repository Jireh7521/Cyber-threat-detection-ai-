"""Hide the trailing <summary>{...}</summary> tag from streamed text and parse it.

The model streams the human-readable report and then a machine-readable summary
tag. Text arrives in arbitrary chunks, so the tag can be split anywhere
(e.g. "<sum" + "mary>"). This filter holds back only what *might* be the start
of the tag, so the user never sees it flash up on screen.
"""
import json
import re

OPEN = "<summary>"
CLOSE = "</summary>"

VALID_RISKS = {"Critical", "High", "Medium", "Low", "Clean"}


class SummaryFilter:
    def __init__(self) -> None:
        self._pending = ""      # text not yet released (might be a tag prefix)
        self._tag = ""          # everything from "<summary>" onward
        self._in_tag = False

    def feed(self, text: str) -> str:
        """Add a chunk; return the part that is safe to show the user."""
        if self._in_tag:
            self._tag += text
            return ""

        self._pending += text
        idx = self._pending.find(OPEN)
        if idx != -1:
            out = self._pending[:idx]
            self._tag = self._pending[idx:]
            self._pending = ""
            self._in_tag = True
            return out

        # Hold back the longest suffix that could still become "<summary>".
        hold = 0
        for n in range(min(len(OPEN) - 1, len(self._pending)), 0, -1):
            if OPEN.startswith(self._pending[-n:]):
                hold = n
                break
        out = self._pending[: len(self._pending) - hold]
        self._pending = self._pending[len(self._pending) - hold:]
        return out

    def finish(self) -> tuple[str, dict | None]:
        """Stream ended. Return (leftover safe text, parsed summary or None)."""
        leftover = "" if self._in_tag else self._pending
        self._pending = ""
        return leftover, parse_summary(self._tag)


def parse_summary(tag_text: str) -> dict | None:
    """Parse and validate the summary tag. Returns None if missing or malformed."""
    m = re.search(re.escape(OPEN) + r"(.*?)" + re.escape(CLOSE), tag_text, re.DOTALL)
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    risk = data.get("risk")
    threats = data.get("threat_count")
    conf = data.get("confidence")
    if risk not in VALID_RISKS:
        return None
    if not isinstance(threats, int) or isinstance(threats, bool) or threats < 0:
        return None
    if not isinstance(conf, (int, float)) or isinstance(conf, bool):
        conf = None
    else:
        conf = max(0, min(100, int(conf)))
    return {"threat_count": threats, "risk": risk, "confidence": conf}
