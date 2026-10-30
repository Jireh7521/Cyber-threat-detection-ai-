from app.streamfilter import SummaryFilter, parse_summary

TAG = '<summary>{"threat_count": 2, "risk": "High", "confidence": 88}</summary>'


def run(chunks):
    f = SummaryFilter()
    shown = "".join(f.feed(c) for c in chunks)
    leftover, summary = f.finish()
    return shown + leftover, summary


def test_hides_tag_and_parses_summary():
    shown, summary = run(["Report text.\n", TAG])
    assert shown == "Report text.\n"
    assert summary == {"threat_count": 2, "risk": "High", "confidence": 88}


def test_tag_split_across_many_chunks():
    text = "Findings here.\n" + TAG
    chunks = [text[i:i + 3] for i in range(0, len(text), 3)]
    shown, summary = run(chunks)
    assert shown == "Findings here.\n"
    assert summary["risk"] == "High"


def test_partial_prefix_that_is_not_a_tag_is_released():
    shown, summary = run(["Use a <sum", "mer> of values"])
    assert shown == "Use a <summer> of values"
    assert summary is None


def test_trailing_lt_released_at_finish():
    shown, summary = run(["x <"])
    assert shown == "x <"
    assert summary is None


def test_missing_summary_returns_none():
    shown, summary = run(["Just a report."])
    assert shown == "Just a report."
    assert summary is None


def test_invalid_summaries_rejected():
    assert parse_summary('<summary>not json</summary>') is None
    assert parse_summary('<summary>{"threat_count": 1, "risk": "Bogus", "confidence": 5}</summary>') is None
    assert parse_summary('<summary>{"threat_count": -1, "risk": "High", "confidence": 5}</summary>') is None
    assert parse_summary('<summary>{"threat_count": true, "risk": "High", "confidence": 5}</summary>') is None
    assert parse_summary('<summary>[1,2]</summary>') is None
    assert parse_summary('<summary>{"threat_count": 1, "risk": "High"') is None  # unclosed


def test_confidence_clamped_and_optional():
    s = parse_summary('<summary>{"threat_count": 0, "risk": "Clean", "confidence": 250}</summary>')
    assert s["confidence"] == 100
    s = parse_summary('<summary>{"threat_count": 0, "risk": "Clean"}</summary>')
    assert s["confidence"] is None
