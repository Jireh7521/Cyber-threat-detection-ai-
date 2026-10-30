/* Cyber Threat Detection AI — frontend logic.
 *
 * Talks to the FastAPI backend (/api/analyze, /api/followup). The backend holds
 * the Anthropic API key and streams results back as Server-Sent Events:
 *   {type:"text", text}  {type:"summary", threat_count, risk, confidence}
 *   {type:"done"}        {type:"error", message}
 * SAMPLES is defined in samples.js.
 */

const MAX_CHARS = 100000;           // keep in sync with MAX_INPUT_CHARS on the server

/* ── STATE ───────────────────────────────────────────────────── */
let curTab = 'a';                   // 'a' = analysis, 'i' = IOC report, 'e' = plain English
let busy   = false;
let traffic = '';                   // the log text the cached results belong to
const cache = {};                   // mode -> { text, summary, qa: [{role, content}] }

const EMPTY_HTML = document.getElementById('rbody').innerHTML;

const RISK_UI = {                   // risk label -> [stat colour class, badge class]
  Critical: ['cv-r', 'bd-critical'],
  High:     ['cv-a', 'bd-high'],
  Medium:   ['cv-b', 'bd-medium'],
  Low:      ['cv-b', 'bd-medium'],
  Clean:    ['cv-g', 'bd-clean'],
};

/* ── SMALL HELPERS ───────────────────────────────────────────── */
const $ = id => document.getElementById(id);

function load(key) {
  $('ti').value = SAMPLES[key];
  $('ti').focus();
}

function setStat(id, val, cls) {
  const el = $(id);
  el.textContent = val;
  el.className = 'stat-val' + (cls ? ' ' + cls : '');
}

function setBadge(text, cls) {
  const b = $('rbadge');
  b.textContent = text;
  b.className = 'badge ' + cls;
}

function setBusy(on) {
  busy = on;
  $('scan-line').className = 'scan-line' + (on ? ' on' : '');
  $('abtn').disabled = on;
  $('spin').style.display = on ? 'block' : 'none';
  $('blbl').textContent = on ? 'Scanning…' : 'Analyze Traffic';
}

/* Safe rendering: textContent only, so log/AI text can never inject HTML. */
function showText(el, text, cursor) {
  el.textContent = text;
  if (cursor) {
    const c = document.createElement('span');
    c.className = 'cur';
    el.appendChild(c);
  }
}

function showError(el, message) {
  const s = document.createElement('span');
  s.style.color = 'var(--red)';
  s.textContent = 'Error: ' + message;
  el.appendChild(s);
}

function addQABlock(body, question) {
  const q = document.createElement('div');
  q.className = 'qa-q';
  q.textContent = '> ' + question;
  const a = document.createElement('div');
  a.className = 'qa-a';
  body.append(q, a);
  body.scrollTop = body.scrollHeight;
  return a;
}

/* ── SSE STREAMING ───────────────────────────────────────────── */
/* POSTs JSON and calls onEvent for every SSE event. Events can be split across
   network chunks, so we buffer and only parse complete "\n\n"-terminated ones. */
async function streamSSE(url, payload, onEvent) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const detail = Array.isArray(err.detail) ? 'Invalid request.' : err.detail;
    throw new Error(detail || `HTTP ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });

    let sep;
    while ((sep = buf.indexOf('\n\n')) !== -1) {
      const block = buf.slice(0, sep);
      buf = buf.slice(sep + 2);
      for (const line of block.split('\n')) {
        if (!line.startsWith('data: ')) continue;
        try { onEvent(JSON.parse(line.slice(6))); } catch (_) { /* ignore malformed event */ }
      }
    }
  }
}

/* ── TABS ────────────────────────────────────────────────────── */
function setTab(t, el) {
  if (busy) return;                 // don't swap views mid-stream
  curTab = t;
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('on'));
  el.classList.add('on');
  renderCurrent();
}

/* Show the cached result for the active tab, or a hint if there isn't one. */
function renderCurrent() {
  const body = $('rbody');
  const r = cache[curTab];
  body.innerHTML = '';

  if (!r) {
    body.innerHTML = EMPTY_HTML;
    $('fbar').style.display = 'none';
    if (Object.keys(cache).length) {
      body.querySelector('p').textContent =
        'No result for this view yet. Click "Analyze Traffic" to generate it.';
    }
    return;
  }

  const main = document.createElement('div');
  showText(main, r.text, false);
  body.appendChild(main);
  for (let i = 0; i < r.qa.length; i += 2) {
    addQABlock(body, r.qa[i].content).textContent = r.qa[i + 1] ? r.qa[i + 1].content : '';
  }
  applySummary(r.summary);
  $('fbar').style.display = 'flex';
}

function applySummary(s) {
  const lines = traffic.split('\n').filter(l => l.trim()).length;
  setStat('s-pkt', lines, 'cv-g');
  setStat('s-stat', 'COMPLETE', 'cv-g');

  if (!s) {                         // model skipped/garbled the summary — don't guess
    setStat('s-thr', '?', '');
    setStat('s-risk', 'N/A', '');
    $('rtitle').textContent = 'Analysis complete';
    setBadge('DONE', 'bd-ready');
    return;
  }
  const [valCls, badgeCls] = RISK_UI[s.risk] || ['', 'bd-ready'];
  const label = s.risk.toUpperCase();
  setStat('s-thr', s.threat_count, 'cv-r');
  setStat('s-risk', label, valCls);
  const conf = s.confidence != null ? ` (${s.confidence}% confidence)` : '';
  $('rtitle').textContent = `Analysis complete — ${label} risk${conf}`;
  setBadge(label, badgeCls);
}

/* ── ANALYZE ─────────────────────────────────────────────────── */
async function analyze() {
  const input = $('ti').value.trim();
  if (!input) { alert('Please paste some network traffic data first.'); return; }
  if (input.length > MAX_CHARS) {
    alert(`Input is too large (${input.length.toLocaleString()} characters). Limit is ${MAX_CHARS.toLocaleString()}.`);
    return;
  }

  // New log text invalidates every cached view.
  if (input !== traffic) { for (const k of Object.keys(cache)) delete cache[k]; }
  traffic = input;
  const mode = curTab;

  setBusy(true);
  setStat('s-pkt', '…', '');
  setStat('s-thr', '…', 'cv-r');
  setStat('s-risk', '…', '');
  setStat('s-stat', 'SCANNING', 'cv-a');
  $('rtitle').textContent = 'AI scanning traffic…';
  setBadge('SCANNING', 'bd-scanning');
  $('fbar').style.display = 'none';

  const body = $('rbody');
  body.innerHTML = '';
  const out = document.createElement('div');
  body.appendChild(out);

  let text = '';
  let summary = null;
  let failed = false;

  try {
    await streamSSE('/api/analyze', { traffic: input, mode }, ev => {
      if (ev.type === 'text') {
        text += ev.text;
        showText(out, text, true);
        body.scrollTop = body.scrollHeight;
      } else if (ev.type === 'summary') {
        summary = ev;
      } else if (ev.type === 'error') {
        throw new Error(ev.message);
      }
    });
  } catch (err) {
    failed = true;
    showText(out, text, false);
    showError(body, err.message);
    setStat('s-stat', 'ERROR', 'cv-r');
    setStat('s-thr', '—', 'cv-r');
    setStat('s-risk', '—', '');
    $('rtitle').textContent = 'Analysis failed';
    setBadge('ERROR', 'bd-critical');
  }

  if (!failed) {
    showText(out, text, false);
    cache[mode] = { text, summary, qa: [] };
    applySummary(summary);
    $('fbar').style.display = 'flex';
  }
  setBusy(false);
}

/* ── FOLLOW-UP Q&A ───────────────────────────────────────────── */
async function followUp() {
  const r = cache[curTab];
  const inp = $('fq');
  const q = inp.value.trim();
  if (!q || !r || busy) return;

  inp.value = '';
  inp.disabled = true;
  busy = true;

  const body = $('rbody');
  const aDiv = addQABlock(body, q);
  let text = '';
  let failed = false;

  try {
    await streamSSE('/api/followup',
      { traffic, report: r.text, previous_qa: r.qa, question: q },
      ev => {
        if (ev.type === 'text') {
          text += ev.text;
          showText(aDiv, text, true);
          body.scrollTop = body.scrollHeight;
        } else if (ev.type === 'error') {
          throw new Error(ev.message);
        }
      });
  } catch (err) {
    failed = true;
    showText(aDiv, text, false);
    showError(aDiv, err.message);
  }

  if (!failed) {
    showText(aDiv, text, false);
    r.qa.push({ role: 'user', content: q }, { role: 'assistant', content: text });
  }
  busy = false;
  inp.disabled = false;
  inp.focus();
}
