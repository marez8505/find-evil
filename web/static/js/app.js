/**
 * FIND EVIL — Web GUI Client
 *
 * No external libraries. Vanilla JS only.
 * Security: uses textContent/createElement — never innerHTML with user data.
 * All state-changing requests send X-CSRF-Token header.
 */

'use strict';

// ── Globals ───────────────────────────────────────────────────────────────────
let _sseSource   = null;
let _autoscroll  = true;
let _caseId      = null;

// ── CSRF helper ───────────────────────────────────────────────────────────────

function getCSRF() {
  // Injected into case.html via Jinja: const CSRF = "..."
  return (typeof CSRF !== 'undefined') ? CSRF : '';
}

async function apiFetch(url, options = {}) {
  const defaults = {
    headers: {
      'X-CSRF-Token': getCSRF(),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    credentials: 'same-origin',
  };
  return fetch(url, Object.assign(defaults, options));
}

// ── Config save ───────────────────────────────────────────────────────────────

async function saveConfig() {
  const form    = document.getElementById('config-form');
  const btn     = document.getElementById('save-btn');
  const status  = document.getElementById('save-status');

  btn.disabled  = true;
  status.textContent = '';

  const params = new URLSearchParams({
    csrf_token:     getCSRF(),
    disk_path:      form.disk_path.value.trim(),
    memory_path:    form.memory_path.value.trim(),
    max_iterations: form.max_iterations.value,
  });

  try {
    const res = await apiFetch(`/cases/${CASE_ID}/config`, {
      method: 'POST',
      body:   params.toString(),
    });
    if (res.ok) {
      status.textContent = '✓ Saved';
      status.style.color = 'var(--green)';
    } else {
      status.textContent = '✗ Save failed';
      status.style.color = 'var(--err)';
    }
  } catch (e) {
    status.textContent = '✗ Network error';
    status.style.color = 'var(--err)';
  } finally {
    btn.disabled = false;
    setTimeout(() => { status.textContent = ''; }, 3000);
  }
}

// ── Analysis: run ─────────────────────────────────────────────────────────────

async function runAnalysis(caseId) {
  _caseId = caseId;
  clearLog();
  setStatus('running');

  const params = new URLSearchParams({ csrf_token: getCSRF() });
  try {
    const res = await apiFetch(`/cases/${caseId}/run`, {
      method: 'POST',
      body:   params.toString(),
    });
    const data = await res.json();
    if (res.ok && data.started) {
      appendLog({ type: 'log', msg: `[FIND EVIL] Analysis started (PID ${data.pid})` });
      connectStream(caseId);
    } else {
      appendLog({ type: 'error', msg: `Failed to start: ${data.error || 'Unknown error'}` });
      setStatus('idle');
    }
  } catch (e) {
    appendLog({ type: 'error', msg: `Network error: ${e.message}` });
    setStatus('idle');
  }
}

// ── Analysis: stop ────────────────────────────────────────────────────────────

async function stopAnalysis(caseId) {
  disconnectStream();
  const params = new URLSearchParams({ csrf_token: getCSRF() });
  try {
    await apiFetch(`/cases/${caseId}/stop`, {
      method: 'POST',
      body:   params.toString(),
    });
    appendLog({ type: 'log', msg: '[FIND EVIL] Analysis stopped by user.' });
  } catch (e) {
    appendLog({ type: 'error', msg: `Stop error: ${e.message}` });
  }
  setStatus('done');
}

// ── SSE: connect stream ───────────────────────────────────────────────────────

function connectStream(caseId) {
  _caseId = caseId;
  disconnectStream();

  const logStatus = document.getElementById('log-status');
  if (logStatus) logStatus.textContent = 'Connecting...';

  _sseSource = new EventSource(`/cases/${caseId}/stream`);

  _sseSource.onmessage = function (e) {
    try {
      const ev = JSON.parse(e.data);
      handleStreamEvent(ev);
    } catch (_) {
      appendRaw(e.data);
    }
  };

  _sseSource.onerror = function () {
    if (_sseSource.readyState === EventSource.CLOSED) {
      if (logStatus) logStatus.textContent = 'Disconnected';
      disconnectStream();
    }
  };
}

function disconnectStream() {
  if (_sseSource) {
    _sseSource.close();
    _sseSource = null;
  }
}

function handleStreamEvent(ev) {
  const logStatus = document.getElementById('log-status');

  switch (ev.type) {
    case 'connected':
      if (logStatus) logStatus.textContent = 'Streaming...';
      break;

    case 'log':
      appendLog(ev);
      break;

    case 'done':
      if (logStatus) logStatus.textContent = ev.code === 0 ? 'Complete' : `Exited (${ev.code})`;
      appendLog({ type: 'done', msg: `[FIND EVIL] Analysis finished (exit ${ev.code})` });
      disconnectStream();
      setStatus(ev.code === 0 ? 'done' : 'idle');
      // Refresh findings after completion
      setTimeout(() => loadFindings(_caseId), 1200);
      break;

    case 'timeout':
      if (logStatus) logStatus.textContent = 'Timed out';
      appendLog({ type: 'error', msg: '[FIND EVIL] Stream timed out (no output for 5 min).' });
      disconnectStream();
      setStatus('idle');
      break;

    case 'error':
      appendLog({ type: 'error', msg: `[FIND EVIL] ${ev.msg}` });
      if (logStatus) logStatus.textContent = 'Error';
      break;
  }
}

// ── Log rendering ─────────────────────────────────────────────────────────────

function appendLog(ev) {
  const content = document.getElementById('log-content');
  if (!content) return;

  const line = document.createElement('div');
  line.className = 'log-line ' + classifyLine(ev.msg || '');
  line.textContent = ev.msg || '';
  content.appendChild(line);

  if (_autoscroll) {
    const viewer = document.getElementById('log-viewer');
    if (viewer) viewer.scrollTop = viewer.scrollHeight;
  }
}

function appendRaw(msg) {
  appendLog({ type: 'log', msg });
}

function classifyLine(msg) {
  if (!msg) return 'log-line';
  const m = msg.toUpperCase();
  if (m.includes('[CONFIRMED]'))   return 'log-confirmed';
  if (m.includes('[INFERRED]'))    return 'log-inferred';
  if (m.includes('[UNCONFIRMED]')) return 'log-unconfirmed';
  if (m.includes('↺') || m.includes('CORRECTION') || m.includes('SELF-CORRECT')) return 'log-correction';
  if (m.includes('PHASE:') || m.startsWith('='))  return 'log-phase';
  if (m.includes('[ERROR]') || m.includes('FAIL')) return 'log-error';
  if (m.includes('[FIND EVIL] ✓') || m.includes('COMPLETE')) return 'log-done';
  if (m.startsWith('---') || m.startsWith('===')) return 'log-sep';
  return 'log-line';
}

function clearLog() {
  const content = document.getElementById('log-content');
  if (content) content.textContent = '';
}

function toggleAutoscroll() {
  _autoscroll = !_autoscroll;
  const btn = document.getElementById('autoscroll-btn');
  if (btn) {
    btn.style.color = _autoscroll ? 'var(--green)' : 'var(--muted)';
    btn.title       = _autoscroll ? 'Autoscroll: ON' : 'Autoscroll: OFF';
  }
}

// ── Status management ─────────────────────────────────────────────────────────

function setStatus(status) {
  const badge   = document.getElementById('status-badge');
  const runBtn  = document.getElementById('run-btn');
  const stopBtn = document.getElementById('stop-btn');

  if (badge) {
    badge.className   = `status-badge status-${status}`;
    badge.textContent = status.toUpperCase();
    // Re-add ::before pseudo — handled by CSS, no JS needed
  }
  if (runBtn)  runBtn.disabled  = (status === 'running');
  if (stopBtn) stopBtn.disabled = (status !== 'running');
}

// ── Findings loader ───────────────────────────────────────────────────────────

async function loadFindings(caseId) {
  if (!caseId) return;
  try {
    const res  = await fetch(`/cases/${caseId}/findings`, { credentials: 'same-origin' });
    if (!res.ok) return;
    const data = await res.json();
    renderFindings(data.findings || []);
    renderCriteria(data.criteria || {});
  } catch (_) {
    // silently fail — findings panel remains empty
  }
}

function renderFindings(findings) {
  const empty = document.getElementById('findings-empty');
  const table = document.getElementById('findings-table');
  const tbody = document.getElementById('findings-body');

  if (!empty || !table || !tbody) return;

  if (!findings.length) {
    empty.style.display = 'block';
    table.style.display = 'none';
    updatePills(0, 0, 0);
    return;
  }

  // Count by confidence
  const counts = { CONFIRMED: 0, INFERRED: 0, UNCONFIRMED: 0 };
  findings.forEach(f => {
    const c = (f.confidence || 'UNCONFIRMED').toUpperCase();
    if (c in counts) counts[c]++;
  });
  updatePills(counts.CONFIRMED, counts.INFERRED, counts.UNCONFIRMED);

  // Sort: CONFIRMED first, then INFERRED, then UNCONFIRMED
  const order = { CONFIRMED: 0, INFERRED: 1, UNCONFIRMED: 2 };
  const sorted = [...findings].sort((a, b) =>
    (order[a.confidence] ?? 3) - (order[b.confidence] ?? 3)
  );

  // Render rows — use DOM methods, never innerHTML with user content
  tbody.textContent = '';
  sorted.forEach(f => {
    const tr = document.createElement('tr');

    const tdConf = document.createElement('td');
    const badge  = document.createElement('span');
    badge.className   = `conf-badge conf-${f.confidence || 'UNCONFIRMED'}`;
    badge.textContent = f.confidence || 'UNCONFIRMED';
    tdConf.appendChild(badge);

    const tdFinding = document.createElement('td');
    tdFinding.className   = 'td-finding';
    tdFinding.textContent = f.finding || '';

    const tdTool = document.createElement('td');
    tdTool.className   = 'td-tool';
    tdTool.textContent = f.source_tool || '—';

    const tdTime = document.createElement('td');
    tdTime.className   = 'td-time';
    tdTime.textContent = formatTimestamp(f.timestamp_utc || '');

    tr.appendChild(tdConf);
    tr.appendChild(tdFinding);
    tr.appendChild(tdTool);
    tr.appendChild(tdTime);
    tbody.appendChild(tr);
  });

  empty.style.display = 'none';
  table.style.display = 'table';
}

function updatePills(confirmed, inferred, unconfirmed) {
  const set = (id, count, label) => {
    const el = document.getElementById(id);
    if (el) el.textContent = `${count} ${label}`;
  };
  set('pill-confirmed',   confirmed,   'Confirmed');
  set('pill-inferred',    inferred,    'Inferred');
  set('pill-unconfirmed', unconfirmed, 'Unconfirmed');
}

function renderCriteria(criteria) {
  const panel = document.getElementById('criteria-panel');
  const grid  = document.getElementById('criteria-grid');
  if (!panel || !grid) return;

  const entries = Object.entries(criteria);
  if (!entries.length) return;

  grid.textContent = '';
  entries.forEach(([key, met]) => {
    const item  = document.createElement('div');
    item.className = 'criteria-item';

    const icon = document.createElement('span');
    icon.className   = `criteria-check ${met ? 'met' : 'unmet'}`;
    icon.textContent = met ? '✓' : '○';

    const label = document.createElement('span');
    label.textContent = key.replace(/_/g, ' ');

    item.appendChild(icon);
    item.appendChild(label);
    grid.appendChild(item);
  });

  panel.style.display = 'block';
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  } catch (_) {
    return ts;
  }
}

// ── Periodic findings refresh (while streaming) ───────────────────────────────

setInterval(() => {
  if (typeof CASE_ID !== 'undefined' && _sseSource) {
    loadFindings(CASE_ID);
  }
}, 8000);
