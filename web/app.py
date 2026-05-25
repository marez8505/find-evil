#!/usr/bin/env python3
"""
FIND EVIL — Web GUI
════════════════════════════════════════════════════════════════
Local-only web interface for the FIND EVIL autonomous DFIR agent.

SECURITY DESIGN:
  • Binds to 127.0.0.1 ONLY — never exposed to the network
  • bcrypt password hash stored in .env — password shown once at startup
  • CSRF tokens on all state-changing requests
  • Rate limiting on login (5 attempts / 5 min per IP)
  • Strict CSP headers — no external resources permitted
  • Path traversal protection on all case_id inputs
  • Subprocess list-form args — no shell injection possible
  • No case data ever sent to external services
════════════════════════════════════════════════════════════════
"""

import json
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import bcrypt
from dotenv import load_dotenv
from flask import (
    Flask, Response, abort, flash, jsonify, redirect,
    render_template, request, send_file, session, url_for,
)

# ── Bootstrap ────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
PROJECT_DIR = BASE_DIR.parent
ENV_FILE    = BASE_DIR / '.env'

load_dotenv(ENV_FILE)

CASES_DIR = Path(os.getenv('CASES_DIR', '/cases'))
LOOP_PY   = str(PROJECT_DIR / 'agent' / 'loop.py')
PORT      = int(os.getenv('PORT', 8080))

# ── Path Validation (Security: CWE-78 Command Injection Prevention) ──────────

def _validate_data_path(user_path: str | None, case_dir: Path) -> str | None:
    """
    Validate that user_path is within the case directory.
    Prevents path traversal and command injection attacks.
    
    Args:
        user_path: User-provided file path from config
        case_dir: The current case's directory (safe boundary)
    
    Returns:
        Validated absolute path, or None if invalid
    
    Raises:
        ValueError: If path is outside case directory
    """
    if not user_path:
        return None
    
    # Resolve to absolute path
    p = Path(user_path).resolve()
    
    # Ensure path is within case directory
    try:
        p.relative_to(case_dir.resolve())
    except ValueError:
        raise ValueError(f'Path {user_path} is outside case directory {case_dir}')
    
    # Ensure path exists and is readable
    if not p.exists():
        raise ValueError(f'Path {user_path} does not exist')
    
    return str(p)

# ── First-run password generation ────────────────────────────────────────────

def _ensure_password():
    """Generate a random password on first run and save the hash to .env."""
    if os.getenv('PW_HASH'):
        return  # already set

    pw = secrets.token_urlsafe(16)
    hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    # Append to .env
    with open(ENV_FILE, 'a') as f:
        f.write(f'\nPW_HASH={hashed}\n')
        f.write(f'FLASK_SECRET={secrets.token_hex(32)}\n')

    # Reload env
    load_dotenv(ENV_FILE, override=True)

    print()
    print('╔══════════════════════════════════════════════════╗')
    print('║         FIND EVIL — First Run Setup              ║')
    print('╠══════════════════════════════════════════════════╣')
    print(f'║  Password:  {pw:<36} ║')
    print('║                                                  ║')
    print('║  This password is shown ONCE.                    ║')
    print('║  Save it now. To reset: delete .env and restart. ║')
    print('╚══════════════════════════════════════════════════╝')
    print()

_ensure_password()

# ── Flask app ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_NAME      = 'fe_session',
    SESSION_COOKIE_HTTPONLY  = True,
    SESSION_COOKIE_SAMESITE  = 'Strict',
    SESSION_COOKIE_SECURE    = False,   # localhost — no HTTPS needed
    PERMANENT_SESSION_LIFETIME = 7200,  # 2h session
)

# ── Runtime state (single-user local tool) ───────────────────────────────────

# {case_id: {'process': Popen, 'log': Path, 'handle': file, 'started': str}}
_running: dict = {}

# {ip: [timestamps]} — login rate limiting
_login_attempts: dict = {}

# ── Security middleware ───────────────────────────────────────────────────────

@app.after_request
def security_headers(response):
    """Apply strict security headers. No external resources ever leave."""
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    h = response.headers
    h['Content-Security-Policy'] = csp
    h['X-Frame-Options']          = 'DENY'
    h['X-Content-Type-Options']   = 'nosniff'
    h['Referrer-Policy']          = 'no-referrer'
    h['Permissions-Policy']       = 'geolocation=(), camera=(), microphone=()'
    h['Cache-Control']            = 'no-store, no-cache, must-revalidate'
    return response

# ── Auth helpers ──────────────────────────────────────────────────────────────

def _check_password(pw: str) -> bool:
    h = os.getenv('PW_HASH', '').encode()
    if not h:
        return False
    return bcrypt.checkpw(pw.encode(), h)

def _rate_limited(ip: str) -> bool:
    now   = time.time()
    tries = [t for t in _login_attempts.get(ip, []) if now - t < 300]
    _login_attempts[ip] = tries
    return len(tries) >= 5

def _record_attempt(ip: str):
    _login_attempts.setdefault(ip, []).append(time.time())

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def _csrf():
    """Return (and lazily create) the CSRF token for the current session."""
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(32)
    return session['csrf']

def _check_csrf():
    """Abort 403 if CSRF token is missing or wrong."""
    token = (
        request.form.get('csrf_token')
        or request.headers.get('X-CSRF-Token', '')
    )
    if not token or token != session.get('csrf'):
        abort(403)

app.jinja_env.globals['csrf_token'] = _csrf

# ── Input validation ──────────────────────────────────────────────────────────

_CASE_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')

def _valid_case_id(case_id: str) -> bool:
    return bool(_CASE_ID_RE.match(case_id))

def _safe_path(raw: str) -> str:
    """Strip shell-dangerous characters from a user-supplied path."""
    return re.sub(r'[;&|`$<>!]', '', raw).strip()

# ── Case helpers ──────────────────────────────────────────────────────────────

def _case_status(case_id: str) -> str:
    info = _running.get(case_id)
    if info:
        return 'running' if info['process'].poll() is None else 'done'
    findings = CASES_DIR / case_id / 'analysis' / 'findings.json'
    return 'done' if findings.exists() else 'idle'

def _list_cases() -> list:
    if not CASES_DIR.exists():
        return []
    cases = []
    for d in sorted(CASES_DIR.iterdir()):
        if not d.is_dir():
            continue
        ffile = d / 'analysis' / 'findings.json'
        count = 0
        if ffile.exists():
            try:
                count = len(json.loads(ffile.read_text()).get('findings', []))
            except Exception:
                pass
        cases.append({
            'id':       d.name,
            'status':   _case_status(d.name),
            'findings': count,
        })
    return cases

def _get_case(case_id: str) -> dict | None:
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        return None

    findings, accuracy, config = {}, {}, {
        'disk_path': '', 'memory_path': '', 'max_iterations': 10
    }

    for attr, path in [
        ('findings', case_dir / 'analysis' / 'findings.json'),
        ('accuracy', case_dir / 'reports'  / 'accuracy_report.json'),
        ('config',   case_dir / 'web_config.json'),
    ]:
        if path.exists():
            try:
                locals()[attr].update(json.loads(path.read_text()))
            except Exception:
                pass

    # re-read locals properly
    ffile = case_dir / 'analysis' / 'findings.json'
    afile = case_dir / 'reports'  / 'accuracy_report.json'
    cfile = case_dir / 'web_config.json'

    findings = json.loads(ffile.read_text()) if ffile.exists() else {}
    accuracy = json.loads(afile.read_text()) if afile.exists() else {}
    config   = json.loads(cfile.read_text()) if cfile.exists() else {
        'disk_path': '', 'memory_path': '', 'max_iterations': 10
    }

    return {
        'id':         case_id,
        'status':     _case_status(case_id),
        'config':     config,
        'findings':   findings,
        'accuracy':   accuracy,
        'has_report': (case_dir / 'reports' / 'incident_report.pdf').exists(),
        'started_at': _running.get(case_id, {}).get('started', ''),
    }

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))

    error = None
    if request.method == 'POST':
        ip = request.remote_addr or '0.0.0.0'
        if _rate_limited(ip):
            error = 'Too many attempts. Wait 5 minutes.'
        else:
            if _check_password(request.form.get('password', '')):
                session.clear()
                session['authenticated'] = True
                session['csrf']          = secrets.token_hex(32)
                session.permanent        = True
                return redirect(url_for('dashboard'))
            _record_attempt(ip)
            error = 'Incorrect password.'

    return render_template('login.html', error=error)


@app.route('/logout', methods=['POST'])
def logout():
    _check_csrf()
    session.clear()
    return redirect(url_for('login'))

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html',
                           cases=_list_cases(),
                           cases_dir=str(CASES_DIR))

# ── Cases: create ─────────────────────────────────────────────────────────────

@app.route('/cases', methods=['POST'])
@login_required
def create_case():
    _check_csrf()
    case_id = request.form.get('case_id', '').strip().upper()
    if not _valid_case_id(case_id):
        flash('Invalid case ID. Use letters, numbers, dash, underscore (max 32).', 'error')
        return redirect(url_for('dashboard'))

    case_dir = CASES_DIR / case_id
    if case_dir.exists():
        flash(f'Case {case_id} already exists.', 'error')
        return redirect(url_for('dashboard'))

    try:
        case_dir.mkdir(parents=True)
        (case_dir / 'analysis').mkdir()
        (case_dir / 'reports').mkdir()
        tpl = PROJECT_DIR / 'case-templates' / 'CLAUDE.md'
        if tpl.exists():
            (case_dir / 'CLAUDE.md').write_text(tpl.read_text())
        flash(f'Case {case_id} created successfully.', 'success')
    except Exception as e:
        flash(f'Failed to create case: {e}', 'error')
        return redirect(url_for('dashboard'))

    return redirect(url_for('view_case', case_id=case_id))

# ── Cases: view ───────────────────────────────────────────────────────────────

@app.route('/cases/<case_id>')
@login_required
def view_case(case_id: str):
    if not _valid_case_id(case_id):
        abort(400)
    case = _get_case(case_id)
    if not case:
        abort(404)
    return render_template('case.html', case=case)

# ── Cases: save config ────────────────────────────────────────────────────────

@app.route('/cases/<case_id>/config', methods=['POST'])
@login_required
def save_config(case_id: str):
    _check_csrf()
    if not _valid_case_id(case_id):
        abort(400)
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        abort(404)

    try:
        max_iter = max(1, min(20, int(request.form.get('max_iterations', 10))))
    except ValueError:
        max_iter = 10

    config = {
        'disk_path':      _safe_path(request.form.get('disk_path', '')),
        'memory_path':    _safe_path(request.form.get('memory_path', '')),
        'max_iterations': max_iter,
    }
    (case_dir / 'web_config.json').write_text(json.dumps(config, indent=2))
    return jsonify({'saved': True})

# ── Analysis: start ───────────────────────────────────────────────────────────

@app.route('/cases/<case_id>/run', methods=['POST'])
@login_required
def run_analysis(case_id: str):
    _check_csrf()
    if not _valid_case_id(case_id):
        abort(400)
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        abort(404)

    # Prevent double-start
    info = _running.get(case_id)
    if info and info['process'].poll() is None:
        return jsonify({'error': 'Analysis already running.'}), 409

    # Load config
    cfile = case_dir / 'web_config.json'
    cfg   = json.loads(cfile.read_text()) if cfile.exists() else {}

    log_file = case_dir / 'analysis' / 'web_stream.log'
    log_file.parent.mkdir(exist_ok=True)
    # Truncate log for new run
    log_file.write_text('')

    # Validate paths from user config to prevent command injection (CWE-78)
    try:
        disk_path = _validate_data_path(cfg.get('disk_path'), case_dir)
        memory_path = _validate_data_path(cfg.get('memory_path'), case_dir)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    cmd = ['python3', LOOP_PY, '--case', str(case_dir)]
    if disk_path:
        cmd += ['--disk', disk_path]
    if memory_path:
        cmd += ['--memory', memory_path]
    cmd += ['--max-iterations', str(cfg.get('max_iterations', 10))]

    log_handle = open(log_file, 'w', buffering=1)  # line-buffered
    # nosemgrep: python.lang.security.dangerous-subprocess-use
    proc = subprocess.Popen(
        cmd,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    _running[case_id] = {
        'process': proc,
        'log':     log_file,
        'handle':  log_handle,
        'started': datetime.now(timezone.utc).isoformat(),
    }
    return jsonify({'started': True, 'pid': proc.pid})

# ── Analysis: stop ────────────────────────────────────────────────────────────

@app.route('/cases/<case_id>/stop', methods=['POST'])
@login_required
def stop_analysis(case_id: str):
    _check_csrf()
    if not _valid_case_id(case_id):
        abort(400)

    info = _running.get(case_id)
    if not info:
        return jsonify({'error': 'No running analysis.'}), 404

    proc = info['process']
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    handle = info.get('handle')
    if handle:
        handle.close()

    return jsonify({'stopped': True})

# ── Analysis: SSE stream ──────────────────────────────────────────────────────

@app.route('/cases/<case_id>/stream')
@login_required
def stream(case_id: str):
    if not _valid_case_id(case_id):
        abort(400)

    log_file = CASES_DIR / case_id / 'analysis' / 'web_stream.log'

    def _generate():
        # Wait up to 3s for log to appear
        for _ in range(30):
            if log_file.exists():
                break
            time.sleep(0.1)

        if not log_file.exists():
            yield 'data: {"type":"error","msg":"Log not found — did you start an analysis?"}\n\n'
            return

        yield 'data: {"type":"connected"}\n\n'

        pos       = 0
        idle_s    = 0
        MAX_IDLE  = 300  # 5 minutes

        with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
            while True:
                f.seek(pos)
                line = f.readline()
                if line:
                    pos      = f.tell()
                    idle_s   = 0
                    payload  = json.dumps({'type': 'log', 'msg': line.rstrip()})
                    yield f'data: {payload}\n\n'
                else:
                    info = _running.get(case_id, {})
                    proc = info.get('process')
                    if proc and proc.poll() is not None:
                        code = proc.returncode
                        yield f'data: {{"type":"done","code":{code}}}\n\n'
                        break
                    idle_s += 0.4
                    if idle_s >= MAX_IDLE:
                        yield 'data: {"type":"timeout"}\n\n'
                        break
                    time.sleep(0.4)

    return Response(
        _generate(),
        mimetype='text/event-stream',
        headers={
            'X-Accel-Buffering': 'no',
            'Cache-Control':     'no-cache',
            'Connection':        'keep-alive',
        },
    )

# ── Findings API ──────────────────────────────────────────────────────────────

@app.route('/cases/<case_id>/findings')
@login_required
def get_findings(case_id: str):
    if not _valid_case_id(case_id):
        abort(400)
    ffile = CASES_DIR / case_id / 'analysis' / 'findings.json'
    if not ffile.exists():
        return jsonify({'findings': [], 'iterations': [], 'criteria': {}})
    return jsonify(json.loads(ffile.read_text()))

# ── PDF download ──────────────────────────────────────────────────────────────

@app.route('/cases/<case_id>/report')
@login_required
def download_report(case_id: str):
    if not _valid_case_id(case_id):
        abort(400)
    report = CASES_DIR / case_id / 'reports' / 'incident_report.pdf'
    if not report.exists():
        abort(404)
    return send_file(
        report,
        as_attachment=True,
        download_name=f'{case_id}_incident_report.pdf',
        mimetype='application/pdf',
    )

# ── Status API (polled by frontend) ──────────────────────────────────────────

@app.route('/cases/<case_id>/status')
@login_required
def case_status(case_id: str):
    if not _valid_case_id(case_id):
        abort(400)
    return jsonify({'status': _case_status(case_id)})

# ── Error pages ───────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, msg='Forbidden'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, msg='Not Found'), 404

# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    print(f'[FIND EVIL] Web GUI → http://127.0.0.1:{PORT}')
    print(f'[FIND EVIL] Cases directory: {CASES_DIR}')
    print(f'[FIND EVIL] Listening on localhost only — not exposed to network.')
    app.run(
        host='127.0.0.1',
        port=PORT,
        debug=False,
        threaded=True,
    )
