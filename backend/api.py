"""
CyberFinGuard — Backend API (Flask)
Serves scan control endpoints to the Next.js frontend.

Fixes applied:
- UTF-8 encoding for subprocess pipes (Windows emoji crash)
- venv-safe subprocess (sys.executable, not 'python')
- Background threading (non-blocking scan start)
- Correct config path (data/scan_config.json — matches main.py)
- Missing endpoints added (/api/scan/status, /api/assets/website)
- Port 8000 (matches frontend proxy)
- Localhost binding only
"""

from flask import Flask, request, jsonify
from importlib import import_module

try:
    CORS = import_module('flask_cors').CORS
except ImportError:
    def CORS(_app):
        """No-op fallback when flask-cors is not installed."""
        return None

import subprocess
import json
import os
import sys
import threading
from datetime import datetime

# ─── UTF-8 FORCE (Windows subprocess emoji fix) ───────────────────
if sys.platform == 'win32':
    os.environ.setdefault('PYTHONIOENCODING', 'utf-8')
    os.environ.setdefault('PYTHONUTF8', '1')

# ─── PATHS ────────────────────────────────────────────────────────
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BACKEND_DIR)
DATA_DIR = os.path.join(ROOT_DIR, 'data')
SCAN_CONFIG_PATH = os.path.join(DATA_DIR, 'scan_config.json')
SCAN_STATUS_PATH = os.path.join(DATA_DIR, 'scan_status.json')
UNIFIED_DIR = os.path.join(DATA_DIR, 'unified_findings')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UNIFIED_DIR, exist_ok=True)

# ─── APP ──────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# In-memory config (also persisted to disk)
scan_config = {
    "target_url": None,
    "website_asset_id": None,
    "cloud": {"provider": None, "account_id": None, "role_arn": None},
    "identity": {"url": None, "realm": None, "client_id": None, "client_secret": None},
    "business": {
        "asset_name": None,
        "asset_type": None,
        "business_unit": None,
        "asset_owner": None,
        "business_value": None,
        "downtime_cost": None,
        "recovery_cost": None,
        "asset_criticality": None,
    },
}

# Track running scan process
_scan_lock = threading.Lock()
_scan_running = False


# ─── HELPERS ──────────────────────────────────────────────────────
def _write_json(path, payload):
    """Atomic JSON write."""
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, default=str)
    os.replace(tmp, path)


def _read_json(path, default=None):
    """Safe JSON read."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _persist_scan_config():
    """Save in-memory config to data/scan_config.json (where main.py reads it)."""
    _write_json(SCAN_CONFIG_PATH, scan_config)


def _update_status(status, stage, error=None, scanner_results=None):
    """Update scan_status.json — same format main.py uses."""
    previous = _read_json(SCAN_STATUS_PATH, {}) or {}
    payload = {
        k: previous.get(k)
        for k in ('started_at', 'target_url', 'asset_id')
        if k in previous
    }
    payload.update(
        status=status,
        stage=stage,
        updated_at=datetime.now().isoformat(),
    )
    if error:
        payload['error'] = str(error)
    if scanner_results is not None:
        payload['scanner_results'] = scanner_results
    _write_json(SCAN_STATUS_PATH, payload)


def _generate_asset_id(target_url):
    """Deterministic asset_id from URL."""
    import hashlib
    digest = hashlib.md5(target_url.encode()).hexdigest()[:12]
    return f"web-{digest}"


def _run_pipeline_background(target_url):
    """Run main.py in a background thread and update status as it goes."""
    global _scan_running
    try:
        _update_status('running', 'Starting pipeline')

        proc = subprocess.run(
            [
                sys.executable,
                '-X', 'utf8',
                os.path.join(ROOT_DIR, 'main.py'),
                target_url,
            ],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=3600,
        )

        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or '')[-2000:]
            _update_status('failed', 'Pipeline returned non-zero', error=tail)
        else:
            _update_status('complete', 'Complete')

    except subprocess.TimeoutExpired:
        _update_status('failed', 'Pipeline timed out', error='Scan exceeded 1 hour')
    except Exception as exc:
        import traceback
        traceback.print_exc()
        _update_status('failed', 'Spawn error', error=str(exc))
    finally:
        with _scan_lock:
            _scan_running = False


# ─── CONFIG ENDPOINTS ─────────────────────────────────────────────
@app.route('/api/config/website', methods=['POST'])
def set_website():
    data = request.json or {}
    scan_config['target_url'] = data.get('target_url')
    if scan_config['target_url']:
        scan_config['website_asset_id'] = _generate_asset_id(scan_config['target_url'])
    _persist_scan_config()
    return jsonify({
        "status": "ok",
        "target_url": scan_config['target_url'],
        "website_asset_id": scan_config['website_asset_id'],
    })


@app.route('/api/config/cloud', methods=['POST'])
def set_cloud():
    data = request.json or {}
    scan_config['cloud'] = {
        "provider": data.get('provider'),
        "account_id": data.get('account_id'),
        "role_arn": data.get('role_arn'),
    }
    _persist_scan_config()
    return jsonify({"status": "ok", "cloud": scan_config['cloud']})


@app.route('/api/config/identity', methods=['POST'])
def set_identity():
    data = request.json or {}
    scan_config['identity'] = {
        "url": data.get('keycloak_url'),
        "realm": data.get('realm'),
        "client_id": data.get('client_id'),
        "client_secret": data.get('client_secret'),
    }
    _persist_scan_config()
    return jsonify({"status": "ok", "identity": scan_config['identity']})


@app.route('/api/config/business', methods=['POST'])
def set_business():
    data = request.json or {}
    scan_config['business'] = {
        "asset_name": data.get('asset_name'),
        "asset_type": data.get('asset_type'),
        "business_unit": data.get('business_unit'),
        "asset_owner": data.get('asset_owner'),
        "business_value": data.get('business_value'),
        "downtime_cost": data.get('downtime_cost'),
        "recovery_cost": data.get('recovery_cost'),
        "asset_criticality": data.get('asset_criticality'),
    }
    _persist_scan_config()
    return jsonify({"status": "ok", "business": scan_config['business']})


@app.route('/api/assessment/config', methods=['GET'])
def get_assessment_config():
    """Frontend calls this on load to get current config."""
    return jsonify({
        "target_url": scan_config.get('target_url'),
        "website_asset_id": scan_config.get('website_asset_id'),
        "cloud": scan_config.get('cloud'),
        "identity": scan_config.get('identity'),
        "business": scan_config.get('business'),
    })


# ─── FRONTEND-FACING SCAN ENDPOINTS ───────────────────────────────
@app.route('/api/assets/website', methods=['POST'])
def save_website_asset():
    """
    Frontend calls this with {'target_url': 'https://...'}.
    Saves the URL, spawns main.py in the background, returns immediately.
    """
    global _scan_running

    data = request.json or {}
    target = data.get('target_url') or data.get('url')

    if not target:
        return jsonify({"error": "target_url required"}), 400

    with _scan_lock:
        if _scan_running:
            return jsonify({
                "error": "A scan is already running. Wait for it to complete.",
            }), 409
        _scan_running = True

    # 1. Save config
    scan_config['target_url'] = target
    if not scan_config.get('website_asset_id'):
        scan_config['website_asset_id'] = _generate_asset_id(target)
    _persist_scan_config()

    # 2. Reset status to 'running'
    _write_json(SCAN_STATUS_PATH, {
        "status": "running",
        "stage": "Queued",
        "started_at": datetime.now().isoformat(),
        "target_url": target,
        "asset_id": scan_config['website_asset_id'],
    })

    # 3. Spawn background thread
    thread = threading.Thread(
        target=_run_pipeline_background,
        args=(target,),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "status": "started",
        "target_url": target,
        "asset_id": scan_config['website_asset_id'],
        "message": "Scan started in background",
    })


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Frontend polls this to know the scan progress."""
    status = _read_json(SCAN_STATUS_PATH, {
        "status": "idle",
        "stage": "No scan running",
        "target_url": None,
    })
    return jsonify(status)


@app.route('/api/scan/findings', methods=['GET'])
def scan_findings():
    """Return unified findings for the dashboard."""
    latest = _read_json(
        os.path.join(UNIFIED_DIR, 'latest.json'),
        {"total_findings": 0, "findings": [], "summary": {}},
    )
    return jsonify(latest)


@app.route('/api/scan/run', methods=['POST'])
def run_scan():
    """Legacy synchronous endpoint (kept for compat)."""
    target = scan_config.get('target_url')
    if not target:
        return jsonify({"error": "Target URL not set"}), 400

    _persist_scan_config()

    try:
        result = subprocess.run(
            [
                sys.executable,
                '-X', 'utf8',
                os.path.join(ROOT_DIR, 'main.py'),
                target,
            ],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=1800,
        )
        return jsonify({
            "status": "ok",
            "returncode": result.returncode,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-1000:],
            "config": scan_config,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out"}), 504
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ─── HEALTH ───────────────────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "time": datetime.now().isoformat(),
        "scan_running": _scan_running,
    })


@app.route('/', methods=['GET'])
def index():
    """Simple root for sanity checking."""
    return jsonify({
        "service": "CyberFinGuard Backend API",
        "endpoints": [
            "GET  /api/health",
            "GET  /api/scan/status",
            "GET  /api/scan/findings",
            "GET  /api/assessment/config",
            "POST /api/assets/website",
            "POST /api/config/website",
            "POST /api/config/business",
            "POST /api/config/cloud",
            "POST /api/config/identity",
            "POST /api/scan/run",
        ],
    })


# ─── START ────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Keep the historical `python backend/api.py` command compatible with the
    # live frontend.  The old app above is retained for imports, but it does
    # not expose the complete dashboard/risk API used by Next.js.
    from backend.live_api import app as live_app

    live_app.run(
        host=os.getenv('API_HOST', '127.0.0.1'),
        port=int(os.getenv('API_PORT', '8000')),
        debug=False,
        threaded=True,
    )
