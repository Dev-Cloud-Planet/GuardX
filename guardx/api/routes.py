"""
GuardX API v1 Routes
REST endpoints for CI/CD and SIEM integration with API key authentication.
"""

import os
import json
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Optional, Dict, Any, Tuple

from flask import Blueprint, request, jsonify

# Try to import optional modules
try:
    from guardx.core.rate_limiter import get_limiter
except ImportError:
    get_limiter = None

try:
    from guardx.core.database import get_db
except ImportError:
    get_db = None

try:
    from guardx.reporting import generate_report
except ImportError:
    generate_report = None


# ── Blueprint Definition ──────────────────────────────────────
api_bp = Blueprint('api_v1', __name__, url_prefix='/api/v1')


# ── Configuration ─────────────────────────────────────────────
# API keys from environment variable (comma-separated)
GUARDX_API_KEYS = set(
    key.strip() for key in os.getenv('GUARDX_API_KEYS', '').split(',')
    if key.strip()
)

# Default API version and stats (auto-count from loaded modules)
API_VERSION = '3.1'
try:
    from guardx.llm.client import TOOLS as _TOOLS, TOOL_EXECUTORS as _EXECUTORS
    TOOLS_COUNT = len(_TOOLS)
except ImportError:
    TOOLS_COUNT = 20

try:
    from guardx.skills import get_all_skills as _get_skills
    SKILLS_COUNT = len(_get_skills())
except ImportError:
    SKILLS_COUNT = 26

# In-memory scan storage (would use DB in production)
_scans: Dict[str, dict] = {}


# ── Authentication ────────────────────────────────────────────
def api_key_required(f):
    """Decorator to check API key authentication.

    Accepts API key via:
    - Authorization: Bearer <key> header
    - X-API-Key: <key> header
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract API key from headers
        auth_header = request.headers.get('Authorization', '')
        api_key = None

        # Check Bearer token
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:].strip()

        # Check X-API-Key header
        if not api_key:
            api_key = request.headers.get('X-API-Key', '').strip()

        # Validate API key
        if not api_key or api_key not in GUARDX_API_KEYS:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid or missing API key'
            }), 401

        return f(*args, **kwargs)

    return decorated_function


# ── Rate Limiting ─────────────────────────────────────────────
def apply_rate_limit(f):
    """Decorator to apply rate limiting per API key."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if get_limiter is None:
            # Rate limiter not available, skip
            return f(*args, **kwargs)

        try:
            api_key = _extract_api_key()
            limiter = get_limiter()
            # Use API key as domain identifier
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(limiter.acquire(f'api_key_{api_key}'))
            loop.close()
        except Exception:
            # If rate limiting fails, continue anyway
            pass

        return f(*args, **kwargs)

    return decorated_function


def _extract_api_key() -> str:
    """Extract API key from request headers."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:].strip()
    return request.headers.get('X-API-Key', '').strip()


# ── Utility Functions ─────────────────────────────────────────
def _create_scan_record(target: str, phases: list, options: dict) -> dict:
    """Create a new scan record."""
    scan_id = str(uuid.uuid4())[:12]
    return {
        'scan_id': scan_id,
        'target': target,
        'phases': phases,
        'options': options,
        'status': 'started',
        'phase': 'started',
        'started_at': datetime.now(timezone.utc).isoformat(),
        'findings': [],
        'findings_count': 0,
    }


def _get_scan(scan_id: str) -> Optional[dict]:
    """Get scan by ID."""
    return _scans.get(scan_id)


# ── Health Check ──────────────────────────────────────────────
@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint.

    Returns:
        JSON with status, version, tools count, and skills count
    """
    return jsonify({
        'status': 'ok',
        'version': API_VERSION,
        'tools': TOOLS_COUNT,
        'skills': SKILLS_COUNT,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


# ── Scan Endpoints ────────────────────────────────────────────
@api_bp.route('/scan', methods=['POST'])
@api_key_required
@apply_rate_limit
def start_scan():
    """Start a new scan.

    Request body:
    {
        "target": "https://example.com",
        "phases": ["recon", "exploit"],
        "options": {}
    }

    Returns:
        JSON with scan_id and status
    """
    try:
        data = request.get_json() or {}

        # Validate required fields
        target = data.get('target', '').strip()
        if not target:
            return jsonify({
                'error': 'Bad request',
                'message': 'target field is required'
            }), 400

        phases = data.get('phases', ['recon', 'exploit'])
        if not isinstance(phases, list) or len(phases) == 0:
            return jsonify({
                'error': 'Bad request',
                'message': 'phases must be a non-empty list'
            }), 400

        options = data.get('options', {})

        # Create scan record
        scan = _create_scan_record(target, phases, options)
        _scans[scan['scan_id']] = scan

        return jsonify({
            'scan_id': scan['scan_id'],
            'status': 'started',
            'message': f'Scan started for {target}',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }), 202

    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@api_bp.route('/scan/<scan_id>', methods=['GET'])
@api_key_required
@apply_rate_limit
def get_scan_status(scan_id: str):
    """Get scan status.

    Args:
        scan_id: Scan identifier

    Returns:
        JSON with scan status details
    """
    scan = _get_scan(scan_id)

    if not scan:
        return jsonify({
            'error': 'Not found',
            'message': f'Scan {scan_id} not found'
        }), 404

    return jsonify({
        'scan_id': scan['scan_id'],
        'target': scan['target'],
        'phase': scan['phase'],
        'status': scan['status'],
        'started_at': scan['started_at'],
        'findings_count': scan['findings_count'],
    })


@api_bp.route('/scan/<scan_id>/findings', methods=['GET'])
@api_key_required
@apply_rate_limit
def get_scan_findings(scan_id: str):
    """Get scan findings.

    Args:
        scan_id: Scan identifier

    Returns:
        JSON with list of findings
    """
    scan = _get_scan(scan_id)

    if not scan:
        return jsonify({
            'error': 'Not found',
            'message': f'Scan {scan_id} not found'
        }), 404

    return jsonify({
        'scan_id': scan['scan_id'],
        'findings': scan['findings'],
        'count': len(scan['findings']),
    })


@api_bp.route('/scan/<scan_id>/report', methods=['GET'])
@api_key_required
@apply_rate_limit
def get_scan_report(scan_id: str):
    """Get scan report.

    Query params:
    - format: 'html' or 'json' (defaults to 'json', also respects Accept header)

    Args:
        scan_id: Scan identifier

    Returns:
        Report in requested format (HTML or JSON)
    """
    scan = _get_scan(scan_id)

    if not scan:
        return jsonify({
            'error': 'Not found',
            'message': f'Scan {scan_id} not found'
        }), 404

    # Determine format from Accept header or query param
    format_param = request.args.get('format', '').lower()
    accept_header = request.headers.get('Accept', 'application/json')

    is_html = (
        format_param == 'html' or
        'text/html' in accept_header
    )

    if is_html:
        if generate_report is None:
            return jsonify({
                'error': 'Service unavailable',
                'message': 'Report generation not available'
            }), 503

        # Generate HTML report
        try:
            html_report = generate_report(scan, format='html')
            return html_report, 200, {'Content-Type': 'text/html; charset=utf-8'}
        except Exception as e:
            return jsonify({
                'error': 'Internal server error',
                'message': f'Failed to generate report: {str(e)}'
            }), 500
    else:
        # Return JSON report
        return jsonify({
            'scan_id': scan['scan_id'],
            'target': scan['target'],
            'started_at': scan['started_at'],
            'status': scan['status'],
            'findings': scan['findings'],
            'findings_count': scan['findings_count'],
        })


@api_bp.route('/scans', methods=['GET'])
@api_key_required
@apply_rate_limit
def list_scans():
    """List all scans with pagination.

    Query params:
    - page: Page number (default: 1)
    - per_page: Results per page (default: 20, max: 100)

    Returns:
        JSON with list of scans and pagination info
    """
    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = int(request.args.get('per_page', 20))

        # Validate per_page
        per_page = min(100, max(1, per_page))

        # Sort scans by started_at (newest first)
        sorted_scans = sorted(
            _scans.values(),
            key=lambda s: s['started_at'],
            reverse=True
        )

        total = len(sorted_scans)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page

        scans_page = sorted_scans[start_idx:end_idx]

        return jsonify({
            'scans': scans_page,
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
        })

    except ValueError:
        return jsonify({
            'error': 'Bad request',
            'message': 'Invalid page or per_page parameter'
        }), 400
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@api_bp.route('/scan/<scan_id>', methods=['DELETE'])
@api_key_required
@apply_rate_limit
def cancel_scan(scan_id: str):
    """Cancel a running scan.

    Args:
        scan_id: Scan identifier

    Returns:
        JSON with cancellation status
    """
    scan = _get_scan(scan_id)

    if not scan:
        return jsonify({
            'error': 'Not found',
            'message': f'Scan {scan_id} not found'
        }), 404

    if scan['status'] in ('completed', 'cancelled'):
        return jsonify({
            'error': 'Bad request',
            'message': f'Cannot cancel a {scan["status"]} scan'
        }), 400

    # Mark scan as cancelled
    scan['status'] = 'cancelled'
    scan['phase'] = 'cancelled'

    return jsonify({
        'scan_id': scan['scan_id'],
        'status': 'cancelled',
        'message': f'Scan {scan_id} cancelled',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


# ── Error Handlers ────────────────────────────────────────────
@api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'error': 'Not found',
        'message': 'Endpoint not found'
    }), 404


@api_bp.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return jsonify({
        'error': 'Method not allowed',
        'message': f'Method {request.method} not allowed on this endpoint'
    }), 405


@api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500
