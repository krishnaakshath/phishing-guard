"""
Phishing Guard - Backend API Server v2.0
Industry-Ready Flask application with enhanced security features
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import logging
from datetime import datetime
import os

# Import modules
from detector import scan_url, scan_content
from threat_intel import check_url, check_domain, analyze_content, add_whitelist, add_blacklist, get_lists
import models
import security_grade
import breach_check
import secret_scanner
import notifications

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'phishing-guard-secret-key-change-in-production')

# Enable CORS for Chrome extension and dashboard.
# Defaults to the extension + production dashboard origins rather than '*' -
# set ALLOWED_ORIGINS explicitly (comma-separated) to override in your own
# deployment. Chrome extensions send an "chrome-extension://<id>" origin
# that changes per install, so that scheme is allowed broadly; tighten it
# to your specific extension ID once published if you want to lock it down.
DEFAULT_ALLOWED_ORIGINS = 'chrome-extension://*,https://phishing-guard-seven.vercel.app,http://localhost:5173,http://localhost:3000'
ALLOWED_ORIGINS = (os.environ.get('ALLOWED_ORIGINS') or DEFAULT_ALLOWED_ORIGINS).split(',')
CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-Key"]
    }
})

# Rate limiting - protects /api/scan from abuse (each scan can trigger a
# WHOIS lookup + SSL handshake + external feed check) and /api/auth/* from
# brute force. Storage defaults to in-memory, which is fine for a single
# instance; note in README if scaling to multiple workers.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)

# Global statistics (in-memory, for quick access)
stats = {
    'total_scans': 0,
    'threats_detected': 0,
    'start_time': datetime.now().isoformat()
}


def require_admin(f):
    """Decorator to require an authenticated admin user.
    Always re-checks is_admin server-side - never trusts a client flag."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401

        user = models.get_user_by_api_key(api_key)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401

        if not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403

        g.user = user
        return f(*args, **kwargs)
    return decorated


# ============================================
# AUTHENTICATION MIDDLEWARE
# ============================================

def require_api_key(f):
    """Decorator to require API key for protected endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        user = models.get_user_by_api_key(api_key)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        g.user = user
        return f(*args, **kwargs)
    return decorated


def optional_api_key(f):
    """Decorator to optionally authenticate user"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = models.get_user_by_api_key(api_key)
            g.user = user
        else:
            g.user = None
        return f(*args, **kwargs)
    return decorated


# ============================================
# HEALTH & INFO ENDPOINTS
# ============================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing Guard API',
        'version': '2.0.0',
        'uptime_since': stats['start_time'],
        'features': [
            'phishing_detection',
            'threat_intelligence',
            'password_protection',
            'user_settings_sync',
            'whitelist_blacklist'
        ]
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get global scanning statistics"""
    return jsonify({
        'total_scans': stats['total_scans'],
        'threats_detected': stats['threats_detected'],
        'uptime_since': stats['start_time']
    })


# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    """Register new user"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        user = models.create_user(email, password)
        if not user:
            return jsonify({'error': 'Email already registered'}), 409
        
        logger.info(f"New user registered: {email}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email']
            },
            'api_key': user['api_key']
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("15 per hour")
def login():
    """Authenticate user"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = models.authenticate_user(email, password)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        logger.info(f"User logged in: {email}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email']
            },
            'api_key': user['api_key']
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/auth/me', methods=['GET'])
@require_api_key
def get_current_user():
    """Get current authenticated user"""
    return jsonify({
        'user': {
            'id': g.user['id'],
            'email': g.user['email'],
            'is_admin': g.user.get('is_admin', False)
        }
    })


# ============================================
# SETTINGS ENDPOINTS
# ============================================

@app.route('/api/settings', methods=['GET'])
@require_api_key
def get_settings():
    """Get user settings"""
    settings = models.get_user_settings(g.user['id'])
    return jsonify({
        'success': True,
        'settings': settings
    })


@app.route('/api/settings', methods=['PUT'])
@require_api_key
def update_settings():
    """Update user settings"""
    try:
        data = request.get_json()
        success = models.update_user_settings(g.user['id'], data)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Settings updated'
            })
        else:
            return jsonify({'error': 'Failed to update settings'}), 500
            
    except Exception as e:
        logger.error(f"Settings update error: {e}")
        return jsonify({'error': 'Update failed'}), 500


# ============================================
# SCANNING ENDPOINTS
# ============================================

@app.route('/api/scan', methods=['POST'])
@limiter.limit("60 per minute")
@optional_api_key
def scan_endpoint():
    """
    Main scanning endpoint with enhanced detection
    Accepts: { "url": "https://example.com", "content": {...} }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        url = data.get('url')
        content = data.get('content', {})
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        logger.info(f"Scanning URL: {url}")
        
        # Perform URL analysis
        url_result = scan_url(url)
        
        # Enhanced threat intelligence check
        threat_result = check_url(url)
        
        # Merge threat intelligence results
        if threat_result.get('risk_factors'):
            url_result['warnings'].extend(threat_result['risk_factors'])
        
        if threat_result.get('reputation_score', 100) < 60:
            url_result['risk_score'] = min(100, url_result['risk_score'] + (60 - threat_result['reputation_score']))
        
        # Perform content analysis if provided
        content_result = {}
        if content:
            content_result = scan_content(content)
            url_result['risk_score'] = min(100, 
                url_result['risk_score'] + content_result.get('risk_score', 0))
            url_result['warnings'].extend(content_result.get('content_risks', []))
        
        # Recalculate risk level
        if url_result['risk_score'] >= 70:
            url_result['risk_level'] = 'dangerous'
            url_result['is_phishing'] = True
        elif url_result['risk_score'] >= 50:
            url_result['risk_level'] = 'suspicious'
            url_result['is_phishing'] = True
        elif url_result['risk_score'] >= 30:
            url_result['risk_level'] = 'warning'
        
        # Update statistics
        stats['total_scans'] += 1
        if url_result['is_phishing']:
            stats['threats_detected'] += 1
        
        # Record scan for authenticated users
        if g.user:
            models.add_scan_record(g.user['id'], url, url_result)
        
        # Build response
        response = {
            'success': True,
            'url': url,
            'analysis': {
                'is_phishing': url_result['is_phishing'],
                'risk_score': url_result['risk_score'],
                'risk_level': url_result['risk_level'],
                'warnings': url_result['warnings'],
                'details': url_result['details'],
                'threat_intel': {
                    'reputation_score': threat_result.get('reputation_score'),
                    'threat_types': threat_result.get('threat_types', [])
                }
            },
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Scan complete - Risk: {url_result['risk_level']} ({url_result['risk_score']})")
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/verify-site', methods=['POST'])
@optional_api_key
def verify_site():
    """Deep site verification endpoint"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # Get comprehensive threat intelligence
        reputation = check_domain(domain)
        
        return jsonify({
            'success': True,
            'domain': domain,
            'verification': {
                'reputation_score': reputation.get('reputation_score', 0),
                'is_malicious': reputation.get('is_malicious', False),
                'risk_factors': reputation.get('risk_factors', []),
                'threat_types': reputation.get('threat_types', []),
                'ssl_info': reputation.get('ssl_info'),
                'domain_age_days': reputation.get('domain_age_days'),
                'checks_performed': reputation.get('checks_performed', [])
            }
        })
        
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze-content', methods=['POST'])
@optional_api_key
def analyze_content_endpoint():
    """Analyze page content for threats"""
    try:
        data = request.get_json()
        content = data.get('content', '')
        
        result = analyze_content(content)
        
        return jsonify({
            'success': True,
            'analysis': result
        })
        
    except Exception as e:
        logger.error(f"Content analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch-scan', methods=['POST'])
@optional_api_key
def batch_scan_endpoint():
    """Batch scanning endpoint for multiple URLs"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({'error': 'URLs array is required'}), 400
        
        if len(urls) > 50:
            return jsonify({'error': 'Maximum 50 URLs per batch'}), 400
        
        results = []
        for url in urls:
            result = scan_url(url)
            results.append({
                'url': url,
                'is_phishing': result['is_phishing'],
                'risk_score': result['risk_score'],
                'risk_level': result['risk_level']
            })
            stats['total_scans'] += 1
            if result['is_phishing']:
                stats['threats_detected'] += 1
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results)
        })
    
    except Exception as e:
        logger.error(f"Batch scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# WHITELIST / BLACKLIST ENDPOINTS
# ============================================

@app.route('/api/whitelist', methods=['GET'])
@require_api_key
def get_whitelist():
    """Get user whitelist"""
    whitelist = models.get_whitelist(g.user['id'])
    return jsonify({
        'success': True,
        'whitelist': whitelist
    })


@app.route('/api/whitelist', methods=['POST'])
@require_api_key
def add_to_whitelist_endpoint():
    """Add domain to whitelist"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        notes = data.get('notes', '')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        success = models.add_to_whitelist(g.user['id'], domain, notes)
        add_whitelist(domain)  # Update in-memory list
        
        return jsonify({
            'success': success,
            'message': f'Added {domain} to whitelist'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist/<domain>', methods=['DELETE'])
@require_api_key
def remove_from_whitelist_endpoint(domain):
    """Remove domain from whitelist"""
    success = models.remove_from_whitelist(g.user['id'], domain)
    return jsonify({
        'success': success,
        'message': f'Removed {domain} from whitelist'
    })


@app.route('/api/blacklist', methods=['GET'])
@require_api_key
def get_blacklist():
    """Get user blacklist"""
    blacklist = models.get_blacklist(g.user['id'])
    return jsonify({
        'success': True,
        'blacklist': blacklist
    })


@app.route('/api/blacklist', methods=['POST'])
@require_api_key
def add_to_blacklist_endpoint():
    """Add domain to blacklist"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        reason = data.get('reason', '')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        success = models.add_to_blacklist(g.user['id'], domain, reason)
        add_blacklist(domain)  # Update in-memory list
        
        return jsonify({
            'success': success,
            'message': f'Added {domain} to blacklist'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/blacklist/<domain>', methods=['DELETE'])
@require_api_key
def remove_from_blacklist_endpoint(domain):
    """Remove domain from blacklist"""
    success = models.remove_from_blacklist(g.user['id'], domain)
    return jsonify({
        'success': success,
        'message': f'Removed {domain} from blacklist'
    })


# ============================================
# HISTORY & STATISTICS ENDPOINTS
# ============================================

@app.route('/api/history', methods=['GET'])
@require_api_key
def get_history():
    """Get user scan history"""
    limit = request.args.get('limit', 50, type=int)
    history = models.get_scan_history(g.user['id'], limit)
    return jsonify({
        'success': True,
        'history': history
    })


@app.route('/api/stats/user', methods=['GET'])
@require_api_key
def get_user_stats():
    """Get user statistics"""
    days = request.args.get('days', 30, type=int)
    statistics = models.get_user_statistics(g.user['id'], days)
    return jsonify({
        'success': True,
        'statistics': statistics
    })


# ============================================
# REPORT PHISHING
# ============================================

@app.route('/api/report-phishing', methods=['POST'])
@optional_api_key
def report_phishing():
    """Report a phishing URL"""
    try:
        data = request.get_json()
        url = data.get('url')
        reason = data.get('reason', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        from urllib.parse import urlparse
        domain = urlparse(url).netloc

        # Add to the in-memory blocklist (immediate effect for future scans)
        # and the persistent threat database (admin-reviewable record)
        add_blacklist(domain)
        models.add_threat_report(domain, threat_type='phishing', severity='medium')

        # Warn anyone who'd whitelisted this domain that it's now been
        # reported - best-effort, never fails the report itself.
        try:
            for whitelister in models.get_users_who_whitelisted(domain):
                notifications.notify_whitelisted_domain_reported(whitelister['email'], domain)
        except Exception as e:
            logger.warning(f"Failed to notify whitelisters of {domain}: {e}")

        logger.info(f"Phishing report received: {url}")
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your report. It will be reviewed.'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# PUBLIC SECURITY TOOLS (no auth required)
# ============================================

@app.route('/api/check-password-breach', methods=['POST'])
@limiter.limit("20 per hour")
def check_password_breach_endpoint():
    """
    Check whether a password appears in known breach data via HIBP's
    k-anonymity API. Only a 5-char hash prefix ever leaves this server.
    """
    try:
        data = request.get_json()
        password = data.get('password') if data else None

        if not password:
            return jsonify({'error': 'Password is required'}), 400

        result = breach_check.check_password_breach(password)
        return jsonify({'success': True, 'result': result})

    except Exception as e:
        logger.error(f"Password breach check error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/site-scan', methods=['GET'])
@limiter.limit("20 per hour")
def site_scan_endpoint():
    """
    Public site security checkup: security header/TLS/cookie grade plus
    an exposed-secrets scan of the page's HTML. No auth required - this
    is meant to be shareable, like Mozilla Observatory.
    """
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'url query parameter is required'}), 400

    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'

    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc

        posture = security_grade.grade_site(url)

        try:
            import requests as _requests
            page_resp = _requests.get(url, timeout=6)
            secrets = secret_scanner.scan_for_secrets(page_resp.text)
        except Exception as e:
            logger.warning(f"Secret scan fetch failed for {url}: {e}")
            secrets = []

        threat_result = check_url(url)

        return jsonify({
            'success': True,
            'url': url,
            'domain': domain,
            'posture': posture,
            'secrets': secrets,
            'threat_intel': {
                'reputation_score': threat_result.get('reputation_score'),
                'threat_types': threat_result.get('threat_types', [])
            }
        })

    except Exception as e:
        logger.error(f"Site scan error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ADMIN ENDPOINTS
# ============================================

@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    return jsonify({'success': True, 'stats': models.get_global_stats()})


@app.route('/api/admin/threats', methods=['GET'])
@require_admin
def admin_list_threats():
    return jsonify({'success': True, 'threats': models.list_threat_reports()})


@app.route('/api/admin/threats/<int:threat_id>/verify', methods=['POST'])
@require_admin
def admin_verify_threat(threat_id):
    success = models.verify_threat_report(threat_id)
    if not success:
        return jsonify({'error': 'Threat report not found'}), 404
    return jsonify({'success': True})


@app.route('/api/admin/threats/<int:threat_id>', methods=['DELETE'])
@require_admin
def admin_delete_threat(threat_id):
    success = models.delete_threat_report(threat_id)
    if not success:
        return jsonify({'error': 'Threat report not found'}), 404
    return jsonify({'success': True})


@app.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_list_users():
    return jsonify({'success': True, 'users': models.list_all_users()})


# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    logger.info("=" * 50)
    logger.info("Starting Phishing Guard API Server v2.0")
    logger.info("=" * 50)
    logger.info("API available at http://localhost:5000")
    logger.info("")
    logger.info("Public Endpoints:")
    logger.info("  GET  /api/health       - Health check")
    logger.info("  GET  /api/stats        - Global statistics")
    logger.info("  POST /api/scan         - Scan URL/content")
    logger.info("  POST /api/verify-site  - Deep site verification")
    logger.info("  POST /api/batch-scan   - Batch URL scan")
    logger.info("")
    logger.info("Auth Endpoints:")
    logger.info("  POST /api/auth/register - Register user")
    logger.info("  POST /api/auth/login    - Login user")
    logger.info("  GET  /api/auth/me       - Get current user")
    logger.info("")
    logger.info("Protected Endpoints (require X-API-Key header):")
    logger.info("  GET/PUT  /api/settings  - User settings")
    logger.info("  GET/POST /api/whitelist - Whitelist management")
    logger.info("  GET/POST /api/blacklist - Blacklist management")
    logger.info("  GET      /api/history   - Scan history")
    logger.info("  GET      /api/stats/user- User statistics")
    logger.info("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
