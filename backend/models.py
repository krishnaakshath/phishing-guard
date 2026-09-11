"""
Database Models and User Settings for Phishing Guard
SQLite-based storage for user settings, scan history, and threat data
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import secrets

# Database path - override with DB_PATH pointing at a persistent disk mount
# in production (see render.yaml). Without this, SQLite lives on the
# container's ephemeral filesystem and every redeploy wipes all users.
DB_PATH = os.environ.get('DB_PATH') or os.path.join(os.path.dirname(__file__), 'phishing_guard.db')


def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')

    # Older databases won't have is_admin - add it if missing rather than
    # forcing everyone through a migration tool for one column.
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    if 'is_admin' not in existing_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0')
    
    # User settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            protection_level TEXT DEFAULT 'medium',
            phishing_protection BOOLEAN DEFAULT 1,
            password_guard BOOLEAN DEFAULT 1,
            payment_protection BOOLEAN DEFAULT 1,
            link_scanner BOOLEAN DEFAULT 1,
            real_time_alerts BOOLEAN DEFAULT 1,
            auto_block_dangerous BOOLEAN DEFAULT 1,
            notification_sound BOOLEAN DEFAULT 0,
            theme_mode TEXT DEFAULT 'auto',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Older databases had a boolean dark_mode column instead of the 3-state
    # theme_mode ('auto'/'light'/'dark') - add the new column if missing.
    cursor.execute("PRAGMA table_info(user_settings)")
    settings_columns = {row[1] for row in cursor.fetchall()}
    if 'theme_mode' not in settings_columns:
        cursor.execute("ALTER TABLE user_settings ADD COLUMN theme_mode TEXT DEFAULT 'auto'")
    
    # Whitelist table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, domain)
        )
    ''')
    
    # Blacklist table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT NOT NULL,
            reason TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, domain)
        )
    ''')
    
    # Scan history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            domain TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            is_phishing BOOLEAN,
            threats_detected TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Global threat database
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_database (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            threat_type TEXT,
            severity TEXT,
            reported_count INTEGER DEFAULT 1,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verified BOOLEAN DEFAULT 0
        )
    ''')
    
    # Statistics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date DATE,
            scans_count INTEGER DEFAULT 0,
            threats_blocked INTEGER DEFAULT 0,
            phishing_detected INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, date)
        )
    ''')
    
    conn.commit()
    conn.close()


# ============================================
# USER MANAGEMENT
# ============================================

def hash_password(password: str) -> str:
    """Hash password with salt"""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{hash_obj.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    try:
        salt, hash_hex = password_hash.split(':')
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hash_obj.hex() == hash_hex
    except:
        return False


def create_user(email: str, password: str) -> Optional[Dict]:
    """Create new user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        api_key = secrets.token_urlsafe(32)
        password_hash = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (email, password_hash, api_key)
            VALUES (?, ?, ?)
        ''', (email.lower(), password_hash, api_key))
        
        user_id = cursor.lastrowid
        
        # Create default settings
        cursor.execute('''
            INSERT INTO user_settings (user_id) VALUES (?)
        ''', (user_id,))
        
        conn.commit()

        return {
            'id': user_id,
            'email': email.lower(),
            'api_key': api_key,
            'is_admin': False
        }
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def authenticate_user(email: str, password: str) -> Optional[Dict]:
    """Authenticate user and return user data"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ?', (email.lower(),))
    user = cursor.fetchone()
    
    if user and verify_password(password, user['password_hash']):
        # Update last login
        cursor.execute('''
            UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
        ''', (user['id'],))
        conn.commit()
        conn.close()

        return {
            'id': user['id'],
            'email': user['email'],
            'api_key': user['api_key'],
            'is_admin': bool(user['is_admin'])
        }

    conn.close()
    return None


def get_user_by_api_key(api_key: str) -> Optional[Dict]:
    """Get user by API key"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE api_key = ?', (api_key,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return {
            'id': user['id'],
            'email': user['email'],
            'api_key': user['api_key'],
            'is_admin': bool(user['is_admin'])
        }
    return None


def add_threat_report(domain: str, threat_type: str = 'phishing', severity: str = 'medium') -> bool:
    """Record a user-submitted phishing report in the global threat database
    (upsert - repeated reports for the same domain bump reported_count
    instead of creating duplicate rows)."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO threat_database (domain, threat_type, severity, reported_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(domain) DO UPDATE SET
                reported_count = reported_count + 1,
                last_seen = CURRENT_TIMESTAMP
        ''', (domain.lower(), threat_type, severity))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding threat report: {e}")
        return False
    finally:
        conn.close()


# ============================================
# ADMIN
# ============================================

def list_all_users() -> List[Dict]:
    """List all users for the admin panel. Never includes password_hash."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT id, email, is_admin, created_at, last_login FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    conn.close()

    return [{
        'id': u['id'],
        'email': u['email'],
        'is_admin': bool(u['is_admin']),
        'created_at': u['created_at'],
        'last_login': u['last_login']
    } for u in users]


def get_global_stats() -> Dict:
    """Aggregate stats across all users for the admin overview."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as count FROM users')
    total_users = cursor.fetchone()['count']

    cursor.execute('SELECT COUNT(*) as count FROM scan_history')
    total_scans = cursor.fetchone()['count']

    cursor.execute('SELECT COUNT(*) as count FROM scan_history WHERE is_phishing = 1')
    total_threats = cursor.fetchone()['count']

    cursor.execute('SELECT COUNT(*) as count FROM threat_database WHERE verified = 0')
    reports_pending = cursor.fetchone()['count']

    conn.close()

    return {
        'total_users': total_users,
        'total_scans': total_scans,
        'total_threats': total_threats,
        'reports_pending': reports_pending
    }


def list_threat_reports() -> List[Dict]:
    """List all entries in the global threat database for moderation."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, domain, threat_type, severity, reported_count, verified, first_seen, last_seen
        FROM threat_database ORDER BY last_seen DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    return [{
        'id': r['id'],
        'domain': r['domain'],
        'threat_type': r['threat_type'],
        'severity': r['severity'],
        'reported_count': r['reported_count'],
        'verified': bool(r['verified']),
        'first_seen': r['first_seen'],
        'last_seen': r['last_seen']
    } for r in rows]


def verify_threat_report(report_id: int) -> bool:
    """Mark a threat database entry as verified by an admin."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE threat_database SET verified = 1 WHERE id = ?', (report_id,))
    conn.commit()
    changed = cursor.rowcount > 0
    conn.close()
    return changed


def delete_threat_report(report_id: int) -> bool:
    """Remove a threat database entry (e.g. a false positive report)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM threat_database WHERE id = ?', (report_id,))
    conn.commit()
    changed = cursor.rowcount > 0
    conn.close()
    return changed


# ============================================
# USER SETTINGS
# ============================================

def get_user_settings(user_id: int) -> Dict:
    """Get user settings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM user_settings WHERE user_id = ?', (user_id,))
    settings = cursor.fetchone()
    conn.close()
    
    if settings:
        return {
            'protection_level': settings['protection_level'],
            'modules': {
                'phishing_protection': bool(settings['phishing_protection']),
                'password_guard': bool(settings['password_guard']),
                'payment_protection': bool(settings['payment_protection']),
                'link_scanner': bool(settings['link_scanner'])
            },
            'preferences': {
                'real_time_alerts': bool(settings['real_time_alerts']),
                'auto_block_dangerous': bool(settings['auto_block_dangerous']),
                'notification_sound': bool(settings['notification_sound']),
                'theme_mode': settings['theme_mode'] or 'auto'
            }
        }

    # Return defaults
    return {
        'protection_level': 'medium',
        'modules': {
            'phishing_protection': True,
            'password_guard': True,
            'payment_protection': True,
            'link_scanner': True
        },
        'preferences': {
            'real_time_alerts': True,
            'auto_block_dangerous': True,
            'notification_sound': False,
            'theme_mode': 'auto'
        }
    }


def update_user_settings(user_id: int, settings: Dict) -> bool:
    """Update user settings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        modules = settings.get('modules', {})
        preferences = settings.get('preferences', {})
        
        cursor.execute('''
            INSERT INTO user_settings (user_id, protection_level,
                phishing_protection, password_guard, payment_protection, link_scanner,
                real_time_alerts, auto_block_dangerous, notification_sound, theme_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                protection_level = excluded.protection_level,
                phishing_protection = excluded.phishing_protection,
                password_guard = excluded.password_guard,
                payment_protection = excluded.payment_protection,
                link_scanner = excluded.link_scanner,
                real_time_alerts = excluded.real_time_alerts,
                auto_block_dangerous = excluded.auto_block_dangerous,
                notification_sound = excluded.notification_sound,
                theme_mode = excluded.theme_mode,
                updated_at = CURRENT_TIMESTAMP
        ''', (
            user_id,
            settings.get('protection_level', 'medium'),
            modules.get('phishing_protection', True),
            modules.get('password_guard', True),
            modules.get('payment_protection', True),
            modules.get('link_scanner', True),
            preferences.get('real_time_alerts', True),
            preferences.get('auto_block_dangerous', True),
            preferences.get('notification_sound', False),
            preferences.get('theme_mode', 'auto')
        ))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating settings: {e}")
        return False
    finally:
        conn.close()


# ============================================
# WHITELIST / BLACKLIST
# ============================================

def get_whitelist(user_id: int = None) -> List[Dict]:
    """Get whitelist for user or global"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute('SELECT * FROM whitelist WHERE user_id = ? ORDER BY added_at DESC', (user_id,))
    else:
        cursor.execute('SELECT * FROM whitelist ORDER BY added_at DESC')
    
    items = cursor.fetchall()
    conn.close()
    
    return [{'domain': item['domain'], 'added_at': item['added_at'], 'notes': item['notes']} for item in items]


def add_to_whitelist(user_id: int, domain: str, notes: str = None) -> bool:
    """Add domain to whitelist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Remove from blacklist if present
        cursor.execute('DELETE FROM blacklist WHERE user_id = ? AND domain = ?', (user_id, domain.lower()))
        
        cursor.execute('''
            INSERT INTO whitelist (user_id, domain, notes)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, domain) DO UPDATE SET notes = excluded.notes
        ''', (user_id, domain.lower(), notes))
        
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()


def remove_from_whitelist(user_id: int, domain: str) -> bool:
    """Remove domain from whitelist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM whitelist WHERE user_id = ? AND domain = ?', (user_id, domain.lower()))
    conn.commit()
    conn.close()
    return True


def get_users_who_whitelisted(domain: str) -> List[Dict]:
    """Find users who whitelisted a domain - used to notify them if it's
    later reported as phishing (see notifications.py)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT users.id, users.email
        FROM whitelist
        JOIN users ON users.id = whitelist.user_id
        WHERE whitelist.domain = ?
    ''', (domain.lower(),))
    rows = cursor.fetchall()
    conn.close()
    return [{'id': r['id'], 'email': r['email']} for r in rows]


def get_blacklist(user_id: int = None) -> List[Dict]:
    """Get blacklist for user or global"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute('SELECT * FROM blacklist WHERE user_id = ? ORDER BY added_at DESC', (user_id,))
    else:
        cursor.execute('SELECT * FROM blacklist ORDER BY added_at DESC')
    
    items = cursor.fetchall()
    conn.close()
    
    return [{'domain': item['domain'], 'added_at': item['added_at'], 'reason': item['reason']} for item in items]


def add_to_blacklist(user_id: int, domain: str, reason: str = None) -> bool:
    """Add domain to blacklist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Remove from whitelist if present
        cursor.execute('DELETE FROM whitelist WHERE user_id = ? AND domain = ?', (user_id, domain.lower()))
        
        cursor.execute('''
            INSERT INTO blacklist (user_id, domain, reason)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, domain) DO UPDATE SET reason = excluded.reason
        ''', (user_id, domain.lower(), reason))
        
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()


def remove_from_blacklist(user_id: int, domain: str) -> bool:
    """Remove domain from blacklist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM blacklist WHERE user_id = ? AND domain = ?', (user_id, domain.lower()))
    conn.commit()
    conn.close()
    return True


# ============================================
# SCAN HISTORY & STATISTICS
# ============================================

def add_scan_record(user_id: int, url: str, result: Dict) -> bool:
    """Add scan to history"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        cursor.execute('''
            INSERT INTO scan_history (user_id, url, domain, risk_score, risk_level, is_phishing, threats_detected)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            url,
            domain,
            result.get('risk_score', 0),
            result.get('risk_level', 'unknown'),
            result.get('is_phishing', False),
            json.dumps(result.get('warnings', []))
        ))
        
        # Update daily statistics
        today = datetime.now().date().isoformat()
        cursor.execute('''
            INSERT INTO statistics (user_id, date, scans_count, threats_blocked, phishing_detected)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(user_id, date) DO UPDATE SET
                scans_count = scans_count + 1,
                threats_blocked = threats_blocked + excluded.threats_blocked,
                phishing_detected = phishing_detected + excluded.phishing_detected
        ''', (
            user_id,
            today,
            1 if result.get('is_phishing') else 0,
            1 if result.get('is_phishing') else 0
        ))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding scan record: {e}")
        return False
    finally:
        conn.close()


def get_scan_history(user_id: int, limit: int = 50) -> List[Dict]:
    """Get scan history for user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM scan_history 
        WHERE user_id = ? 
        ORDER BY scanned_at DESC 
        LIMIT ?
    ''', (user_id, limit))
    
    items = cursor.fetchall()
    conn.close()
    
    return [{
        'url': item['url'],
        'domain': item['domain'],
        'risk_score': item['risk_score'],
        'risk_level': item['risk_level'],
        'is_phishing': bool(item['is_phishing']),
        'threats': json.loads(item['threats_detected']) if item['threats_detected'] else [],
        'scanned_at': item['scanned_at']
    } for item in items]


def get_user_statistics(user_id: int, days: int = 30) -> Dict:
    """Get user statistics for the past N days"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            SUM(scans_count) as total_scans,
            SUM(threats_blocked) as total_threats,
            SUM(phishing_detected) as total_phishing
        FROM statistics 
        WHERE user_id = ? 
        AND date >= date('now', ?)
    ''', (user_id, f'-{days} days'))
    
    totals = cursor.fetchone()
    
    # Daily breakdown
    cursor.execute('''
        SELECT date, scans_count, threats_blocked, phishing_detected
        FROM statistics 
        WHERE user_id = ? 
        AND date >= date('now', ?)
        ORDER BY date DESC
    ''', (user_id, f'-{days} days'))
    
    daily = cursor.fetchall()
    conn.close()
    
    return {
        'totals': {
            'scans': totals['total_scans'] or 0,
            'threats_blocked': totals['total_threats'] or 0,
            'phishing_detected': totals['total_phishing'] or 0
        },
        'daily': [{
            'date': item['date'],
            'scans': item['scans_count'],
            'threats': item['threats_blocked'],
            'phishing': item['phishing_detected']
        } for item in daily]
    }


# Initialize database on module load
init_database()
