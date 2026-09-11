"""
Threat Intelligence Module for Phishing Guard
Real-time threat intelligence, reputation scoring, and blocklist management
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta
from io import BytesIO
from typing import Dict, List, Optional, Tuple
import re
import socket
import ssl
import requests
from urllib.parse import urlparse

import imagehash
from PIL import Image

import cache

logger = logging.getLogger(__name__)

# Optional external feeds. Both are safe to leave unconfigured/unreachable -
# every call site here degrades to "no signal" rather than raising, so a
# missing API key or a feed outage never breaks a scan.
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
SAFE_BROWSING_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt'
DOMAIN_INTEL_CACHE_TTL = 24 * 3600
OPENPHISH_FEED_CACHE_TTL = 6 * 3600


def check_safe_browsing(url: str) -> Optional[Dict]:
    """
    Check a URL against Google Safe Browsing v4.
    Returns None (no signal) if no API key is configured or the request fails.
    """
    if not SAFE_BROWSING_API_KEY:
        return None

    payload = {
        'client': {'clientId': 'phishing-guard', 'clientVersion': '3.0.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                             'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }

    try:
        resp = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={'key': SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=4
        )
        resp.raise_for_status()
        matches = resp.json().get('matches', [])
        return {
            'flagged': len(matches) > 0,
            'threat_types': [m.get('threatType') for m in matches]
        }
    except Exception as e:
        logger.warning(f"Safe Browsing check failed: {e}")
        return None


def _get_openphish_feed() -> set:
    """Fetch (or return cached) OpenPhish community feed as a set of URLs."""
    cached = cache.get_cached('openphish_feed', OPENPHISH_FEED_CACHE_TTL)
    if cached is not None:
        return set(cached['urls'])

    try:
        resp = requests.get(OPENPHISH_FEED_URL, timeout=5)
        resp.raise_for_status()
        urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
        cache.set_cached('openphish_feed', {'urls': urls})
        return set(urls)
    except Exception as e:
        logger.warning(f"OpenPhish feed fetch failed: {e}")
        return set()


def check_openphish(url: str) -> bool:
    """Check a URL against the cached OpenPhish community feed."""
    feed = _get_openphish_feed()
    return url in feed or url.rstrip('/') in feed


# Perceptual-hash-based favicon impersonation check. KNOWN_FAVICON_HASHES is
# static data checked into the repo (see scripts/generate_favicon_hashes.py)
# - real pHashes fetched from each brand's actual live favicon, not
# fabricated. Distance <= FAVICON_HASH_THRESHOLD is treated as "visually
# the same icon" (pHash literature typically uses ~10 as the same-image
# cutoff for a 64-bit hash; 10 is intentionally conservative here to avoid
# false positives on legitimately similar-but-different icons).
FAVICON_HASH_THRESHOLD = 10
_KNOWN_FAVICONS_PATH = os.path.join(os.path.dirname(__file__), 'known_favicons.json')


def _load_known_favicon_hashes() -> Dict[str, 'imagehash.ImageHash']:
    try:
        with open(_KNOWN_FAVICONS_PATH) as f:
            raw = json.load(f)
        return {domain: imagehash.hex_to_hash(hex_hash) for domain, hex_hash in raw.items()}
    except Exception as e:
        logger.warning(f"Could not load known_favicons.json: {e}")
        return {}


KNOWN_FAVICON_HASHES = _load_known_favicon_hashes()


def check_favicon_hash(domain: str) -> Optional[Dict]:
    """
    Fetch a domain's favicon and compare it against a small set of known
    brand favicon hashes. Flags likely impersonation: a site whose icon is
    visually identical to a trusted brand's icon, but isn't that brand's
    own domain. Returns None (no signal) on any failure - a missing or
    unparseable favicon is common and not itself suspicious.
    """
    if not KNOWN_FAVICON_HASHES or domain in KNOWN_FAVICON_HASHES:
        return None

    try:
        resp = requests.get(f'https://{domain}/favicon.ico', timeout=5,
                             headers={'User-Agent': 'Mozilla/5.0 (PhishingGuard)'})
        resp.raise_for_status()
        target_hash = imagehash.phash(Image.open(BytesIO(resp.content)))
    except Exception:
        return None

    best_match, best_distance = None, None
    for brand_domain, brand_hash in KNOWN_FAVICON_HASHES.items():
        distance = target_hash - brand_hash
        if best_distance is None or distance < best_distance:
            best_match, best_distance = brand_domain, distance

    if best_match is not None and best_distance <= FAVICON_HASH_THRESHOLD:
        return {
            'impersonating': best_match,
            'distance': int(best_distance)
        }

    return None

# ============================================
# THREAT INTELLIGENCE DATABASES
# ============================================

# Known phishing domains (expanded list)
KNOWN_PHISHING_PATTERNS = [
    r'.*-login.*\..*',
    r'.*login-.*\..*',
    r'.*secure-.*\..*',
    r'.*-secure.*\..*',
    r'.*verify-.*\..*',
    r'.*-verify.*\..*',
    r'.*update-.*\..*',
    r'.*-update.*\..*',
    r'.*account-.*\..*',
    r'.*-account.*\..*',
    r'.*signin-.*\..*',
    r'.*-signin.*\..*',
]

# Malicious script patterns
MALICIOUS_SCRIPT_PATTERNS = {
    'crypto_miner': [
        r'coinhive',
        r'cryptonight',
        r'coin-hive',
        r'minero\.cc',
        r'webminepool',
        r'cryptoloot',
        r'deepminer',
        r'monerominer',
    ],
    'keylogger': [
        r'keylog',
        r'keystroke',
        r'onkeypress.*send',
        r'onkeydown.*post',
        r'keyboard.*capture',
        r'addEventListener.*keydown.*XMLHttpRequest',
    ],
    'credential_stealer': [
        r'password.*exfil',
        r'formgrabber',
        r'form.*hijack',
        r'credential.*harvest',
        r'phish.*kit',
    ],
    'drive_by_download': [
        r'auto.*download',
        r'silent.*install',
        r'exploit.*kit',
        r'browser.*exploit',
        r'\.exe.*download.*hidden',
    ],
    'obfuscation': [
        r'eval\s*\(\s*atob',
        r'eval\s*\(\s*unescape',
        r'String\.fromCharCode.*eval',
        r'\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*eval',
        r'document\.write\s*\(\s*unescape',
    ]
}

# Suspicious form action patterns
SUSPICIOUS_FORM_PATTERNS = [
    r'action=["\']https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
    r'action=["\']https?://[^"\']*\.tk[/"\']',
    r'action=["\']https?://[^"\']*\.ml[/"\']',
    r'action=["\']https?://[^"\']*\.ga[/"\']',
    r'action=["\']https?://[^"\']*\.cf[/"\']',
    r'action=["\']https?://[^"\']*\.gq[/"\']',
]

# Data exfiltration patterns
EXFILTRATION_PATTERNS = [
    r'btoa\s*\(\s*.*password',
    r'encodeURIComponent\s*\(\s*.*password',
    r'\.src\s*=.*\?.*password',
    r'new\s+Image\(\)\.src.*password',
    r'fetch\s*\(.*password',
    r'XMLHttpRequest.*password',
]


class ThreatIntelligence:
    """Real-time threat intelligence engine"""
    
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        self.custom_whitelist = set()
        self.custom_blacklist = set()
        
    def check_domain_reputation(self, domain: str) -> Dict:
        """
        Check domain reputation using multiple sources
        Returns comprehensive threat assessment
        """
        cache_key = f"reputation:{domain}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached['timestamp'] < self.cache_ttl:
                return cached['data']
        
        result = {
            'domain': domain,
            'reputation_score': 100,  # Start with max score
            'risk_factors': [],
            'is_malicious': False,
            'threat_types': [],
            'checks_performed': []
        }
        
        # Check custom lists first
        if domain in self.custom_whitelist:
            result['checks_performed'].append('custom_whitelist')
            result['reputation_score'] = 100
            return result
            
        if domain in self.custom_blacklist:
            result['checks_performed'].append('custom_blacklist')
            result['is_malicious'] = True
            result['reputation_score'] = 0
            result['risk_factors'].append('Domain is in custom blacklist')
            return result
        
        # Check against known phishing patterns
        for pattern in KNOWN_PHISHING_PATTERNS:
            if re.match(pattern, domain, re.IGNORECASE):
                result['risk_factors'].append('Matches known phishing URL pattern')
                result['reputation_score'] -= 40
                result['threat_types'].append('phishing_pattern')
                break
        
        result['checks_performed'].append('pattern_matching')

        # Check domain age if possible (cached - WHOIS lookups are slow and
        # often rate-limited, and this runs on every page navigation)
        cache_key = f"domain_age:{domain}"
        age_result = cache.get_cached(cache_key, DOMAIN_INTEL_CACHE_TTL)
        if age_result is None:
            age_result = self._check_domain_age(domain) or {}
            cache.set_cached(cache_key, age_result)
        if age_result:
            result['domain_age_days'] = age_result.get('age_days')
            if age_result.get('age_days', 365) < 30:
                result['risk_factors'].append(f"Domain is only {age_result.get('age_days')} days old")
                result['reputation_score'] -= 25
                result['threat_types'].append('new_domain')
            result['checks_performed'].append('domain_age')

        # Check SSL certificate (also cached - opens a live socket otherwise)
        ssl_cache_key = f"ssl_cert:{domain}"
        ssl_result = cache.get_cached(ssl_cache_key, DOMAIN_INTEL_CACHE_TTL)
        if ssl_result is None:
            ssl_result = self._check_ssl_certificate(domain) or {}
            cache.set_cached(ssl_cache_key, ssl_result)
        if ssl_result:
            result['ssl_info'] = ssl_result
            # Only penalize for actual verification failures, not connection errors
            if ssl_result.get('valid') == False:
                result['risk_factors'].append('Invalid or expired SSL certificate')
                result['reputation_score'] -= 30
                result['threat_types'].append('ssl_issue')
            elif ssl_result.get('valid') == True and ssl_result.get('days_until_expiry', 365) < 7:
                result['risk_factors'].append('SSL certificate expiring soon')
                result['reputation_score'] -= 10
            result['checks_performed'].append('ssl_check')
        
        # Determine if malicious based on score
        result['reputation_score'] = max(0, result['reputation_score'])
        if result['reputation_score'] < 40:
            result['is_malicious'] = True
        
        # Cache result
        self.cache[cache_key] = {
            'data': result,
            'timestamp': time.time()
        }
        
        return result
    
    def _check_domain_age(self, domain: str) -> Optional[Dict]:
        """Check domain registration age via WHOIS"""
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                age_days = (datetime.now() - creation).days
                return {
                    'age_days': age_days,
                    'created': creation.isoformat() if creation else None,
                    'registrar': w.registrar
                }
        except Exception:
            pass
        return None
    
    def _check_ssl_certificate(self, domain: str) -> Optional[Dict]:
        """Check SSL certificate validity and details"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': not_after.isoformat(),
                        'days_until_expiry': days_until_expiry
                    }
        except ssl.SSLCertVerificationError as e:
            # Check if it's a system-level issue (missing root certs)
            if 'unable to get local issuer certificate' in str(e):
                # This is a system config issue, not the domain's fault
                return {'valid': None, 'error': 'System SSL config issue - skipped'}
            return {'valid': False, 'error': 'Certificate verification failed'}
        except Exception as e:
            return {'valid': None, 'error': str(e)}
    
    def analyze_page_content(self, content: str) -> Dict:
        """
        Analyze page content for malicious scripts and patterns
        """
        result = {
            'threats_detected': [],
            'risk_score': 0,
            'is_malicious': False,
            'details': {}
        }
        
        if not content:
            return result
        
        content_lower = content.lower()
        
        # Check for malicious script patterns
        for threat_type, patterns in MALICIOUS_SCRIPT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    result['threats_detected'].append({
                        'type': threat_type,
                        'pattern': pattern,
                        'severity': 'high' if threat_type in ['keylogger', 'credential_stealer'] else 'medium'
                    })
                    result['risk_score'] += 30
                    break
        
        # Check for data exfiltration patterns
        for pattern in EXFILTRATION_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                result['threats_detected'].append({
                    'type': 'data_exfiltration',
                    'pattern': pattern,
                    'severity': 'critical'
                })
                result['risk_score'] += 40
                break
        
        # Check for suspicious form actions
        for pattern in SUSPICIOUS_FORM_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                result['threats_detected'].append({
                    'type': 'suspicious_form',
                    'pattern': pattern,
                    'severity': 'high'
                })
                result['risk_score'] += 35
                break
        
        # Check for hidden credential fields
        hidden_password = re.search(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'].*(?:pass|pwd|password)',
            content_lower
        )
        if hidden_password:
            result['threats_detected'].append({
                'type': 'hidden_credential_field',
                'severity': 'critical'
            })
            result['risk_score'] += 50
        
        # Check for fake login forms
        if self._detect_fake_login_form(content):
            result['threats_detected'].append({
                'type': 'fake_login_form',
                'severity': 'high'
            })
            result['risk_score'] += 35
        
        # Normalize score
        result['risk_score'] = min(100, result['risk_score'])
        result['is_malicious'] = result['risk_score'] >= 50 or len(result['threats_detected']) >= 2
        
        return result
    
    def _detect_fake_login_form(self, content: str) -> bool:
        """Detect characteristics of fake login forms"""
        indicators = 0
        content_lower = content.lower()
        
        # Multiple brand mentions in one page
        brands = ['google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal', 'netflix']
        brand_count = sum(1 for brand in brands if brand in content_lower)
        if brand_count >= 2:
            indicators += 1
        
        # Password field without proper autocomplete
        if re.search(r'<input[^>]*type=["\']password["\'][^>]*(?!autocomplete)', content_lower):
            indicators += 1
        
        # Form without action or with javascript action
        if re.search(r'<form[^>]*action=["\']javascript:', content_lower):
            indicators += 1
        
        # Urgent language
        urgent_phrases = ['urgent', 'immediate', 'suspended', 'verify now', 'act now', 'limited time']
        if any(phrase in content_lower for phrase in urgent_phrases):
            indicators += 1
        
        return indicators >= 2
    
    def check_url_safety(self, url: str) -> Dict:
        """
        Comprehensive URL safety check
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Get domain reputation
            reputation = self.check_domain_reputation(domain)

            # Cross-check against external threat feeds. These are keyed on
            # the full URL (not just domain) and never raise - a missing key
            # or an unreachable feed just means "no additional signal".
            sb_result = check_safe_browsing(url)
            if sb_result and sb_result.get('flagged'):
                reputation['risk_factors'].append('Flagged by Google Safe Browsing')
                reputation['reputation_score'] = max(0, reputation['reputation_score'] - 60)
                reputation['threat_types'].extend(sb_result.get('threat_types', []))
                reputation['checks_performed'].append('safe_browsing')

            if check_openphish(url):
                reputation['risk_factors'].append('Listed in OpenPhish community feed')
                reputation['reputation_score'] = max(0, reputation['reputation_score'] - 50)
                reputation['threat_types'].append('known_phishing_feed')
                reputation['checks_performed'].append('openphish_feed')

            favicon_cache_key = f"favicon_match:{domain}"
            favicon_result = cache.get_cached(favicon_cache_key, DOMAIN_INTEL_CACHE_TTL)
            if favicon_result is None:
                favicon_result = check_favicon_hash(domain) or {}
                cache.set_cached(favicon_cache_key, favicon_result)
            if favicon_result and favicon_result.get('impersonating'):
                reputation['risk_factors'].append(
                    f"Favicon visually matches {favicon_result['impersonating']} but domain doesn't"
                )
                reputation['reputation_score'] = max(0, reputation['reputation_score'] - 45)
                reputation['threat_types'].append('favicon_impersonation')
                reputation['checks_performed'].append('favicon_hash')

            result = {
                'url': url,
                'domain': domain,
                'is_safe': reputation['reputation_score'] >= 60,
                'reputation_score': reputation['reputation_score'],
                'risk_factors': reputation['risk_factors'],
                'threat_types': reputation['threat_types'],
                'recommendation': 'proceed' if reputation['reputation_score'] >= 60 else 'caution'
            }

            if reputation['reputation_score'] < 40:
                result['recommendation'] = 'avoid'

            return result
            
        except Exception as e:
            return {
                'url': url,
                'is_safe': False,
                'error': str(e),
                'recommendation': 'caution'
            }
    
    def add_to_whitelist(self, domain: str):
        """Add domain to custom whitelist"""
        self.custom_whitelist.add(domain.lower())
        self.custom_blacklist.discard(domain.lower())
        # Clear cache for this domain
        cache_key = f"reputation:{domain.lower()}"
        self.cache.pop(cache_key, None)
    
    def add_to_blacklist(self, domain: str):
        """Add domain to custom blacklist"""
        self.custom_blacklist.add(domain.lower())
        self.custom_whitelist.discard(domain.lower())
        # Clear cache for this domain
        cache_key = f"reputation:{domain.lower()}"
        self.cache.pop(cache_key, None)
    
    def remove_from_lists(self, domain: str):
        """Remove domain from both lists"""
        self.custom_whitelist.discard(domain.lower())
        self.custom_blacklist.discard(domain.lower())
        cache_key = f"reputation:{domain.lower()}"
        self.cache.pop(cache_key, None)
    
    def get_lists(self) -> Dict:
        """Get current whitelist and blacklist"""
        return {
            'whitelist': list(self.custom_whitelist),
            'blacklist': list(self.custom_blacklist)
        }


# Singleton instance
threat_intel = ThreatIntelligence()


def check_url(url: str) -> Dict:
    """Public function to check URL safety"""
    return threat_intel.check_url_safety(url)


def check_domain(domain: str) -> Dict:
    """Public function to check domain reputation"""
    return threat_intel.check_domain_reputation(domain)


def analyze_content(content: str) -> Dict:
    """Public function to analyze page content for threats"""
    return threat_intel.analyze_page_content(content)


def add_whitelist(domain: str):
    """Add domain to whitelist"""
    threat_intel.add_to_whitelist(domain)


def add_blacklist(domain: str):
    """Add domain to blacklist"""
    threat_intel.add_to_blacklist(domain)


def get_lists() -> Dict:
    """Get whitelist/blacklist"""
    return threat_intel.get_lists()
