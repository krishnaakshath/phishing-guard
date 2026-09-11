"""
Site security posture grading.

Grades a site's security headers, TLS setup, and cookie flags into an
A-F score, similar in spirit to Mozilla Observatory / SSL Labs but
lightweight enough to run inline. Used by /api/site-scan.
"""

import logging
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# (header name, points if present, advice if missing)
HEADER_CHECKS = [
    ('strict-transport-security', 20, 'Missing HSTS - HTTPS downgrade attacks are not prevented'),
    ('content-security-policy', 20, 'Missing Content-Security-Policy - reduces XSS protection'),
    ('x-content-type-options', 15, 'Missing X-Content-Type-Options - MIME sniffing not blocked'),
    ('x-frame-options', 15, 'Missing X-Frame-Options - page can be framed (clickjacking risk)'),
    ('referrer-policy', 10, 'Missing Referrer-Policy - full URLs may leak to third parties'),
]

# Cookie attribute checks: (attribute, points, advice if any cookie lacks it)
COOKIE_CHECKS = [
    ('secure', 10, 'Cookie set without Secure flag - can be sent over plain HTTP'),
    ('httponly', 10, 'Cookie set without HttpOnly flag - readable by page JavaScript'),
]


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return 'A'
    if score >= 75:
        return 'B'
    if score >= 60:
        return 'C'
    if score >= 40:
        return 'D'
    return 'F'


def _check_headers(headers: Dict[str, str]) -> Tuple[int, List[str]]:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    score = 0
    findings = []
    for header, points, advice in HEADER_CHECKS:
        if header in lower_headers:
            score += points
        else:
            findings.append(advice)
    return score, findings


def _check_cookies(set_cookie_headers: List[str]) -> Tuple[int, List[str]]:
    if not set_cookie_headers:
        return sum(p for _, p, _ in COOKIE_CHECKS), []

    score = 0
    findings = []
    for attribute, points, advice in COOKIE_CHECKS:
        if all(attribute in cookie.lower() for cookie in set_cookie_headers):
            score += points
        else:
            findings.append(advice)
    return score, findings


def _check_tls(scheme: str) -> Tuple[int, List[str]]:
    if scheme == 'https':
        return 10, []
    return 0, ['Site is not served over HTTPS at all']


def grade_site(url: str) -> Dict:
    """
    Fetch a URL and grade its security posture.
    Raises no exceptions to the caller for unreachable sites - returns a
    result with grade 'F' and an explanatory finding instead.
    """
    parsed = urlparse(url)

    try:
        resp = requests.get(url, timeout=6, allow_redirects=True)
    except Exception as e:
        logger.warning(f"Security grade fetch failed for {url}: {e}")
        return {
            'grade': 'F',
            'score': 0,
            'header_findings': [f'Could not reach site: {e}'],
            'tls_findings': [],
            'cookie_findings': [],
        }

    header_score, header_findings = _check_headers(resp.headers)
    tls_score, tls_findings = _check_tls(urlparse(resp.url).scheme)

    if hasattr(resp.raw, 'headers') and hasattr(resp.raw.headers, 'getlist'):
        set_cookie_headers = resp.raw.headers.getlist('Set-Cookie')
    else:
        single = resp.headers.get('Set-Cookie')
        set_cookie_headers = [single] if single else []

    cookie_score, cookie_findings = _check_cookies(set_cookie_headers)

    total_score = min(100, header_score + tls_score + cookie_score)

    return {
        'grade': _grade_from_score(total_score),
        'score': total_score,
        'header_findings': header_findings,
        'tls_findings': tls_findings,
        'cookie_findings': cookie_findings,
    }
