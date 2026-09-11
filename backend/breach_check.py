"""
Password breach checking via the Have I Been Pwned k-anonymity API.

Only the first 5 characters of the password's SHA-1 hash ever leave this
process - the full password (and even the full hash) is never sent
anywhere, including to HIBP itself.
"""

import hashlib
import logging
from typing import Dict

import requests

logger = logging.getLogger(__name__)

HIBP_RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range/'


def check_password_breach(password: str) -> Dict:
    """
    Check whether a password appears in known breach data.
    Returns {'breached': bool, 'count': int}. On any error, returns
    {'breached': False, 'count': 0, 'error': '...'} - callers should treat
    that as "couldn't check", not "confirmed safe".
    """
    if not password:
        return {'breached': False, 'count': 0, 'error': 'No password provided'}

    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(f'{HIBP_RANGE_ENDPOINT}{prefix}', timeout=5,
                             headers={'Add-Padding': 'true'})
        resp.raise_for_status()
    except Exception as e:
        logger.warning(f"HIBP breach check failed: {e}")
        return {'breached': False, 'count': 0, 'error': 'Breach check unavailable'}

    for line in resp.text.splitlines():
        parts = line.split(':')
        if len(parts) != 2:
            continue
        candidate_suffix, count = parts
        if candidate_suffix.strip() == suffix:
            return {'breached': True, 'count': int(count)}

    return {'breached': False, 'count': 0}
