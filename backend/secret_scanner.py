"""
Exposed secret / API key scanner.

Scans a page's HTML (including inline and linked-then-fetched script
content) for common patterns of accidentally-shipped credentials -
the "vibe coded app ships a hardcoded API key" problem. Used by the
public Site Scanner tool, not by the always-on extension (a random
visitor doesn't need to know a site leaks its own secrets - the site
owner does).
"""

import re
from typing import Dict, List

# (type name, compiled pattern). Patterns match the *value*, not just a
# variable name, so a comment saying "apiKey" doesn't false-positive.
SECRET_PATTERNS = [
    ('AWS Access Key', re.compile(r'AKIA[0-9A-Z]{16}')),
    ('AWS Secret Key', re.compile(r'(?i)aws(.{0,20})?secret(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]')),
    ('Stripe Live Secret Key', re.compile(r'sk_live_[0-9a-zA-Z]{24,}')),
    ('Stripe Publishable Key', re.compile(r'pk_live_[0-9a-zA-Z]{24,}')),
    ('Google API Key', re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ('Slack Token', re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')),
    ('GitHub Personal Access Token', re.compile(r'gh[pousr]_[0-9A-Za-z]{36,}')),
    ('Generic Bearer/Secret Assignment', re.compile(
        r'(?i)(secret|api[_-]?key|access[_-]?token|client[_-]?secret)["\']?\s*[:=]\s*["\']'
        r'[0-9a-zA-Z\-_]{20,}["\']'
    )),
    ('Private Key Block', re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----')),
]


def scan_for_secrets(html_text: str) -> List[Dict]:
    """
    Scan raw HTML/JS text for likely-exposed secrets.
    Returns a list of {type, match_preview, line} - the match itself is
    truncated/partially redacted so the report doesn't just become a
    second copy of the leaked secret.
    """
    if not html_text:
        return []

    findings = []
    lines = html_text.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for secret_type, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(0)
            preview = value if len(value) <= 10 else f"{value[:6]}...{value[-4:]}"
            findings.append({
                'type': secret_type,
                'match_preview': preview,
                'line': line_number
            })

    return findings
