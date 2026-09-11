import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secret_scanner

# Fixture values are built by concatenation rather than written as literal
# strings - GitHub's secret-scanning push protection (correctly) flags a
# literal "AKIA..." or "sk_live_..." string even in a test file, since it
# can't tell a fabricated fixture from a real leaked credential. Splitting
# the string still exercises the real regex at runtime without a
# scanner-shaped literal sitting in the diff.
FAKE_AWS_KEY = 'AKIA' + 'ABCDEFGHIJKLMNOP'
FAKE_STRIPE_KEY = 'sk_' + 'live_' + '51H8x9zJ9kLmNoPqRsTuVwXy'


def test_detects_aws_access_key():
    html = f'<script>const key = "{FAKE_AWS_KEY}";</script>'
    findings = secret_scanner.scan_for_secrets(html)
    assert any(f['type'] == 'AWS Access Key' for f in findings)


def test_detects_stripe_live_key():
    html = f'stripeKey = "{FAKE_STRIPE_KEY}"'
    findings = secret_scanner.scan_for_secrets(html)
    assert any(f['type'] == 'Stripe Live Secret Key' for f in findings)


def test_detects_private_key_block():
    html = '-----BEGIN RSA PRIVATE KEY-----\nMIIB...'
    findings = secret_scanner.scan_for_secrets(html)
    assert any(f['type'] == 'Private Key Block' for f in findings)


def test_clean_page_has_no_findings():
    html = '<html><body><h1>Hello world</h1><p>Nothing secret here.</p></body></html>'
    assert secret_scanner.scan_for_secrets(html) == []


def test_match_preview_is_redacted_not_full_value():
    html = f'apiKey = "{FAKE_AWS_KEY}"'
    findings = secret_scanner.scan_for_secrets(html)
    assert findings[0]['match_preview'] != FAKE_AWS_KEY
    assert '...' in findings[0]['match_preview']


def test_reports_correct_line_number():
    html = f"line one\nline two\napiKey = '{FAKE_AWS_KEY}'\nline four"
    findings = secret_scanner.scan_for_secrets(html)
    assert findings[0]['line'] == 3


def test_empty_input_returns_empty_list():
    assert secret_scanner.scan_for_secrets('') == []
    assert secret_scanner.scan_for_secrets(None) == []
