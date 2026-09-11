import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import security_grade


def _mock_response(headers, url='https://example.com', set_cookie=None):
    resp = MagicMock()
    resp.headers = headers
    resp.url = url
    resp.raw.headers.getlist.return_value = set_cookie or []
    return resp


def test_full_marks_for_all_good_headers_and_cookies():
    headers = {
        'Strict-Transport-Security': 'max-age=63072000',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
    }
    resp = _mock_response(headers, set_cookie=['session=abc; Secure; HttpOnly'])

    with patch('security_grade.requests.get', return_value=resp):
        result = security_grade.grade_site('https://example.com')

    assert result['grade'] == 'A'
    assert result['score'] == 100
    assert result['header_findings'] == []


def test_missing_everything_grades_f():
    resp = _mock_response({}, url='http://example.com')

    with patch('security_grade.requests.get', return_value=resp):
        result = security_grade.grade_site('http://example.com')

    assert result['grade'] == 'F'
    assert 'Site is not served over HTTPS at all' in result['tls_findings']
    assert len(result['header_findings']) == len(security_grade.HEADER_CHECKS)


def test_unreachable_site_returns_f_with_explanation():
    with patch('security_grade.requests.get', side_effect=Exception('connection refused')):
        result = security_grade.grade_site('https://does-not-resolve.invalid')

    assert result['grade'] == 'F'
    assert result['score'] == 0
    assert 'connection refused' in result['header_findings'][0]


def test_cookie_without_secure_flag_flagged():
    headers = {
        'Strict-Transport-Security': 'max-age=1',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
    }
    resp = _mock_response(headers, set_cookie=['session=abc; HttpOnly'])

    with patch('security_grade.requests.get', return_value=resp):
        result = security_grade.grade_site('https://example.com')

    assert any('Secure flag' in f for f in result['cookie_findings'])
