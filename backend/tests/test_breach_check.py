import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import breach_check


def test_check_password_breach_detects_known_hash_suffix():
    # sha1('password123') = CBFDAC6008F9CAB4083784CBD1874F76618D2A97
    # prefix = CBFDA, suffix = C6008F9CAB4083784CBD1874F76618D2A97
    fake_response_body = "C6008F9CAB4083784CBD1874F76618D2A97:12345\nOTHERSUFFIX00000000000000000000:1"
    mock_resp = MagicMock()
    mock_resp.text = fake_response_body
    mock_resp.raise_for_status.return_value = None

    with patch('breach_check.requests.get', return_value=mock_resp):
        result = breach_check.check_password_breach('password123')

    assert result['breached'] is True
    assert result['count'] == 12345


def test_check_password_breach_not_found():
    mock_resp = MagicMock()
    mock_resp.text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"
    mock_resp.raise_for_status.return_value = None

    with patch('breach_check.requests.get', return_value=mock_resp):
        result = breach_check.check_password_breach('some-unique-password-that-hashes-elsewhere')

    assert result['breached'] is False
    assert result['count'] == 0


def test_check_password_breach_handles_network_error():
    with patch('breach_check.requests.get', side_effect=Exception('timeout')):
        result = breach_check.check_password_breach('anything')

    assert result['breached'] is False
    assert 'error' in result


def test_check_password_breach_empty_password():
    result = breach_check.check_password_breach('')
    assert result['breached'] is False
    assert 'error' in result
