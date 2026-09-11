import os
import sys
import uuid
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models
import app as app_module


def _make_user():
    email = f"{uuid.uuid4().hex}@example.com"
    return models.create_user(email, 'testpassword123')


def _client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_get_users_who_whitelisted_finds_matching_users():
    user = _make_user()
    domain = f"{uuid.uuid4().hex}.example.com"
    models.add_to_whitelist(user['id'], domain)

    matches = models.get_users_who_whitelisted(domain)
    assert any(m['email'] == user['email'] for m in matches)


def test_get_users_who_whitelisted_empty_for_unlisted_domain():
    matches = models.get_users_who_whitelisted(f"{uuid.uuid4().hex}.example.com")
    assert matches == []


def test_report_phishing_notifies_whitelisters():
    user = _make_user()
    domain = f"{uuid.uuid4().hex}.example.com"
    models.add_to_whitelist(user['id'], domain)

    client = _client()
    with patch('app.notifications.notify_whitelisted_domain_reported', return_value=True) as mock_notify:
        resp = client.post('/api/report-phishing', json={'url': f'https://{domain}/login'})

    assert resp.status_code == 200
    mock_notify.assert_called_once()
    call_args = mock_notify.call_args[0]
    assert call_args[0] == user['email']
    assert call_args[1] == domain


def test_report_phishing_survives_notification_failure():
    user = _make_user()
    domain = f"{uuid.uuid4().hex}.example.com"
    models.add_to_whitelist(user['id'], domain)

    client = _client()
    with patch('app.notifications.notify_whitelisted_domain_reported', side_effect=Exception('smtp down')):
        resp = client.post('/api/report-phishing', json={'url': f'https://{domain}/login'})

    # The report itself must still succeed even if notifying whitelisters blows up.
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
