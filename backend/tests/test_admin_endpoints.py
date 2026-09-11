import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models
import app as app_module


def _make_user(is_admin=False):
    email = f"{uuid.uuid4().hex}@example.com"
    user = models.create_user(email, 'testpassword123')

    if is_admin:
        conn = models.get_db_connection()
        conn.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (user['id'],))
        conn.commit()
        conn.close()

    return user


def _client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_admin_stats_rejects_missing_api_key():
    client = _client()
    resp = client.get('/api/admin/stats')
    assert resp.status_code == 401


def test_admin_stats_rejects_non_admin_user():
    user = _make_user(is_admin=False)
    client = _client()
    resp = client.get('/api/admin/stats', headers={'X-API-Key': user['api_key']})
    assert resp.status_code == 403


def test_admin_stats_allows_admin_user():
    admin = _make_user(is_admin=True)
    client = _client()
    resp = client.get('/api/admin/stats', headers={'X-API-Key': admin['api_key']})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert 'total_users' in body['stats']


def test_admin_list_users_excludes_password_hash():
    admin = _make_user(is_admin=True)
    client = _client()
    resp = client.get('/api/admin/users', headers={'X-API-Key': admin['api_key']})
    assert resp.status_code == 200
    for user in resp.get_json()['users']:
        assert 'password_hash' not in user
        assert 'api_key' not in user


def test_admin_threat_report_lifecycle():
    admin = _make_user(is_admin=True)
    client = _client()

    domain = f"{uuid.uuid4().hex}.example.com"
    assert models.add_threat_report(domain, 'phishing', 'high') is True

    resp = client.get('/api/admin/threats', headers={'X-API-Key': admin['api_key']})
    threats = resp.get_json()['threats']
    match = next(t for t in threats if t['domain'] == domain)
    assert match['verified'] is False

    verify_resp = client.post(f"/api/admin/threats/{match['id']}/verify",
                               headers={'X-API-Key': admin['api_key']})
    assert verify_resp.status_code == 200

    delete_resp = client.delete(f"/api/admin/threats/{match['id']}",
                                 headers={'X-API-Key': admin['api_key']})
    assert delete_resp.status_code == 200

    missing_resp = client.delete(f"/api/admin/threats/{match['id']}",
                                  headers={'X-API-Key': admin['api_key']})
    assert missing_resp.status_code == 404
