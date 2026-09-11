import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models


def _make_user():
    email = f"{uuid.uuid4().hex}@example.com"
    return models.create_user(email, 'testpassword123')


def test_default_settings_have_auto_theme_mode():
    settings = models.get_user_settings(999999999)  # no row yet - defaults path
    assert settings['preferences']['theme_mode'] == 'auto'


def test_update_settings_persists_theme_mode():
    user = _make_user()

    ok = models.update_user_settings(user['id'], {
        'protection_level': 'medium',
        'modules': {'phishing_protection': True, 'password_guard': True,
                    'payment_protection': True, 'link_scanner': True},
        'preferences': {'real_time_alerts': True, 'auto_block_dangerous': True,
                         'notification_sound': False, 'theme_mode': 'dark'}
    })
    assert ok is True

    settings = models.get_user_settings(user['id'])
    assert settings['preferences']['theme_mode'] == 'dark'


def test_update_settings_defaults_to_auto_when_theme_mode_omitted():
    user = _make_user()

    models.update_user_settings(user['id'], {
        'protection_level': 'medium',
        'modules': {'phishing_protection': True, 'password_guard': True,
                    'payment_protection': True, 'link_scanner': True},
        'preferences': {'real_time_alerts': True, 'auto_block_dangerous': True,
                         'notification_sound': False}
    })

    settings = models.get_user_settings(user['id'])
    assert settings['preferences']['theme_mode'] == 'auto'
