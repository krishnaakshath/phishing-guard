import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import notifications


def test_send_email_skips_when_not_configured():
    with patch.object(notifications, 'SMTP_HOST', None):
        result = notifications.send_email('user@example.com', 'subject', 'body')
    assert result is False


def test_send_email_sends_when_configured():
    with patch.object(notifications, 'SMTP_HOST', 'smtp.example.com'), \
         patch.object(notifications, 'SMTP_USER', 'bot@example.com'), \
         patch.object(notifications, 'SMTP_PASSWORD', 'secret'), \
         patch.object(notifications, 'SMTP_FROM', 'bot@example.com'):

        mock_server = MagicMock()
        mock_smtp_cm = MagicMock()
        mock_smtp_cm.__enter__.return_value = mock_server
        with patch('notifications.smtplib.SMTP', return_value=mock_smtp_cm):
            result = notifications.send_email('user@example.com', 'subject', 'body')

    assert result is True
    mock_server.login.assert_called_once_with('bot@example.com', 'secret')
    mock_server.sendmail.assert_called_once()


def test_send_email_returns_false_on_smtp_error():
    with patch.object(notifications, 'SMTP_HOST', 'smtp.example.com'), \
         patch.object(notifications, 'SMTP_USER', 'bot@example.com'), \
         patch.object(notifications, 'SMTP_PASSWORD', 'secret'):
        with patch('notifications.smtplib.SMTP', side_effect=Exception('connection refused')):
            result = notifications.send_email('user@example.com', 'subject', 'body')
    assert result is False


def test_notify_whitelisted_domain_reported_includes_domain_in_subject():
    with patch('notifications.send_email', return_value=True) as mock_send:
        notifications.notify_whitelisted_domain_reported('user@example.com', 'evil.example.com')

    args, _ = mock_send.call_args
    assert args[0] == 'user@example.com'
    assert 'evil.example.com' in args[1]
