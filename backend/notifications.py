"""
Email notifications via SMTP.

Optional, like the Safe Browsing integration - if SMTP isn't configured,
send_email() logs and returns False instead of raising. Nothing in the
app depends on email actually being deliverable.
"""

import logging
import os
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

SMTP_HOST = os.environ.get('SMTP_HOST')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SMTP_FROM = os.environ.get('SMTP_FROM') or SMTP_USER


def is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)


def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Send a plain-text email. Returns True on success, False if SMTP isn't
    configured or the send failed - callers should treat both as "the
    notification didn't go out" and continue, never as a reason to fail
    the request that triggered it.
    """
    if not is_configured():
        logger.info(f"SMTP not configured - skipping email to {to_email}: {subject}")
        return False

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = to_email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return True
    except Exception as e:
        logger.warning(f"Failed to send email to {to_email}: {e}")
        return False


def notify_whitelisted_domain_reported(to_email: str, domain: str) -> bool:
    subject = f"Phishing Guard: a site you trusted was just reported - {domain}"
    body = (
        f"Hi,\n\n"
        f"You previously added {domain} to your Phishing Guard whitelist. "
        f"Someone has just reported this domain as phishing.\n\n"
        f"We recommend reviewing this site before trusting it again - you can "
        f"remove it from your whitelist from the Phishing Guard dashboard.\n\n"
        f"This is an automated notification. If you believe this report is "
        f"mistaken, no action is needed - reports are reviewed before being "
        f"treated as confirmed threats.\n\n"
        f"- Phishing Guard"
    )
    return send_email(to_email, subject, body)
