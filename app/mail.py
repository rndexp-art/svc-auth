"""Tiny SMTP mailer.

When SMTP is unconfigured (no AUTH_SMTP_HOST), this module logs the message
to stderr and returns `MailResult(sent=False, ...)` rather than raising. The
caller is expected to surface the link to the admin UI in that case so an
operator can copy/paste it manually. This keeps the dashboard's "invite" and
"reset password" flows working end-to-end before SMTP is wired up.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

log = logging.getLogger("rndexp_auth.mail")


@dataclass(frozen=True)
class MailResult:
    sent: bool
    reason: str = ""


def smtp_configured() -> bool:
    return bool(os.environ.get("AUTH_SMTP_HOST"))


def _from_address() -> str:
    return os.environ.get("AUTH_SMTP_FROM") or "no-reply@rndexp.art"


def send(to: str, subject: str, body_text: str, body_html: str | None = None) -> MailResult:
    """Send an email. Returns MailResult — never raises on transport errors,
    so the caller can decide how to communicate failure to the user.
    """
    if not smtp_configured():
        log.warning(
            "SMTP not configured; dropping mail to %s (subject=%r). Body:\n%s",
            to, subject, body_text,
        )
        return MailResult(sent=False, reason="smtp_not_configured")

    msg = EmailMessage()
    msg["From"] = _from_address()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    host = os.environ["AUTH_SMTP_HOST"]
    port = int(os.environ.get("AUTH_SMTP_PORT", "587"))
    user = os.environ.get("AUTH_SMTP_USER")
    password = os.environ.get("AUTH_SMTP_PASSWORD")
    use_tls = os.environ.get("AUTH_SMTP_TLS", "starttls").lower()
    timeout = int(os.environ.get("AUTH_SMTP_TIMEOUT", "10"))

    try:
        ctx = ssl.create_default_context()
        if use_tls == "ssl":
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx) as s:
                if user and password:
                    s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as s:
                if use_tls == "starttls":
                    s.starttls(context=ctx)
                if user and password:
                    s.login(user, password)
                s.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        log.exception("SMTP send to %s failed: %s", to, e)
        return MailResult(sent=False, reason=f"smtp_error:{type(e).__name__}")

    return MailResult(sent=True)
