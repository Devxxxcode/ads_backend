import logging
import os
import time

import resend
from django.conf import settings

logger = logging.getLogger(__name__)

RESEND_API_KEY = os.getenv(
    "RESEND_API_KEY",
    getattr(settings, "RESEND_API_KEY", ""),
).strip()
RESEND_FROM_EMAIL = os.getenv(
    "RESEND_FROM_EMAIL",
    getattr(settings, "RESEND_FROM_EMAIL", "ho_reply@adsterra-opt.com"),
).strip()
RESEND_FROM_NAME = os.getenv(
    "RESEND_FROM_NAME",
    getattr(settings, "RESEND_FROM_NAME", "no_reply@adsterra-opt.com"),
).strip()
def _format_from_address() -> str:
    if RESEND_FROM_NAME:
        return f"{RESEND_FROM_NAME} <{RESEND_FROM_EMAIL}>"
    return RESEND_FROM_EMAIL


def _send_resend_email(to_email, subject, text, username=None):
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY is not configured")

    resend.api_key = RESEND_API_KEY
    params = {
        "from": _format_from_address(),
        "to": [to_email],
        "subject": subject,
        "text": text,
    }

    print(
        f"RESEND_CALL: to={to_email} from={params['from']!r} subject={subject!r}"
        + (f" username={username}" if username else "")
    )
    logger.info(
        "Sending mail via Resend to=%s from=%s subject=%s username=%s",
        to_email,
        params["from"],
        subject,
        username,
    )

    response = resend.Emails.send(params)
    print(f"RESEND_RESPONSE: to={to_email} response={response}")
    logger.info("Resend response for %s: %s", to_email, response)

    return True


def send_otp_via_service(email, otp_code):
    """Send OTP email directly through Resend."""
    safe_otp = str(otp_code).strip()[:6]
    subject = "Email Verification Code - Adsterra Opt"
    message = (
        "Dear User,\n\n"
        "Thank you for registering with Adsterra Opt. To complete your account verification, "
        f"please use the following verification code:\n\nVerification Code: {safe_otp}\n\n"
        f"This code will expire in {getattr(settings, 'OTP_EXPIRY_MINUTES', 10)} minutes for security purposes.\n\n"
        "If you did not request this verification code, please ignore this email and do not share this code with anyone.\n\n"
        "For security reasons, never share your verification code with others.\n\n"
        "Best regards,\nAdsterra Opt Support Team\nWebsite: adsterra-opt.com\n"
    )

    max_retries = 3
    retry_delay = 1

    for attempt in range(1, max_retries + 1):
        try:
            print(f"RESEND_SEND_OTP_ATTEMPT: email={email} attempt={attempt}")
            return _send_resend_email(
                to_email=email,
                subject=subject,
                text=message,
            )
        except Exception as e:
            print(f"RESEND_SEND_OTP_ERROR: email={email} attempt={attempt} error={e}")
            logger.error("Resend OTP send failed for %s: %s", email, str(e))
            if attempt == max_retries:
                return False
            time.sleep(retry_delay)
            retry_delay *= 2

    return False


def send_welcome_via_service(email, username):
    """Send welcome email directly through Resend."""
    subject = "Welcome to Adsterra Opt - Account Created Successfully"
    message = (
        f"Dear {username},\n\n"
        "Welcome to Adsterra Opt! Your account has been successfully created and verified.\n\n"
        "Account Information:\n"
        f"- Username: {username}\n"
        f"- Email Address: {email}\n\n"
        "Your account is now active and you can:\n\n"
        "1. Access your personal dashboard\n"
        "2. Start using our platform features\n"
        "3. Explore available opportunities\n"
        "4. Manage your account settings\n\n"
        "If you have any questions or need assistance, please contact our support team.\n\n"
        "Thank you for choosing Adsterra Opt!\n\n"
        "Best regards,\nAdsterra Opt Support Team\nWebsite: adsterra-opt.com\n"
    )

    max_retries = 3
    retry_delay = 1

    for attempt in range(1, max_retries + 1):
        try:
            print(f"RESEND_SEND_WELCOME_ATTEMPT: email={email} username={username} attempt={attempt}")
            return _send_resend_email(
                to_email=email,
                subject=subject,
                text=message,
                username=username,
            )
        except Exception as e:
            print(f"RESEND_SEND_WELCOME_ERROR: email={email} attempt={attempt} error={e}")
            logger.error("Resend welcome send failed for %s: %s", email, str(e))
            if attempt == max_retries:
                return False
            time.sleep(retry_delay)
            retry_delay *= 2

    return False
