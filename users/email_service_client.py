import logging
import os
import time

import mailtrap as mt
from django.conf import settings

logger = logging.getLogger(__name__)

MAILTRAP_API_TOKEN = os.getenv(
    "MAILTRAP_API_TOKEN",
    getattr(settings, "MAILTRAP_API_TOKEN", "0c98e43226e123cf26a0a6fa801ae124"),
).strip()
MAILTRAP_SENDER_EMAIL = os.getenv(
    "MAILTRAP_SENDER_EMAIL",
    getattr(settings, "MAILTRAP_SENDER_EMAIL", "ho_reply@adsterra-opt.com"),
).strip()
MAILTRAP_SENDER_NAME = os.getenv(
    "MAILTRAP_SENDER_NAME",
    getattr(settings, "MAILTRAP_SENDER_NAME", "no_reply@adsterra-opt.com"),
).strip()


def _send_mailtrap_email(to_email, subject, text, category, username=None):
    if not MAILTRAP_API_TOKEN:
        raise RuntimeError("MAILTRAP_API_TOKEN is not configured")

    mail = mt.Mail(
        sender=mt.Address(email=MAILTRAP_SENDER_EMAIL, name=MAILTRAP_SENDER_NAME),
        to=[mt.Address(email=to_email)],
        subject=subject,
        text=text,
        category=category,
    )

    client = mt.MailtrapClient(token=MAILTRAP_API_TOKEN)
    print(
        f"MAILTRAP_CALL: to={to_email} subject={subject!r} category={category!r}"
        + (f" username={username}" if username else "")
    )
    logger.info(
        "Sending mail via Mailtrap to=%s subject=%s category=%s username=%s",
        to_email,
        subject,
        category,
        username,
    )

    response = client.send(mail)
    print(f"MAILTRAP_RESPONSE: to={to_email} response={response}")
    logger.info("Mailtrap response for %s: %s", to_email, response)
    return True


def send_otp_via_service(email, otp_code):
    """Send OTP email directly through Mailtrap."""
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
            print(f"MAILTRAP_SEND_OTP_ATTEMPT: email={email} attempt={attempt}")
            return _send_mailtrap_email(
                to_email=email,
                subject=subject,
                text=message,
                category="OTP Verification",
            )
        except Exception as e:
            print(f"MAILTRAP_SEND_OTP_ERROR: email={email} attempt={attempt} error={e}")
            logger.error("Mailtrap OTP send failed for %s: %s", email, str(e))
            if attempt == max_retries:
                return False
            time.sleep(retry_delay)
            retry_delay *= 2

    return False


def send_welcome_via_service(email, username):
    """Send welcome email directly through Mailtrap."""
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
            print(f"MAILTRAP_SEND_WELCOME_ATTEMPT: email={email} username={username} attempt={attempt}")
            return _send_mailtrap_email(
                to_email=email,
                subject=subject,
                text=message,
                category="Welcome Email",
                username=username,
            )
        except Exception as e:
            print(f"MAILTRAP_SEND_WELCOME_ERROR: email={email} attempt={attempt} error={e}")
            logger.error("Mailtrap welcome send failed for %s: %s", email, str(e))
            if attempt == max_retries:
                return False
            time.sleep(retry_delay)
            retry_delay *= 2

    return False
