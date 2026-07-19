from django.apps import AppConfig
from django.conf import settings
import logging


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        marker = (
            "ADS_BACKEND_STARTUP_MARKER: users app loaded with Resend email delivery "
            f"(otp_limit={getattr(settings, 'OTP_EMAILS_PER_DAY', 5)}, "
            f"otp_cooldown={getattr(settings, 'OTP_SEND_COOLDOWN_SECONDS', 60)}s)"
        )
        print(marker)
        logging.getLogger(__name__).info(
            marker,
        )
