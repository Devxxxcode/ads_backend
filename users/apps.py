from django.apps import AppConfig
import logging


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        print("ADS_BACKEND_STARTUP_MARKER: users app loaded with EMAIL_SERVICE_URL=https://email.adsterra-opt.com")
        logging.getLogger(__name__).info(
            "ADS_BACKEND_STARTUP_MARKER: users app loaded with email service URL %s",
            "https://email.adsterra-opt.com",
        )
