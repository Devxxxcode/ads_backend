from django.apps import AppConfig
import logging


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        logging.getLogger(__name__).info(
            "ADS_BACKEND_STARTUP_MARKER: users app loaded with email service URL %s",
            "https://email.adsterra-opt.com",
        )
