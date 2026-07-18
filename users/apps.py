from django.apps import AppConfig
import logging


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        print("ADS_BACKEND_STARTUP_MARKER: users app loaded with Mailtrap email delivery")
        logging.getLogger(__name__).info(
            "ADS_BACKEND_STARTUP_MARKER: users app loaded with Mailtrap email delivery",
        )
