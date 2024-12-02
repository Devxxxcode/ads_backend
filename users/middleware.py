from datetime import datetime
from django.utils.timezone import now


class UpdateLastConnectionMiddleware:
    """
    Middleware to update the `last_connection` field for authenticated users.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Update last_connection only for authenticated users
        if request.user.is_authenticated:
            request.user.last_connection = now()
            request.user.save(update_fields=['last_connection'])

        response = self.get_response(request)
        return response

from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils.timezone import now

class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        user = super().authenticate(request)
        if user and user[0]:  # user[0] is the User instance
            if not user[0].is_staff:
                user[0].last_connection = now()
                user[0].save(update_fields=['last_connection'])
        return user