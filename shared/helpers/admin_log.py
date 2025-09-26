from notification.models import AdminLog
from django.contrib.auth.models import AnonymousUser

def create_admin_log(request, message, reason=None):
    """
    Creates a log entry in the AdminLog model.
    
    Args:
        request (HttpRequest): The HTTP request object containing the user.
        message (str): The message to be logged.
        reason (str, optional): The reason for the log entry. Defaults to None.
    """
    try:
        user = getattr(request, "user", None)
        if user and not isinstance(user, AnonymousUser):
            AdminLog.objects.create(
                user=user,
                description=message,
                reason=reason
            )
            print("Admin log created successfully.")
        else:
            print("The user isn't authenticated, unable to create log.")
    except Exception as e:
        # Optional: Use a logger here for better production error handling.
        print(f"Failed to create admin log: {str(e)}")
