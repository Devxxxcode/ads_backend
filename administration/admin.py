from django.contrib import admin
from django.utils.html import format_html
from .models import Settings

@admin.register(Settings)
class SettingsAdmin(admin.ModelAdmin):
    """
    Admin interface for managing global settings.
    """
    list_display = [
        "percentage_of_sponsors",
        "bonus_when_registering",
        "service_availability_start_time",
        "service_availability_end_time",
        "token_validity_period_hours",
        "timezone",
        "video_preview",  # Add video preview to the list view
    ]
    readonly_fields = ["video_preview"]  # Preview video in the admin detail view

    fieldsets = (
        ("General", {
            "fields": (
                "percentage_of_sponsors",
                "bonus_when_registering",
                "minimum_balance_for_submissions",
                "token_validity_period_hours",
            ),
        }),
        ("Service Availability", {
            "fields": (
                "service_availability_start_time",
                "service_availability_end_time",
                "timezone",
            ),
        }),
        ("Contacts", {
            "fields": (
                "whatsapp_contact",
                "telegram_contact",
                "telegram_username",
                "online_chat_url",
            ),
        }),
        ("Blockchain Addresses", {
            "fields": (
                "erc_address",
                "trc_address",
            ),
        }),
        ("Video Management", {  # New section for video management
            "fields": (
                "video",
                "video_preview",  # Add a preview field for the video
            ),
        }),
    )

    def video_preview(self, obj):
        """
        Render an HTML video player to preview the uploaded video.
        """
        if obj.video:
            return format_html(
                f'<video width="320" height="240" controls>'
                f'<source src="{obj.video.url}" type="video/mp4">'
                f'Your browser does not support the video tag.'
                f'</video>'
            )
        return "No video uploaded"

    video_preview.short_description = "Video Preview"

    def has_add_permission(self, request):
        # Limit to a single instance
        return not Settings.objects.exists()
