from django.contrib import admin
from .models import Pack

@admin.register(Pack)
class PackAdmin(admin.ModelAdmin):
    list_display = ("name", "usd_value", "daily_missions", "daily_withdrawals", "is_active",'short_description','description', "created_by", "created_at")
    list_filter = ("is_active", "created_by")
    search_fields = ("name",)
