from django.contrib import admin

from .models import AuthToken, Message, UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "created_at", "last_rotated_at")
    search_fields = ("user__username",)


@admin.register(AuthToken)
class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "key", "created_at")
    search_fields = ("user__username", "key")


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("id", "sender", "recipient", "sent_at")
    search_fields = ("sender__username", "recipient__username")
    ordering = ("-sent_at",)
