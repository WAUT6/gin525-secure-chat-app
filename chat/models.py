import secrets

from django.conf import settings
from django.db import models


class UserProfile(models.Model):
    """
    Stores encryption metadata for each user. The private key is never persisted in
    plaintext; it is encrypted with a key derived from the user's password.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    public_key = models.TextField()
    encrypted_private_key = models.TextField()
    private_key_nonce = models.CharField(max_length=128)
    private_key_salt = models.CharField(max_length=128)
    private_key_iterations = models.PositiveIntegerField(
        default=settings.ENCRYPTION_SETTINGS["private_key_iterations"]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_rotated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"Profile<{self.user.username}>"


class AuthToken(models.Model):
    """
    Simple token used by the API to avoid exposing Django sessions over HTTP.
    """

    key = models.CharField(max_length=64, unique=True, default=secrets.token_hex)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="auth_tokens"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"Token<{self.user.username}>"


class Message(models.Model):
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages"
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="received_messages"
    )
    encrypted_message = models.TextField(blank=True)
    encrypted_attachment = models.TextField(blank=True)
    attachment_name = models.CharField(max_length=255, blank=True)
    attachment_mime = models.CharField(max_length=255, blank=True)
    encrypted_symmetric_key = models.TextField()
    message_nonce = models.CharField(max_length=64, blank=True)
    attachment_nonce = models.CharField(max_length=64, blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)

    def has_attachment(self) -> bool:
        return bool(self.encrypted_attachment)

    def __str__(self) -> str:
        return f"Message<{self.id} {self.sender.username}->{self.recipient.username}>"
