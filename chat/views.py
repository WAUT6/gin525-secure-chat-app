"""API views for the secure chat backend."""
from __future__ import annotations

import base64
import binascii

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import crypto
from .models import AuthToken, Message, UserProfile
from .serializers import (
    LoginSerializer,
    MessageCreateSerializer,
    MessageSerializer,
    RegistrationSerializer,
    UserSerializer,
)

User = get_user_model()


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes: list = []

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.save()
        return Response(payload, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes: list = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.save()
        return Response(payload, status=status.HTTP_200_OK)


class LogoutView(APIView):
    def post(self, request):
        token = request.auth
        if isinstance(token, AuthToken):
            token.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserListView(APIView):
    def get(self, request):
        queryset = User.objects.exclude(id=request.user.id)
        data = []
        for user in queryset.select_related("profile"):
            data.append(
                {
                    "user": UserSerializer(user).data,
                    "public_key": user.profile.public_key,
                }
            )
        return Response(data)


class PublicKeyView(APIView):
    def get(self, request, username: str):
        user = User.objects.filter(username=username).first()
        if not user or not hasattr(user, "profile"):
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(
            {
                "user": UserSerializer(user).data,
                "public_key": user.profile.public_key,
            }
        )


class RotateKeysView(APIView):
    def post(self, request):
        password = request.data.get("password")
        if not password:
            return Response({"detail": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not request.user.check_password(password):
            return Response({"detail": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)

        private_key, public_key = crypto.generate_rsa_keypair()
        encrypted_private = crypto.encrypt_private_key(private_key, password)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.public_key = public_key.decode("utf-8")
        profile.encrypted_private_key = encrypted_private.ciphertext
        profile.private_key_nonce = encrypted_private.nonce
        profile.private_key_salt = encrypted_private.salt
        profile.private_key_iterations = encrypted_private.iterations
        profile.last_rotated_at = timezone.now()
        profile.save(update_fields=[
            "public_key",
            "encrypted_private_key",
            "private_key_nonce",
            "private_key_salt",
            "private_key_iterations",
            "last_rotated_at",
        ])
        return Response(
            {
                "public_key": profile.public_key,
                "encrypted_private_key": profile.encrypted_private_key,
                "private_key_nonce": profile.private_key_nonce,
                "private_key_salt": profile.private_key_salt,
                "private_key_iterations": profile.private_key_iterations,
            }
        )


class SendMessageView(APIView):
    def post(self, request):
        serializer = MessageCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        recipient = data["recipient_obj"]

        if not hasattr(recipient, "profile"):
            return Response({"detail": "Recipient has no encryption profile"}, status=400)

        symmetric_key = crypto.generate_symmetric_key()
        encrypted_key = crypto.encrypt_key_for_recipient(
            symmetric_key, recipient.profile.public_key.encode("utf-8")
        )

        encrypted_message = ""
        message_nonce = ""
        if data.get("message"):
            chunk = crypto.encrypt_with_key(symmetric_key, data["message"].encode("utf-8"))
            encrypted_message = chunk.ciphertext
            message_nonce = chunk.nonce

        encrypted_attachment = ""
        attachment_nonce = ""
        attachment_data = data.get("attachment_data")
        if attachment_data:
            try:
                raw_bytes = base64.b64decode(attachment_data)
            except binascii.Error as exc:
                return Response({"detail": "Attachment data must be base64"}, status=400)
            chunk = crypto.encrypt_with_key(symmetric_key, raw_bytes)
            encrypted_attachment = chunk.ciphertext
            attachment_nonce = chunk.nonce

        message = Message.objects.create(
            sender=request.user,
            recipient=recipient,
            encrypted_message=encrypted_message,
            encrypted_attachment=encrypted_attachment,
            attachment_name=data.get("attachment_name") or "",
            attachment_mime=data.get("attachment_mime") or "",
            encrypted_symmetric_key=encrypted_key,
            message_nonce=message_nonce,
            attachment_nonce=attachment_nonce,
        )
        return Response(MessageSerializer(message).data, status=status.HTTP_201_CREATED)


class MessageListView(APIView):
    def get(self, request):
        direction = request.query_params.get("direction", "inbox")
        if direction == "sent":
            queryset = Message.objects.filter(sender=request.user)
        else:
            queryset = Message.objects.filter(recipient=request.user)
        queryset = queryset.select_related("sender", "recipient").order_by("-sent_at")
        return Response(MessageSerializer(queryset, many=True).data)


class MessageDetailView(APIView):
    def get(self, request, pk: int):
        try:
            message = Message.objects.select_related("sender", "recipient").get(pk=pk)
        except Message.DoesNotExist:
            return Response({"detail": "Message not found"}, status=status.HTTP_404_NOT_FOUND)
        if message.sender != request.user and message.recipient != request.user:
            return Response({"detail": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
        return Response(MessageSerializer(message).data)
