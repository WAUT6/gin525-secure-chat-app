"""REST serializers for the secure chat backend."""
from __future__ import annotations

from typing import Any

from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

from . import crypto
from .models import AuthToken, Message, UserProfile

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username"]


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            "public_key",
            "encrypted_private_key",
            "private_key_nonce",
            "private_key_salt",
            "private_key_iterations",
        ]


class RegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(min_length=8, write_only=True)

    def validate_username(self, value: str) -> str:
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        user = User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"],
        )
        private_key, public_key = crypto.generate_rsa_keypair()
        encrypted_private = crypto.encrypt_private_key(private_key, validated_data["password"])
        profile = UserProfile.objects.create(
            user=user,
            public_key=public_key.decode("utf-8"),
            encrypted_private_key=encrypted_private.ciphertext,
            private_key_nonce=encrypted_private.nonce,
            private_key_salt=encrypted_private.salt,
            private_key_iterations=encrypted_private.iterations,
        )
        token = AuthToken.objects.create(user=user)
        return {
            "user": UserSerializer(user).data,
            "token": token.key,
            "profile": ProfileSerializer(profile).data,
        }


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        user = authenticate(username=attrs.get("username"), password=attrs.get("password"))
        if not user:
            raise serializers.ValidationError("Invalid username or password")
        attrs["user"] = user
        return attrs

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        user = validated_data["user"]
        try:
            profile = user.profile
        except UserProfile.DoesNotExist as exc:
            raise serializers.ValidationError("User profile is missing encryption keys") from exc
        token = AuthToken.objects.create(user=user)
        return {
            "user": UserSerializer(user).data,
            "token": token.key,
            "profile": ProfileSerializer(profile).data,
        }


class MessageCreateSerializer(serializers.Serializer):
    recipient = serializers.CharField(help_text="Recipient username")
    message = serializers.CharField(required=False, allow_blank=True)
    attachment_name = serializers.CharField(required=False, allow_blank=True)
    attachment_mime = serializers.CharField(required=False, allow_blank=True)
    attachment_data = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if not attrs.get("message") and not attrs.get("attachment_data"):
            raise serializers.ValidationError("Provide a message body or attachment data")
        try:
            recipient = User.objects.get(username=attrs["recipient"])
        except User.DoesNotExist as exc:
            raise serializers.ValidationError("Recipient does not exist") from exc
        attrs["recipient_obj"] = recipient
        return attrs


class MessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer()
    recipient = UserSerializer()
    has_attachment = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "sender",
            "recipient",
            "encrypted_message",
            "encrypted_attachment",
            "attachment_name",
            "attachment_mime",
            "encrypted_symmetric_key",
            "message_nonce",
            "attachment_nonce",
            "sent_at",
            "has_attachment",
        ]

    def get_has_attachment(self, obj: Message) -> bool:
        return bool(obj.encrypted_attachment)
