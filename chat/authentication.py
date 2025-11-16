"""Custom token authentication for REST framework."""
from __future__ import annotations

from rest_framework import authentication, exceptions

from .models import AuthToken


class HeaderTokenAuthentication(authentication.BaseAuthentication):
    """Reads the API token from the X-Auth-Token header."""

    header = "X-Auth-Token"

    def authenticate(self, request):
        token = request.headers.get(self.header)
        if not token:
            return None

        try:
            auth_token = AuthToken.objects.select_related("user").get(key=token)
        except AuthToken.DoesNotExist as exc:
            raise exceptions.AuthenticationFailed("Invalid API token") from exc

        return auth_token.user, auth_token
