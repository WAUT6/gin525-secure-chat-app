from django.urls import path

from . import views

urlpatterns = [
    path("auth/register/", views.RegisterView.as_view(), name="register"),
    path("auth/login/", views.LoginView.as_view(), name="login"),
    path("auth/logout/", views.LogoutView.as_view(), name="logout"),
    path("users/", views.UserListView.as_view(), name="user-list"),
    path("users/<str:username>/public-key/", views.PublicKeyView.as_view(), name="public-key"),
    path("keys/rotate/", views.RotateKeysView.as_view(), name="rotate-keys"),
    path("messages/send/", views.SendMessageView.as_view(), name="send-message"),
    path("messages/", views.MessageListView.as_view(), name="message-list"),
    path("messages/<int:pk>/", views.MessageDetailView.as_view(), name="message-detail"),
]
