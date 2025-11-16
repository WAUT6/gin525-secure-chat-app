# Secure Chat Backend

This repository contains the backend for a secure, end-to-end encrypted chat application implemented as a Django REST API. It demonstrates hybrid encryption (RSA + AES), secure key storage, message delivery, and optional encrypted file transfer between authenticated users.

## Key Features
- **Hybrid cryptography**: RSA key pairs per user, AES-GCM per message, and RSA-encrypted symmetric keys for delivery.
- **Secure credential flow**: Django's password hashing along with per-user encrypted private keys and optional key rotation.
- **Message transport**: Authenticated REST endpoints for sending and retrieving encrypted chat messages.
- **File transfer**: Attach base64-encoded files to any message; payloads are encrypted just like plaintext messages.
- **Token auth**: Lightweight header-based tokens to avoid storing Django sessions on the client.

## Getting Started
1. **Install dependencies**
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Apply migrations**
   ```bash
   python3 manage.py migrate
   ```
3. **Run the API**
   ```bash
   python3 manage.py runserver 0.0.0.0:8000
   ```
4. **Interact with endpoints** using any HTTP client. Send `X-Auth-Token` headers after logging in.

## Project Layout
- `secure_chat/` – Django project configuration.
- `chat/` – App with models, serializers, crypto helpers, and REST views.
- `docs/architecture.md` – Cryptographic and component design notes.
- `docs/api.md` – Complete endpoint reference with example requests/responses.

