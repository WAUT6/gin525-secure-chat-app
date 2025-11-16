# Architecture & Cryptography Notes

## Component Overview
- **Django project (`secure_chat/`)** – standard settings plus REST framework configuration and custom token auth wiring.
- **Chat app (`chat/`)** – houses domain models, crypto helpers, serializers, and API views.
- **Storage** – SQLite (default) persists users, RSA key metadata, API tokens, and encrypted messages.

## Authentication & Registration
1. Clients register via `POST /api/auth/register/` with a username + password.
2. Backend creates a Django `User`, generates a 2048-bit RSA key pair, encrypts the private key with AES-GCM using a PBKDF2-derived key from the password, and stores the encrypted blob plus salt/nonce.
3. Login via `POST /api/auth/login/` issues a random `AuthToken` (hex) that must be provided in the `X-Auth-Token` header for all authenticated requests.
4. Logout deletes the token. Tokens are stored server-side so they can be revoked at any time.

## Key Management & Exchange
- Each user has a `UserProfile` capturing the public key and encrypted private key metadata.
- `GET /api/users/` returns other users and their public keys for initial exchange.
- `GET /api/users/<username>/public-key/` exposes a single public key (authentication required).
- `POST /api/keys/rotate/` rotates the RSA pair after re-validating the user's password; the response contains the new encrypted private key envelope for the client to cache.

## Message Encryption Flow
1. Sender authenticates to receive an `X-Auth-Token`.
2. To send a message, the client calls `POST /api/messages/send/` with:
   - Recipient username.
   - Plaintext message (optional) and/or base64 file payload.
   - Optional attachment metadata (filename/MIME type).
3. Backend generates a fresh 32-byte AES key, encrypts the plaintext (if present) and file bytes (if present) separately with AES-GCM (unique nonce per payload).
4. The AES key is encrypted with the recipient's RSA public key (OAEP + SHA-256) and stored alongside the ciphertext and nonces.
5. Recipients fetch messages via `GET /api/messages/` (default inbox or `?direction=sent`). The response delivers:
   - Encrypted message text + nonce.
   - Optional encrypted attachment + nonce + metadata.
   - RSA-encrypted AES key.
6. The recipient client decrypts the AES key with its private key, then decrypts the ciphertext.

## File Transfer
- Files are supplied as base64 data in `attachment_data` during the send call.
- Files share the same AES key as the message but are encrypted with a dedicated nonce to preserve AES-GCM security guarantees.
- Metadata (name + MIME) stays in plaintext for discoverability; content remains encrypted.

