# REST API Reference
All endpoints live under `/api/`. Authenticated requests require the `X-Auth-Token` header returned after login/registration.

## Authentication

### POST `/api/auth/register/`
Registers a new user, generates an RSA key pair, and returns the encrypted private key envelope.

**Body**
```json
{
  "username": "alice",
  "password": "ExamplePass123"
}
```

**Response 201**
```json
{
  "user": {"id": 1, "username": "alice"},
  "token": "282bd0...",
  "profile": {
    "public_key": "-----BEGIN PUBLIC KEY-----...",
    "encrypted_private_key": "j0a...=",
    "private_key_nonce": "5pd...=",
    "private_key_salt": "r1c...=",
    "private_key_iterations": 390000
  }
}
```
Store the encrypted private key blob and decrypt it locally using the same password when needed.

### POST `/api/auth/login/`
Returns a fresh API token and the caller's profile envelope.

**Body** – same as register.

**Response 200** – same shape as register.

### POST `/api/auth/logout/`
Invalidates the current token. Requires `X-Auth-Token` header. Returns `204 No Content`.

## Users & Keys

### GET `/api/users/`
Lists all other users and their public keys.

**Response 200**
```json
[
  {
    "user": {"id": 2, "username": "bob"},
    "public_key": "-----BEGIN PUBLIC KEY-----..."
  }
]
```

### GET `/api/users/<username>/public-key/`
Fetches a single public key (authentication required). Returns `404` if the user or profile does not exist.

### POST `/api/keys/rotate/`
Regenerates the caller's RSA key pair after verifying their password.

**Body**
```json
{"password": "ExamplePass123"}
```

**Response 200** – same profile envelope as registration.

## Messaging & File Transfer

### POST `/api/messages/send/`
Sends an encrypted message, optional attachment, or both. Either `message` or `attachment_data` must be provided.

**Body**
```json
{
  "recipient": "bob",
  "message": "hello there",
  "attachment_name": "diagram.png",
  "attachment_mime": "image/png",
  "attachment_data": "iVBORw0KGgoAAAANSUhEUg..."
}
```
- `attachment_data` must be base64-encoded binary data.

**Response 201**
```json
{
  "id": 12,
  "sender": {"id": 1, "username": "alice"},
  "recipient": {"id": 2, "username": "bob"},
  "encrypted_message": "NWc...=",
  "encrypted_attachment": "a2Y...=",
  "attachment_name": "diagram.png",
  "attachment_mime": "image/png",
  "encrypted_symmetric_key": "Rko...=",
  "message_nonce": "o9B...=",
  "attachment_nonce": "c20...=",
  "sent_at": "2025-11-16T08:52:00Z",
  "has_attachment": true
}
```
Use the encrypted symmetric key + private key to decrypt `message_nonce`/`encrypted_message` and, if present, the attachment pair.

### GET `/api/messages/`
Returns inbox messages by default. Use `?direction=sent` to view messages you sent.

**Response 200** – array of the same objects returned by the send endpoint.

### GET `/api/messages/<id>/`
Retrieves a single message if you are the sender or recipient. Returns `403` otherwise or `404` if absent.

## Decryption Workflow (Client-side)
1. After login, decrypt the encrypted private key using AES-GCM:
   - Derive a 32-byte key from the user's password using PBKDF2 (salt + iteration count provided by the server).
   - Decrypt the `encrypted_private_key` using the provided nonce.
2. When receiving a message:
   - Base64-decode `encrypted_symmetric_key` and decrypt it with the private key to recover the AES key.
   - Base64-decode the `message_nonce` + `encrypted_message` and decrypt with AES-GCM.
   - Repeat for `attachment_nonce` + `encrypted_attachment` if `has_attachment` is true.

## Error Handling
- Validation errors return `400` with a `detail` string (e.g., missing password, base64 parsing issues).
- Authentication failures return `401` (`Invalid API token`).
- Forbidden access returns `403`.
- Missing resources return `404`.
