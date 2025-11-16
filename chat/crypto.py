"""Utility helpers for key management and authenticated encryption."""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings


@dataclass
class EncryptedPrivateKey:
    ciphertext: str
    salt: str
    nonce: str
    iterations: int


@dataclass
class EncryptedChunk:
    ciphertext: str
    nonce: str


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("utf-8")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("utf-8"))


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    size = settings.ENCRYPTION_SETTINGS["private_key_length"]
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_bytes, public_bytes


def _derive_key(password: str, salt: bytes, iterations: Optional[int] = None) -> bytes:
    iterations = iterations or settings.ENCRYPTION_SETTINGS["private_key_iterations"]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(private_key: bytes, password: str) -> EncryptedPrivateKey:
    salt = os.urandom(16)
    nonce = os.urandom(settings.ENCRYPTION_SETTINGS["aes_nonce_bytes"])
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_key, None)
    return EncryptedPrivateKey(
        ciphertext=_b64encode(ciphertext),
        salt=_b64encode(salt),
        nonce=_b64encode(nonce),
        iterations=settings.ENCRYPTION_SETTINGS["private_key_iterations"],
    )


def decrypt_private_key(encrypted: EncryptedPrivateKey, password: str) -> bytes:
    salt = _b64decode(encrypted.salt)
    nonce = _b64decode(encrypted.nonce)
    ciphertext = _b64decode(encrypted.ciphertext)
    key = _derive_key(password, salt, encrypted.iterations)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_symmetric_key() -> bytes:
    return os.urandom(32)


def encrypt_with_key(key: bytes, plaintext: bytes) -> EncryptedChunk:
    nonce = os.urandom(settings.ENCRYPTION_SETTINGS["aes_nonce_bytes"])
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return EncryptedChunk(ciphertext=_b64encode(ciphertext), nonce=_b64encode(nonce))


def encrypt_key_for_recipient(key: bytes, recipient_public_key: bytes) -> str:
    public_key = serialization.load_pem_public_key(recipient_public_key)
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return _b64encode(encrypted_key)


def decrypt_key_with_private(encrypted_key: str, private_key: bytes) -> bytes:
    private_obj = serialization.load_pem_private_key(private_key, password=None)
    return private_obj.decrypt(
        _b64decode(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_chunk(key: bytes, chunk: EncryptedChunk) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(_b64decode(chunk.nonce), _b64decode(chunk.ciphertext), None)
