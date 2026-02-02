"""
AES File Encryption/Decryption helper.

This module provides simple high-level helpers to encrypt and decrypt files
using a password-derived key (PBKDF2 + AES-GCM).

Requires the `cryptography` package:
    pip install cryptography
"""

import os
from dataclasses import dataclass
from typing import Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False


SALT_SIZE = 16  # bytes
NONCE_SIZE = 12  # bytes for AES-GCM
PBKDF2_ITERATIONS = 200_000


@dataclass
class AesResult:
    success: bool
    message: str
    output_path: str | None = None


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_path: str, password: str) -> AesResult:
    """Encrypt a file with AES-GCM using a password.

    Output format (binary):
        [salt (16 bytes)] [nonce (12 bytes)] [ciphertext+tag (...)]
    """
    if not CRYPTO_AVAILABLE:
        return AesResult(
            False,
            "Cryptography library not available. Install it with: pip install cryptography",
        )

    if not os.path.isfile(input_path):
        return AesResult(False, f"Input file not found: {input_path}")

    if not password:
        return AesResult(False, "Password cannot be empty.")

    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()

        salt = os.urandom(SALT_SIZE)
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(NONCE_SIZE)

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        output_path = input_path + ".aes"
        with open(output_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

        msg = (
            f"AES Encryption Successful\n"
            f"Input : {os.path.basename(input_path)}\n"
            f"Output: {os.path.basename(output_path)}\n"
            f"Salt size : {SALT_SIZE} bytes\n"
            f"Nonce size: {NONCE_SIZE} bytes\n"
            f"PBKDF2 iterations: {PBKDF2_ITERATIONS}\n"
        )
        return AesResult(True, msg, output_path)
    except Exception as exc:
        return AesResult(False, f"Encryption failed: {exc}")


def decrypt_file(input_path: str, password: str, output_path: str | None = None) -> AesResult:
    """Decrypt a file previously encrypted with encrypt_file()."""
    if not CRYPTO_AVAILABLE:
        return AesResult(
            False,
            "Cryptography library not available. Install it with: pip install cryptography",
        )

    if not os.path.isfile(input_path):
        return AesResult(False, f"Input file not found: {input_path}")

    if not password:
        return AesResult(False, "Password cannot be empty.")

    try:
        with open(input_path, "rb") as f:
            data = f.read()

        if len(data) <= SALT_SIZE + NONCE_SIZE:
            return AesResult(False, "Encrypted file is too short or corrupted.")

        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = data[SALT_SIZE + NONCE_SIZE :]

        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Default output: remove .aes extension if present
        if output_path is None:
            if input_path.lower().endswith(".aes"):
                output_path = input_path[:-4]
            else:
                output_path = input_path + ".dec"

        with open(output_path, "wb") as f:
            f.write(plaintext)

        msg = (
            f"AES Decryption Successful\n"
            f"Input : {os.path.basename(input_path)}\n"
            f"Output: {os.path.basename(output_path)}\n"
        )
        return AesResult(True, msg, output_path)
    except Exception as exc:
        return AesResult(False, f"Decryption failed: {exc}")


