"""
AES File Encryption/Decryption helper.

This module provides simple high-level helpers to encrypt and decrypt files
using a password-derived key (PBKDF2 + AES-GCM).

Requires the `cryptography` package:
    pip install cryptography
"""

import os
import shutil
import zipfile
import tempfile
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


def _zip_folder(folder_path: str, zip_path: str) -> None:
    """Compress a folder into a zip file."""
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zipf.write(file_path, arcname)


def encrypt_file(input_path: str, password: str, is_folder: bool = False) -> AesResult:
    """Encrypt a file with AES-GCM using a password.

    Output format (binary):
        [salt (16 bytes)] [nonce (12 bytes)] [ciphertext+tag (...)]
    """
    if not CRYPTO_AVAILABLE:
        return AesResult(
            False,
            "Cryptography library not available. Install it with: pip install cryptography",
        )

    # Handle folder encryption
    temp_zip = None
    original_input = input_path
    
    if is_folder:
        if not os.path.isdir(input_path):
            return AesResult(False, f"Folder not found: {input_path}")
        
        # Create temporary zip file
        temp_zip = tempfile.mktemp(suffix='.zip')
        try:
            _zip_folder(input_path, temp_zip)
            input_path = temp_zip
        except Exception as e:
            if temp_zip and os.path.exists(temp_zip):
                os.remove(temp_zip)
            return AesResult(False, f"Failed to compress folder: {e}")
    else:
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

        # Use original input path for output naming
        if is_folder:
            output_path = original_input + ".aes"
        else:
            output_path = input_path + ".aes"
            
        with open(output_path, "wb") as f:
            f.write(salt + nonce + ciphertext)
        
        # Cleanup temp zip if created
        if temp_zip and os.path.exists(temp_zip):
            os.remove(temp_zip)

        input_display = os.path.basename(original_input) if is_folder else os.path.basename(input_path)
        msg = (
            f"AES Encryption Successful\n"
            f"Input : {input_display}{' (folder)' if is_folder else ''}\n"
            f"Output: {os.path.basename(output_path)}\n"
            f"Salt size : {SALT_SIZE} bytes\n"
            f"Nonce size: {NONCE_SIZE} bytes\n"
            f"PBKDF2 iterations: {PBKDF2_ITERATIONS}\n"
        )
        return AesResult(True, msg, output_path)
    except Exception as exc:
        # Cleanup temp zip on error
        if temp_zip and os.path.exists(temp_zip):
            try:
                os.remove(temp_zip)
            except:
                pass
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
        
        # Check if decrypted file is a zip and auto-extract
        extracted_folder = None
        if zipfile.is_zipfile(output_path):
            try:
                # Extract to folder with same name (without .zip extension)
                extract_dir = output_path.replace('.zip', '') if output_path.endswith('.zip') else output_path + '_extracted'
                
                with zipfile.ZipFile(output_path, 'r') as zipf:
                    zipf.extractall(extract_dir)
                
                extracted_folder = extract_dir
                # Remove the intermediate zip file
                os.remove(output_path)
                output_path = extract_dir
            except Exception as e:
                # If extraction fails, keep the zip file
                pass

        msg = (
            f"AES Decryption Successful\n"
            f"Input : {os.path.basename(input_path)}\n"
            f"Output: {os.path.basename(output_path)}{' (folder extracted)' if extracted_folder else ''}\n"
        )
        return AesResult(True, msg, output_path)
    except Exception as exc:
        return AesResult(False, f"Decryption failed: {exc}")


