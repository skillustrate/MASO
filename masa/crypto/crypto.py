"""Security and encryption utilities for MASA / MASO."""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("MASACrypto")


class SensitiveDataFilter(logging.Filter):
    """
    Filters sensitive data from log messages to prevent credential leakage.
    OWASP Top 10 protection.
    """

    PATTERNS = [
        (
            re.compile(r'(api[-_]?key\s*[:=]\s*["\']?)([^"\'\s]{6,})', re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r"(bearer\s+)([a-zA-Z0-9_\-\.]{8,})", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r'(password\s*[:=]\s*["\']?)([^"\'\s]+)', re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r'(secret\s*[:=]\s*["\']?)([^"\'\s]{6,})', re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r'(token\s*[:=]\s*["\']?)([^"\'\s]{8,})', re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(
                r'(aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?)([^"\'\s]{20,})',
                re.IGNORECASE,
            ),
            r"\1[REDACTED]",
        ),
        (
            re.compile(
                r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----",
                re.IGNORECASE,
            ),
            r"[REDACTED PRIVATE KEY]",
        ),
        (
            re.compile(
                r"((?:postgres|postgresql|mysql|mongodb|redis):\/\/[^\s:]+:)([^@\s]+)(@[^\s]+)",
                re.IGNORECASE,
            ),
            r"\1[REDACTED]\3",
        ),
        (
            re.compile(
                r'(jwt[_-]?token\s*[:=]\s*["\']?)(eyJ[A-Za-z0-9_-]{10,})', re.IGNORECASE
            ),
            r"\1[REDACTED]",
        ),
        (
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
            ),
            r"[REDACTED JWT]",
        ),
    ]

    def __init__(self, name: str = "SensitiveDataFilter"):
        super().__init__(name)

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, replacement in self.PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        return True


class ConfigCrypto:
    """
    Provides authenticated encryption/decryption at rest for MASA user configuration.
    Uses OS-native keyring with local file fallback (~/.masa/config.key with 0600 permissions).
    """

    SERVICE_NAME = "masa_framework"
    USERNAME = "masa_user_key"
    KEY_FILE_PATH = "~/.masa/config.key"

    @classmethod
    def _key_dir(cls) -> Path:
        return Path(os.environ.get("MASA_KEY_DIR", os.path.expanduser("~/.masa")))

    @classmethod
    def _key_file(cls) -> Path:
        key_dir = cls._key_dir()
        return key_dir / "config.key"

    @classmethod
    def _get_or_create_key(cls) -> bytes:
        import keyring

        try:
            key_str = keyring.get_password(cls.SERVICE_NAME, cls.USERNAME)
            if key_str:
                k_bytes = key_str.encode("utf-8")
                if len(k_bytes) == 44:
                    return k_bytes
                elif len(k_bytes) == 32:
                    return base64.urlsafe_b64encode(k_bytes)
        except Exception as e:
            logger.debug(f"Keyring retrieval failed: {type(e).__name__}")

        cls._ensure_key_file_exists()
        return cls._load_key_from_file()

    @classmethod
    def _ensure_key_file_exists(cls) -> None:
        key_dir = cls._key_dir()
        key_dir.mkdir(parents=True, exist_ok=True)
        try:
            key_dir.chmod(0o700)
        except PermissionError:
            pass

    @classmethod
    def _load_key_from_file(cls) -> bytes:
        key_file = cls._key_file()
        if key_file.exists():
            try:
                content = key_file.read_bytes().strip()
                if len(content) == 44:
                    return content
                elif len(content) == 32:
                    return base64.urlsafe_b64encode(content)
            except Exception as e:
                logger.warning(f"Failed to load key from file: {e}")

        return cls._generate_new_key()

    @classmethod
    def _generate_new_key(cls) -> bytes:
        import base64

        key = base64.urlsafe_b64encode(os.urandom(32))

        try:
            import keyring

            keyring.set_password(cls.SERVICE_NAME, cls.USERNAME, key.decode("utf-8"))
        except Exception as e:
            logger.debug(f"Failed to store key in keyring: {e}")

        cls._save_key_to_file(key)
        return key

    @classmethod
    def _save_key_to_file(cls, key: bytes) -> None:
        key_file = cls._key_file()
        try:
            fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(key)
            except Exception:
                key_file.write_bytes(key)
                key_file.chmod(0o600)
        except Exception as e:
            logger.error(f"Failed to save encryption key to file: {e}")
            raise

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        key = cls._get_or_create_key()

        try:
            from cryptography.fernet import Fernet

            f = Fernet(key)
            encrypted_payload = f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
            return json.dumps(
                {"_encrypted": True, "engine": "fernet", "payload": encrypted_payload},
                indent=2,
            )
        except Exception:
            # Fallback: Stream cipher with HMAC authentication
            raw_key = base64.urlsafe_b64decode(key) if len(key) == 44 else key
            raw_bytes = plaintext.encode("utf-8")
            iv = os.urandom(16)
            stream_key = hashlib.sha256(raw_key + iv).digest()
            keystream = (stream_key * ((len(raw_bytes) // len(stream_key)) + 1))[
                : len(raw_bytes)
            ]
            ciphertext = bytes([b ^ k for b, k in zip(raw_bytes, keystream)])
            mac = hmac.new(raw_key, iv + ciphertext, hashlib.sha256).hexdigest()

            return json.dumps(
                {
                    "_encrypted": True,
                    "engine": "hmac_stream",
                    "iv": base64.b64encode(iv).decode("utf-8"),
                    "payload": base64.b64encode(ciphertext).decode("utf-8"),
                    "mac": mac,
                },
                indent=2,
            )

    @classmethod
    def decrypt(cls, data_str: str) -> str:
        try:
            data = json.loads(data_str)
            if not isinstance(data, dict) or not data.get("_encrypted"):
                return data_str

            key = cls._get_or_create_key()
            engine = data.get("engine")

            if engine == "fernet":
                from cryptography.fernet import Fernet

                f = Fernet(key)
                return f.decrypt(data["payload"].encode("utf-8")).decode("utf-8")

            elif engine == "hmac_stream":
                raw_key = base64.urlsafe_b64decode(key) if len(key) == 44 else key
                iv = base64.b64decode(data["iv"])
                ciphertext = base64.b64decode(data["payload"])
                expected_mac = hmac.new(
                    raw_key, iv + ciphertext, hashlib.sha256
                ).hexdigest()

                if not hmac.compare_digest(data.get("mac", ""), expected_mac):
                    raise ValueError("MAC verification failed on encrypted config.")

                stream_key = hashlib.sha256(raw_key + iv).digest()
                keystream = (stream_key * ((len(ciphertext) // len(stream_key)) + 1))[
                    : len(ciphertext)
                ]
                decrypted = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
                return decrypted.decode("utf-8")

        except Exception as e:
            logger.debug(f"Error decrypting config: {e}. Falling back to raw content.")

        return data_str
