"""Authenticated encryption for backend-managed gateway credentials."""

import json
import re

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


SECRET_FIELDS = frozenset({"password", "private_key", "key_passphrase", "secret_key"})


class SecretError(Exception):
    pass


class SecretVault:
    def __init__(self, key):
        try:
            self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)
        except (ValueError, TypeError, UnicodeError):
            raise SecretError("GATEWAY_SECRET_KEY must be a valid Fernet key.") from None

    def encrypt(self, value):
        return self._fernet.encrypt(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

    def decrypt(self, value):
        try:
            return json.loads(self._fernet.decrypt(value.encode("ascii")))
        except (InvalidToken, ValueError, TypeError, UnicodeError, AttributeError):
            raise SecretError("Stored credentials could not be decrypted.") from None


def validate_private_key(value, passphrase=None):
    try:
        encoded = value.encode("utf-8")
        password = passphrase.encode("utf-8") if passphrase else None
        loader = (
            serialization.load_ssh_private_key
            if encoded.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
            else serialization.load_pem_private_key
        )
        key = loader(encoded, password=password)
        if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
            raise ValueError("Unsupported key")
        if isinstance(key, ec.EllipticCurvePrivateKey) and not isinstance(
            key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
        ):
            raise ValueError("Unsupported curve")
    except Exception:
        raise SecretError("Invalid or unsupported SSH private key or passphrase.") from None


def public_fields(value):
    if isinstance(value, dict):
        return {k: public_fields(v) for k, v in value.items() if k not in SECRET_FIELDS}
    if isinstance(value, list):
        return [public_fields(v) for v in value]
    return value


def credential_values(value):
    values = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in SECRET_FIELDS and isinstance(item, str) and item:
                values.add(item)
            elif isinstance(item, (dict, list)):
                values.update(credential_values(item))
    elif isinstance(value, list):
        for item in value:
            values.update(credential_values(item))
    return values


def redact(value, secrets):
    text = str(value)
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
        "[redacted]", text, flags=re.DOTALL,
    )[:2000]
