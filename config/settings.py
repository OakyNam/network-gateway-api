"""Environment-backed settings for gateway features."""

import os
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID


def device_data_provider() -> Literal["fake", "disabled"]:
    provider = os.environ.get("GATEWAY_DEVICE_DATA_PROVIDER", "disabled")
    if provider == "fake":
        return "fake"
    if provider == "disabled":
        return "disabled"
    raise ValueError("GATEWAY_DEVICE_DATA_PROVIDER must be 'fake' or 'disabled'.")


AuthMode = Literal["entra", "demo", "disabled"]
GatewayRole = Literal["Viewer", "Operator", "Administrator"]
_ROLES = frozenset({"Viewer", "Operator", "Administrator"})


def _uuid_setting(name: str) -> str:
    value = os.environ.get(name, "").strip()
    try:
        return str(UUID(value))
    except ValueError:
        raise ValueError(f"{name} must be a UUID.") from None


def _absolute_redirect_uri(value: str, name: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    localhost = parsed is not None and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (parsed.scheme == "http" and not localhost)
    ):
        raise ValueError(f"{name} must be an absolute HTTPS URI (or HTTP localhost URI).")
    return value


def _redirect_uris() -> tuple[str, ...]:
    values = tuple(value.strip() for value in os.environ.get("GATEWAY_ENTRA_REDIRECT_URIS", "").split(",") if value.strip())
    if not values:
        raise ValueError("GATEWAY_ENTRA_REDIRECT_URIS must contain at least one URI.")
    return tuple(_absolute_redirect_uri(value, "GATEWAY_ENTRA_REDIRECT_URIS") for value in values)


@dataclass(frozen=True)
class AuthSettings:
    mode: AuthMode
    tenant_id: str | None = None
    client_id: str | None = None
    api_client_id: str | None = None
    client_secret: str | None = None
    redirect_uris: tuple[str, ...] = ()
    post_logout_redirect_uri: str | None = None
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    demo_user_id: str | None = None
    demo_user_email: str | None = None
    demo_user_name: str | None = None
    demo_user_role: GatewayRole | None = None


def auth_settings() -> AuthSettings:
    """Load authentication settings, validating all enabled modes fail closed."""
    mode = os.environ.get("GATEWAY_AUTH_MODE", "disabled").strip()
    if mode not in {"entra", "demo", "disabled"}:
        raise ValueError("GATEWAY_AUTH_MODE must be 'entra', 'demo', or 'disabled'.")
    if mode == "disabled":
        return AuthSettings(mode="disabled")
    if mode == "demo":
        role = os.environ.get("GATEWAY_DEMO_USER_ROLE", "").strip()
        if role not in _ROLES:
            raise ValueError("GATEWAY_DEMO_USER_ROLE must be Viewer, Operator, or Administrator.")
        subject = os.environ.get("GATEWAY_DEMO_USER_ID", "").strip()
        name = os.environ.get("GATEWAY_DEMO_USER_NAME", "").strip()
        if not subject or not name:
            raise ValueError("GATEWAY_DEMO_USER_ID and GATEWAY_DEMO_USER_NAME are required in demo mode.")
        return AuthSettings(
            mode="demo", demo_user_id=subject,
            demo_user_email=os.environ.get("GATEWAY_DEMO_USER_EMAIL", "").strip() or None,
            demo_user_name=name, demo_user_role=role,
        )

    secret = os.environ.get("GATEWAY_ENTRA_CLIENT_SECRET", "")
    if not secret:
        raise ValueError("GATEWAY_ENTRA_CLIENT_SECRET is required in entra mode.")
    scopes = tuple(value for value in os.environ.get(
        "GATEWAY_ENTRA_SCOPES", "openid,profile,email"
    ).replace(",", " ").split() if value)
    if "openid" not in scopes:
        raise ValueError("GATEWAY_ENTRA_SCOPES must include openid.")
    post_logout = os.environ.get("GATEWAY_ENTRA_POST_LOGOUT_REDIRECT_URI", "").strip()
    client_id = _uuid_setting("GATEWAY_ENTRA_CLIENT_ID")
    api_client_id = _uuid_setting("GATEWAY_ENTRA_API_CLIENT_ID") if os.environ.get(
        "GATEWAY_ENTRA_API_CLIENT_ID", ""
    ).strip() else client_id
    return AuthSettings(
        mode="entra",
        tenant_id=_uuid_setting("GATEWAY_ENTRA_TENANT_ID"),
        client_id=client_id,
        api_client_id=api_client_id,
        client_secret=secret,
        redirect_uris=_redirect_uris(),
        post_logout_redirect_uri=(
            _absolute_redirect_uri(post_logout, "GATEWAY_ENTRA_POST_LOGOUT_REDIRECT_URI")
            if post_logout else None
        ),
        scopes=scopes,
    )
