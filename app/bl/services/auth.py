"""Entra OIDC browser flow and bearer-token verification."""

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from fastapi import HTTPException, Request

from app.common.identity import AuthenticatedUser
from config.settings import AuthSettings, auth_settings

_DISCOVERY_TTL_SECONDS = 3600
_JWKS_TTL_SECONDS = 3600
_HTTP_TIMEOUT_SECONDS = (2, 5)
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise ValueError("Invalid token encoding.")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_segment(value: str) -> dict[str, Any]:
    decoded = json.loads(_decode_b64url(value))
    if not isinstance(decoded, dict):
        raise ValueError("Invalid token JSON.")
    return decoded


def _sign(payload: dict[str, Any], secret: str) -> str:
    encoded = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return encoded + "." + _b64url(signature)


def _unsign(value: str | None, secret: str) -> dict[str, Any]:
    if not value or "." not in value:
        raise ValueError("Missing signed value.")
    encoded, signature = value.rsplit(".", 1)
    expected = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _decode_b64url(signature)):
        raise ValueError("Invalid signed value.")
    return _json_segment(encoded)


@dataclass(frozen=True)
class LoginStart:
    authorization_url: str
    state_cookie: str


class AuthenticationService:
    def __init__(self, settings: AuthSettings):
        self.settings = settings

    @classmethod
    def from_request(cls, request: Request) -> "AuthenticationService":
        return cls(auth_settings())

    def _cookie_secret(self) -> str:
        if self.settings.mode != "entra" or not self.settings.client_secret:
            raise ValueError("Session signing is unavailable.")
        return self.settings.client_secret

    def _discovery(self) -> dict[str, Any]:
        tenant_id = self.settings.tenant_id
        if not tenant_id:
            raise ValueError("Entra tenant is unavailable.")
        key = f"discovery:{tenant_id}"
        cached = _CACHE.get(key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        try:
            response = requests.get(url, timeout=_HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            document = response.json()
        except requests.RequestException:
            raise HTTPException(status_code=401, detail="Authentication provider is unavailable.") from None
        required = {"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"}
        if not isinstance(document, dict) or not required.issubset(document):
            raise HTTPException(status_code=401, detail="Authentication provider configuration is invalid.")
        _CACHE[key] = (time.monotonic() + _DISCOVERY_TTL_SECONDS, document)
        return document

    def _jwks(self, uri: str) -> dict[str, Any]:
        cached = _CACHE.get(f"jwks:{uri}")
        if cached and cached[0] > time.monotonic():
            return cached[1]
        try:
            response = requests.get(uri, timeout=_HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            document = response.json()
        except requests.RequestException:
            raise HTTPException(status_code=401, detail="Authentication provider is unavailable.") from None
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise HTTPException(status_code=401, detail="Authentication provider configuration is invalid.")
        _CACHE[f"jwks:{uri}"] = (time.monotonic() + _JWKS_TTL_SECONDS, document)
        return document

    def _verify_token(self, token: str, audience: str, nonce: str | None = None) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=401, detail="Invalid bearer token.")
        try:
            header = _json_segment(parts[0])
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise ValueError("Unsupported token algorithm.")
            discovery = self._discovery()
            jwk = next(
                key for key in self._jwks(discovery["jwks_uri"])["keys"]
                if key.get("kid") == header["kid"] and key.get("kty") == "RSA"
            )
            public_key = rsa.RSAPublicNumbers(
                int.from_bytes(_decode_b64url(jwk["e"]), "big"),
                int.from_bytes(_decode_b64url(jwk["n"]), "big"),
            ).public_key()
            public_key.verify(
                _decode_b64url(parts[2]), f"{parts[0]}.{parts[1]}".encode("ascii"),
                padding.PKCS1v15(), hashes.SHA256(),
            )
            claims = _json_segment(parts[1])
        except (ValueError, KeyError, StopIteration, json.JSONDecodeError, InvalidSignature):
            raise HTTPException(status_code=401, detail="Invalid bearer token.") from None
        now = time.time()
        issuer = f"https://login.microsoftonline.com/{self.settings.tenant_id}/v2.0"
        audiences = claims.get("aud")
        if (
            claims.get("iss") != issuer
            or claims.get("tid") != self.settings.tenant_id
            or (audience not in audiences if isinstance(audiences, list) else audiences != audience)
            or not isinstance(claims.get("exp"), (int, float))
            or claims["exp"] <= now
            or (isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] > now)
            or (nonce is not None and claims.get("nonce") != nonce)
        ):
            raise HTTPException(status_code=401, detail="Invalid bearer token.")
        return claims

    def _user_from_claims(self, claims: dict[str, Any]) -> AuthenticatedUser:
        roles = claims.get("roles")
        if not isinstance(roles, list) or not roles or any(role not in {"Viewer", "Operator", "Administrator"} for role in roles):
            raise HTTPException(status_code=401, detail="Token does not contain valid application roles.")
        subject = claims.get("oid") or claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise HTTPException(status_code=401, detail="Invalid bearer token.")
        name = claims.get("name") or claims.get("preferred_username") or subject
        email = claims.get("email") or claims.get("preferred_username")
        return AuthenticatedUser(
            subject=subject, tenant_id=self.settings.tenant_id, name=str(name),
            email=str(email) if isinstance(email, str) else None,
            roles=frozenset(roles), auth_mode="entra",
        )

    def authenticate_request(self, request: Request) -> AuthenticatedUser:
        if self.settings.mode == "demo":
            if not getattr(request.app.state, "demo_mode", False):
                raise HTTPException(status_code=401, detail="Demo authentication is disabled.")
            return AuthenticatedUser(
                subject=self.settings.demo_user_id or "", tenant_id=None,
                name=self.settings.demo_user_name or "", email=self.settings.demo_user_email,
                roles=frozenset({self.settings.demo_user_role}), auth_mode="demo",
            )
        if self.settings.mode != "entra":
            raise HTTPException(status_code=401, detail="Authentication is required.")
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer ") and authorization.count(" ") == 1:
            return self._user_from_claims(self._verify_token(authorization[7:], self.settings.api_client_id or ""))
        claims = _unsign(request.cookies.get("gateway_session"), self._cookie_secret())
        if not isinstance(claims.get("expires_at"), (int, float)) or claims["expires_at"] <= time.time():
            raise HTTPException(status_code=401, detail="Authentication is required.")
        return self._user_from_claims(claims)

    def start_login(self, redirect_uri: str) -> LoginStart:
        if self.settings.mode != "entra" or redirect_uri not in self.settings.redirect_uris:
            raise HTTPException(status_code=401, detail="Browser authentication is unavailable.")
        state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        params = {
            "client_id": self.settings.client_id, "response_type": "code", "redirect_uri": redirect_uri,
            "response_mode": "query", "scope": " ".join(self.settings.scopes), "state": state,
            "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
        }
        cookie = _sign(
            {
                "state": state, "nonce": nonce, "verifier": verifier,
                "redirect_uri": redirect_uri, "iat": time.time(),
            },
            self._cookie_secret(),
        )
        return LoginStart(self._discovery()["authorization_endpoint"] + "?" + urlencode(params), cookie)

    def complete_login(self, code: str, state: str, state_cookie: str | None) -> AuthenticatedUser:
        if self.settings.mode != "entra":
            raise HTTPException(status_code=401, detail="Browser authentication is unavailable.")
        try:
            flow = _unsign(state_cookie, self._cookie_secret())
            flow_state, nonce, verifier, redirect_uri, issued_at = (
                flow["state"], flow["nonce"], flow["verifier"], flow["redirect_uri"], float(flow["iat"])
            )
        except (KeyError, TypeError, ValueError):
            raise HTTPException(status_code=401, detail="Invalid login state.") from None
        if (
            not isinstance(flow_state, str)
            or not isinstance(nonce, str)
            or not isinstance(verifier, str)
            or not isinstance(redirect_uri, str)
            or redirect_uri not in self.settings.redirect_uris
            or not hmac.compare_digest(flow_state, state)
            or issued_at > time.time()
            or time.time() - issued_at > 600
        ):
            raise HTTPException(status_code=401, detail="Invalid login state.")
        try:
            response = requests.post(self._discovery()["token_endpoint"], data={
                "client_id": self.settings.client_id, "client_secret": self.settings.client_secret,
                "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            }, timeout=_HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            id_token = response.json()["id_token"]
        except (requests.RequestException, KeyError, TypeError, ValueError):
            raise HTTPException(status_code=401, detail="Sign-in could not be completed.") from None
        return self._user_from_claims(self._verify_token(id_token, self.settings.client_id or "", nonce))

    def session_cookie(self, user: AuthenticatedUser, expires_at: float) -> str:
        return _sign({**user.public(), "expires_at": expires_at}, self._cookie_secret())
