"""Offline tests for authentication settings and cryptographic JWT validation."""

import base64
import json
import os
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api.routes.auth import router
from app.bl.services.auth import AuthenticationService, _CACHE, _unsign
from app.common.identity import AuthenticatedUser
from config.settings import AuthSettings, auth_settings


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _token(private_key, claims, kid="local-test-key"):
    header = _b64(json.dumps({"alg": "RS256", "kid": kid}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature = private_key.sign(
        f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{header}.{payload}.{_b64(signature)}"


class AuthSettingsTests(unittest.TestCase):
    def test_entra_settings_accept_local_and_https_redirects(self):
        values = {
            "GATEWAY_AUTH_MODE": "entra",
            "GATEWAY_ENTRA_TENANT_ID": "11111111-1111-1111-1111-111111111111",
            "GATEWAY_ENTRA_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
            "GATEWAY_ENTRA_API_CLIENT_ID": "33333333-3333-3333-3333-333333333333",
            "GATEWAY_ENTRA_CLIENT_SECRET": "test-secret",
            "GATEWAY_ENTRA_REDIRECT_URIS": "http://localhost:8000/api/v1/callback,https://gateway.example/api/v1/callback",
        }
        with patch.dict(os.environ, values, clear=True):
            settings = auth_settings()
        self.assertEqual(settings.mode, "entra")
        self.assertEqual(len(settings.redirect_uris), 2)

    def test_entra_settings_reject_missing_or_nonlocal_http(self):
        values = {
            "GATEWAY_AUTH_MODE": "entra",
            "GATEWAY_ENTRA_TENANT_ID": "11111111-1111-1111-1111-111111111111",
            "GATEWAY_ENTRA_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
            "GATEWAY_ENTRA_API_CLIENT_ID": "33333333-3333-3333-3333-333333333333",
            "GATEWAY_ENTRA_CLIENT_SECRET": "test-secret",
            "GATEWAY_ENTRA_REDIRECT_URIS": "http://gateway.example/callback",
        }
        with patch.dict(os.environ, values, clear=True):
            with self.assertRaises(ValueError):
                auth_settings()

    def test_api_audience_defaults_to_web_client(self):
        values = {
            "GATEWAY_AUTH_MODE": "entra",
            "GATEWAY_ENTRA_TENANT_ID": "11111111-1111-1111-1111-111111111111",
            "GATEWAY_ENTRA_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
            "GATEWAY_ENTRA_CLIENT_SECRET": "test-secret",
            "GATEWAY_ENTRA_REDIRECT_URIS": "http://localhost/callback",
        }
        with patch.dict(os.environ, values, clear=True):
            self.assertEqual(auth_settings().api_client_id, values["GATEWAY_ENTRA_CLIENT_ID"])
        values.pop("GATEWAY_ENTRA_CLIENT_SECRET")
        with patch.dict(os.environ, values, clear=True):
            with self.assertRaises(ValueError):
                auth_settings()


class JwtValidationTests(unittest.TestCase):
    def setUp(self):
        _CACHE.clear()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self.private_key.public_key().public_numbers()
        self.settings = AuthSettings(
            mode="entra",
            tenant_id="11111111-1111-1111-1111-111111111111",
            client_id="22222222-2222-2222-2222-222222222222",
            api_client_id="33333333-3333-3333-3333-333333333333",
            client_secret="test-secret",
            redirect_uris=("http://localhost/api/v1/callback",),
        )
        self.service = AuthenticationService(self.settings)
        self.discovery = {
            "issuer": f"https://login.microsoftonline.com/{self.settings.tenant_id}/v2.0",
            "authorization_endpoint": "https://login.example/authorize",
            "token_endpoint": "https://login.example/token",
            "jwks_uri": "https://login.example/keys",
        }
        self.jwks = {"keys": [{
            "kty": "RSA", "kid": "local-test-key",
            "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }]}

    def _claims(self, **overrides):
        claims = {
            "iss": self.discovery["issuer"], "tid": self.settings.tenant_id,
            "aud": self.settings.api_client_id, "exp": time.time() + 60,
            "nbf": time.time() - 1, "oid": "user-id", "name": "Test User",
            "roles": ["Operator"],
        }
        claims.update(overrides)
        return claims

    def test_valid_local_signature_produces_authenticated_user(self):
        token = _token(self.private_key, self._claims())
        with patch.object(self.service, "_discovery", return_value=self.discovery), patch.object(
            self.service, "_jwks", return_value=self.jwks
        ):
            user = self.service._user_from_claims(
                self.service._verify_token(token, self.settings.api_client_id)
            )
        self.assertEqual(user.subject, "user-id")
        self.assertEqual(user.roles, frozenset({"Operator"}))

    def test_invalid_signature_claims_and_roles_are_rejected(self):
        cases = [
            _token(rsa.generate_private_key(public_exponent=65537, key_size=2048), self._claims()),
            _token(self.private_key, self._claims(iss="https://invalid.example")),
            _token(self.private_key, self._claims(aud="wrong-audience")),
            _token(self.private_key, self._claims(exp=time.time() - 1)),
            _token(self.private_key, self._claims(roles=["UntrustedRole"])),
        ]
        with patch.object(self.service, "_discovery", return_value=self.discovery), patch.object(
            self.service, "_jwks", return_value=self.jwks
        ):
            for token in cases:
                with self.subTest(token=token[:12]), self.assertRaises(HTTPException) as raised:
                    claims = self.service._verify_token(token, self.settings.api_client_id)
                    self.service._user_from_claims(claims)
                self.assertEqual(raised.exception.status_code, 401)

    def test_nonce_and_state_fail_closed(self):
        token = _token(self.private_key, self._claims(nonce="actual-nonce"))
        with patch.object(self.service, "_discovery", return_value=self.discovery), patch.object(
            self.service, "_jwks", return_value=self.jwks
        ):
            with self.assertRaises(HTTPException):
                self.service._verify_token(token, self.settings.client_id, nonce="expected-nonce")
        with self.assertRaises(HTTPException) as raised:
            self.service.complete_login(
                "authorization-code", "wrong-state", "invalid-flow-cookie",
            )
        self.assertEqual(raised.exception.status_code, 401)

    def test_demo_identity_fails_closed_unless_application_demo_mode_is_enabled(self):
        app = FastAPI()
        app.include_router(router)
        values = {
            "GATEWAY_AUTH_MODE": "demo", "GATEWAY_DEMO_USER_ID": "demo-user",
            "GATEWAY_DEMO_USER_NAME": "Demo User", "GATEWAY_DEMO_USER_ROLE": "Viewer",
        }
        with patch.dict(os.environ, values, clear=True):
            app.state.demo_mode = False
            with TestClient(app) as client:
                self.assertEqual(client.get("/api/v1/session").json(), {"user": None})
            app.state.demo_mode = True
            with TestClient(app) as client:
                self.assertEqual(client.get("/api/v1/session").json()["user"]["auth_mode"], "demo")

    def test_login_selects_exact_request_callback_and_callback_recovers_signed_uri(self):
        app = FastAPI()
        app.include_router(router)
        redirect_uri = "http://testserver/api/v1/callback"
        settings = AuthSettings(
            mode="entra", tenant_id=self.settings.tenant_id, client_id=self.settings.client_id,
            api_client_id=self.settings.api_client_id, client_secret="test-secret",
            redirect_uris=(redirect_uri,),
        )
        service = AuthenticationService(settings)
        user = AuthenticatedUser(
            subject="user-id", tenant_id=settings.tenant_id, name="Test User",
            email=None, roles=frozenset({"Viewer"}), auth_mode="entra",
        )
        with patch("app.api.routes.auth.AuthenticationService.from_request", return_value=service), patch.object(
            service, "_discovery", return_value=self.discovery
        ), patch.object(service, "complete_login", return_value=user) as complete:
            with TestClient(app) as client:
                response = client.get("/api/v1/login", follow_redirects=False)
                self.assertEqual(response.status_code, 302)
                self.assertIn("redirect_uri=http%3A%2F%2Ftestserver%2Fapi%2Fv1%2Fcallback", response.headers["location"])
                flow = _unsign(client.cookies.get("gateway_oidc_flow"), settings.client_secret)
                self.assertEqual(flow["redirect_uri"], redirect_uri)
                response = client.get(
                    "/api/v1/callback?code=authorization-code&state=" + flow["state"],
                    follow_redirects=False,
                )
        self.assertEqual(response.status_code, 302)
        complete.assert_called_once_with(
            "authorization-code", flow["state"], unittest.mock.ANY,
        )

    def test_login_fails_closed_when_request_callback_is_not_allowlisted(self):
        app = FastAPI()
        app.include_router(router)
        settings = AuthSettings(
            mode="entra", tenant_id=self.settings.tenant_id, client_id=self.settings.client_id,
            api_client_id=self.settings.api_client_id, client_secret="test-secret",
            redirect_uris=("http://localhost:8000/api/v1/callback",),
        )
        with patch("app.api.routes.auth.AuthenticationService.from_request", return_value=AuthenticationService(settings)):
            with TestClient(app) as client:
                self.assertEqual(client.get("/api/v1/login").status_code, 401)


if __name__ == "__main__":
    unittest.main()
