"""Management use cases; persistence and connector imports stay lazy."""

import math
import re
import time
import uuid


def resolve_correlation_id(request):
    """Use a caller-supplied X-Correlation-ID only if it is a valid UUID, else mint one."""
    header = request.headers.get("x-correlation-id") if request is not None else None
    if header:
        try:
            return str(uuid.UUID(header))
        except ValueError:
            pass
    return str(uuid.uuid4())


class ManagementError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


ERROR_MESSAGES = {
    400: "Invalid management operation.",
    401: "Device authentication failed.",
    403: "Device access was rejected.",
    404: "The requested resource was not found.",
    409: "The resource is referenced or conflicts with the current operation.",
    422: "Invalid resource configuration.",
    501: "The requested device operation is unsupported.",
    503: "Management storage is unavailable.",
}


def store_call(store, method, *args, **kwargs):
    try:
        return getattr(store, method)(*args, **kwargs)
    except Exception as exc:
        # Store/backend exception text can contain credentials or connection URLs.
        code = getattr(exc, "status_code", 500)
        if code not in ERROR_MESSAGES:
            code = 500
        raise ManagementError(
            ERROR_MESSAGES.get(code, "The management operation failed."), code
        ) from None


def run_test(profile, demo_mode=False):
    from app.bl.services.connection_tests import run_connection_test

    return run_connection_test(profile, demo_mode=demo_mode)


def capabilities():
    from app.bl.services.connection_tests import CAPABILITIES

    return CAPABILITIES


def _secrets(value):
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"password", "private_key", "key_passphrase"} and isinstance(item, str) and item:
                found.append(item)
            elif isinstance(item, (dict, list)):
                found.extend(_secrets(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_secrets(item))
    return found


def safe_test(profile, tester=run_test, demo_mode=False, *, simulated=False):
    started = time.monotonic()
    secrets = sorted(_secrets(profile), key=len, reverse=True)
    try:
        result = tester(profile, demo_mode=demo_mode)
        duration = float(result.get("duration_ms", (time.monotonic() - started) * 1000))
        if not math.isfinite(duration) or duration < 0:
            duration = (time.monotonic() - started) * 1000
        detail = str(result.get("detail", ""))
        stage = str(result.get("stage", "connection"))
        for secret in secrets:
            detail = detail.replace(secret, "[redacted]")
            stage = stage.replace(secret, "[redacted]")
        detail = re.sub(
            r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
            "[redacted]", detail, flags=re.DOTALL,
        )
        return {
            "success": result.get("success") is True,
            "simulated": simulated,
            "stage": stage[:80],
            "detail": detail[:4096],
            "duration_ms": duration,
        }
    except Exception:
        return {
            "success": False,
            "simulated": simulated,
            "stage": "internal",
            "detail": "Connection test failed.",
            "duration_ms": (time.monotonic() - started) * 1000,
        }


class ManagementService:
    def __init__(self, store, *, tester=run_test, demo_mode=False, device_data_provider="disabled"):
        self.store = store
        self.tester = tester
        self.demo_mode = demo_mode
        self.device_data_provider = device_data_provider

    def list(self, resource):
        return {"items": store_call(self.store, "list", resource)}

    def get(self, resource, item_id):
        return store_call(self.store, "get", resource, item_id)

    def save(self, resource, payload, item_id=None):
        return store_call(self.store, "save", resource, payload, item_id=item_id)

    def delete(self, resource, item_id):
        store_call(self.store, "delete", resource, item_id)

    def test(self, item_id):
        profile = store_call(self.store, "resolve_connection", item_id)
        return self.test_profile(profile)

    def check_test_provider(self, profile):
        client_type = profile.get("client_type", "network")
        if client_type not in {"network", "fake"}:
            raise ManagementError("Invalid device client type.", 422)
        if client_type == "fake" and self.device_data_provider != "fake":
            raise ManagementError("Simulated device access is disabled.", 503)

    def test_profile(self, profile):
        """Dispatch resolved profiles, including immutable batch snapshots."""
        self.check_test_provider(profile)
        if profile.get("client_type", "network") == "fake":
            from app.dal.device.fake_client import test_fake_connection

            def tester(resolved, *, demo_mode=False):
                return test_fake_connection(resolved)

            return safe_test(profile, tester, simulated=True)
        return safe_test(profile, self.tester, self.demo_mode)

    def get_config(self, name):
        return store_call(self.store, "get_config", name)

    def save_config(self, name, payload):
        return store_call(self.store, "save_config", name, payload)
