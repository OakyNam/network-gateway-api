"""Shared credential resolution for device clients.

Per-device credentials (e.g. from the demo SQLite profile) take precedence over
the global environment defaults so operators can override credentials per
device without code changes. Callers must never log the returned values.
"""

from typing import Any, Dict

from decouple import config


def resolve_credentials(router_info: Dict[str, Any]) -> Dict[str, str]:
    """Resolve username/password for a device.

    Looks up ``username``/``password`` on the device metadata first (e.g. a
    per-device row from the configured DB table); falls back to the global
    ``ROUTER_USERNAME``/``ROUTER_PASSWORD`` environment configuration.
    """
    username = router_info.get("username") or str(config("ROUTER_USERNAME"))
    password = router_info.get("password") or str(config("ROUTER_PASSWORD"))
    return {"username": str(username), "password": str(password)}
