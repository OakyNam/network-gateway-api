"""Reject inherited production storage and obsolete JSON mapping overrides.

Demo entrypoints validate before creating files, databases or listeners.
Mapping configuration lives in the isolated gateway database, not JSON files.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from config.settings import device_data_provider
from demo import demo_config


class DemoSafetyError(RuntimeError):
    """Raised when the effective environment is not a safe, isolated demo
    environment. Callers must not catch this to "fall back" to production
    settings - it means abort."""


def load_demo_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from `demo/.env.demo` into os.environ without
    overriding a value the caller/shell already exported.

    This alone does NOT make the environment safe: an inherited production
    value survives untouched. Every entrypoint must follow this with
    `validate_demo_environment()`, which fails closed instead of silently
    running against whatever was inherited.
    """
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def _resolve(path_str: str) -> Path:
    return Path(path_str).expanduser().resolve()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_demo_environment(storage_dir: Path | None = None) -> None:
    """Validate that the *current* process environment is a safe, isolated
    demo environment. Raises `DemoSafetyError` (with every failing check
    listed) if not. Must be called after loading `demo/.env.demo` and before
    any DB session, file write, or socket bind happens.
    """
    problems: List[str] = []

    try:
        provider = device_data_provider()
    except ValueError as error:
        problems.append(str(error))
    else:
        if provider != "fake":
            problems.append(
                "GATEWAY_DEVICE_DATA_PROVIDER must be 'fake' for the demo; "
                "unset the inherited setting to use the explicit demo opt-in."
            )

    backend = str(os.environ.get("DB_BACKEND", "")).strip().lower()
    if backend != "sqlite":
        problems.append(
            "DB_BACKEND must be 'sqlite' for the demo (found "
            f"{backend!r}). The demo refuses to run against a non-SQLite "
            "backend - it will not silently target a real/production "
            "database."
        )

    sqlite_path = os.environ.get("DB_SQLITE_PATH", "").strip()
    if sqlite_path:
        resolved = _resolve(sqlite_path)
        allowed_dir = (storage_dir or demo_config.DATA_DIR).resolve()
        if not _is_within(resolved, allowed_dir):
            problems.append(
                f"DB_SQLITE_PATH ({resolved}) must live under "
                f"{allowed_dir} (explicit demo storage). Refusing to "
                "seed/open a SQLite file outside the demo's own data "
                "directory."
            )

    for env_var in ("DB_CLIENT_CONFIG_PATH", "CLIENT_CONFIG_PATH", "PROXY_CONFIG_PATH"):
        if env_var in os.environ:
            problems.append(
                f"Unset obsolete {env_var}; demo mappings are stored in the gateway database."
            )

    if demo_config.LOOPBACK_HOST != "127.0.0.1":
        problems.append(
            "demo_config.LOOPBACK_HOST must be 127.0.0.1; refusing to bind "
            "demo emulators to a non-loopback address."
        )
    for device in demo_config.DEMO_DEVICES:
        if device.get("host") != demo_config.LOOPBACK_HOST:
            problems.append(
                f"Demo device {device.get('hostname')!r} targets host "
                f"{device.get('host')!r} instead of the loopback address."
            )

    if problems:
        raise DemoSafetyError(
            "Refusing to run the Network Gateway API demo - the effective "
            "environment is not a safe, isolated demo environment:\n- "
            + "\n- ".join(problems)
        )


def prepare_demo_environment(storage_dir: Path | None = None) -> Path:
    """Validate inherited settings before selecting an explicitly opted-in path.

    No files, keys, databases or listeners are created here. External storage
    can only enter through the CLI argument, never ambient gateway settings.
    """
    for name in (
        "GATEWAY_DATABASE_URL", "GATEWAY_SQLITE_PATH", "GATEWAY_SECRET_KEY",
        "GATEWAY_SECRET_KEY_FILE", "GATEWAY_DEMO_STORAGE_DIR", "DATABASE_URL",
        "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
    ):
        if os.environ.get(name, "").strip():
            raise DemoSafetyError(f"Unset inherited {name} before starting the isolated demo.")
    for name in ("DB_CLIENT_CONFIG_PATH", "CLIENT_CONFIG_PATH", "PROXY_CONFIG_PATH"):
        if name in os.environ:
            raise DemoSafetyError(f"Unset obsolete {name}; JSON mapping overrides are no longer supported.")
    if os.environ.get("GATEWAY_DEMO_MODE", "true").lower() not in {"true", "1"}:
        raise DemoSafetyError("GATEWAY_DEMO_MODE cannot disable demo safety.")
    if os.environ.get("ROUTER_NETCONF_HOSTKEY_VERIFY", "true").lower() != "true":
        raise DemoSafetyError("The demo requires NETCONF host-key verification.")

    load_demo_env_file(demo_config.DEMO_ROOT / ".env.demo")
    validate_demo_environment()
    for name, expected in (
        ("ROUTER_KNOWN_HOSTS_PATH", demo_config.KNOWN_HOSTS_PATH),
        ("ROUTER_SSH_CONFIG_PATH", demo_config.SSH_CONFIG_PATH),
    ):
        if _resolve(os.environ.get(name, str(expected))) != expected.resolve():
            raise DemoSafetyError(f"Unset inherited {name}; demo trust is locally generated.")
    chosen = (storage_dir or demo_config.DATA_DIR).expanduser()
    if str(chosen).startswith(("\\\\", "//")):
        raise DemoSafetyError("--storage-dir must be local, not a UNC/network path.")
    target = chosen.resolve()
    if str(target).startswith(("\\\\", "//")):
        raise DemoSafetyError("--storage-dir must resolve to a local directory.")
    if target.exists() and not target.is_dir():
        raise DemoSafetyError("--storage-dir must designate a directory.")
    os.environ.update({
        "DB_SQLITE_PATH": str(target / "demo_devices.sqlite3"),
        "GATEWAY_SQLITE_PATH": str(target / "gateway.sqlite3"),
        "GATEWAY_DEMO_MODE": "true",
        "GATEWAY_DEMO_STORAGE_DIR": str(target),
        "ROUTER_KNOWN_HOSTS_PATH": str(target / "demo_known_hosts"),
        "ROUTER_SSH_CONFIG_PATH": str(target / "demo_ssh_config"),
    })
    validate_demo_environment(storage_dir=target)
    return target
