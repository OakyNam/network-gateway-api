"""Non-destructive management inventory for the isolated loopback demo."""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet

from app.dal.db.store import StoreError
from app.dal.device import fake_client
from demo import demo_config as config
from demo.env_safety import DemoSafetyError


def configure_management_key(storage_dir: Path) -> str:
    key_path = storage_dir / "gateway.key"
    if not key_path.exists():
        if (storage_dir / "gateway.sqlite3").exists():
            raise DemoSafetyError("Demo database exists but gateway.key is missing; restore its original key.")
        storage_dir.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(Fernet.generate_key())
    try:
        key = key_path.read_text(encoding="ascii").strip()
        Fernet(key)
    except (ValueError, UnicodeError):
        raise DemoSafetyError("The demo gateway.key is not a valid encryption key.") from None
    os.environ["GATEWAY_SECRET_KEY"] = key
    return key


def seed_demo_settings(store) -> None:
    """Create missing legacy mappings without replacing operator edits."""
    settings = {
        "client_mapping": {
            "key_columns": ["vendor", "protocol"],
            "map": {
                "demo-juniper:netconf": "app.dal.device.nccclient_juniper.JuniperNCCClient",
                "demo-ios:ssh": "app.dal.device.nccclient_ios.IOSNCCClient",
                "demo-generic:telnet": "app.dal.device.telnet_client.GenericTelnetNCCClient",
            },
        },
        "proxy_mapping": {"key_columns": ["owner"], "map": {}},
        "device_lookup": {"table": "devices", "search_column": "hostname"},
    }
    for name, payload in settings.items():
        try:
            existing = store.get_config(name)
        except StoreError as error:
            if error.status_code != 404:
                raise
            existing = None
        if existing is None:
            store.save_config(name, payload)


def seed_management(store, storage_dir: Path) -> dict:
    """Insert absent demo profiles; retain IDs, renames, secrets and edits."""
    seed_demo_settings(store)
    manifest_path = storage_dir / "management_seed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    if not isinstance(manifest, dict):
        raise DemoSafetyError("Invalid demo seed manifest.")
    inventory = {resource: store.list(resource) for resource in ("role_accounts", "proxies", "connections")}

    def ensure(resource, slot, payload):
        candidates = inventory[resource]
        existing = next((row for row in candidates if row["id"] == manifest.get(slot)), None)
        if existing is None:
            existing = next((row for row in candidates if row["name"] == payload["name"]), None)
        row = existing or store.save(resource, payload)
        if existing is None:
            candidates.append(row)
        manifest[slot] = row["id"]
        return row["id"]

    device_role = ensure("role_accounts", "device_role", {
        "name": "Demo device login", "username": config.DEMO_USERNAME,
        "authentication_type": "password", "password": config.DEMO_PASSWORD,
    })
    bastion_role = ensure("role_accounts", "bastion_role", {
        "name": "Demo bastion login", "username": config.BASTION_USERNAME,
        "authentication_type": "password", "password": config.BASTION_PASSWORD,
    })
    proxy_ids = {}
    for connector_type, port in (
        ("ssh_tunnel", config.SSH_TUNNEL_EMULATOR_PORT),
        ("ssh_shell", config.SSH_SHELL_EMULATOR_PORT),
        ("socks5", config.SOCKS5_EMULATOR_PORT),
        ("http_connect", config.HTTP_CONNECT_EMULATOR_PORT),
    ):
        payload = {
            "name": f"Demo {connector_type}", "type": connector_type,
            "host": config.LOOPBACK_HOST, "port": port, "role_account_id": bastion_role,
        }
        if connector_type.startswith("ssh_"):
            payload["known_hosts_path"] = str(storage_dir / "demo_bastion_known_hosts")
        proxy_ids[connector_type] = ensure("proxies", connector_type, payload)

    profiles = (
        ("Direct SSH", "ssh", config.SSH_EMULATOR_PORT, None),
        ("Direct NETCONF", "netconf", config.NETCONF_EMULATOR_PORT, None),
        ("Direct Telnet", "telnet", config.TELNET_EMULATOR_PORT, None),
        ("SSH tunnel NETCONF", "netconf", config.NETCONF_EMULATOR_PORT, "ssh_tunnel"),
        ("SSH shell Telnet", "telnet", config.TELNET_EMULATOR_PORT, "ssh_shell"),
        ("SOCKS5 SSH", "ssh", config.SSH_EMULATOR_PORT, "socks5"),
        ("HTTP CONNECT Telnet", "telnet", config.TELNET_EMULATOR_PORT, "http_connect"),
    )
    for name, protocol, port, proxy in profiles:
        payload = {
            "name": f"Demo {name}", "client_type": "network",
            "protocol": protocol, "host": config.LOOPBACK_HOST,
            "port": port, "timeout_seconds": 8, "role_account_id": device_role,
            "proxy_id": proxy_ids[proxy] if proxy else None,
            "known_hosts_path": str(storage_dir / "demo_known_hosts"),
        }
        if proxy is None:
            payload["connector"] = {"type": "direct"}
        ensure("connections", name, payload)

    fake_device_role = ensure("role_accounts", "fake_device_role", {
        "name": fake_client.FAKE_DEVICE_ROLE_NAME, "username": fake_client.FAKE_DEVICE_USERNAME,
        "authentication_type": "password", "password": fake_client.FAKE_DEVICE_PASSWORD,
    })
    fake_proxy_role = ensure("role_accounts", "fake_proxy_role", {
        "name": fake_client.FAKE_PROXY_ROLE_NAME, "username": fake_client.FAKE_PROXY_USERNAME,
        "authentication_type": "password", "password": fake_client.FAKE_PROXY_PASSWORD,
    })
    fake_proxy = ensure("proxies", "fake_bastion", {
        "name": fake_client.FAKE_PROXY_NAME, "type": fake_client.FAKE_PROXY_TYPE,
        "host": fake_client.FAKE_PROXY_HOST, "port": fake_client.FAKE_PROXY_PORT,
        "role_account_id": fake_proxy_role,
    })
    ensure("connections", "fake_device", {
        "name": fake_client.FAKE_CONNECTION_NAME, "client_type": "fake",
        "protocol": fake_client.FAKE_DEVICE_PROTOCOL, "host": fake_client.FAKE_DEVICE_HOST,
        "port": fake_client.FAKE_DEVICE_PORT, "timeout_seconds": 8,
        "role_account_id": fake_device_role, "proxy_id": fake_proxy,
    })
    pending = manifest_path.with_suffix(".json.new")
    pending.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    pending.replace(manifest_path)
    return {resource: len(rows) for resource, rows in inventory.items()}
