"""Orchestrates the Network Gateway API loopback demo.

Loads `demo/.env.demo`, generates/loads demo host-key trust files, seeds the
SQLite demo device table, starts the three local loopback protocol emulators
(NETCONF-over-SSH, plain SSH, generic Telnet), then runs the FastAPI gateway
itself against them.

Everything here is bound to 127.0.0.1 only; nothing leaves the machine.

Usage (from the repo root, with the project's virtualenv active):

    python -m demo.run_demo
    python -m demo.run_demo --storage-dir D:\\gateway-demo
"""

from __future__ import annotations

import sys
import argparse
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

ENV_FILE = _REPO_ROOT / "demo" / ".env.demo"


def _start_emulators(emulators: list) -> list:
    """Start each emulator in order. If any `.start()` call fails partway
    through (e.g. a port is already occupied), stop whichever emulators
    already started successfully before re-raising, so a failed startup
    never leaks a running listener/thread."""
    started: list = []
    try:
        for emulator in emulators:
            emulator.start()
            started.append(emulator)
    except Exception:
        for emulator in started:
            emulator.stop()
        raise
    return started


def _build_emulators(host_key, bastion_key) -> list:
    from demo import demo_config
    from demo.emulators.netconf_emulator import NetconfEmulator
    from demo.emulators.ssh_emulator import SSHEmulator
    from demo.emulators.telnet_emulator import TelnetEmulator
    from demo.emulators.proxy_protocols import HttpConnectPeer, Socks5Peer, SSHPeer

    host = demo_config.LOOPBACK_HOST
    credentials = (demo_config.DEMO_USERNAME, demo_config.DEMO_PASSWORD)
    proxy_credentials = {
        "username": demo_config.BASTION_USERNAME, "password": demo_config.BASTION_PASSWORD,
    }
    return [
        NetconfEmulator(host, demo_config.NETCONF_EMULATOR_PORT, host_key, *credentials),
        SSHEmulator(host, demo_config.SSH_EMULATOR_PORT, host_key, *credentials),
        TelnetEmulator(host, demo_config.TELNET_EMULATOR_PORT, *credentials),
        SSHPeer(bastion_key, bastion=True, port=demo_config.SSH_TUNNEL_EMULATOR_PORT, **proxy_credentials),
        SSHPeer(bastion_key, bastion=True, port=demo_config.SSH_SHELL_EMULATOR_PORT, **proxy_credentials),
        Socks5Peer(port=demo_config.SOCKS5_EMULATOR_PORT, **proxy_credentials),
        HttpConnectPeer(port=demo_config.HTTP_CONNECT_EMULATOR_PORT, **proxy_credentials),
    ]


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Run the isolated loopback gateway demo.")
    parser.add_argument("--storage-dir", type=Path, help="Explicit directory for both demo databases, keys and trust files.")
    args = parser.parse_args(argv)
    from demo.env_safety import prepare_demo_environment

    storage_dir = prepare_demo_environment(args.storage_dir)
    from demo.emulators.hostkeys import ensure_bastion_trust_files, ensure_demo_trust_files
    from demo.management_seed import configure_management_key, seed_management
    from app.dal.db.store import GatewayStore
    from demo.seed_demo_db import seed
    from app.dal.db import db_client

    configure_management_key(storage_dir)
    host_key = ensure_demo_trust_files(storage_dir)
    bastion_key = ensure_bastion_trust_files(storage_dir)
    started: list = []
    try:
        store = GatewayStore()
        try:
            counts = seed_management(store, storage_dir)
        finally:
            store.close()
        seed()
        started = _start_emulators(_build_emulators(host_key, bastion_key))

        print(
            f"\nDemo storage: {storage_dir}\n"
            f"Management inventory: {counts['connections']} devices, "
            f"{counts['proxies']} proxies, {counts['role_accounts']} role accounts.\n"
            "Three protocol peers and four proxy peers listening on loopback only.\n"
            "Fake transport device uses persisted fake device/proxy roles and Fake bastion; "
            "its data and connection tests are simulated without sockets.\n"
            "\nStarting Network Gateway UI/API on http://127.0.0.1:8000 ...\n"
            "Try, in another shell:\n"
            "  curl http://127.0.0.1:8000/devices/demo-router-netconf/config\n"
            "  curl http://127.0.0.1:8000/devices/demo-router-ssh/show-interface\n"
            "  curl http://127.0.0.1:8000/devices/demo-router-telnet/show-interface\n"
            "\nPress Ctrl+C to stop.\n"
        )

        import uvicorn

        from app.main import app
        from config.settings import device_data_provider

        app.state.demo_mode = True
        app.state.device_data_provider = device_data_provider()
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
    finally:
        # Covers both a fully successful run (Ctrl+C) and any failure after
        # emulators started (e.g. `app.main` import errors, uvicorn startup
        # failure): whatever is in `started` gets stopped exactly once.
        for emulator in reversed(started):
            emulator.stop()
        if db_client._engine is not None:
            db_client._engine.dispose()
            db_client._engine = None
            db_client._session_factory = None


if __name__ == "__main__":
    main()
