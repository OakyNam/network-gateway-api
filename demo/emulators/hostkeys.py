"""Generate (or reuse) a demo-only SSH host key and known_hosts/ssh_config
files for the loopback SSH and NETCONF emulators.

This exists so the gateway's *real* host-key verification code paths
(``paramiko.RejectPolicy`` and ``ncclient``'s ``hostkey_verify=True``) can be
exercised genuinely against the demo emulators, instead of being bypassed.
The host key itself is demo-only (never used for anything but 127.0.0.1
loopback emulators), generated randomly once and reused on later starts.
"""

from __future__ import annotations

import io
import os
import stat
from pathlib import Path

import paramiko

from demo import demo_config


def ensure_demo_host_key(key_path: Path | None = None) -> paramiko.ECDSAKey:
    """Load the demo host key, generating and persisting one if absent."""
    key_path = key_path or demo_config.HOST_KEY_PATH
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return paramiko.ECDSAKey.from_private_key_file(str(key_path))

    key = paramiko.ECDSAKey.generate()
    buf = io.StringIO()
    key.write_private_key(buf)
    key_path.write_text(buf.getvalue(), encoding="utf-8")
    try:
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # best-effort on platforms without POSIX permission bits
    return key


def write_known_hosts(key: paramiko.ECDSAKey, path: Path | None = None, ports=None) -> None:
    """Write a known_hosts file trusting the demo key for our loopback ports."""
    entries = []
    for port in ports or (demo_config.NETCONF_EMULATOR_PORT, demo_config.SSH_EMULATOR_PORT):
        host_pattern = f"[{demo_config.LOOPBACK_HOST}]:{port}"
        entries.append(f"{host_pattern} {key.get_name()} {key.get_base64()}")
    (path or demo_config.KNOWN_HOSTS_PATH).write_text("\n".join(entries) + "\n", encoding="utf-8")


def write_ssh_config(path: Path | None = None, known_hosts: Path | None = None) -> None:
    """Write an OpenSSH-style config so ncclient's NETCONF client looks up the
    demo known_hosts file (via UserKnownHostsFile) instead of ~/.ssh/known_hosts.
    hostkey_verify itself remains True; only the trust store location changes.
    """
    content = (
        f"Host {demo_config.LOOPBACK_HOST}\n"
        f'    UserKnownHostsFile "{(known_hosts or demo_config.KNOWN_HOSTS_PATH).as_posix()}"\n'
    )
    (path or demo_config.SSH_CONFIG_PATH).write_text(content, encoding="utf-8")


def ensure_demo_trust_files(storage_dir: Path | None = None) -> paramiko.ECDSAKey:
    """Ensure host key, known_hosts, and ssh_config all exist; return the key."""
    directory = storage_dir or demo_config.DATA_DIR
    key = ensure_demo_host_key(directory / "demo_host_key")
    known_hosts = directory / "demo_known_hosts"
    write_known_hosts(key, known_hosts)
    write_ssh_config(directory / "demo_ssh_config", known_hosts)
    return key


def ensure_bastion_trust_files(storage_dir: Path) -> paramiko.ECDSAKey:
    """Use an independent key and trust file for the two SSH bastions."""
    key = ensure_demo_host_key(storage_dir / "demo_bastion_host_key")
    write_known_hosts(
        key, storage_dir / "demo_bastion_known_hosts",
        (demo_config.SSH_TUNNEL_EMULATOR_PORT, demo_config.SSH_SHELL_EMULATOR_PORT),
    )
    return key


if __name__ == "__main__":
    ensure_demo_trust_files()
    print(f"Demo host key:    {demo_config.HOST_KEY_PATH}")
    print(f"Demo known_hosts: {demo_config.KNOWN_HOSTS_PATH}")
    print(f"Demo ssh_config:  {demo_config.SSH_CONFIG_PATH}")
