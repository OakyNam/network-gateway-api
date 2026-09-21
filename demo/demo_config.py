"""Shared constants for the Network Gateway API loopback demo.

Single source of truth for demo ports, hostnames, and fake credentials so the
seed script, emulators, and orchestrator stay consistent. All values here are
fake/demo-only; nothing is a real secret.
"""

from pathlib import Path

DEMO_ROOT = Path(__file__).resolve().parent
DATA_DIR = DEMO_ROOT / "data"

SQLITE_PATH = DATA_DIR / "demo_devices.sqlite3"
HOST_KEY_PATH = DATA_DIR / "demo_host_key"
KNOWN_HOSTS_PATH = DATA_DIR / "demo_known_hosts"
SSH_CONFIG_PATH = DATA_DIR / "demo_ssh_config"

LOOPBACK_HOST = "127.0.0.1"

NETCONF_EMULATOR_PORT = 8830
SSH_EMULATOR_PORT = 8822
TELNET_EMULATOR_PORT = 8023
SSH_TUNNEL_EMULATOR_PORT = 8823
SSH_SHELL_EMULATOR_PORT = 8824
SOCKS5_EMULATOR_PORT = 1080
HTTP_CONNECT_EMULATOR_PORT = 8888

# Fake, demo-only credentials. Never used against real equipment.
DEMO_USERNAME = "demo-fake-user"
DEMO_PASSWORD = "demo-fake-pass"
BASTION_USERNAME = "demo-fake-proxy-user"
BASTION_PASSWORD = "demo-fake-proxy-pass"

DEMO_DEVICES = [
    {
        "hostname": "demo-router-netconf",
        "vendor": "demo-juniper",
        "software": "demo",
        "protocol": "netconf",
        "host": LOOPBACK_HOST,
        "netconf_port": NETCONF_EMULATOR_PORT,
        "username": DEMO_USERNAME,
        "password": DEMO_PASSWORD,
        "notes": "Real ncclient/paramiko NETCONF-over-SSH session against a local emulator.",
    },
    {
        "hostname": "demo-router-ssh",
        "vendor": "demo-ios",
        "software": "demo",
        "protocol": "ssh",
        "host": LOOPBACK_HOST,
        "ssh_port": SSH_EMULATOR_PORT,
        "username": DEMO_USERNAME,
        "password": DEMO_PASSWORD,
        "notes": "Real paramiko SSH exec_command session against a local emulator.",
    },
    {
        "hostname": "demo-router-telnet",
        "vendor": "demo-generic",
        "software": "demo",
        "protocol": "telnet",
        "host": LOOPBACK_HOST,
        "telnet_port": TELNET_EMULATOR_PORT,
        "username": DEMO_USERNAME,
        "password": DEMO_PASSWORD,
        "notes": (
            "Generic simulated Telnet login shell. Not a Lucent DDM2200 emulation: "
            "no DDM2200 authentication details or command syntax were supplied, so "
            "none are emulated here."
        ),
    },
]
