"""Fictional device data authenticated through persisted role and proxy references."""

from copy import deepcopy

from app.dal.db.storage import StoreError


FAKE_DEVICE_ROLE_NAME = "Fake device login"
FAKE_PROXY_ROLE_NAME = "Fake proxy login"
FAKE_PROXY_NAME = "Fake bastion"
FAKE_CONNECTION_NAME = "Fake transport device"
FAKE_DEVICE_USERNAME = "fake-device-user"
FAKE_DEVICE_PASSWORD = "fake-device-password"
FAKE_DEVICE_HOST = "fake-device.invalid"
FAKE_DEVICE_PORT = 22
FAKE_DEVICE_PROTOCOL = "ssh"
FAKE_PROXY_USERNAME = "fake-proxy-user"
FAKE_PROXY_PASSWORD = "fake-proxy-password"
FAKE_PROXY_HOST = "fake-bastion.invalid"
FAKE_PROXY_PORT = 22
FAKE_PROXY_TYPE = "ssh_tunnel"

_INVENTORY = {
    "system": {
        "hostname": "fictional-transport-device", "model": "Fictional Gateway Simulator",
        "software_version": "SIMULATED-1.0", "serial_number": "FICTIONAL-0001",
        "uptime_seconds": 86400,
    },
    "interfaces": [
        {"name": "eth0", "description": "Simulated IPv4 uplink", "admin_status": "up",
         "oper_status": "up", "mtu": 1500, "mac_address": "02:00:00:00:00:01",
         "addresses": ["192.0.2.2/24"], "rx_bytes": 120000, "tx_bytes": 80000},
        {"name": "eth1", "description": "Simulated IPv6 uplink", "admin_status": "up",
         "oper_status": "up", "mtu": 1500, "mac_address": "02:00:00:00:00:02",
         "addresses": ["2001:db8:1::2/64"], "rx_bytes": 90000, "tx_bytes": 60000},
        {"name": "lo", "description": "Simulated loopback", "admin_status": "up",
         "oper_status": "up", "mtu": 65536, "mac_address": "00:00:00:00:00:00",
         "addresses": ["203.0.113.10/32"], "rx_bytes": 1000, "tx_bytes": 1000},
    ],
    "bgp": {
        "local_asn": 64512, "router_id": "203.0.113.10",
        "neighbors": [
            {"address": "192.0.2.1", "remote_asn": 64513, "state": "Established",
             "uptime_seconds": 3600, "prefixes_received": 2, "prefixes_sent": 1},
        ],
    },
    "mpls": {
        "interfaces": [{"name": "eth0", "enabled": True}, {"name": "eth1", "enabled": False}],
        "ldp_neighbors": [
            {"router_id": "203.0.113.1", "address": "192.0.2.1", "state": "Operational",
             "uptime_seconds": 3600},
        ],
        "lsps": [
            {"name": "simulated-lsp", "source": "203.0.113.10", "destination": "203.0.113.1",
             "state": "up", "label": 16001},
        ],
    },
}


def _validate_fake_path(profile):
    if profile.get("client_type", "network") != "fake":
        raise StoreError("Device-data simulation requires a fake connection.", 501)
    connector = profile.get("connector")
    if not isinstance(connector, dict):
        raise StoreError("Simulated proxy access validation failed.", 403)
    if (not profile.get("id") or not profile.get("role_account_id")
            or profile.get("protocol") != FAKE_DEVICE_PROTOCOL
            or profile.get("host") != FAKE_DEVICE_HOST
            or type(profile.get("port")) is not int or profile["port"] != FAKE_DEVICE_PORT
            or profile.get("authentication_type") != "password"
            or profile.get("username") != FAKE_DEVICE_USERNAME
            or profile.get("password") != FAKE_DEVICE_PASSWORD):
        raise StoreError("Simulated device access validation failed.", 403)
    if (not profile.get("proxy_id") or connector.get("id") != profile["proxy_id"]
            or not connector.get("role_account_id")
            or connector.get("type") != FAKE_PROXY_TYPE
            or connector.get("host") != FAKE_PROXY_HOST
            or type(connector.get("port")) is not int or connector["port"] != FAKE_PROXY_PORT
            or connector.get("authentication_type") != "password"
            or connector.get("username") != FAKE_PROXY_USERNAME
            or connector.get("password") != FAKE_PROXY_PASSWORD):
        raise StoreError("Simulated proxy access validation failed.", 403)


def test_fake_connection(resolved_profile):
    """Validate an immutable resolved job snapshot without opening a transport."""
    try:
        _validate_fake_path(resolved_profile)
    except StoreError as exc:
        return {"success": False, "stage": "simulation", "detail": str(exc),
                "duration_ms": 0.0, "simulated": True}
    return {"success": True, "stage": "simulation",
            "detail": "Simulated device and proxy authentication passed; no network connection was made.",
            "duration_ms": 0.0, "simulated": True}


class FakeDeviceClient:
    def __init__(self, store, connection_id):
        self.store = store
        self.connection_id = connection_id

    def _profile(self):
        profile = self.store.resolve_connection(self.connection_id)
        _validate_fake_path(profile)
        return profile

    def inventory(self):
        profile = self._profile()
        return {
            "provider": "fake", "simulated": True,
            "device": {key: profile[key] for key in ("id", "name", "protocol", "host", "port")},
            "access": {
                "role_account_id": profile["role_account_id"], "proxy_id": profile["proxy_id"],
                "proxy_role_account_id": profile["connector"]["role_account_id"],
                "connector_type": profile["connector"]["type"],
            },
            **deepcopy(_INVENTORY),
        }

    def list_static_routes(self):
        self._profile()
        return self.store.list_static_routes(self.connection_id)

    def create_static_route(self, payload, *, audit=None):
        self._profile()
        if audit is not None:
            return self.store.create_static_route_audited(self.connection_id, payload, audit)
        return self.store.create_static_route(self.connection_id, payload)

    def update_static_route(self, route_id, payload, *, audit=None):
        self._profile()
        if audit is not None:
            return self.store.update_static_route_audited(self.connection_id, route_id, payload, audit)
        return self.store.update_static_route(self.connection_id, route_id, payload)

    def delete_static_route(self, route_id, *, audit=None):
        self._profile()
        if audit is not None:
            self.store.delete_static_route_audited(self.connection_id, route_id, audit)
        else:
            self.store.delete_static_route(self.connection_id, route_id)
