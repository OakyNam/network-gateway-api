"""Transactional gateway inventory and encrypted, immutable job snapshots."""

import ipaddress
import math
import os
import re
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import and_, delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.dal.db.secrets import (
    SECRET_FIELDS, SecretError, SecretVault, credential_values, public_fields,
    redact, validate_private_key,
)
from app.dal.db.storage import (
    TABLES, StoreError, build_engine, configurations, configured_url, connections, gateway_transactions, jobs,
    metadata, proxies, role_accounts, static_route_initializations, static_routes,
)


_GATEWAY_ROLES = frozenset({"Viewer", "Operator", "Administrator"})
_AUTH_MODES = frozenset({"entra", "demo"})
_TRANSACTION_OUTCOMES = frozenset({"succeeded", "failed"})
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Defense-in-depth: redact by key name (even for fields secrets.py does not know about)
# and by value pattern, so secrets accidentally passed through before/after state or
# free-text audit detail never reach durable storage.
_SENSITIVE_KEY_NAMES = SECRET_FIELDS | {
    "secret", "secrets", "token", "access_token", "refresh_token", "id_token", "authorization",
    "client_secret", "api_key", "apikey", "connection_string", "database_url", "db_url", "dsn",
}
_SENSITIVE_KEY_RE = re.compile(
    r"(password|passphrase|secret|token|private[_-]?key|api[_-]?key|authorization|"
    r"credential|connection[_-]?string|database[_-]?url|db[_-]?url|dsn)", re.IGNORECASE,
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9\-_.=]+", re.IGNORECASE)
_PEM_KEY_RE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\$)", re.DOTALL)


def _redact_text(value):
    value = _BEARER_RE.sub("Bearer [redacted]", value)
    value = _PEM_KEY_RE.sub("[redacted]", value)
    return value[:4000]


def _redact_recursive(value):
    """Recursively strip sensitive keys/values from audit before/after state and detail."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in _SENSITIVE_KEY_NAMES or _SENSITIVE_KEY_RE.search(key_text):
                redacted[key] = "[redacted]"
            else:
                redacted[key] = _redact_recursive(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact_recursive(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


_PROXY_TYPES = {"ssh_tunnel", "ssh_shell", "socks5", "http_connect"}
_INLINE_FIELDS = {"username", "password", "private_key", "private_key_path", "key_passphrase"}
_COMMON = {"name", "host", "port", "username", "password", "private_key_path",
           "known_hosts_path", "role_account_id"}
_FIELDS = {
    "role_accounts": {"name", "username", "authentication_type", "password", "private_key", "key_passphrase"},
    "proxies": _COMMON | {"type"},
    "connections": _COMMON | {"protocol", "timeout_seconds", "proxy_id", "connector", "client_type"},
}
_CONNECTOR_FIELDS = {
    "type", "host", "port", "username", "password", "private_key_path", "known_hosts_path",
    "private_key", "key_passphrase", "timeout_seconds",
}

CONFIG_NAMES = frozenset({"device_lookup", "client_mapping", "proxy_mapping"})
CLIENT_CLASSES = frozenset({
    "app.dal.device.nccclient_adva.AdvaFSP114ProNCCClient",
    "app.dal.device.nccclient_alcatel.AlcatelNCCClient",
    "app.dal.device.nccclient_ceina.CeinaNCCClient",
    "app.dal.device.nccclient_ios.IOSNCCClient",
    "app.dal.device.nccclient_iox.IOXNCCClient",
    "app.dal.device.nccclient_juniper.JuniperNCCClient",
    "app.dal.device.telnet_client.GenericTelnetNCCClient",
})


def validate_config(name, payload):
    """Validate credential-free operational mappings before reads and writes."""
    if not isinstance(name, str) or name not in CONFIG_NAMES:
        raise StoreError("Unknown configuration name.", 404)
    if not isinstance(payload, dict):
        raise StoreError("Configuration must be an object.")

    def identifier(value):
        return (isinstance(value, str) and len(value) <= 128 and value.lower() != "none"
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value))

    if name == "device_lookup":
        if set(payload) != {"table", "search_column"} or not all(identifier(v) for v in payload.values()):
            raise StoreError("Device lookup requires valid table and search_column identifiers.")
        return dict(payload)
    if set(payload) != {"key_columns", "map"}:
        raise StoreError("Mapping requires only key_columns and map.")
    columns, mappings = payload["key_columns"], payload["map"]
    if (not isinstance(columns, list) or not 1 <= len(columns) <= 8
            or not all(identifier(column) for column in columns) or len(set(columns)) != len(columns)):
        raise StoreError("Mapping key_columns must contain unique metadata identifiers.")
    if not isinstance(mappings, dict) or len(mappings) > 1000 or (name == "client_mapping" and not mappings):
        raise StoreError("Invalid mapping entries.")
    for key, value in mappings.items():
        if (not isinstance(key, str) or not key or len(key) > 255 or key != key.lower()
                or any(ord(char) < 32 for char in key)):
            raise StoreError("Mapping keys must be nonempty lowercase strings.")
        if name == "client_mapping":
            if not isinstance(value, str) or value not in CLIENT_CLASSES:
                raise StoreError("Client mapping must select a supported gateway client class.")
        elif value is not None and (
            not isinstance(value, str) or len(value) > 255
            or not re.fullmatch(r"[A-Za-z0-9_.:-]+", value)
        ):
            raise StoreError("Proxy mappings accept only hostnames, IP addresses, or null for direct access.")
    return {"key_columns": list(columns), "map": dict(mappings)}


class GatewayStore:
    def __init__(self, database_url=None, sqlite_path=None, secret_key=None):
        self._lock = threading.RLock()
        self._closed = False
        key = secret_key if secret_key is not None else os.environ.get("GATEWAY_SECRET_KEY")
        if not key:
            raise StoreError("GATEWAY_SECRET_KEY is required for encrypted credential storage.", 503)
        try:
            self._vault = SecretVault(key)
        except SecretError as exc:
            raise StoreError(str(exc), 503) from None
        self.engine = None
        try:
            self.engine = build_engine(configured_url(database_url, sqlite_path))
            metadata.create_all(self.engine)
            with self._transaction() as db:
                # Detect a wrong key before marking any pending work interrupted.
                for table, column in ((role_accounts, "secrets"), (proxies, "secrets"),
                                      (connections, "secrets"), (jobs, "snapshot")):
                    for value in db.execute(select(table.c[column])).scalars():
                        self._vault.decrypt(value)
                db.execute(update(jobs).where(jobs.c.active_slot == 1).values(
                    status="failed", active_slot=None,
                    error="Interrupted by gateway restart.",
                ))
        except StoreError:
            if self.engine is not None:
                self.engine.dispose()
            raise
        except Exception:
            if self.engine is not None:
                self.engine.dispose()
            raise StoreError("Gateway database initialization failed.", 503) from None

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self._closed:
                raise StoreError("Gateway store is closed.", 503)
            try:
                with self.engine.begin() as db:
                    yield db
            except StoreError:
                raise
            except SecretError as exc:
                raise StoreError(str(exc), 503) from None
            except IntegrityError:
                raise StoreError("Operation conflicts with a reference or an active job.", 409) from None
            except SQLAlchemyError:
                raise StoreError("Gateway database operation failed.", 503) from None

    @staticmethod
    def _table(resource):
        if not isinstance(resource, str) or resource not in TABLES:
            raise StoreError("Unknown resource.", 404)
        return TABLES[resource]

    @staticmethod
    def _row(db, table, item_id, lock=False):
        statement = select(table).where(table.c.id == item_id)
        if lock:
            statement = statement.with_for_update()
        row = db.execute(statement).mappings().first()
        if row is None:
            raise StoreError("Resource not found.", 404)
        return dict(row)

    @staticmethod
    def _text(value, label, required=False, limit=255):
        if not isinstance(value, str) or len(value) > limit or "\x00" in value:
            raise StoreError("Invalid " + label + ".")
        if required and not value.strip():
            raise StoreError(label.capitalize() + " is required.")
        return value.strip() if required else value

    @staticmethod
    def _port(value):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise StoreError("Port must be an integer between 1 and 65535.")
        return value

    @staticmethod
    def _timeout(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= value <= 30:
            raise StoreError("Timeout must be between 1 and 30 seconds.")
        return value

    @staticmethod
    def _check_fields(payload, allowed):
        if not isinstance(payload, dict) or any(key not in allowed for key in payload):
            raise StoreError("Invalid or unsupported profile fields.")

    def _stored_profile(self, row):
        result = {key: value for key, value in row.items() if key not in {"secrets", "configuration"}}
        result.update(row.get("configuration", {}))
        secrets = self._vault.decrypt(row["secrets"])
        connector_secrets = secrets.pop("connector", None)
        result.update(secrets)
        if connector_secrets:
            result.setdefault("connector", {}).update(connector_secrets)
        return result

    def _role_credentials(self, db, role_id):
        role = self._row(db, role_accounts, role_id)
        return {"username": role["username"], "authentication_type": role["authentication_type"],
                **self._vault.decrypt(role["secrets"])}

    def _resolve_proxy(self, db, row):
        profile = self._stored_profile(row)
        if profile.get("role_account_id"):
            profile.update(self._role_credentials(db, profile["role_account_id"]))
        return profile

    def _resolve_connection(self, db, item_id):
        profile = self._stored_profile(self._row(db, connections, item_id))
        profile.setdefault("client_type", "network")
        if profile.get("role_account_id"):
            profile.update(self._role_credentials(db, profile["role_account_id"]))
        if profile.get("proxy_id"):
            profile["connector"] = self._resolve_proxy(db, self._row(db, proxies, profile["proxy_id"]))
        profile.setdefault("connector", {"type": "direct"})
        return profile

    @staticmethod
    def _public_runtime(profile):
        result = public_fields(profile)
        result["password_configured"] = bool(profile.get("password"))
        if "connector" in profile:
            result["connector"] = GatewayStore._public_runtime(profile["connector"])
        return result

    def _public(self, db, resource, row):
        if resource == "role_accounts":
            secrets = self._vault.decrypt(row["secrets"])
            return {key: row[key] for key in ("id", "name", "username", "authentication_type")} | {
                "password_configured": bool(secrets.get("password")),
                "private_key_configured": bool(secrets.get("private_key")),
            }
        profile = (self._resolve_connection(db, row["id"]) if resource == "connections"
                   else self._resolve_proxy(db, row))
        return self._public_runtime(profile)

    def list(self, resource):
        table = self._table(resource)
        with self._transaction() as db:
            rows = db.execute(select(table).order_by(table.c.name, table.c.id)).mappings().all()
            return [self._public(db, resource, dict(row)) for row in rows]

    def get(self, resource, item_id):
        table = self._table(resource)
        with self._transaction() as db:
            return self._public(db, resource, self._row(db, table, item_id))

    def get_config(self, name):
        if not isinstance(name, str) or name not in CONFIG_NAMES:
            raise StoreError("Unknown configuration name.", 404)
        with self._transaction() as db:
            payload = db.execute(select(configurations.c.payload).where(configurations.c.name == name)).scalar_one_or_none()
            if payload is None:
                raise StoreError("Required database configuration is missing.", 404)
            return validate_config(name, payload)

    def save_config(self, name, payload):
        validated = validate_config(name, payload)
        with self._transaction() as db:
            from sqlalchemy.dialects.postgresql import insert as postgres_insert
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert
            dialect_insert = sqlite_insert if db.dialect.name == "sqlite" else postgres_insert
            statement = dialect_insert(configurations).values(name=name, payload=validated)
            db.execute(statement.on_conflict_do_update(
                index_elements=[configurations.c.name], set_={"payload": validated},
            ))
        return validated

    def _save_role(self, payload, previous):
        profile = {**previous, **payload}
        name = self._text(profile.get("name"), "name", True, 200)
        username = self._text(profile.get("username"), "username", True)
        method = profile.get("authentication_type")
        if method not in ("password", "ssh_key"):
            raise StoreError("Authentication type must be password or ssh_key.")
        for key in ("password", "private_key", "key_passphrase"):
            if key in payload:
                self._text(payload[key], "credential", limit=65536)
        switched = previous.get("authentication_type") != method
        if method == "password":
            if payload.get("private_key") or payload.get("key_passphrase"):
                raise StoreError("Password authentication cannot include SSH key credentials.")
            password = payload.get("password") if switched else profile.get("password")
            if not password:
                raise StoreError("Password authentication requires a password.")
            secrets = {"password": password}
        else:
            if payload.get("password"):
                raise StoreError("SSH key authentication cannot include a password.")
            private_key = payload.get("private_key") if switched else profile.get("private_key")
            passphrase = payload.get("key_passphrase", "" if switched else previous.get("key_passphrase", ""))
            if not private_key:
                raise StoreError("SSH key authentication requires a private key.")
            try:
                validate_private_key(private_key, passphrase)
            except SecretError as exc:
                raise StoreError(str(exc)) from None
            secrets = {"private_key": private_key}
            if passphrase:
                secrets["key_passphrase"] = passphrase
        return {"name": name, "username": username, "authentication_type": method,
                "secrets": self._vault.encrypt(secrets)}

    def _inline_credentials(self, profile, payload):
        for key in _INLINE_FIELDS | {"known_hosts_path"}:
            if key in payload:
                if key in {"private_key_path", "known_hosts_path"} and payload[key] is None:
                    profile.pop(key, None)
                    continue
                self._text(payload[key], "credential or trust field", limit=65536)
        if profile.get("password") and (profile.get("private_key_path") or profile.get("private_key")):
            raise StoreError("Choose password or SSH key authentication, not both.")
        if profile.get("key_passphrase") and not (profile.get("private_key_path") or profile.get("private_key")):
            raise StoreError("A key passphrase requires an SSH key.")

    def _connector(self, value, previous=None):
        self._check_fields(value, _CONNECTOR_FIELDS)
        profile = {**(previous or {}), **value}
        kind = profile.get("type", "direct")
        if not isinstance(kind, str) or kind not in _PROXY_TYPES | {"direct"}:
            raise StoreError("Unsupported connector type.")
        if previous and previous.get("type") != kind:
            profile = dict(value)
        if kind == "direct":
            if any(v not in (None, "") for k, v in value.items() if k != "type"):
                raise StoreError("Direct connections cannot include proxy settings.")
            return {"type": "direct"}
        profile["type"] = kind
        profile["host"] = self._text(profile.get("host"), "proxy host", True)
        profile["port"] = self._port(profile.get("port"))
        if "timeout_seconds" in profile:
            self._timeout(profile["timeout_seconds"])
        self._inline_credentials(profile, value)
        if profile.get("private_key"):
            try:
                validate_private_key(profile["private_key"], profile.get("key_passphrase"))
            except SecretError as exc:
                raise StoreError(str(exc)) from None
        return profile

    def _save_profile(self, db, resource, payload, previous):
        profile = {**previous, **payload}
        values = {"name": self._text(profile.get("name"), "name", True, 200),
                  "host": self._text(profile.get("host"), "host", True),
                  "port": self._port(profile.get("port"))}
        role_id = profile.get("role_account_id")
        if role_id is not None:
            self._text(role_id, "role reference", True, 36)
            self._row(db, role_accounts, role_id, lock=True)
            if any(payload.get(field) for field in _INLINE_FIELDS):
                raise StoreError("A role reference cannot include inline credentials.")
            for field in _INLINE_FIELDS:
                profile.pop(field, None)
        self._inline_credentials(profile, payload)
        values["role_account_id"] = role_id
        configuration = {k: profile[k] for k in ("username", "private_key_path", "known_hosts_path") if k in profile}
        secret_data = {k: profile[k] for k in SECRET_FIELDS if k in profile and profile[k]}
        if resource == "proxies":
            if not isinstance(profile.get("type"), str) or profile["type"] not in _PROXY_TYPES:
                raise StoreError("Unsupported proxy type.")
            values["type"] = profile["type"]
        else:
            if profile.get("protocol") not in ("ssh", "netconf", "telnet"):
                raise StoreError("Unsupported protocol.")
            client_type = profile.get("client_type", "network")
            if client_type not in ("network", "fake"):
                raise StoreError("Client type must be network or fake.")
            configuration["client_type"] = client_type
            values["protocol"] = profile["protocol"]
            values["timeout_seconds"] = self._timeout(profile.get("timeout_seconds", 10))
            proxy_id = profile.get("proxy_id")
            if proxy_id is not None:
                self._text(proxy_id, "proxy reference", True, 36)
                self._row(db, proxies, proxy_id, lock=True)
                if "connector" in payload:
                    raise StoreError("A saved proxy cannot include an inline connector.")
            else:
                connector = self._connector(
                    payload.get("connector", profile.get("connector", {"type": "direct"})),
                    previous.get("connector") if "connector" in payload else None,
                )
                configuration["connector"] = public_fields(connector)
                connector_secrets = {k: connector[k] for k in SECRET_FIELDS if connector.get(k)}
                if connector_secrets:
                    secret_data["connector"] = connector_secrets
            values["proxy_id"] = proxy_id
        values["configuration"] = configuration
        values["secrets"] = self._vault.encrypt(secret_data)
        return values

    def save(self, resource, payload, item_id=None):
        table = self._table(resource)
        self._check_fields(payload, _FIELDS[resource])
        with self._transaction() as db:
            previous = self._stored_profile(self._row(db, table, item_id, lock=True)) if item_id else {}
            values = (self._save_role(payload, previous) if resource == "role_accounts"
                      else self._save_profile(db, resource, payload, previous))
            if item_id:
                db.execute(update(table).where(table.c.id == item_id).values(**values))
            else:
                item_id = str(uuid.uuid4())
                db.execute(insert(table).values(id=item_id, **values))
            return self._public(db, resource, self._row(db, table, item_id))

    def delete(self, resource, item_id):
        table = self._table(resource)
        with self._transaction() as db:
            self._row(db, table, item_id, lock=True)
            if resource == "role_accounts":
                references = ((connections, connections.c.role_account_id), (proxies, proxies.c.role_account_id))
            elif resource == "proxies":
                references = ((connections, connections.c.proxy_id),)
            else:
                references = ()
            for referenced, column in references:
                if db.execute(select(referenced.c.id).where(column == item_id).limit(1)).first():
                    raise StoreError("Resource is still referenced.", 409)
            db.execute(delete(table).where(table.c.id == item_id))

    def resolve_connection(self, item_id):
        with self._transaction() as db:
            return self._resolve_connection(db, item_id)

    @staticmethod
    def _validate_static_route(payload):
        fields = {"destination", "next_hop", "interface", "metric", "description", "enabled"}
        if not isinstance(payload, dict) or set(payload) != fields:
            raise StoreError("Static routes require destination, next_hop, interface, metric, description and enabled.")
        destination, next_hop = payload["destination"], payload["next_hop"]
        if (not isinstance(destination, str) or not re.fullmatch(r"[^/]+/[0-9]{1,3}", destination)
                or not isinstance(next_hop, str) or "%" in destination or "%" in next_hop):
            raise StoreError("A valid network prefix and next-hop address are required.")
        try:
            network = ipaddress.ip_network(destination, strict=True)
            address = ipaddress.ip_address(next_hop)
        except ValueError:
            raise StoreError("A valid network prefix and next-hop address are required.") from None
        if network.version != address.version:
            raise StoreError("Destination and next hop must use the same address family.")
        interface = payload["interface"]
        if interface is not None and interface not in ("eth0", "eth1", "lo"):
            raise StoreError("Unsupported simulated interface.")
        metric = payload["metric"]
        if isinstance(metric, bool) or not isinstance(metric, int) or not 0 <= metric <= 65535:
            raise StoreError("Metric must be an integer between 0 and 65535.")
        description = GatewayStore._text(payload["description"], "route description", limit=200)
        if not isinstance(payload["enabled"], bool):
            raise StoreError("Route enabled must be a boolean.")
        return {**payload, "destination": str(network), "next_hop": str(address), "description": description}

    def _initialize_static_routes(self, db, connection_id):
        profile = self._stored_profile(self._row(db, connections, connection_id, lock=True))
        if profile.get("client_type", "network") != "fake":
            raise StoreError("Static-route simulation requires a fake connection.", 501)
        initialized = db.execute(select(static_route_initializations.c.connection_id).where(
            static_route_initializations.c.connection_id == connection_id,
        )).first()
        if initialized:
            return
        db.execute(insert(static_route_initializations).values(connection_id=connection_id))
        for payload in (
            {"destination": "198.51.100.0/24", "next_hop": "192.0.2.1", "interface": "eth0",
             "metric": 10, "description": "Simulated documentation route", "enabled": True},
            {"destination": "2001:db8:2::/64", "next_hop": "2001:db8:1::1", "interface": "eth1",
             "metric": 20, "description": "Simulated IPv6 documentation route", "enabled": True},
        ):
            db.execute(insert(static_routes).values(
                id=str(uuid.uuid4()), connection_id=connection_id, **self._validate_static_route(payload),
            ))

    @staticmethod
    def _owned_static_route(db, connection_id, route_id):
        row = GatewayStore._row(db, static_routes, route_id, lock=True)
        if row["connection_id"] != connection_id:
            raise StoreError("Resource not found.", 404)
        return row

    def list_static_routes(self, connection_id):
        with self._transaction() as db:
            self._initialize_static_routes(db, connection_id)
            rows = db.execute(select(static_routes).where(
                static_routes.c.connection_id == connection_id,
            ).order_by(static_routes.c.destination, static_routes.c.id)).mappings()
            return [dict(row) for row in rows]

    def _create_static_route_row(self, db, connection_id, payload):
        self._initialize_static_routes(db, connection_id)
        values = self._validate_static_route(payload)
        route_id = str(uuid.uuid4())
        db.execute(insert(static_routes).values(id=route_id, connection_id=connection_id, **values))
        return self._row(db, static_routes, route_id)

    def create_static_route(self, connection_id, payload):
        with self._transaction() as db:
            return self._create_static_route_row(db, connection_id, payload)

    def _update_static_route_row(self, db, connection_id, route_id, payload):
        self._initialize_static_routes(db, connection_id)
        before = dict(self._owned_static_route(db, connection_id, route_id))
        values = self._validate_static_route(payload)
        db.execute(update(static_routes).where(static_routes.c.id == route_id).values(**values))
        return before, self._row(db, static_routes, route_id)

    def update_static_route(self, connection_id, route_id, payload):
        with self._transaction() as db:
            _, after = self._update_static_route_row(db, connection_id, route_id, payload)
            return after

    def _delete_static_route_row(self, db, connection_id, route_id):
        self._initialize_static_routes(db, connection_id)
        before = dict(self._owned_static_route(db, connection_id, route_id))
        db.execute(delete(static_routes).where(static_routes.c.id == route_id))
        return before

    def delete_static_route(self, connection_id, route_id):
        with self._transaction() as db:
            self._delete_static_route_row(db, connection_id, route_id)

    def create_static_route_audited(self, connection_id, payload, audit):
        """Create a static route and its audit record in one atomic DB transaction.

        `audit` supplies the actor/correlation/action metadata (see
        `_validate_transaction`); this method fills in resource_type,
        resource_id, connection_id, outcome and before/after state. If the
        route mutation itself fails validation, no transaction row is written
        here -- callers should append a separate "failed" record via
        `append_transaction`. If the mutation succeeds but the audit record
        cannot be written/validated, the whole transaction (including the
        route change) is rolled back so a successful change is never left
        unaudited.
        """
        with self._transaction() as db:
            route = self._create_static_route_row(db, connection_id, payload)
            self._insert_transaction(db, {
                **audit, "resource_type": "static_route", "resource_id": route["id"],
                "connection_id": connection_id, "outcome": "succeeded",
                "before_state": None, "after_state": dict(route),
            })
            return route

    def update_static_route_audited(self, connection_id, route_id, payload, audit):
        """Update a static route and its audit record in one atomic DB transaction."""
        with self._transaction() as db:
            before, after = self._update_static_route_row(db, connection_id, route_id, payload)
            self._insert_transaction(db, {
                **audit, "resource_type": "static_route", "resource_id": route_id,
                "connection_id": connection_id, "outcome": "succeeded",
                "before_state": before, "after_state": dict(after),
            })
            return after

    def delete_static_route_audited(self, connection_id, route_id, audit):
        """Delete a static route and its audit record in one atomic DB transaction."""
        with self._transaction() as db:
            before = self._delete_static_route_row(db, connection_id, route_id)
            self._insert_transaction(db, {
                **audit, "resource_type": "static_route", "resource_id": route_id,
                "connection_id": connection_id, "outcome": "succeeded",
                "before_state": before, "after_state": None,
            })

    @staticmethod
    def _public_job(row):
        public = {key: row[key] for key in ("id", "status", "total", "completed", "results")}
        public["results"] = [{"simulated": False, **result} for result in row["results"]]
        if row.get("error"):
            public["error"] = row["error"]
        return public

    def create_job(self, connection_ids):
        if (not isinstance(connection_ids, (list, tuple)) or not connection_ids
                or len(connection_ids) > 1000 or any(not isinstance(x, str) for x in connection_ids)):
            raise StoreError("Select between 1 and 1000 connections.")
        if len(set(connection_ids)) != len(connection_ids):
            raise StoreError("Connection IDs must be unique.")
        with self._transaction() as db:
            if db.execute(select(jobs.c.id).where(jobs.c.active_slot == 1)).first():
                raise StoreError("A connection-test job is already active.", 409)
            snapshot = [{"id": item_id, "profile": self._resolve_connection(db, item_id)}
                        for item_id in connection_ids]
            job_id = str(uuid.uuid4())
            db.execute(insert(jobs).values(
                id=job_id, status="queued", total=len(snapshot), completed=0,
                snapshot=self._vault.encrypt(snapshot), results=[], error=None, active_slot=1,
            ))
            return self._public_job(self._row(db, jobs, job_id))

    def get_job(self, job_id):
        with self._transaction() as db:
            return self._public_job(self._row(db, jobs, job_id))

    def get_job_connections(self, job_id):
        with self._transaction() as db:
            row = self._row(db, jobs, job_id)
            return [(item["id"], {"client_type": "network", **item["profile"]})
                    for item in self._vault.decrypt(row["snapshot"])]

    def record_job_result(self, job_id, result):
        if not isinstance(result, dict):
            raise StoreError("Invalid job result.")
        with self._transaction() as db:
            row = self._row(db, jobs, job_id, lock=True)
            if row["status"] not in {"queued", "running"}:
                raise StoreError("Job is not active.", 409)
            snapshot = self._vault.decrypt(row["snapshot"])
            profiles = {item["id"]: item["profile"] for item in snapshot}
            item_id = result.get("connection_id")
            if not isinstance(item_id, str) or item_id not in profiles:
                raise StoreError("Result connection does not belong to this job.")
            if any(item["connection_id"] == item_id for item in row["results"]):
                raise StoreError("A result already exists for this connection.", 409)
            profile = profiles[item_id]
            secrets = credential_values(snapshot)
            duration = result.get("duration_ms", 0)
            if (isinstance(duration, bool) or not isinstance(duration, (int, float))
                    or not math.isfinite(duration) or duration < 0):
                raise StoreError("Invalid result duration.")
            if not isinstance(result.get("success"), bool):
                raise StoreError("Invalid result success value.")
            simulated = profile.get("client_type", "network") == "fake"
            if "simulated" in result and (
                not isinstance(result["simulated"], bool) or result["simulated"] != simulated
            ):
                raise StoreError("Result simulation flag does not match the stored connection.")
            cleaned = {
                "connection_id": item_id,
                "name": redact(profile["name"], secrets),
                "protocol": profile["protocol"],
                "host": redact(profile["host"], secrets),
                "port": profile["port"],
                "connector_type": profile["connector"]["type"],
                "success": result["success"],
                "simulated": simulated,
                "stage": redact(result.get("stage", "unknown"), secrets),
                "detail": redact(result.get("detail", ""), secrets),
                "duration_ms": duration,
            }
            results = row["results"] + [cleaned]
            db.execute(update(jobs).where(jobs.c.id == job_id).values(results=results, completed=len(results)))

    def set_job_status(self, job_id, status, error=None):
        if status not in ("queued", "running", "completed", "failed"):
            raise StoreError("Invalid job status.")
        with self._transaction() as db:
            row = self._row(db, jobs, job_id, lock=True)
            allowed = {"queued": {"queued", "running", "failed"},
                       "running": {"running", "completed", "failed"},
                       "completed": {"completed"}, "failed": {"failed"}}
            if status not in allowed[row["status"]]:
                raise StoreError("Invalid job status transition.", 409)
            if status == "completed" and row["completed"] != row["total"]:
                raise StoreError("Cannot complete a job with missing results.", 409)
            snapshot = self._vault.decrypt(row["snapshot"])
            clean_error = redact(error, credential_values(snapshot)) if error else None
            db.execute(update(jobs).where(jobs.c.id == job_id).values(
                status=status, active_slot=1 if status in {"queued", "running"} else None,
                error=clean_error,
            ))

    @staticmethod
    def _validate_uuid(value, label):
        if not isinstance(value, str):
            raise StoreError(f"Invalid {label}; must be a UUID string.")
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError, TypeError):
            raise StoreError(f"Invalid {label}; must be a UUID string.") from None
        return str(parsed)

    @staticmethod
    def _format_utc(moment):
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime(_TIMESTAMP_FORMAT)

    @staticmethod
    def _parse_filter_timestamp(value, label):
        if not isinstance(value, str):
            raise StoreError(f"Invalid {label} filter; must be an ISO-8601 timestamp.")
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            raise StoreError(f"Invalid {label} filter; must be an ISO-8601 timestamp.") from None
        return GatewayStore._format_utc(parsed)

    def _validate_transaction(self, payload):
        if not isinstance(payload, dict):
            raise StoreError("Transaction payload must be an object.")
        correlation_id = payload.get("correlation_id")
        correlation_id = (self._validate_uuid(correlation_id, "correlation_id")
                           if correlation_id else str(uuid.uuid4()))
        actor_subject = self._text(payload.get("actor_subject"), "actor_subject", required=True, limit=255)
        actor_tenant_id = payload.get("actor_tenant_id")
        if actor_tenant_id is not None:
            actor_tenant_id = self._validate_uuid(actor_tenant_id, "actor_tenant_id")
        actor_name = self._text(payload.get("actor_name"), "actor_name", required=True, limit=200)
        actor_email = payload.get("actor_email")
        if actor_email is not None:
            actor_email = self._text(actor_email, "actor_email", limit=320)
        actor_roles = payload.get("actor_roles")
        if (not isinstance(actor_roles, (list, tuple, set, frozenset))
                or not all(isinstance(role, str) for role in actor_roles)):
            raise StoreError("actor_roles must be a list of role names.")
        if not set(actor_roles) <= _GATEWAY_ROLES:
            raise StoreError("actor_roles must only contain Viewer, Operator, or Administrator.")
        normalized_roles = sorted(set(actor_roles))
        auth_mode = payload.get("auth_mode")
        if auth_mode not in _AUTH_MODES:
            raise StoreError("auth_mode must be entra or demo.")
        action = self._text(payload.get("action"), "action", required=True, limit=100)
        resource_type = self._text(payload.get("resource_type"), "resource_type", required=True, limit=64)
        resource_id = payload.get("resource_id")
        if resource_id is not None:
            resource_id = self._text(resource_id, "resource_id", limit=64)
        connection_id = payload.get("connection_id")
        if connection_id is not None:
            connection_id = self._validate_uuid(connection_id, "connection_id")
        outcome = payload.get("outcome")
        if outcome not in _TRANSACTION_OUTCOMES:
            raise StoreError("outcome must be succeeded or failed.")
        before_state = payload.get("before_state")
        if before_state is not None and not isinstance(before_state, (dict, list)):
            raise StoreError("before_state must be an object, array, or null.")
        after_state = payload.get("after_state")
        if after_state is not None and not isinstance(after_state, (dict, list)):
            raise StoreError("after_state must be an object, array, or null.")
        detail = payload.get("detail")
        if detail is not None:
            detail = self._text(detail, "detail", limit=4000)
        request_method = payload.get("request_method")
        if request_method is not None:
            request_method = self._text(request_method, "request_method", limit=10)
        request_path = payload.get("request_path")
        if request_path is not None:
            request_path = self._text(request_path, "request_path", limit=2048)

        return {
            "id": str(uuid.uuid4()),
            "timestamp_utc": self._format_utc(datetime.now(timezone.utc)),
            "correlation_id": correlation_id,
            "actor_subject": actor_subject,
            "actor_tenant_id": actor_tenant_id,
            "actor_name": actor_name,
            "actor_email": actor_email,
            "actor_roles": normalized_roles,
            "auth_mode": auth_mode,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "connection_id": connection_id,
            "outcome": outcome,
            "before_state": _redact_recursive(before_state),
            "after_state": _redact_recursive(after_state),
            "detail": _redact_recursive(detail),
            "request_method": request_method,
            "request_path": request_path,
        }

    def _insert_transaction(self, db, payload):
        values = self._validate_transaction(payload)
        db.execute(insert(gateway_transactions).values(**values))
        return self._row(db, gateway_transactions, values["id"])

    def append_transaction(self, payload):
        """Append an immutable audit record. Append-only: there is no update/delete API."""
        with self._transaction() as db:
            return self._insert_transaction(db, payload)

    def list_transactions(self, filters=None, limit=50, offset=0):
        """Return a page of immutable audit records, newest first.

        `filters` may include: connection_id, action, actor_subject, outcome,
        resource_type, since (inclusive ISO-8601 UTC), until (inclusive ISO-8601 UTC).
        """
        filters = filters or {}
        if not isinstance(filters, dict):
            raise StoreError("Invalid transaction filters.")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise StoreError("Limit must be an integer between 1 and 500.")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise StoreError("Offset must be a non-negative integer.")

        conditions = []
        if filters.get("connection_id") is not None:
            conditions.append(gateway_transactions.c.connection_id
                               == self._validate_uuid(filters["connection_id"], "connection_id"))
        if filters.get("action") is not None:
            conditions.append(gateway_transactions.c.action
                               == self._text(filters["action"], "action filter", limit=100))
        if filters.get("actor_subject") is not None:
            conditions.append(gateway_transactions.c.actor_subject
                               == self._text(filters["actor_subject"], "actor_subject filter", limit=255))
        if filters.get("resource_type") is not None:
            conditions.append(gateway_transactions.c.resource_type
                               == self._text(filters["resource_type"], "resource_type filter", limit=64))
        if filters.get("outcome") is not None:
            if filters["outcome"] not in _TRANSACTION_OUTCOMES:
                raise StoreError("outcome filter must be succeeded or failed.")
            conditions.append(gateway_transactions.c.outcome == filters["outcome"])
        if filters.get("since") is not None:
            conditions.append(gateway_transactions.c.timestamp_utc
                               >= self._parse_filter_timestamp(filters["since"], "since"))
        if filters.get("until") is not None:
            conditions.append(gateway_transactions.c.timestamp_utc
                               <= self._parse_filter_timestamp(filters["until"], "until"))

        with self._transaction() as db:
            base = select(gateway_transactions)
            if conditions:
                base = base.where(and_(*conditions))
            total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()
            rows = db.execute(
                base.order_by(gateway_transactions.c.timestamp_utc.desc(), gateway_transactions.c.id.desc())
                .limit(limit).offset(offset)
            ).mappings().all()
            return {"items": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset}

    def close(self):
        with self._lock:
            if not self._closed:
                self.engine.dispose()
                self._closed = True


_default_store = None
_default_lock = threading.Lock()


def get_store():
    """Configure management persistence only when a management endpoint needs it."""
    global _default_store
    with _default_lock:
        if _default_store is None or _default_store._closed:
            _default_store = GatewayStore()
        return _default_store
