"""Portable, non-destructive SQLAlchemy schema and database configuration."""

import os
from pathlib import Path

from sqlalchemy import (
    JSON, Boolean, CheckConstraint, Column, Float, ForeignKey, Index, Integer, MetaData,
    String, Table, Text, UniqueConstraint, create_engine, event,
)
from sqlalchemy.engine import make_url
from sqlalchemy.pool import StaticPool


class StoreError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


metadata = MetaData()

configurations = Table(
    "gateway_configurations", metadata,
    Column("name", String(32), primary_key=True),
    Column("payload", JSON, nullable=False),
    CheckConstraint("name IN ('device_lookup', 'client_mapping', 'proxy_mapping')", name="configuration_name"),
)

role_accounts = Table(
    "gateway_role_accounts", metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("username", String(255), nullable=False),
    Column("authentication_type", String(16), nullable=False),
    Column("secrets", Text, nullable=False),
    CheckConstraint("authentication_type IN ('password', 'ssh_key')", name="role_auth_type"),
)

proxies = Table(
    "gateway_proxies", metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("type", String(32), nullable=False),
    Column("host", String(255), nullable=False),
    Column("port", Integer, nullable=False),
    Column("role_account_id", String(36), ForeignKey(role_accounts.c.id, ondelete="RESTRICT")),
    Column("configuration", JSON, nullable=False),
    Column("secrets", Text, nullable=False),
    CheckConstraint("port >= 1 AND port <= 65535", name="proxy_port"),
    CheckConstraint("type IN ('ssh_tunnel', 'ssh_shell', 'socks5', 'http_connect')", name="proxy_type"),
)

connections = Table(
    "gateway_connections", metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("protocol", String(16), nullable=False),
    Column("host", String(255), nullable=False),
    Column("port", Integer, nullable=False),
    Column("timeout_seconds", Float, nullable=False),
    Column("role_account_id", String(36), ForeignKey(role_accounts.c.id, ondelete="RESTRICT")),
    Column("proxy_id", String(36), ForeignKey(proxies.c.id, ondelete="RESTRICT")),
    Column("configuration", JSON, nullable=False),
    Column("secrets", Text, nullable=False),
    CheckConstraint("port >= 1 AND port <= 65535", name="connection_port"),
    CheckConstraint("timeout_seconds >= 1 AND timeout_seconds <= 30", name="connection_timeout"),
    CheckConstraint("protocol IN ('ssh', 'netconf', 'telnet')", name="connection_protocol"),
)

static_route_initializations = Table(
    "gateway_static_route_initializations", metadata,
    Column("connection_id", String(36), ForeignKey(connections.c.id, ondelete="CASCADE"), primary_key=True),
)

static_routes = Table(
    "gateway_static_routes", metadata,
    Column("id", String(36), primary_key=True),
    Column("connection_id", String(36), ForeignKey(connections.c.id, ondelete="CASCADE"), nullable=False),
    Column("destination", String(43), nullable=False),
    Column("next_hop", String(39), nullable=False),
    Column("interface", String(16)),
    Column("metric", Integer, nullable=False),
    Column("description", String(200), nullable=False),
    Column("enabled", Boolean, nullable=False),
    UniqueConstraint("connection_id", "destination", name="static_route_destination"),
    CheckConstraint("metric >= 0 AND metric <= 65535", name="static_route_metric"),
    CheckConstraint("interface IS NULL OR interface IN ('eth0', 'eth1', 'lo')", name="static_route_interface"),
)

jobs = Table(
    "gateway_jobs", metadata,
    Column("id", String(36), primary_key=True),
    Column("status", String(16), nullable=False),
    Column("total", Integer, nullable=False),
    Column("completed", Integer, nullable=False),
    Column("snapshot", Text, nullable=False),
    Column("results", JSON, nullable=False),
    Column("error", Text),
    Column("active_slot", Integer),
    UniqueConstraint("active_slot", name="one_active_gateway_job"),
    CheckConstraint("status IN ('queued', 'running', 'completed', 'failed')", name="job_status"),
    CheckConstraint("total > 0 AND completed >= 0 AND completed <= total", name="job_progress"),
    CheckConstraint(
        "(status IN ('queued', 'running') AND active_slot IS NOT NULL AND active_slot = 1) OR "
        "(status IN ('completed', 'failed') AND active_slot IS NULL)",
        name="job_active_slot",
    ),
)

gateway_transactions = Table(
    "gateway_transactions", metadata,
    Column("id", String(36), primary_key=True),
    Column("timestamp_utc", String(32), nullable=False),
    Column("correlation_id", String(36), nullable=False),
    Column("actor_subject", String(255), nullable=False),
    Column("actor_tenant_id", String(36)),
    Column("actor_name", String(200), nullable=False),
    Column("actor_email", String(320)),
    Column("actor_roles", JSON, nullable=False),
    Column("auth_mode", String(16), nullable=False),
    Column("action", String(100), nullable=False),
    Column("resource_type", String(64), nullable=False),
    Column("resource_id", String(64)),
    Column("connection_id", String(36)),
    Column("outcome", String(16), nullable=False),
    Column("before_state", JSON),
    Column("after_state", JSON),
    Column("detail", Text),
    Column("request_method", String(10)),
    Column("request_path", String(2048)),
    CheckConstraint("auth_mode IN ('entra', 'demo')", name="transaction_auth_mode"),
    CheckConstraint("outcome IN ('succeeded', 'failed')", name="transaction_outcome"),
    Index("gateway_transactions_timestamp_idx", "timestamp_utc", "id"),
    Index("gateway_transactions_connection_idx", "connection_id"),
    Index("gateway_transactions_actor_idx", "actor_subject"),
    Index("gateway_transactions_action_idx", "action"),
    Index("gateway_transactions_outcome_idx", "outcome"),
)

TABLES = {"connections": connections, "proxies": proxies, "role_accounts": role_accounts}


def configured_url(database_url=None, sqlite_path=None):
    if database_url is None and sqlite_path is None:
        database_url = os.environ.get("GATEWAY_DATABASE_URL")
        sqlite_path = os.environ.get("GATEWAY_SQLITE_PATH")
    if database_url and sqlite_path:
        raise StoreError("Configure only GATEWAY_DATABASE_URL or GATEWAY_SQLITE_PATH.", 503)
    if sqlite_path:
        if str(sqlite_path) == ":memory:":
            database_url = "sqlite+pysqlite:///:memory:"
        else:
            from sqlalchemy.engine import URL
            database_url = URL.create("sqlite+pysqlite", database=str(Path(sqlite_path).resolve()))
    if not database_url:
        raise StoreError("Configure GATEWAY_DATABASE_URL or GATEWAY_SQLITE_PATH.", 503)
    try:
        url = make_url(database_url)
        if url.get_backend_name() not in {"sqlite", "postgresql"}:
            raise ValueError("Unsupported backend")
        if url.get_backend_name() == "sqlite" and not url.database:
            raise ValueError("Missing SQLite path")
        return url
    except Exception:
        raise StoreError("Invalid database configuration; use SQLite or PostgreSQL.", 503) from None


def build_engine(url):
    options = {"echo": False, "hide_parameters": True}
    if url.get_backend_name() == "sqlite":
        options["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if url.database == ":memory:":
            options["poolclass"] = StaticPool
        else:
            Path(url.database).resolve().parent.mkdir(parents=True, exist_ok=True)
    else:
        options["isolation_level"] = "REPEATABLE READ"
        options["pool_pre_ping"] = True
    engine = create_engine(url, **options)
    if url.get_backend_name() == "sqlite":
        @event.listens_for(engine, "connect")
        def sqlite_setup(connection, _):
            connection.isolation_level = None
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        @event.listens_for(engine, "begin")
        def sqlite_begin(connection):
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    return engine
