"""
DB client utilities for device metadata lookup.
"""

import re
from typing import Any, Dict, Optional

from decouple import config
from loguru import logger
from sqlalchemy import bindparam, column, create_engine, literal_column, select, table
from sqlalchemy.orm import Session, sessionmaker

from app.common.errors import ConfigNotFoundError, DatabaseError
from app.dal.db.store import StoreError, get_store


def _validate_identifier(name: Any, label: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ConfigNotFoundError(f"Missing {label} in DB config")
    normalized = name.strip()
    if normalized.lower() == "none" or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", normalized):
        raise ConfigNotFoundError(f"Invalid {label} in database configuration")
    return normalized


_engine = None
_session_factory = None


def _get_db_url() -> str:
    backend = str(config("DB_BACKEND", default="postgresql")).strip().lower()
    if backend == "sqlite":
        # Demo-only backend: a local file (or `:memory:`) SQLite database used
        # for the loopback demo profile. Never used unless explicitly opted
        # into via DB_BACKEND=sqlite.
        sqlite_path = str(config("DB_SQLITE_PATH", default="./demo/data/demo_devices.sqlite3"))
        return f"sqlite:///{sqlite_path}"
    return (
        f"postgresql://{config('DB_USER')}:{config('DB_PASSWORD')}"
        f"@{config('DB_HOST')}:{config('DB_PORT')}/{config('DB_NAME')}"
    )


def _ensure_session_factory() -> None:
    global _engine, _session_factory
    if _session_factory is not None:
        return
    try:
        backend = str(config("DB_BACKEND", default="postgresql")).strip().lower()
        connect_args = {"check_same_thread": False} if backend == "sqlite" else {}
        _engine = create_engine(_get_db_url(), pool_pre_ping=True, connect_args=connect_args)
        _session_factory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
        logger.info(f"Database engine initialized (backend={backend})")
    except Exception:
        logger.error("Failed to initialize metadata database engine")
        raise DatabaseError("Failed to initialize metadata database engine") from None


def get_session() -> Session:
    """Create a lookup-owned Session; the caller must close it."""
    _ensure_session_factory()
    try:
        return _session_factory()
    except Exception:
        logger.error("Failed to create metadata database session")
        raise DatabaseError("Failed to create metadata database session") from None


def get_engine():
    """Return the shared SQLAlchemy engine, initializing it if needed.

    Exposed so tooling such as the demo seed script can reuse the same
    engine/session configuration as the gateway itself, instead of opening a
    second, divergent connection to the database.
    """
    _ensure_session_factory()
    return _engine


def get_device_info(search_value: Any) -> Optional[Dict[str, Any]]:
    try:
        try:
            cfg = get_store().get_config("device_lookup")
        except StoreError:
            raise ConfigNotFoundError("Required device_lookup database configuration is missing or invalid") from None

        table_name = _validate_identifier(cfg.get("table"), "table")
        search_column = _validate_identifier(cfg.get("search_column"), "search_column")
        db_table = table(table_name, column(search_column))
        query = (
            select(literal_column("*"))
            .where(db_table.c[search_column] == bindparam("search_value"))
            .select_from(db_table)
            .limit(1)
        )
        with get_session() as session:
            result = session.execute(query, {"search_value": search_value})
            row = result.fetchone()
            return dict(row._mapping) if row is not None else None
    except ConfigNotFoundError:
        raise
    except Exception:
        logger.error("Database error during device lookup")
        raise DatabaseError("Database error during device lookup") from None
