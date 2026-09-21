"""Create/upsert the demo SQLite device table used by the loopback demo.

Reuses the gateway's own SQLAlchemy engine/session abstractions
(`app.dal.db.db_client.get_engine`/`get_session`) instead of a second, divergent
DB connection path. Safe to run repeatedly: it creates the table only if
absent, *inserts* any of the three demo device rows that are missing, and
*never overwrites* an existing row's columns - so any edits a user makes to
a seeded demo row (custom notes, a tweaked port, etc.) survive a re-seed.
Pass ``reset=True`` (or run with ``--reset`` from the command line) to
explicitly restore the three canonical demo rows to their default values;
this still never touches any other row (e.g. a device a user added
manually).

Credentials stored here are explicitly fake demo values (see
`demo/demo_config.py`), not a production secret store, and are never logged.

Safety: `seed()` refuses to run unless `DB_BACKEND=sqlite` is the *effective*
environment value, so it can never be pointed at a real database backend
just because a caller's shell happened to already export a production
`DB_BACKEND`. This check runs before any engine/session is created. The
fuller storage validation (`demo.env_safety.prepare_demo_environment`)
is applied by the command-line entrypoints below and by `demo/run_demo.py`,
which use `demo/data` unless `--storage-dir` explicitly selects another local
directory. Legacy mappings are seeded into the isolated gateway database;
`seed()` itself stays intentionally narrower so it can also be
exercised directly (e.g. by tests) against an explicit, non-default SQLite
path that is still clearly a local SQLite file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from sqlalchemy import Column, Integer, MetaData, String, Table, inspect

# Ensure the repo root is importable when this script is run directly
# (`python demo/seed_demo_db.py`) rather than as `python -m demo.seed_demo_db`.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from demo import demo_config  # noqa: E402
from demo.env_safety import DemoSafetyError  # noqa: E402

from app.dal.db import db_client  # noqa: E402

_METADATA = MetaData()

DEVICES_TABLE = Table(
    "devices",
    _METADATA,
    Column("hostname", String, primary_key=True),
    Column("vendor", String),
    Column("software", String),
    Column("protocol", String),
    Column("host", String),
    Column("netconf_port", Integer, nullable=True),
    Column("ssh_port", Integer, nullable=True),
    Column("telnet_port", Integer, nullable=True),
    Column("username", String),  # fake demo credential, not a real secret
    Column("password", String),  # fake demo credential, not a real secret
    Column("notes", String),
)


def _assert_sqlite_backend() -> None:
    """Refuse to create/use an engine at all unless the effective
    `DB_BACKEND` is `sqlite`. This is the last line of defense against
    seeding demo rows into an inherited, non-demo (e.g. production
    PostgreSQL) database."""
    backend = str(os.environ.get("DB_BACKEND", "")).strip().lower()
    if backend != "sqlite":
        raise DemoSafetyError(
            "Refusing to seed the demo device table: DB_BACKEND is "
            f"{backend!r}, not 'sqlite'. The demo seed script never writes "
            "to a non-SQLite backend, even if one was already configured in "
            "the calling shell."
        )


def seed(devices=None, reset: bool = False) -> int:
    """Create the table if absent, insert any missing demo rows, and return
    the number of demo rows present afterward (matching `devices`).

    By default this never modifies an existing row - if a demo row already
    exists (whether untouched or edited by the user), it is left alone.
    Pass `reset=True` to explicitly overwrite the three canonical demo rows
    back to their default values (still without touching unrelated rows).
    """
    _assert_sqlite_backend()

    sqlite_path = os.environ.get("DB_SQLITE_PATH", str(demo_config.SQLITE_PATH))
    if sqlite_path != ":memory:":
        Path(sqlite_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    devices = devices if devices is not None else demo_config.DEMO_DEVICES
    engine = db_client.get_engine()

    inspector = inspect(engine)
    if not inspector.has_table("devices"):
        _METADATA.create_all(engine)

    present = 0
    with engine.begin() as connection:
        for device in devices:
            row = {
                "hostname": device["hostname"],
                "vendor": device.get("vendor"),
                "software": device.get("software"),
                "protocol": device.get("protocol"),
                "host": device.get("host"),
                "netconf_port": device.get("netconf_port"),
                "ssh_port": device.get("ssh_port"),
                "telnet_port": device.get("telnet_port"),
                "username": device.get("username"),
                "password": device.get("password"),
                "notes": device.get("notes"),
            }
            existing = connection.execute(
                DEVICES_TABLE.select().where(DEVICES_TABLE.c.hostname == row["hostname"])
            ).fetchone()
            if existing is None:
                connection.execute(DEVICES_TABLE.insert(), row)
            elif reset:
                connection.execute(
                    DEVICES_TABLE.update()
                    .where(DEVICES_TABLE.c.hostname == row["hostname"])
                    .values(**{k: v for k, v in row.items() if k != "hostname"})
                )
            # else: row already exists and reset was not requested - leave
            # any user edits to it untouched.
            present += 1
    return present


def main(argv=None):
    import argparse
    from demo.env_safety import prepare_demo_environment
    from demo.management_seed import configure_management_key, seed_demo_settings
    from app.dal.db.store import GatewayStore

    parser = argparse.ArgumentParser(description="Seed isolated legacy demo inventory and database-backed mappings.")
    parser.add_argument("--storage-dir", type=Path, help="Explicit local directory for both demo databases and encryption key.")
    parser.add_argument("--reset", action="store_true", help="Restore only the three canonical legacy inventory rows.")
    args = parser.parse_args(argv)
    storage_dir = prepare_demo_environment(args.storage_dir)
    configure_management_key(storage_dir)
    store = GatewayStore()
    try:
        seed_demo_settings(store)
        count = seed(reset=args.reset)
    finally:
        store.close()
        if db_client._engine is not None:
            db_client._engine.dispose()
            db_client._engine = None
            db_client._session_factory = None
    action = "Reset" if args.reset else "Seeded/verified"
    print(f"{action} {count} demo device row(s) in {storage_dir / 'demo_devices.sqlite3'}")


if __name__ == "__main__":
    main()
