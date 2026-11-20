"""Database URL handling and consistent backups for the panel database."""

import os
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from pathlib import Path

from sqlalchemy.engine import make_url


DEFAULT_DATABASE_URL = "sqlite:///instance/wg_panel.db"
POSTGRES_BACKUP = "db/wg_panel.pg.dump"


def database_url(value, root):
    url = make_url(value or DEFAULT_DATABASE_URL)
    if url.drivername in ("postgres", "postgresql"):
        return url.set(drivername="postgresql+psycopg")
    if url.get_backend_name() == "sqlite" and url.database not in (None, "", ":memory:"):
        path = Path(root) / url.database
        path.parent.mkdir(parents=True, exist_ok=True)
        return url.set(database=str(path))
    return url


def snapshot_sqlite(source: Path, target: Path):
    # Open read-only so a wrong source path cannot create an empty database.
    with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(target)) as dst:
            src.backup(dst)


def bundle_database(archive, engine):
    backend = engine.dialect.name
    with tempfile.TemporaryDirectory(prefix="wg-panel-backup-") as directory:
        target = Path(directory) / "database"
        if backend == "sqlite" and engine.url.database not in (None, "", ":memory:"):
            source = Path(engine.url.database)
            if not source.is_file():
                return False
            snapshot_sqlite(source, target)
            archive.write(target, arcname="db/" + source.name)
        elif backend == "postgresql":
            _dump_postgresql(engine, target)
            archive.write(target, arcname=POSTGRES_BACKUP)
        else:
            return False
    return True


def _dump_postgresql(engine, target):
    from psycopg.conninfo import make_conninfo

    # Use the effective libpq settings of an actual connection, including TLS.
    with engine.connect() as connection:
        info = connection.connection.driver_connection.info
        parameters = info.get_parameters()
        password = info.password
    env = os.environ.copy()
    if password:
        env["PGPASSWORD"] = password
    parameters.pop("password", None)
    for option in ("sslpassword", "sslkey"):
        if option in engine.url.query:
            parameters.pop(option, None)
            env["PG" + option.upper()] = engine.url.query[option]
    try:
        with target.open("wb") as output:
            subprocess.run(
                ["pg_dump", "--format=custom", "--no-password", "--dbname", make_conninfo(**parameters)],
                env=env, stdout=output, stderr=subprocess.DEVNULL, timeout=300, check=True,
            )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("PostgreSQL backup failed. Check pg_dump and database access.") from None
