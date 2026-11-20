"""Database URL handling and consistent backups for the panel database."""

import os
import subprocess
import tempfile
from pathlib import Path

from sqlalchemy.engine import make_url


POSTGRES_BACKUP = "db/wg_panel.pg.dump"


def database_url(value):
    message = "Configure a PostgreSQL DATABASE_URL before starting WG Panel."
    if not value:
        raise ValueError(message)
    try:
        url = make_url(value)
    except Exception:
        raise ValueError(message) from None
    if url.drivername not in {"postgres", "postgresql", "postgresql+psycopg"} or not url.database:
        raise ValueError(message)
    return url.set(drivername="postgresql+psycopg")


def bundle_database(archive, engine):
    with tempfile.TemporaryDirectory(prefix="wg-panel-backup-") as directory:
        target = Path(directory) / "database"
        _dump_postgresql(engine, target)
        archive.write(target, arcname=POSTGRES_BACKUP)


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
