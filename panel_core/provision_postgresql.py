"""Provision a dedicated database for local installations."""

import os
import secrets
import subprocess

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


def _provision_database():
    db_name = f"wgpanel_{secrets.token_hex(6)}"
    password = secrets.token_hex(32)
    sql = (
        f"CREATE ROLE {db_name} LOGIN PASSWORD '{password}';\n"
        f"CREATE DATABASE {db_name} OWNER {db_name};\n"
    )
    result = subprocess.run(
        ["runuser", "-u", "postgres", "--", "psql", "-X", "-w",
         "-h", "/var/run/postgresql", "-p", "5432", "-d", "postgres",
         "-v", "ON_ERROR_STOP=1"],
        input=sql, text=True, capture_output=True, timeout=30, cwd="/",
        env={key: value for key, value in os.environ.items() if not key.startswith("PG")},
    )
    if result.returncode:
        raise RuntimeError("Could not provision a database on the local PostgreSQL cluster (port 5432).")
    return URL.create(
        "postgresql+psycopg", username=db_name, password=password,
        host="127.0.0.1", port=5432, database=db_name,
    )


def main():
    url = _provision_database()
    engine = create_engine(url, hide_parameters=True, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    finally:
        engine.dispose()
    print(url.render_as_string(hide_password=False))


if __name__ == "__main__":
    main()
