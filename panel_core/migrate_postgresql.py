"""Migrate an installed systemd panel from SQLite to local PostgreSQL."""

import fcntl
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from dotenv import dotenv_values
from sqlalchemy import Boolean, MetaData, Table, create_engine, func, inspect, select, text
from sqlalchemy.engine import URL

from models import db
from panel_core.database import database_url, snapshot_sqlite


PANEL = "wg-panel.service"
BOT = "wg-panel-bot.service"


def copy_database(source, target):
    """Copy a consistent SQLite snapshot into an empty PostgreSQL database."""
    stage = "schema inspection"
    try:
        with source.connect() as origin, target.begin() as destination:
            inspector = inspect(origin)
            tables = set(inspector.get_table_names()) - {"sqlite_sequence"}
            if not {"admin_account", "interface_config", "peer"} <= tables:
                raise ValueError("The selected SQLite file is not an initialized WG Panel database.")
            unknown = tables - db.metadata.tables.keys()
            if unknown:
                raise ValueError("Unknown SQLite tables: " + ", ".join(sorted(unknown)))
            if inspect(destination).get_table_names():
                raise ValueError("The PostgreSQL destination is not empty.")
            stage = "PostgreSQL schema creation"
            db.metadata.create_all(destination)
            counts = {}
            for table in db.metadata.sorted_tables:
                if table.name not in tables:
                    continue
                stage = f"copy/verification of {table.name}"
                old = Table(table.name, MetaData(), autoload_with=origin, resolve_fks=False)
                unknown = set(old.columns.keys()) - set(table.columns.keys())
                if unknown:
                    raise ValueError(f"Unknown columns in {table.name}: {', '.join(sorted(unknown))}")
                columns = old.columns.keys()
                count = origin.scalar(select(func.count()).select_from(old))
                boolean_columns = [name for name in columns if isinstance(table.c[name].type, Boolean)]
                for batch in origin.execute(select(old).order_by(old.c.id)).mappings().partitions(500):
                    rows = [dict(row) for row in batch]
                    for row in rows:
                        for name in boolean_columns:
                            if row[name] is not None:
                                if row[name] not in (0, 1):
                                    raise ValueError(f"Invalid boolean in {table.name}.{name}.")
                                row[name] = bool(row[name])
                    destination.execute(table.insert(), rows)
                    copied = destination.execute(
                        select(*(table.c[name] for name in columns))
                        .where(table.c.id.in_([row["id"] for row in batch]))
                        .order_by(table.c.id)
                    ).mappings().all()
                    if copied != rows:
                        raise ValueError(f"Row verification failed in {table.name}.")
                if destination.scalar(select(func.count()).select_from(table)) != count:
                    raise ValueError(f"Row count verification failed in {table.name}.")
                counts[table.name] = count
                highest = destination.scalar(select(func.max(table.c.id))) or 0
                if inspector.has_table("sqlite_sequence"):
                    original_sequence = origin.scalar(
                        text("SELECT seq FROM sqlite_sequence WHERE name = :name"), {"name": table.name},
                    ) or 0
                    highest = max(highest, original_sequence)
                if highest > 0:
                    destination.execute(
                        text("SELECT setval(pg_get_serial_sequence(:table, 'id'), :value)"),
                        {"table": table.name, "value": highest},
                    )
            return counts
    except ValueError:
        raise
    except Exception as exc:
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        kind = f"SQLSTATE {sqlstate}" if sqlstate else type(exc).__name__
        raise RuntimeError(f"Database migration failed during {stage} ({kind}).") from None


def _systemctl(*args, check=True):
    return subprocess.run(
        ["systemctl", *args], check=check, capture_output=True, text=True, timeout=90,
    )


def _active(service):
    return _systemctl("is-active", "--quiet", service, check=False).returncode == 0


def _process_environment(service):
    pid = _systemctl("show", "-p", "MainPID", "--value", service).stdout.strip()
    if not pid.isdigit() or int(pid) <= 0:
        raise RuntimeError(f"{service} has no running process.")
    return dict(
        entry.split("=", 1)
        for entry in Path(f"/proc/{pid}/environ").read_bytes().decode(errors="replace").split("\0")
        if "=" in entry
    )


def _login_probe(root, settings):
    instance = root / "instance"
    panel = json.loads((instance / "panel_settings.json").read_text())
    runtime = json.loads((instance / "runtime.json").read_text())
    tls = panel.get("tls_enabled") and all(
        Path(panel.get(key) or "/dev/null/missing").is_file()
        for key in ("tls_cert_path", "tls_key_path")
    )
    fallback_port = (panel.get("https_port") or 443) if tls else (panel.get("http_port") or 8000)
    if settings.get("USE_GUNICORN") == "0":
        host = settings.get("DEV_HOST", "127.0.0.1")
        port = settings.get("DEV_PORT") or (fallback_port if tls else runtime.get("port") or fallback_port)
    else:
        bind = settings.get("BIND") or (None if tls else runtime.get("bind"))
        if bind:
            host, port = bind.rsplit(":", 1)
        else:
            host = settings.get("BIND_HOST") or "0.0.0.0"
            port = fallback_port if tls else runtime.get("port") or fallback_port
    host = host.strip("[]") or "127.0.0.1"
    host = {"0.0.0.0": "127.0.0.1", "*": "127.0.0.1", "::": "::1"}.get(host, host)

    def probe():
        if tls:
            # Local readiness check only. No credentials are transmitted.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, int(port), context=context, timeout=3)
        else:
            conn = http.client.HTTPConnection(host, int(port), timeout=3)
        try:
            conn.request("GET", "/login", headers={"Host": panel.get("domain") or host})
            response = conn.getresponse()
            return response.status == 200 or (
                response.status in (301, 302, 303, 307, 308) and response.getheader("Location") == "/register"
            )
        except (OSError, http.client.HTTPException):
            return False
        finally:
            conn.close()

    return probe


def _wait_for_panel(probe, expected_url):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if _process_environment(PANEL).get("DATABASE_URL") == expected_url and probe():
                return
        except (OSError, RuntimeError, subprocess.SubprocessError):
            pass
        time.sleep(1)
    raise RuntimeError("WG Panel did not pass the /login check with the configured database.")


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


def _write_private(path, contents, owner=None):
    # Keep credentials private and publish the whole file atomically.
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        pending = Path(handle.name)
        try:
            handle.write(contents)
            handle.flush()
            if owner is not None:
                os.fchown(handle.fileno(), owner.st_uid, owner.st_gid)
            os.fsync(handle.fileno())
            pending.replace(path)
        finally:
            pending.unlink(missing_ok=True)


def migrate(root):
    env_path = root / ".env"
    if env_path.is_symlink() or not env_path.is_file():
        raise RuntimeError("The project needs a regular .env file.")
    old_env = env_path.read_bytes()
    old_owner = env_path.stat()
    settings = dotenv_values(env_path, interpolate=False)
    old_url = settings.get("DATABASE_URL")
    source_url = database_url(old_url, root)
    if source_url.get_backend_name() != "sqlite" or not source_url.database or source_url.query:
        raise RuntimeError("The active database must be a local SQLite file.")
    source_path = Path(source_url.database)
    if not source_path.is_file():
        raise RuntimeError("The configured SQLite file does not exist.")
    workdir = _systemctl("show", "-p", "WorkingDirectory", "--value", PANEL).stdout.strip()
    if Path(workdir).resolve() != root or not _active(PANEL):
        raise RuntimeError("Start the installed wg-panel.service for this project before migrating.")
    running = _process_environment(PANEL)
    if database_url(running.get("DATABASE_URL") or old_url, root) != source_url:
        raise RuntimeError("The running service database differs from .env. Resolve this before migrating.")
    probe = _login_probe(root, settings | running)
    if not probe():
        raise RuntimeError("The current panel did not pass the local /login check. Fix it before migrating.")

    bot_state = _systemctl("is-active", BOT, check=False).stdout.strip()
    if bot_state not in ("inactive", "failed", "unknown", "active"):
        raise RuntimeError("Wait for the Telegram service to reach a stable state before migrating.")
    services = [BOT, PANEL] if bot_state == "active" else [PANEL]
    backup = Path(tempfile.mkdtemp(prefix="migration-sqlite-", dir=root / "instance"))
    _write_private(backup / "sqlite.env", old_env)
    print(f"Migration files: {backup}", flush=True)
    target_url = _provision_database()
    new_url = target_url.render_as_string(hide_password=False)
    retained_lines = [
        line for line in old_env.decode("utf-8").splitlines(keepends=True)
        if not re.match(r"^\s*(?:export\s+)?DATABASE_URL\s*=", line)
    ]
    new_env = ("".join(retained_lines).rstrip("\r\n") + f"\nDATABASE_URL={new_url}\n").encode()
    _write_private(backup / "postgresql.env", new_env)
    target = create_engine(target_url, hide_parameters=True, connect_args={"connect_timeout": 5})
    snapshot = backup / "wg_panel.db"
    switched = False
    stopping = False
    try:
        with target.connect() as connection:
            connection.execute(text("SELECT 1"))
            if inspect(connection).get_table_names():
                raise RuntimeError("The PostgreSQL destination is not empty.")
        print("Pausing panel writes and taking a consistent SQLite snapshot...", flush=True)
        stopping = True
        _systemctl("stop", *services)
        snapshot_sqlite(source_path, snapshot)
        source = create_engine(URL.create("sqlite", database=str(snapshot)))
        try:
            counts = copy_database(source, target)
        finally:
            source.dispose()
        print(f"Verified {sum(counts.values())} rows across {len(counts)} SQLite tables.", flush=True)
        if env_path.read_bytes() != old_env:
            raise RuntimeError(".env changed during migration. Restarting without switching the database.")
        switched = True
        _write_private(env_path, new_env, owner=old_owner)
        _systemctl("start", PANEL)
        _wait_for_panel(probe, new_url)
    except BaseException:
        if switched:
            # Restore configuration even when stopping the new service reports an error.
            _systemctl("stop", *services, check=False)
            _write_private(env_path, old_env, owner=old_owner)
        if stopping:
            _systemctl("restart" if switched else "start", *reversed(services))
            if switched:
                _wait_for_panel(probe, running.get("DATABASE_URL"))
            print("Services restarted with the original SQLite configuration.", flush=True)
        raise
    finally:
        target.dispose()
    print("PostgreSQL is active. SQLite and the migration snapshot have been kept.", flush=True)
    if BOT in services:
        # The panel can already be serving writes. Keep the new database if only the bot fails.
        try:
            _systemctl("start", BOT)
            if _active(BOT):
                return
        except (OSError, subprocess.SubprocessError):
            pass
        print(f"Telegram did not restart. Check: systemctl status {BOT}", file=sys.stderr)


def main():
    root = Path.cwd().resolve()
    try:
        with (root / "instance" / ".postgresql-migration.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            migrate(root)
    except BlockingIOError:
        print("Another database migration is already running.", file=sys.stderr)
        return 1
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        print(f"Migration interrupted or failed ({type(exc).__name__}). Check service status and the migration files.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Database migration failed ({type(exc).__name__}). Check service status and the migration files.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
