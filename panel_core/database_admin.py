"""Admin account operations invoked by the installer with the panel's venv."""

import json
import sys
from pathlib import Path

from dotenv import dotenv_values
from sqlalchemy import create_engine, select, update

from models import AdminAccount
from panel_core.database import database_url


def main():
    root = Path.cwd()
    url = database_url(dotenv_values(root / ".env").get("DATABASE_URL"))
    engine = create_engine(url, hide_parameters=True, connect_args={"connect_timeout": 5})
    accounts = AdminAccount.__table__
    try:
        with engine.begin() as connection:
            if sys.argv[1:] == ["list"]:
                names = connection.scalars(select(accounts.c.username).order_by(accounts.c.username))
                print(json.dumps(list(names)))
            elif len(sys.argv) == 3 and sys.argv[1] == "reset":
                username = sys.argv[2]
                password = sys.stdin.read().strip()
                if not password:
                    sys.exit("Password cannot be empty.")
                changed = connection.execute(
                    update(accounts)
                    .where(accounts.c.username == username)
                    .values(password_hash=AdminAccount.hash_pw(password))
                )
                if changed.rowcount != 1:
                    sys.exit("Admin username not found.")
            else:
                sys.exit("Expected list or reset USERNAME.")
    except Exception:
        sys.exit("Could not access PostgreSQL admin accounts.")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
