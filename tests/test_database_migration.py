"""Regression coverage for service cutover and rollback."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.engine import URL

from panel_core import migrate_postgresql as migration


class DatabaseMigrationTest(unittest.TestCase):
    OLD_URL = "sqlite:///instance/wg_panel.db"
    TARGET = URL.create("postgresql+psycopg", host="127.0.0.1", database="test")

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "instance").mkdir()
        self.env = self.root / ".env"
        self.original = f"# preserve comment\nDATABASE_URL={self.OLD_URL}\nSECRET=preserve\n"
        self.env.write_text(self.original)
        self.source = self.root / "instance/wg_panel.db"
        with sqlite3.connect(self.source) as connection:
            connection.execute("CREATE TABLE sample (value TEXT)")
            connection.execute("INSERT INTO sample VALUES ('existing data')")
        self.commands = []
        self.bot_active = False
        self.bot_can_start = True

        def systemctl(*args, **kwargs):
            self.commands.append(args)
            if args[0] == "show":
                return SimpleNamespace(stdout=str(self.root))
            if args[0] == "is-active":
                if args[-1] == migration.BOT:
                    if "--quiet" in args:
                        return SimpleNamespace(returncode=0 if self.bot_can_start else 3)
                    return SimpleNamespace(stdout="active" if self.bot_active else "inactive")
                return SimpleNamespace(returncode=0)
            return SimpleNamespace()

        for name, replacement in {
            "_systemctl": dict(side_effect=systemctl),
            "_process_environment": dict(return_value={"DATABASE_URL": self.OLD_URL}),
            "_provision_database": dict(return_value=self.TARGET),
            "_login_probe": dict(return_value=lambda: True),
            "copy_database": dict(return_value={"sample": 1}),
            "create_engine": dict(side_effect=lambda url, **kwargs: (
                create_engine("sqlite://") if url == self.TARGET else create_engine(url, **kwargs)
            )),
        }.items():
            mock = patch.object(migration, name, **replacement)
            mock.start()
            self.addCleanup(mock.stop)

    def test_copy_failure_leaves_original_config_and_restarts_panel(self):
        migration.copy_database.side_effect = ValueError("copy failed")
        with self.assertRaisesRegex(ValueError, "copy failed"):
            migration.migrate(self.root)
        self.assertEqual(self.env.read_text(), self.original)
        self.assertIn(("start", migration.PANEL), self.commands)
        self.assertNotIn(("start", migration.BOT), self.commands)
        backup, = self.source.parent.glob("migration-sqlite-*/wg_panel.db")
        with sqlite3.connect(backup) as connection:
            self.assertEqual(connection.execute("SELECT value FROM sample").fetchone(), ("existing data",))

    def test_startup_failure_restores_config_and_restarts_previous_services(self):
        self.bot_active = True
        with patch.object(migration, "_wait_for_panel", side_effect=[RuntimeError("failed probe"), None]):
            with self.assertRaisesRegex(RuntimeError, "failed probe"):
                migration.migrate(self.root)
        self.assertEqual(self.env.read_text(), self.original)
        self.assertIn(("restart", migration.PANEL, migration.BOT), self.commands)

    def test_bot_failure_keeps_database_after_panel_passes_readiness(self):
        self.bot_active = True
        self.bot_can_start = False
        with patch.object(migration, "_wait_for_panel"):
            migration.migrate(self.root)
        self.assertIn("DATABASE_URL=postgresql+psycopg://127.0.0.1/test", self.env.read_text())
        self.assertIn("# preserve comment", self.env.read_text())
        self.assertIn(("start", migration.BOT), self.commands)
        self.assertNotIn(("restart", migration.PANEL, migration.BOT), self.commands)


if __name__ == "__main__":
    unittest.main()
