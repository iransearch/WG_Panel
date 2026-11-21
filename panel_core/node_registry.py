"""Create a node record from both the panel and the provisioning worker."""
from datetime import datetime, timezone

from sqlalchemy import text

from models import Node, db


class NodeAlreadyExists(Exception):
    pass


def has_node(name, base_url):
    return Node.query.filter((Node.name == name) | (Node.base_url == base_url)).first() is not None


def add_node(name, base_url, encrypted_key, *, verified=False):
    # PostgreSQL serializes this check with inserts from other panel workers.
    db.session.execute(text("SELECT pg_advisory_xact_lock(714598228796560946)"))
    if has_node(name, base_url):
        db.session.rollback()
        raise NodeAlreadyExists("Node name or URL already exists.")
    node = Node(name=name, base_url=base_url, api_key=encrypted_key, enabled=True)
    if verified:
        node.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.add(node)
    db.session.commit()
    return node.id


def register_provisioned_node(name, base_url, api_key):
    import os
    from pathlib import Path

    from cryptography.fernet import Fernet
    from dotenv import load_dotenv
    from flask import Flask

    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    from config import Config

    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"hide_parameters": True}
    db.init_app(app)
    encrypted_key = Fernet(os.environ["FERNET_KEY"]).encrypt(api_key.encode()).decode()
    with app.app_context():
        return add_node(name, base_url, encrypted_key, verified=True)
