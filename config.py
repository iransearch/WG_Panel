import os

from panel_core.database import database_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)


class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me")
    SQLALCHEMY_DATABASE_URI = database_url(os.getenv("DATABASE_URL"), BASE_DIR)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    WG_CONF_PATH = os.environ.get("AMNEZIAWG_CONF_PATH", "/etc/amnezia/amneziawg/")
    API_KEY = os.environ.get("API_KEY", "")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    SECURE_COOKIES = bool(int(os.environ.get("SECURE_COOKIES", "0")))
    SETUP_TOKEN = os.environ.get("SETUP_TOKEN", "")
    TG_HEARTBEAT_SEC = int(os.environ.get("TG_HEARTBEAT_SEC", "60"))
