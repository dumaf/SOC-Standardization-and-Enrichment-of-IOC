"""TAXII 2.1 Server configuration."""

import os

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database — SQLite by default, stored inside taxii_server/
_db_path = os.path.join(BASE_DIR, "taxii.db").replace("\\", "/")
DATABASE_URI = os.getenv("TAXII_DB_URI", f"sqlite:///{_db_path}")

# Authentication — empty string means no auth (dev mode)
API_KEY = os.getenv("TAXII_API_KEY", "")

# Server binding
HOST = os.getenv("TAXII_HOST", "localhost")
PORT = int(os.getenv("TAXII_PORT", "6100"))

# Server metadata
SERVER_TITLE = "SOC TAXII 2.1 Server"
SERVER_DESCRIPTION = (
    "Custom TAXII 2.1 server for IOC standardization and enrichment pipeline"
)

# API Root metadata
API_ROOT_ID = "api"
API_ROOT_TITLE = "SOC Threat Intelligence"
API_ROOT_DESCRIPTION = (
    "API root for URLhaus and MalwareBazaar threat intelligence collections"
)

# Limits
MAX_CONTENT_LENGTH = 10_485_760  # 10 MB
