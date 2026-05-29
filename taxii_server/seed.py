"""Database initialisation and seeding for the TAXII 2.1 server.

Creates all tables and inserts the default API root and collections
if they do not already exist.  Safe to call on every server start.
"""

import logging

from .models import db, APIRoot, Collection
from . import config

log = logging.getLogger("taxii_server.seed")


def seed_database():
    """Create tables and seed the default API root + collections."""

    db.create_all()

    if not db.session.get(APIRoot, config.API_ROOT_ID):
        db.session.add(
            APIRoot(
                id=config.API_ROOT_ID,
                title=config.API_ROOT_TITLE,
                description=config.API_ROOT_DESCRIPTION,
                max_content_length=config.MAX_CONTENT_LENGTH,
            )
        )
        log.info("Seeded API root: %s", config.API_ROOT_ID)

    collections = [
        {
            "id": "urlhaus-indicators",
            "title": "URLhaus Indicators",
            "description": (
                "STIX 2.1 Indicators from the URLhaus abuse.ch feed"
            ),
        },
        {
            "id": "malwarebazaar-indicators",
            "title": "MalwareBazaar Indicators",
            "description": (
                "STIX 2.1 Malware, Indicator, and Relationship objects "
                "from MalwareBazaar"
            ),
        },
    ]

    for col in collections:
        if not db.session.get(Collection, col["id"]):
            db.session.add(Collection(**col))
            log.info("Seeded collection: %s", col["id"])

    db.session.commit()
    log.info("Database seed complete.")
