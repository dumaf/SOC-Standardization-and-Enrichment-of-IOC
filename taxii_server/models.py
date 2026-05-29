"""SQLAlchemy ORM models for the TAXII 2.1 server."""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def utcnow():

    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Metadata tables
# ---------------------------------------------------------------------------

class APIRoot(db.Model):

    __tablename__ = "api_root"

    id = db.Column(db.String(255), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    max_content_length = db.Column(db.Integer, default=10_485_760)


class Collection(db.Model):


    __tablename__ = "collection"

    id = db.Column(db.String(255), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    can_read = db.Column(db.Boolean, default=True)
    can_write = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)


class STIXObjectMixin:
    """Common columns for every STIX-object table.

    Each concrete subclass (``URLHausObject``, ``MalwareBazaarObject``)
    """

    internal_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stix_id = db.Column(db.String(255), index=True)       # e.g. "indicator--<uuid>"
    stix_type = db.Column(db.String(100), index=True)      # e.g. "indicator"
    spec_version = db.Column(db.String(10), default="2.1")
    created = db.Column(db.DateTime)
    modified = db.Column(db.DateTime)
    date_added = db.Column(db.DateTime, default=utcnow, index=True)
    raw_json = db.Column(db.Text, nullable=False)          
    content_hash = db.Column(db.String(64), index=True, unique=True)  




class URLHausObject(STIXObjectMixin, db.Model):
    

    __tablename__ = "urlhaus_object"


class MalwareBazaarObject(STIXObjectMixin, db.Model):
    

    __tablename__ = "malwarebazaar_object"

COLLECTION_MODELS = {
    "urlhaus-indicators": URLHausObject,
    "malwarebazaar-indicators": MalwareBazaarObject,
}
