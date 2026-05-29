"""Flask application implementing the TAXII 2.1 REST API.

Endpoints
---------
GET  /health                                          Health check
GET  /taxii2/                                         Server discovery
GET  /api/                                            API-root info
GET  /api/collections/                                List collections
GET  /api/collections/<id>/                           Collection details
GET  /api/collections/<id>/objects/                    Get STIX objects
GET  /api/collections/<id>/objects/<stix_id>/          Get object by STIX ID
POST /api/collections/<id>/objects/                    Add STIX objects
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, Response

from .models import (
    db,
    APIRoot,
    Collection,
    COLLECTION_MODELS,
    utcnow,
)
from . import config

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"

log = logging.getLogger("taxii_server.app")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(database_uri=None):
    """Create and configure the Flask application."""

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_uri or config.DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

    db.init_app(app)
    _register_routes(app)

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _taxii_response(data, status=200):
    """Build a ``Response`` with the TAXII 2.1 content-type."""
    return Response(
        json.dumps(data, default=str),
        status=status,
        content_type=TAXII_CONTENT_TYPE,
    )


def _require_auth(fn):
    """Optional API-key gate.  Skipped when ``config.API_KEY`` is empty."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not config.API_KEY:
            return fn(*args, **kwargs)

        provided = (
            request.headers.get("X-TAXII-API-Key")
            or request.headers.get("Authorization", "")
            .removeprefix("Bearer ")
            .strip()
        )
        if provided != config.API_KEY:
            return _taxii_response(
                {"title": "Unauthorized",
                 "description": "Invalid or missing API key"},
                status=401,
            )
        return fn(*args, **kwargs)

    return wrapper


def _parse_iso(ts):
    """Parse an ISO-8601 timestamp to a datetime, or *None*."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def _register_routes(app):  # noqa: C901 — single-module registration is fine
    """Attach all TAXII 2.1 endpoints to *app*."""

    # ---- Health check -----------------------------------------------------

    @app.route("/health", methods=["GET"])
    def health_check():
        return _taxii_response({"status": "ok", "title": config.SERVER_TITLE})

    # ---- Discovery --------------------------------------------------------

    @app.route("/taxii2/", methods=["GET"])
    @_require_auth
    def discovery():
        return _taxii_response({
            "title": config.SERVER_TITLE,
            "description": config.SERVER_DESCRIPTION,
            "default": f"http://{config.HOST}:{config.PORT}/api/",
            "api_roots": [f"http://{config.HOST}:{config.PORT}/api/"],
        })

    # ---- API Root ---------------------------------------------------------

    @app.route("/api/", methods=["GET"])
    @_require_auth
    def api_root_info():
        api_root = db.session.get(APIRoot, config.API_ROOT_ID)
        if not api_root:
            return _taxii_response(
                {"title": "Not Found",
                 "description": "API root not found"},
                status=404,
            )
        return _taxii_response({
            "title": api_root.title,
            "description": api_root.description,
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": api_root.max_content_length,
        })

    # ---- Collections ------------------------------------------------------

    @app.route("/api/collections/", methods=["GET"])
    @_require_auth
    def list_collections():
        collections = Collection.query.all()
        return _taxii_response({
            "collections": [
                {
                    "id": c.id,
                    "title": c.title,
                    "description": c.description or "",
                    "can_read": c.can_read,
                    "can_write": c.can_write,
                }
                for c in collections
            ],
        })

    @app.route("/api/collections/<collection_id>/", methods=["GET"])
    @_require_auth
    def get_collection(collection_id):
        collection = db.session.get(Collection, collection_id)
        if not collection:
            return _taxii_response(
                {"title": "Not Found",
                 "description": f"Collection '{collection_id}' not found"},
                status=404,
            )
        return _taxii_response({
            "id": collection.id,
            "title": collection.title,
            "description": collection.description or "",
            "can_read": collection.can_read,
            "can_write": collection.can_write,
        })

    # ---- GET objects ------------------------------------------------------

    @app.route("/api/collections/<collection_id>/objects/", methods=["GET"])
    @_require_auth
    def get_objects(collection_id):
        collection = db.session.get(Collection, collection_id)
        if not collection:
            return _taxii_response(
                {"title": "Not Found",
                 "description": f"Collection '{collection_id}' not found"},
                status=404,
            )

        model = COLLECTION_MODELS.get(collection_id)
        if not model:
            return _taxii_response(
                {"title": "Internal Error",
                 "description": "No model mapped for this collection"},
                status=500,
            )

        query = model.query

        # Filter: added_after
        added_after = request.args.get("added_after")
        if added_after:
            dt = _parse_iso(added_after)
            if dt:
                query = query.filter(model.date_added > dt)

        # Filter: STIX type
        stix_type = request.args.get("type")
        if stix_type:
            query = query.filter(model.stix_type == stix_type)

        # Ordering
        query = query.order_by(model.date_added.asc())

        # Pagination — fetch limit+1 to know if there are more
        limit = min(request.args.get("limit", 100, type=int), 1000)
        rows = query.limit(limit + 1).all()
        more = len(rows) > limit
        rows = rows[:limit]

        stix_objects = []
        for row in rows:
            try:
                stix_objects.append(json.loads(row.raw_json))
            except json.JSONDecodeError:
                continue

        response_data = {"more": more, "objects": stix_objects}
        if rows:
            first_dt = rows[0].date_added
            last_dt = rows[-1].date_added
            response_data["date_added_first"] = (
                first_dt.isoformat() + ("Z" if not first_dt.tzinfo else "")
            )
            response_data["date_added_last"] = (
                last_dt.isoformat() + ("Z" if not last_dt.tzinfo else "")
            )

        return _taxii_response(response_data)

    # ---- GET single object ------------------------------------------------

    @app.route(
        "/api/collections/<collection_id>/objects/<path:stix_id>/",
        methods=["GET"],
    )
    @_require_auth
    def get_object_by_id(collection_id, stix_id):
        collection = db.session.get(Collection, collection_id)
        if not collection:
            return _taxii_response(
                {"title": "Not Found",
                 "description": f"Collection '{collection_id}' not found"},
                status=404,
            )

        model = COLLECTION_MODELS.get(collection_id)
        if not model:
            return _taxii_response(
                {"title": "Internal Error",
                 "description": "No model mapped for this collection"},
                status=500,
            )

        rows = (
            model.query
            .filter_by(stix_id=stix_id)
            .order_by(model.date_added.desc())
            .all()
        )
        if not rows:
            return _taxii_response(
                {"title": "Not Found",
                 "description": f"Object '{stix_id}' not found"},
                status=404,
            )

        stix_objects = []
        for row in rows:
            try:
                stix_objects.append(json.loads(row.raw_json))
            except json.JSONDecodeError:
                continue

        return _taxii_response({"objects": stix_objects})

    # ---- POST objects (add to collection) ---------------------------------

    @app.route("/api/collections/<collection_id>/objects/", methods=["POST"])
    @_require_auth
    def add_objects(collection_id):
        collection = db.session.get(Collection, collection_id)
        if not collection:
            return _taxii_response(
                {"title": "Not Found",
                 "description": f"Collection '{collection_id}' not found"},
                status=404,
            )

        if not collection.can_write:
            return _taxii_response(
                {"title": "Forbidden",
                 "description": "Collection is read-only"},
                status=403,
            )

        model = COLLECTION_MODELS.get(collection_id)
        if not model:
            return _taxii_response(
                {"title": "Internal Error",
                 "description": "No model mapped for this collection"},
                status=500,
            )

        envelope = request.get_json(silent=True)
        if not envelope or "objects" not in envelope:
            return _taxii_response(
                {"title": "Bad Request",
                 "description": "Expected TAXII envelope with 'objects' array"},
                status=400,
            )

        objects = envelope["objects"]
        if not isinstance(objects, list):
            return _taxii_response(
                {"title": "Bad Request",
                 "description": "'objects' must be an array"},
                status=400,
            )

        added = 0
        duplicates = 0
        errors = []

        for idx, stix_obj in enumerate(objects):
            try:
                raw = json.dumps(stix_obj, sort_keys=True)
                content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

                # Duplicate check
                if model.query.filter_by(content_hash=content_hash).first():
                    duplicates += 1
                    continue

                record = model(
                    stix_id=stix_obj.get("id", ""),
                    stix_type=stix_obj.get("type", ""),
                    spec_version=stix_obj.get("spec_version", "2.1"),
                    created=_parse_iso(stix_obj.get("created")),
                    modified=_parse_iso(stix_obj.get("modified")),
                    raw_json=raw,
                    content_hash=content_hash,
                )
                db.session.add(record)
                added += 1

            except Exception as exc:
                errors.append(f"Object {idx}: {exc}")

        # Commit all inserts in a single transaction
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            return _taxii_response(
                {"title": "Internal Error",
                 "description": f"Database commit failed: {exc}"},
                status=500,
            )

        status_id = hashlib.sha256(
            str(utcnow()).encode("utf-8")
        ).hexdigest()[:16]

        log.info(
            "Collection '%s': added %d, duplicates %d, errors %d",
            collection_id, added, duplicates, len(errors),
        )

        return _taxii_response(
            {
                "id": f"status--{status_id}",
                "status": "complete",
                "total_count": len(objects),
                "success_count": added,
                "failure_count": len(errors),
                "pending_count": 0,
            },
            status=202,
        )
