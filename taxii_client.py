

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger("taxii_client")

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
HEALTH_TIMEOUT = 2  # seconds


class TAXIIClient:
    """TAXII 2.1 client for pushing and polling STIX 2.1 objects."""

    def __init__(
        self,
        server_url: str = "",
        api_key: str = "",
    ):
        server_url = server_url or os.getenv(
            "TAXII_SERVER_URL", "http://localhost:6100"
        )
        api_key = api_key or os.getenv("TAXII_API_KEY", "")

        self.server_url: str = server_url.rstrip("/")
        self.api_key: str = api_key
        self._session: requests.Session = requests.Session()
        self._session.headers.update(
            {
                "Content-Type": TAXII_CONTENT_TYPE,
                "Accept": TAXII_CONTENT_TYPE,
            }
        )
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def is_server_alive(self) -> bool:
        """Return *True* if the TAXII server responds to ``GET /health``."""
        try:
            resp = self._session.get(
                f"{self.server_url}/health", timeout=HEALTH_TIMEOUT
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    # ------------------------------------------------------------------
    # Push
    # ------------------------------------------------------------------

    def push_objects(
        self,
        collection_id: str,
        stix_objects: list,
    ) -> Dict[str, Any]:
        """POST a TAXII envelope of STIX objects to a collection.

        *stix_objects* may be raw dicts **or** ``stix2`` library objects
        (anything with a ``.serialize()`` method).

        Returns the status dict from the server.
        """
        if not stix_objects:
            return {
                "status": "complete",
                "total_count": 0,
                "success_count": 0,
            }

        serialised: List[dict] = []
        for obj in stix_objects:
            if hasattr(obj, "serialize"):
                serialised.append(json.loads(obj.serialize()))
            elif isinstance(obj, dict):
                serialised.append(obj)
            else:
                serialised.append(json.loads(str(obj)))

        envelope = {"objects": serialised}
        resp = self._session.post(
            f"{self.server_url}/api/collections/{collection_id}/objects/",
            json=envelope,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll_objects(
        self,
        collection_id: str,
        added_after: Optional[str] = None,
        stix_type: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """GET STIX objects from a collection (auto-paginates).

        Returns a flat list of STIX dicts.
        """
        result = self.poll(
            collection_id,
            added_after=added_after,
            stix_type=stix_type,
            limit=limit,
        )
        return result["objects"]

    def poll(
        self,
        collection_id: str,
        added_after: Optional[str] = None,
        stix_type: Optional[str] = None,
        limit: int = 500,
    ) -> Dict[str, Any]:
        """GET STIX objects with full metadata (including cursor info).

        Returns::

            {
                "objects": [...],
                "date_added_last": "...",   # or None
                "more": False,
            }
        """
        params: Dict[str, Any] = {"limit": limit}
        if added_after:
            params["added_after"] = added_after
        if stix_type:
            params["type"] = stix_type

        all_objects: List[dict] = []
        date_added_last: Optional[str] = None

        while True:
            resp = self._session.get(
                f"{self.server_url}/api/collections/{collection_id}/objects/",
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            page_objects = data.get("objects", [])
            all_objects.extend(page_objects)
            date_added_last = data.get("date_added_last", date_added_last)
            more = data.get("more", False)

            if more and page_objects and date_added_last:
                params["added_after"] = date_added_last
            else:
                break

        return {
            "objects": all_objects,
            "date_added_last": date_added_last,
            "more": False,  # we've consumed all pages
        }

    # ------------------------------------------------------------------
    # Discovery helpers
    # ------------------------------------------------------------------

    def list_collections(self) -> List[Dict[str, Any]]:
        """Return the list of collection dicts from the server."""
        resp = self._session.get(
            f"{self.server_url}/api/collections/", timeout=10
        )
        resp.raise_for_status()
        return resp.json().get("collections", [])
