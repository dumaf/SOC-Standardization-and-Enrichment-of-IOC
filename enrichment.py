"""IOC Enrichment Scoring Engine — cross-references against local URLhaus + MalwareBazaar databases.

Data source priority:
1. TAXII 2.1 server (polled every 60 s on a background thread)
2. JSONL files on disk (fallback when the server is offline)
"""

import json
import logging
import os
import re
import socket
import argparse
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any

# Config
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
URLHAUS_JSONL = os.path.join(BASE_DIR, "abuse_stream.jsonl")
MB_JSONL      = os.path.join(BASE_DIR, "malwarebazaar_recent.jsonl")
OUTPUT_FILE   = os.path.join(BASE_DIR, "enrichment_results.jsonl")
DEFAULT_TAXII_URL = os.getenv("TAXII_SERVER_URL", "http://localhost:6100")
POLL_INTERVAL = 60  # seconds between TAXII polls

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("enrichment")

DANGEROUS_TAGS = {
    "stealer", "ransomware", "rat", "loader", "botnet", "c2",
    "banker", "trojan", "keylogger", "spyware", "miner",
    "backdoor", "infostealer", "downloader", "dropper",
    "apt", "exploit", "phishing", "cryptojacking",
}

TRUSTED_REPORTERS = {"abuse_ch", "urlhaus", "malwarebazaar", "abuse.ch"}

_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_SHA1_RE   = re.compile(r"^[A-Fa-f0-9]{40}$")
_MD5_RE    = re.compile(r"^[A-Fa-f0-9]{32}$")
_IP_RE     = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# STIX pattern extractors
_STIX_URL_RE    = re.compile(r"url:value\s*=\s*'([^']+)'")
_STIX_SHA256_RE = re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'")
_STIX_SHA1_RE   = re.compile(r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'")
_STIX_MD5_RE    = re.compile(r"file:hashes\.MD5\s*=\s*'([^']+)'")


# IOC Classification

def classify_ioc(value: str) -> str:
    value = value.strip()
    if value.startswith(("http://", "https://")):
        return "url"
    if _SHA256_RE.match(value):
        return "sha256"
    if _SHA1_RE.match(value):
        return "sha1"
    if _MD5_RE.match(value):
        return "md5"
    if _IP_RE.match(value):
        return "ip"
    if "." in value and " " not in value:
        return "domain"
    return "unknown"


def extract_iocs_from_packet(packet: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Extract IOC values from a raw packet dict. Returns {url, domain, ip, sha256, sha1, md5}."""
    iocs: Dict[str, Optional[str]] = {
        "url": None, "domain": None, "ip": None,
        "sha256": None, "sha1": None, "md5": None,
    }

    key_map = {
        "url":    ("url", "uri", "link", "URL"),
        "domain": ("domain", "host", "hostname"),
        "ip":     ("ip", "ip_address", "src_ip", "dst_ip", "ipv4"),
        "sha256": ("sha256", "sha256_hash", "SHA-256", "sha256Hash", "x_mb_sha256"),
        "sha1":   ("sha1", "sha1_hash", "SHA-1", "x_mb_sha1"),
        "md5":    ("md5", "md5_hash", "MD5", "x_mb_md5"),
    }

    for ioc_field, keys in key_map.items():
        for k in keys:
            if packet.get(k):
                iocs[ioc_field] = str(packet[k]).strip()
                break

    # Derive domain + IP from URL
    if iocs["url"]:
        try:
            parsed = urlparse(iocs["url"])
            hostname = parsed.hostname
            if hostname:
                if _IP_RE.match(hostname):
                    iocs["ip"] = iocs["ip"] or hostname
                else:
                    iocs["domain"] = iocs["domain"] or hostname
        except Exception:
            pass

    # Resolve domain -> IP
    if iocs["domain"] and not iocs["ip"]:
        try:
            info = socket.getaddrinfo(iocs["domain"], None, socket.AF_INET)
            if info:
                iocs["ip"] = info[0][4][0]
        except (socket.gaierror, OSError):
            pass

    # Auto-detect from generic fields
    for k in ("ioc", "value", "indicator", "observable"):
        raw = packet.get(k)
        if raw:
            raw = str(raw).strip()
            t = classify_ioc(raw)
            if t != "unknown" and not iocs.get(t):
                iocs[t] = raw
            break

    # Extract from STIX pattern
    pattern = packet.get("pattern", "")
    if pattern:
        m = _STIX_URL_RE.search(pattern)
        if m and not iocs["url"]:
            iocs["url"] = m.group(1)
        m = _STIX_SHA256_RE.search(pattern)
        if m and not iocs["sha256"]:
            iocs["sha256"] = m.group(1)
        m = _STIX_SHA1_RE.search(pattern)
        if m and not iocs["sha1"]:
            iocs["sha1"] = m.group(1)
        m = _STIX_MD5_RE.search(pattern)
        if m and not iocs["md5"]:
            iocs["md5"] = m.group(1)

    return iocs


# Local Database Index

class _LocalIndex:
    """In-memory index built from local JSONL databases."""

    def __init__(self):
        self.urlhaus_by_url: Dict[str, List[dict]]    = defaultdict(list)
        self.urlhaus_by_domain: Dict[str, List[dict]]  = defaultdict(list)
        self.urlhaus_by_ip: Dict[str, List[dict]]      = defaultdict(list)
        self.mb_by_sha256: Dict[str, List[dict]] = defaultdict(list)
        self.mb_by_sha1: Dict[str, List[dict]]   = defaultdict(list)
        self.mb_by_md5: Dict[str, List[dict]]    = defaultdict(list)
        self.urlhaus_count = 0
        self.mb_count = 0

    def load_urlhaus(self, filepath: str) -> None:
        if not os.path.exists(filepath):
            log.warning("URLhaus database not found: %s", filepath)
            return

        count = 0
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if obj.get("type") != "indicator":
                    continue

                pattern = obj.get("pattern", "")
                m = _STIX_URL_RE.search(pattern)
                if m:
                    url = m.group(1)
                    self.urlhaus_by_url[url.lower()].append(obj)
                    try:
                        parsed = urlparse(url)
                        hostname = parsed.hostname
                        if hostname:
                            if _IP_RE.match(hostname):
                                self.urlhaus_by_ip[hostname].append(obj)
                            else:
                                self.urlhaus_by_domain[hostname.lower()].append(obj)
                    except Exception:
                        pass
                    count += 1

        self.urlhaus_count = count
        log.info(
            "URLhaus index: %d indicators, %d URLs, %d domains, %d IPs",
            count, len(self.urlhaus_by_url), len(self.urlhaus_by_domain), len(self.urlhaus_by_ip),
        )

    def load_malwarebazaar(self, filepath: str) -> None:
        if not os.path.exists(filepath):
            log.warning("MalwareBazaar database not found: %s", filepath)
            return

        count = 0
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if obj.get("type") not in ("malware", "indicator"):
                    continue

                sha256 = obj.get("x_mb_sha256", "")
                sha1   = obj.get("x_mb_sha1", "")
                md5    = obj.get("x_mb_md5", "")

                if sha256:
                    self.mb_by_sha256[sha256.lower()].append(obj)
                if sha1:
                    self.mb_by_sha1[sha1.lower()].append(obj)
                if md5:
                    self.mb_by_md5[md5.lower()].append(obj)
                count += 1

        self.mb_count = count
        log.info(
            "MalwareBazaar index: %d objects, %d SHA-256, %d SHA-1, %d MD5",
            count, len(self.mb_by_sha256), len(self.mb_by_sha1), len(self.mb_by_md5),
        )

    # --- TAXII-sourced loading (same indexing logic, list-of-dicts input) --

    def load_urlhaus_from_objects(self, objects: List[dict]) -> int:
        """Index URLhaus STIX objects received from a TAXII poll."""
        count = 0
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            m = _STIX_URL_RE.search(pattern)
            if m:
                url = m.group(1)
                self.urlhaus_by_url[url.lower()].append(obj)
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname:
                        if _IP_RE.match(hostname):
                            self.urlhaus_by_ip[hostname].append(obj)
                        else:
                            self.urlhaus_by_domain[hostname.lower()].append(obj)
                except Exception:
                    pass
                count += 1
        self.urlhaus_count += count
        if count:
            log.info("Indexed %d URLhaus indicators from TAXII", count)
        return count

    def load_malwarebazaar_from_objects(self, objects: List[dict]) -> int:
        """Index MalwareBazaar STIX objects received from a TAXII poll."""
        count = 0
        for obj in objects:
            if obj.get("type") not in ("malware", "indicator"):
                continue
            sha256 = obj.get("x_mb_sha256", "")
            sha1   = obj.get("x_mb_sha1", "")
            md5    = obj.get("x_mb_md5", "")
            if sha256:
                self.mb_by_sha256[sha256.lower()].append(obj)
            if sha1:
                self.mb_by_sha1[sha1.lower()].append(obj)
            if md5:
                self.mb_by_md5[md5.lower()].append(obj)
            count += 1
        self.mb_count += count
        if count:
            log.info("Indexed %d MalwareBazaar objects from TAXII", count)
        return count


# Temporal Weighting

def _parse_timestamp(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            continue
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _compute_temporal_multiplier(timestamp_str: Optional[str]) -> float:
    dt = _parse_timestamp(timestamp_str)
    if dt is None:
        return 1.0

    hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600

    if hours < 24:      return 1.5
    elif hours < 72:    return 1.2
    elif hours < 168:   return 1.0  # 7 days
    elif hours < 720:   return 0.8  # 30 days
    else:               return 0.6


#Confidence Scoring

def _classify_confidence(score: float) -> Dict[str, Any]:
    if score >= 150:
        return {"level": "CRITICAL", "label": "Confirmed active threat", "priority": 1}
    elif score >= 100:
        return {"level": "HIGH", "label": "Strong correlation - prioritize", "priority": 2}
    elif score >= 50:
        return {"level": "MEDIUM", "label": "Investigate further", "priority": 3}
    elif score >= 20:
        return {"level": "LOW", "label": "Informational", "priority": 4}
    else:
        return {"level": "MINIMAL", "label": "Likely benign or stale", "priority": 5}


# Enricher

class Enricher:
    """Loads IOC databases (TAXII or JSONL), provides fast lookups.

    Data-source priority:
      1. TAXII server (if *taxii_url* is set and the server responds)
      2. JSONL files on disk (fallback)

    When TAXII is used, a daemon thread polls for new objects every
    *poll_interval* seconds (default 60).
    """

    def __init__(
        self,
        urlhaus_path: str = URLHAUS_JSONL,
        mb_path: str = MB_JSONL,
        taxii_url: str = DEFAULT_TAXII_URL,
        poll_interval: int = POLL_INTERVAL,
    ):
        self.index = _LocalIndex()
        self._taxii_url = taxii_url
        self._poll_interval = poll_interval
        self._taxii_client = None
        self._last_cursor_urlhaus: Optional[str] = None
        self._last_cursor_mb: Optional[str] = None

        # --- Initial load: prefer TAXII, fall back to JSONL ---------------
        if taxii_url:
            from taxii_client import TAXIIClient
            self._taxii_client = TAXIIClient(taxii_url)
            if self._taxii_client.is_server_alive():
                log.info("TAXII server online — loading from %s", taxii_url)
                self._full_load_from_taxii()
            else:
                log.info("TAXII server offline — loading from JSONL files")
                self._taxii_client = None
                self.index.load_urlhaus(urlhaus_path)
                self.index.load_malwarebazaar(mb_path)
        else:
            self.index.load_urlhaus(urlhaus_path)
            self.index.load_malwarebazaar(mb_path)

        # --- Background polling thread ------------------------------------
        if self._taxii_client:
            t = threading.Thread(target=self._poll_loop, daemon=True)
            t.start()
            log.info(
                "Background TAXII polling started (every %ds)",
                poll_interval,
            )

    # --- TAXII helpers ----------------------------------------------------

    def _full_load_from_taxii(self) -> None:
        """Bulk-load all objects from both TAXII collections."""
        try:
            resp = self._taxii_client.poll("urlhaus-indicators")
            self.index.load_urlhaus_from_objects(resp["objects"])
            self._last_cursor_urlhaus = resp.get("date_added_last")
        except Exception as exc:
            log.error("Failed to load URLhaus from TAXII: %s", exc)

        try:
            resp = self._taxii_client.poll("malwarebazaar-indicators")
            self.index.load_malwarebazaar_from_objects(resp["objects"])
            self._last_cursor_mb = resp.get("date_added_last")
        except Exception as exc:
            log.error("Failed to load MalwareBazaar from TAXII: %s", exc)

    def _poll_loop(self) -> None:
        """Background thread: poll the TAXII server for new data."""
        while True:
            time.sleep(self._poll_interval)
            if not self._taxii_client:
                continue
            try:
                if not self._taxii_client.is_server_alive():
                    log.debug("TAXII server unreachable during poll cycle")
                    continue
                self._poll_incremental()
            except Exception as exc:
                log.warning("TAXII poll cycle failed: %s", exc)

    def _poll_incremental(self) -> None:
        """Fetch only objects added since the last successful poll."""
        # URLhaus
        try:
            resp = self._taxii_client.poll(
                "urlhaus-indicators",
                added_after=self._last_cursor_urlhaus,
            )
            new = self.index.load_urlhaus_from_objects(resp["objects"])
            if resp.get("date_added_last"):
                self._last_cursor_urlhaus = resp["date_added_last"]
            if new:
                log.info("Polled %d new URLhaus objects", new)
        except Exception as exc:
            log.warning("URLhaus poll failed: %s", exc)

        # MalwareBazaar
        try:
            resp = self._taxii_client.poll(
                "malwarebazaar-indicators",
                added_after=self._last_cursor_mb,
            )
            new = self.index.load_malwarebazaar_from_objects(resp["objects"])
            if resp.get("date_added_last"):
                self._last_cursor_mb = resp["date_added_last"]
            if new:
                log.info("Polled %d new MalwareBazaar objects", new)
        except Exception as exc:
            log.warning("MalwareBazaar poll failed: %s", exc)

    def enrich(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single IOC packet against local databases."""
        iocs = extract_iocs_from_packet(packet)
        active = {k: v for k, v in iocs.items() if v}
        log.info("Enriching IOCs: %s", active)

        score = 0
        hits: Dict[str, Any] = {
            "urlhaus_url": None, "urlhaus_domain": None,
            "urlhaus_ip": None, "malwarebazaar": None,
        }
        all_tags: List[str] = []
        earliest_timestamp: Optional[str] = None
        details: List[str] = []

        # 1. URLhaus: exact URL match (+50)
        if iocs["url"]:
            matches = self.index.urlhaus_by_url.get(iocs["url"].lower(), [])
            if matches:
                score += 50
                details.append("URLhaus exact URL match (+50)")
                first = matches[0]
                hits["urlhaus_url"] = {
                    "matched_count": len(matches),
                    "labels": first.get("labels"),
                    "valid_from": first.get("valid_from"),
                    "description": first.get("description", "")[:200],
                }
                earliest_timestamp = first.get("valid_from")

        # 2. URLhaus: domain match (+40)
        if iocs["domain"]:
            matches = self.index.urlhaus_by_domain.get(iocs["domain"].lower(), [])
            if matches:
                score += 40
                details.append(f"URLhaus domain match (+40) [{iocs['domain']}] ({len(matches)} indicators)")
                first = matches[0]
                hits["urlhaus_domain"] = {
                    "matched_count": len(matches),
                    "valid_from": first.get("valid_from"),
                }
                earliest_timestamp = earliest_timestamp or first.get("valid_from")

        # 3. URLhaus: IP match (+20)
        if iocs["ip"]:
            matches = self.index.urlhaus_by_ip.get(iocs["ip"], [])
            if matches:
                score += 20
                details.append(f"URLhaus IP match (+20) [{iocs['ip']}] ({len(matches)} indicators)")
                hits["urlhaus_ip"] = {"matched_count": len(matches)}
                earliest_timestamp = earliest_timestamp or matches[0].get("valid_from")

        # 4. MalwareBazaar: hash match (+60)
        mb_record = None
        hash_hits = 0
        for hash_type, index_map in [
            ("sha256", self.index.mb_by_sha256),
            ("sha1",   self.index.mb_by_sha1),
            ("md5",    self.index.mb_by_md5),
        ]:
            if iocs[hash_type]:
                matches = index_map.get(iocs[hash_type].lower(), [])
                if matches:
                    hash_hits += 1
                    if mb_record is None:
                        mb_record = next((m for m in matches if m.get("type") == "malware"), matches[0])
                        score += 60
                        details.append(f"MalwareBazaar hash match (+60) [{hash_type}]")
                        hits["malwarebazaar"] = {
                            "matched_count": len(matches),
                            "sha256": mb_record.get("x_mb_sha256"),
                            "signature": mb_record.get("name", ""),
                            "file_type": mb_record.get("x_mb_file_type"),
                            "file_name": mb_record.get("x_mb_file_name"),
                            "reporter": mb_record.get("x_mb_reporter"),
                            "first_seen": mb_record.get("x_mb_first_seen"),
                            "delivery_method": mb_record.get("x_mb_delivery_method"),
                            "intelligence": mb_record.get("x_mb_intelligence"),
                        }
                        mb_tags = mb_record.get("x_mb_tags") or []
                        if isinstance(mb_tags, list):
                            all_tags.extend(t for t in mb_tags if t)
                        elif isinstance(mb_tags, str) and mb_tags:
                            all_tags.append(mb_tags)
                        fs = mb_record.get("x_mb_first_seen") or mb_record.get("first_seen")
                        earliest_timestamp = earliest_timestamp or fs

        # 5. Multi-hash confirmation (+15)
        if hash_hits >= 2:
            score += 15
            details.append(f"Multi-hash confirmation (+15) [{hash_hits} hash types]")

        # 6. Dangerous tag boost (+20)
        normalised_tags = list(set(t.lower().strip() for t in all_tags if t))
        dangerous_found = [t for t in normalised_tags if t in DANGEROUS_TAGS]
        if dangerous_found:
            score += 20
            details.append(f"Dangerous tags (+20) [{', '.join(dangerous_found)}]")

        # 7. Delivery method (+10)
        if mb_record and mb_record.get("x_mb_delivery_method"):
            score += 10
            details.append(f"Delivery method known (+10) [{mb_record['x_mb_delivery_method']}]")

        # 8. Trusted reporter (+10)
        reporter = (mb_record or {}).get("x_mb_reporter", "")
        if reporter and reporter.lower().replace("-", "_") in TRUSTED_REPORTERS:
            score += 10
            details.append(f"Trusted reporter (+10) [{reporter}]")

        # 9. Cross-source correlation (+50)
        urlhaus_hit = any([hits["urlhaus_url"], hits["urlhaus_domain"], hits["urlhaus_ip"]])
        mb_hit = hits["malwarebazaar"] is not None
        if urlhaus_hit and mb_hit:
            score += 50
            details.append("Cross-source correlation URLhaus+MalwareBazaar (+50)")

        # 10. Temporal multiplier
        temporal_mul = _compute_temporal_multiplier(earliest_timestamp)
        raw_score = score
        final_score = round(score * temporal_mul, 1)

        # 11. Confidence classification
        confidence = _classify_confidence(final_score)

        return {
            "ioc": active,
            "raw_score": raw_score,
            "temporal_multiplier": temporal_mul,
            "final_score": final_score,
            "confidence": confidence,
            "hits": hits,
            "tags": normalised_tags,
            "scoring_breakdown": details,
            "earliest_seen": earliest_timestamp,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "source_packet": packet,
        }

    def enrich_batch(self, packets: List[Dict[str, Any]], output_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """Enrich a list of IOC packets."""
        results = []
        for i, pkt in enumerate(packets, 1):
            log.info("--- Enriching packet %d / %d ---", i, len(packets))
            try:
                results.append(self.enrich(pkt))
            except Exception as e:
                log.error("Failed to enrich packet %d: %s", i, e)
                results.append({"error": str(e), "source_packet": pkt, "enriched_at": datetime.now(timezone.utc).isoformat()})
        if output_file:
            _write_results(results, output_file)
        return results


# Convenience wrappers (lazy-loaded shared Enricher)

_shared_enricher: Optional[Enricher] = None

def enrich_ioc(packet: Dict[str, Any], taxii_url: str = DEFAULT_TAXII_URL) -> Dict[str, Any]:
    """Enrich a single IOC packet. Loads indices on first call."""
    global _shared_enricher
    if _shared_enricher is None:
        _shared_enricher = Enricher(taxii_url=taxii_url)
    return _shared_enricher.enrich(packet)

def enrich_batch(packets: List[Dict[str, Any]], output_file: Optional[str] = None, taxii_url: str = DEFAULT_TAXII_URL) -> List[Dict[str, Any]]:
    global _shared_enricher
    if _shared_enricher is None:
        _shared_enricher = Enricher(taxii_url=taxii_url)
    return _shared_enricher.enrich_batch(packets, output_file)


def _write_results(results: List[Dict], filepath: str) -> None:
    with open(filepath, "a", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, default=str) + "\n")
    log.info("Wrote %d enrichment results to %s", len(results), filepath)


def _print_result(result: Dict) -> None:
    conf = result.get("confidence", {})
    ioc = result.get("ioc", {})
    print("\n" + "=" * 70)
    print("  IOC ENRICHMENT RESULT")
    print("=" * 70)
    print(f"  IOC Values     : {ioc}")
    print(f"  Raw Score      : {result.get('raw_score', 0)}")
    print(f"  Temporal x     : {result.get('temporal_multiplier', 1.0)}")
    print(f"  Final Score    : {result.get('final_score', 0)}")
    print(f"  Confidence     : {conf.get('level', '?')} - {conf.get('label', '')}")
    print(f"  Earliest Seen  : {result.get('earliest_seen', 'N/A')}")
    print(f"  Tags           : {', '.join(result.get('tags', [])) or 'none'}")
    print("-" * 70)
    print("  Scoring Breakdown:")
    for line in result.get("scoring_breakdown", []):
        print(f"    * {line}")
    if not result.get("scoring_breakdown"):
        print("    * No matches found in any source")
    print("=" * 70 + "\n")


# CLI

def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment - cross-reference against local databases")
    parser.add_argument("ioc_value", help="IOC value to enrich (URL, hash, domain, or IP)")
    parser.add_argument("--type", "-t", choices=["url", "hash", "domain", "ip", "auto"], default="auto")
    parser.add_argument("--output", "-o", default=OUTPUT_FILE)
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")
    parser.add_argument("--urlhaus-db", default=URLHAUS_JSONL)
    parser.add_argument("--mb-db", default=MB_JSONL)
    parser.add_argument("--taxii-url", default=DEFAULT_TAXII_URL,
                        help="TAXII 2.1 server URL (default: %(default)s)")
    parser.add_argument("--no-taxii", action="store_true",
                        help="Disable TAXII and use JSONL files only")
    args = parser.parse_args()

    ioc_value = args.ioc_value.strip()
    ioc_type = args.type
    if ioc_type == "auto":
        ioc_type = classify_ioc(ioc_value)
        log.info("Auto-detected IOC type: %s", ioc_type)

    packet: Dict[str, str] = {}
    if ioc_type == "url":
        packet["url"] = ioc_value
    elif ioc_type in ("sha256", "sha1", "md5", "hash"):
        if _SHA256_RE.match(ioc_value):     packet["sha256"] = ioc_value
        elif _SHA1_RE.match(ioc_value):     packet["sha1"] = ioc_value
        elif _MD5_RE.match(ioc_value):      packet["md5"] = ioc_value
        else:                               packet["sha256"] = ioc_value
    elif ioc_type == "domain":
        packet["domain"] = ioc_value
    elif ioc_type == "ip":
        packet["ip"] = ioc_value
    else:
        packet["ioc"] = ioc_value

    taxii_url = "" if args.no_taxii else args.taxii_url
    enricher = Enricher(
        urlhaus_path=args.urlhaus_db,
        mb_path=args.mb_db,
        taxii_url=taxii_url,
    )
    result = enricher.enrich(packet)
    _write_results([result], args.output)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_result(result)

    return result


if __name__ == "__main__":
    main()
