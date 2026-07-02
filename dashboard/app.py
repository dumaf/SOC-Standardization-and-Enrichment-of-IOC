"""
SOC Analyst Dashboard — Flask backend
Reads enrichment_results.jsonl and exposes a REST API consumed by the
single-page frontend (templates/index.html).

Run:
    pip install flask
    python dashboard/app.py
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_FILE = os.path.join(BASE_DIR, "enrichment_results.jsonl")
SUPPRESSED_FILE = os.path.join(BASE_DIR, "dashboard", "suppressed_iocs.json")

app = Flask(__name__, template_folder="templates", static_folder="static")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load_suppressed() -> set:
    if os.path.exists(SUPPRESSED_FILE):
        with open(SUPPRESSED_FILE) as f:
            return set(json.load(f))
    return set()


def _save_suppressed(suppressed: set):
    with open(SUPPRESSED_FILE, "w") as f:
        json.dump(list(suppressed), f)


def _ioc_key(result: dict) -> str:
    ioc = result.get("ioc", {})
    for field in ("url", "domain", "ip", "sha256", "sha1", "md5"):
        if ioc.get(field):
            return ioc[field]
    return ""


def _load_results(min_score: float = 0.0, limit: int = 500) -> list:
    """
    Read the JSONL file, deduplicate by IOC value (keep highest score),
    filter suppressed IOCs, and return sorted by score descending.
    """
    suppressed = _load_suppressed()
    best: dict = {}  # ioc_key → result

    if not os.path.exists(RESULTS_FILE):
        return []

    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("final_score", 0) < min_score:
                continue
            key = _ioc_key(obj)
            if not key or key in suppressed:
                continue
            if key not in best or obj["final_score"] > best[key]["final_score"]:
                best[key] = obj

    results = list(best.values())
    results.sort(key=lambda x: x.get("final_score", 0), reverse=True)
    return results[:limit]


def _compute_stats(all_results: list) -> dict:
    counts = defaultdict(int)
    for r in all_results:
        level = r.get("confidence", {}).get("level", "MINIMAL")
        counts[level] += 1

    # Count suppressed from full file
    suppressed_count = 0
    suppressed = _load_suppressed()
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                    if _ioc_key(obj) in suppressed:
                        suppressed_count += 1
                except Exception:
                    continue

    total_file_lines = 0
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, "rb") as f:
            total_file_lines = sum(1 for _ in f)

    return {
        "total_alerts": total_file_lines,
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "minimal": counts.get("MINIMAL", 0),
        "suppressed": suppressed_count,
        "unique_iocs_shown": len(all_results),
    }


def _feed_status() -> list:
    statuses = []
    for fname, label in (
        ("abuse_stream.jsonl", "URLhaus"),
        ("malwarebazaar_recent.jsonl", "MalwareBazaar"),
    ):
        fpath = os.path.join(BASE_DIR, fname)
        if os.path.exists(fpath):
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc)
            age_min = (datetime.now(timezone.utc) - mtime).total_seconds() / 60
            size = os.path.getsize(fpath)
            # Count entries roughly by newlines
            with open(fpath, "rb") as f:
                count = sum(1 for _ in f)
            statuses.append({
                "name": label,
                "file": fname,
                "ioc_count": count,
                "last_updated": mtime.isoformat(),
                "age_minutes": round(age_min, 1),
                "size_kb": round(size / 1024, 1),
                "healthy": age_min < 1440,  # warn if > 24h stale
            })
        else:
            statuses.append({"name": label, "file": fname, "healthy": False, "ioc_count": 0})
    return statuses


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    min_score = float(request.args.get("min_score", 0))
    level_filter = request.args.get("level", "").upper()
    limit = int(request.args.get("limit", 200))

    results = _load_results(min_score=min_score, limit=limit)

    if level_filter and level_filter != "ALL":
        results = [r for r in results if r.get("confidence", {}).get("level") == level_filter]

    stats = _compute_stats(_load_results(min_score=0, limit=10000))
    feeds = _feed_status()

    return jsonify({
        "alerts": results,
        "stats": stats,
        "feeds": feeds,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/suppress", methods=["POST"])
def api_suppress():
    data = request.get_json()
    ioc_value = data.get("ioc_value", "").strip()
    if not ioc_value:
        return jsonify({"error": "ioc_value required"}), 400
    suppressed = _load_suppressed()
    suppressed.add(ioc_value)
    _save_suppressed(suppressed)
    return jsonify({"status": "ok", "suppressed": ioc_value, "total_suppressed": len(suppressed)})


@app.route("/api/unsuppress", methods=["POST"])
def api_unsuppress():
    data = request.get_json()
    ioc_value = data.get("ioc_value", "").strip()
    suppressed = _load_suppressed()
    suppressed.discard(ioc_value)
    _save_suppressed(suppressed)
    return jsonify({"status": "ok", "unsuppressed": ioc_value})


@app.route("/api/suppressed")
def api_suppressed():
    return jsonify({"suppressed": sorted(_load_suppressed())})


@app.route("/api/stats")
def api_stats():
    results = _load_results(min_score=0, limit=10000)
    return jsonify({**_compute_stats(results), "feeds": _feed_status()})


if __name__ == "__main__":
    print(f"\n  SOC Dashboard starting...")
    print(f"  Data file : {RESULTS_FILE}")
    print(f"  Open      : http://localhost:5050\n")
    app.run(host="0.0.0.0", port=5050, debug=False)
