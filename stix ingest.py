"""URLhaus STIX ingestion — polls recent URLs, deduplicates, and writes STIX Indicators to JSONL.

Push-pull hybrid: on every cycle the script checks whether the TAXII
server is reachable.  If it is, new indicators are pushed directly;
the JSONL backup file is always written regardless of server state.
"""

import requests
import time
import json
import hashlib
import os
from datetime import datetime
from dotenv import load_dotenv
from stix2 import Indicator

from taxii_client import TAXIIClient
from update_cdb import update_cdb

load_dotenv()

POLL_INTERVAL = 60
OUTPUT_FILE = "abuse_stream.jsonl"
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")

TAXII_COLLECTION = "urlhaus-indicators"

seen_hashes = set()
taxii = TAXIIClient()  # reads TAXII_SERVER_URL / TAXII_API_KEY from env


def hash_entry(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()


def fetch_urlhaus():
    r = requests.get(
        "https://urlhaus.abuse.ch/downloads/json_recent/",
        headers={"User-Agent": "MySOC-Ingest/1.0", "Auth-Key": URLHAUS_API_KEY},
    )
    r.raise_for_status()
    data = r.json()
    entries = []
    for v in data.values():
        if isinstance(v, list):
            entries.extend(v)
    return entries


def normalize(source, entry):
    """Convert a raw entry into a STIX Indicator object."""
    pattern = None
    if "url" in entry:
        pattern = f"[url:value = '{entry['url']}']"
    elif "sha256" in entry:
        pattern = f"[file:hashes.'SHA-256' = '{entry['sha256']}']"
    elif "hash" in entry:
        pattern = f"[file:hashes.'SHA-256' = '{entry['hash']}']"

    return Indicator(
        name=f"{source} indicator",
        description=entry.get("description") or entry.get("malware") or "",
        pattern=pattern or "[x = 'unknown']",
        pattern_type="stix",
        labels=[source],
        valid_from=datetime.utcnow(),
    )


def process_entries(source, entries):
    new_entries = []
    for entry in entries:
        h = hash_entry(entry)
        if h not in seen_hashes:
            seen_hashes.add(h)
            new_entries.append(normalize(source, entry))
    return new_entries


def write_output(entries):
    existing_lines = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing_lines = [line.strip() for line in f if line.strip()]
        except Exception:
            pass

    for bundle in entries:
        existing_lines.append(bundle.serialize())

    # Keep only a maximum of 1000 entries locally
    existing_lines = existing_lines[-1000:]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for line in existing_lines:
            f.write(line + "\n")



def main():
    print("[*] Starting abuse.ch ingestion loop...")
    while True:
        try:
            # --- Push-pull hybrid: check TAXII server each cycle ---
            taxii_alive = taxii.is_server_alive()
            if taxii_alive:
                print("[*] TAXII server is online")
            else:
                print("[*] TAXII server is offline — JSONL-only mode")

            urlhaus_data = fetch_urlhaus()
            processed = process_entries("URLhaus", urlhaus_data)

            if processed:
                # Always write JSONL backup
                write_output(processed)
                print(f"[+] Ingested {len(processed)} new indicators (JSONL written)")

                # Push to TAXII if the server is reachable
                if taxii_alive:
                    try:
                        result = taxii.push_objects(TAXII_COLLECTION, processed)
                        print(
                            f"[+] TAXII push: {result.get('success_count', 0)} added, "
                            f"{result.get('total_count', 0) - result.get('success_count', 0) - result.get('failure_count', 0)} duplicates skipped"
                        )
                    except Exception as e:
                        print(f"[!] TAXII push failed (data safe in JSONL): {e}")

                # Update CDB lists in Wazuh
                try:
                    update_cdb()
                except Exception as e:
                    print(f"[!] CDB update failed: {e}")
            else:
                print("[-] No new data")
        except Exception as e:
            print(f"[!] Error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()