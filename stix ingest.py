import requests
import time
import json
import hashlib
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ---- CONFIG ----
POLL_INTERVAL = 60  # seconds
OUTPUT_FILE = "abuse_stream.jsonl"
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")

# ---- STATE ----
seen_hashes = set()

def hash_entry(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

def fetch_urlhaus():
    r = requests.get(
        "https://urlhaus.abuse.ch/downloads/json_recent/",
        headers={
            "User-Agent": "MySOC-Ingest/1.0",
            "Auth-Key": URLHAUS_API_KEY,
        }
    )
    r.raise_for_status()
    data = r.json()
    # flatten values into a list of entries
    entries = []
    for v in data.values():
        if isinstance(v, list):
            entries.extend(v)
    return entries

from stix2 import Indicator


def normalize(source, entry):
    """Convert a raw ``entry`` into a STIX ``Indicator`` object.

    The previous implementation returned a Bundle. We now return the Indicator
    object directly so we can extract and ingest individual objects.
    """

    # build a simple pattern from whatever fields are available
    pattern = None
    if "url" in entry:
        pattern = f"[url:value = '{entry['url']}']"
    elif "sha256" in entry:
        pattern = f"[file:hashes.'SHA-256' = '{entry['sha256']}']"
    elif "hash" in entry:
        # MalwareBazaar uses "hash" for sample digest
        pattern = f"[file:hashes.'SHA-256' = '{entry['hash']}']"

    indicator = Indicator(
        name=f"{source} indicator",
        description=entry.get("description") or entry.get("malware") or "",
        pattern=pattern or "[x = 'unknown']",
        pattern_type="stix",
        labels=[source],
        valid_from=datetime.utcnow(),
    )

    return indicator

def process_entries(source, entries):
    new_entries = []
    for entry in entries:
        h = hash_entry(entry)
        if h not in seen_hashes:
            seen_hashes.add(h)
            new_entries.append(normalize(source, entry))
    return new_entries

def write_output(entries):
    """Append serialized STIX bundles to the output file (JSONL)."""
    with open(OUTPUT_FILE, "a") as f:
        for bundle in entries:
            # ``bundle`` is already a ``stix2.Bundle`` instance
            f.write(bundle.serialize() + "\n")

def main():
    print("[*] Starting abuse.ch ingestion loop...")
    while True:
        try:
            urlhaus_data = fetch_urlhaus()

            processed = []
            processed += process_entries("URLhaus", urlhaus_data)

            if processed:
                write_output(processed)
                print(f"[+] Ingested {len(processed)} new indicators")
            else:
                print("[-] No new data")

        except Exception as e:
            print(f"[!] Error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()