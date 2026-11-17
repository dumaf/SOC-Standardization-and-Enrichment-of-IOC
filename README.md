# SOC IOC Standardization & Enrichment

Pipeline for ingesting threat intelligence from URLhaus and MalwareBazaar, standardizing it as STIX 2.1, and enriching incoming IOCs with a composite threat score.

### Pipeline Architecture & Flow

```
URLhaus API  ──→  stix ingest.py ──┐ (Push-Pull Hybrid)
                                  ├──→ POST /objects/ ──→ TAXII 2.1 Server ──┐
MalwareBazaar ──→  malwarebazaar_ ─┘                       (SQLite DB)       │
                    recent.py                                                │
                                                                             ▼
                                                                     enrichment.py
                                                                     (polls every 60s)
                                                                             │
                                                                             ▼
                                                                  enrichment_results.jsonl
```

---

## Scripts & Components

### TAXII 2.1 Server (`taxii_server/` & `run_taxii_server.py`)

A Flask + SQLAlchemy threat intelligence server natively supporting STIX 2.1 JSON. Data sources are physically decoupled into separate tables (`urlhaus_object` and `malwarebazaar_object`).

```bash
# Start the TAXII 2.1 server
venv\Scripts\python run_taxii_server.py
```

* **Health Check**: `GET http://localhost:6100/health`
* **Discovery**: `GET http://localhost:6100/taxii2/`
* **Collections**: `GET http://localhost:6100/api/collections/`
* **Collections Seeded**: `urlhaus-indicators`, `malwarebazaar-indicators`

---

### `stix ingest.py` — URLhaus Ingestion

Polls URLhaus recent URLs every 60 seconds, deduplicates entries, and converts them to STIX 2.1 `Indicator` objects.
* **Push-Pull Hybrid**: Before each cycle, it queries `GET /health`. If the server is reachable, it posts new indicators directly to the server's `urlhaus-indicators` collection (no constraints/limits apply to TAXII storage).
* **Backup**: Regardless of server status, it appends the STIX Indicators to `abuse_stream.jsonl` as a local backup. **Local storage is capped at a maximum of 1000 entries (rolling window).**

```bash
python "stix ingest.py"
```

- Runs in an infinite loop (Ctrl+C to stop)
- Output: `abuse_stream.jsonl` — one STIX Indicator per line (maximum 1000 entries)
- Pattern format: `[url:value = '...']`
- Deduplication: in-memory SHA-256 of each raw entry

### `malwarebazaar_recent.py` — MalwareBazaar Ingestion

Fetches the 100 most recent malware samples, converts them into STIX 2.1 objects (`Malware`, `Indicator`, and `Relationship` connecting them), and deduplicates.
* **Push-Pull Hybrid**: Queries server health and pushes objects to the `malwarebazaar-indicators` collection if reachable (no constraints/limits apply to TAXII storage).
* **Backup**: Appends all generated STIX objects to `malwarebazaar_recent.jsonl` as local backup. **Local storage is capped at a maximum of 100 entries/STIX objects (rolling window).**

```bash
python malwarebazaar_recent.py
```

- Output: `malwarebazaar_recent.jsonl` — one STIX object per line (maximum 100 entries)
- Objects per sample:
  - `Malware` — represents the sample with full metadata
  - `Indicator` — contains file hash patterns (SHA-256, SHA-1, MD5, filename)
  - `Relationship` — links Indicator → Malware (`indicates`)
- Custom properties: `x_mb_sha256`, `x_mb_sha1`, `x_mb_md5`, `x_mb_tags`, `x_mb_first_seen`, `x_mb_reporter`, `x_mb_file_type`, `x_mb_delivery_method`, `x_mb_intelligence`
- Deduplication: skips SHA-256 hashes already present in the output file

### `enrichment.py` — IOC Enrichment Scoring Engine

Cross-references incoming IOC packets against the threat intelligence database. It leverages a hybrid data-source model:
1. **TAXII Mode (Priority)**: If the TAXII server is reachable, it loads all indicators on startup and starts a background daemon thread that polls for new objects incrementally (default: every 60 seconds).
2. **Local Fallback**: If the TAXII server is offline, it falls back to parsing `abuse_stream.jsonl` and `malwarebazaar_recent.jsonl` locally.

```python
from enrichment import Enricher, enrich_ioc, enrich_batch

# Class-based (runs background polling thread automatically if TAXII is used)
enricher = Enricher(taxii_url="http://localhost:6100", poll_interval=60)
result = enricher.enrich({"url": "http://evil.com/payload.exe"})
```

```bash
# CLI Usage
venv\Scripts\python enrichment.py "http://evil.com/payload.exe" --type url
venv\Scripts\python enrichment.py --no-taxii "http://evil.com/payload.exe" # local JSONL only
```

---

### Verification & Testing Scripts

* **`test_taxii.py`**: Performs a self-contained health check, lists collections, pushes a mock STIX 2.1 indicator, polls it back, and validates the integration.
* **`test_enrichment.py`**: Validates the enrichment engine's initial TAXII load and background incremental polling logic using a mock indicator.

```bash
venv\Scripts\python test_taxii.py
venv\Scripts\python test_enrichment.py
```

---

## Technical Specifications

### Input Packet Format

Accepts dicts with flexible key names:

| IOC Type | Accepted Keys |
|----------|---------------|
| URL | `url`, `uri`, `link`, `URL` |
| Domain | `domain`, `host`, `hostname` |
| IP | `ip`, `ip_address`, `src_ip`, `dst_ip`, `ipv4` |
| SHA-256 | `sha256`, `sha256_hash`, `SHA-256`, `x_mb_sha256` |
| SHA-1 | `sha1`, `sha1_hash`, `SHA-1`, `x_mb_sha1` |
| MD5 | `md5`, `md5_hash`, `MD5`, `x_mb_md5` |
| Generic | `ioc`, `value`, `indicator`, `observable` |
| STIX | `pattern` (auto-extracts from STIX patterns) |

URLs are automatically decomposed into domain + IP for deeper lookups.

### Scoring Model

| Component | Points | Condition |
|-----------|--------|-----------|
| URLhaus exact URL | +50 | URL found in local URLhaus DB |
| URLhaus domain | +40 | Domain found as URLhaus host |
| URLhaus IP | +20 | IP found as URLhaus host |
| MalwareBazaar hash | +60 | Hash found in local MB DB |
| Dangerous tags | +20 | `stealer`, `ransomware`, `rat`, `loader`, `botnet`, `c2`, `banker`, `trojan`, `keylogger`, `spyware`, `miner`, `backdoor`, `infostealer`, `downloader`, `dropper`, `apt`, `exploit`, `phishing`, `cryptojacking` |
| Delivery method | +10 | MB `delivery_method` non-empty |
| Trusted reporter | +10 | Reporter is `abuse_ch` / `urlhaus` / `malwarebazaar` |
| Multi-hash confirm | +15 | Matched on >=2 hash types |
| Cross-source correlation | +50 | Hit in **both** URLhaus AND MalwareBazaar |

### Temporal Multiplier

| Age | Multiplier |
|-----|------------|
| < 24h | x1.5 |
| 24-72h | x1.2 |
| 3-7 days | x1.0 |
| 7-30 days | x0.8 |
| > 30 days | x0.6 |

### Confidence Levels

`final_score = raw_score * temporal_multiplier`

| Score | Level | Action |
|-------|-------|--------|
| >= 150 | CRITICAL | Confirmed active threat |
| 100-149 | HIGH | Prioritize investigation |
| 50-99 | MEDIUM | Investigate further |
| 20-49 | LOW | Informational |
| < 20 | MINIMAL | Likely benign or stale |

### Enrichment Output JSON Structure

Results appended to `enrichment_results.jsonl`:

```json
{
  "ioc": {"url": "...", "domain": "..."},
  "raw_score": 90,
  "temporal_multiplier": 0.8,
  "final_score": 72.0,
  "confidence": {"level": "MEDIUM", "label": "Investigate further", "priority": 3},
  "hits": {"urlhaus_url": {...}, "urlhaus_domain": {...}, "urlhaus_ip": null, "malwarebazaar": null},
  "tags": ["phishing"],
  "scoring_breakdown": ["URLhaus exact URL match (+50)", "URLhaus domain match (+40)"],
  "earliest_seen": "2026-03-11T10:53:44Z",
  "enriched_at": "2026-04-03T05:22:50Z"
}
```

---

## Configuration & Environment Variables

Create a `.env` file in the root directory to customize configuration:

```ini
# External Feed Credentials
URLHAUS_API_KEY=your_key_here
MALWAREBAZAAR_API_KEY=your_key_here

# TAXII 2.1 Server Config (Defaults shown)
TAXII_HOST=localhost
TAXII_PORT=6100
TAXII_DB_URI=sqlite:///taxii_server/taxii.db
TAXII_API_KEY=  # Leave blank for no auth (dev mode)

# TAXII Client Config (Defaults shown)
TAXII_SERVER_URL=http://localhost:6100
```

---

## How Wazuh Detection Rules Work

### The Short Answer

Rules 100020, 100021, and (planned) 100022 are **not** a limitation or a shortcut. You are not hardcoding "only check these three things." You are writing one rule per *type of Sysmon event*, because each event type has a completely different structure. This is how Wazuh rule authoring works at every level — including Wazuh's own built-in rules, of which there are thousands.

---

### Why One Rule Per Event Type

Sysmon generates different event IDs for different activities. Each event has completely different field names:

| Sysmon Event | What it logs | Key field |
|---|---|---|
| Event 3 — `NetworkConnect` | A process made a TCP/UDP connection | `win.eventdata.destinationIp` |
| Event 22 — `DnsQuery` | A process resolved a domain name | `win.eventdata.queryName` |
| Event 1 — `ProcessCreate` | A new process was launched | `win.eventdata.hashes` (contains SHA256) |

A Wazuh rule works by saying: **"when an event of type X arrives, check field Y against CDB list Z."** Because the field name is different for every event type, you need a separate rule for each one. There is no way to write a single generic rule that works across all three — the fields simply don't exist in each other's events.

---

### What Each Rule Actually Does (Line by Line)

**Rule 100020** — IP detection:
```xml
<rule id="100020" level="10">
  <if_sid>61605</if_sid>                                          <!-- only fires on Sysmon Event 3 (NetworkConnect) -->
  <list field="win.eventdata.destinationIp"                       <!-- take the destination IP from this event -->
        lookup="match_key">etc/lists/urlhaus-ips</list>           <!-- check if it exists in the urlhaus-ips CDB list -->
  <description>CTI Match: Outbound connection to URLhaus-listed IP ...</description>
</rule>
```

- `<if_sid>61605</if_sid>` — this rule only activates if the incoming event already matched Wazuh's built-in Sysmon Event 3 rule (SID 61605). It's a child rule. It doesn't fire on anything else.
- `<list ... lookup="match_key">` — Wazuh does a single O(1) lookup in the CDB file. If the IP is in the list, the rule fires. If not, nothing happens.

**Rule 100021** — Domain detection:
```xml
<rule id="100021" level="10">
  <if_sid>61650</if_sid>                                          <!-- only fires on Sysmon Event 22 (DnsQuery) -->
  <list field="win.eventdata.queryName"                           <!-- take the queried domain name -->
        lookup="match_key">etc/lists/urlhaus-domains</list>       <!-- check against urlhaus-domains CDB -->
</rule>
```

Same structure, different parent SID (61650 = Wazuh's built-in Sysmon Event 22 decoder) and different field name.

**Rule 100022** (planned) — Hash detection:
```xml
<rule id="100022" level="12">
  <if_sid>61603</if_sid>                                          <!-- Sysmon Event 1 (ProcessCreate) -->
  <list field="win.eventdata.hashes"                              <!-- the hashes field contains SHA256=...,MD5=...,etc. -->
        lookup="match_key">etc/lists/malwarebazaar-hashes</list>  <!-- check against MalwareBazaar hash CDB -->
</rule>
```

---

### The CDB Lists Are the Intelligence Layer

The rules themselves have no hardcoded IOC values. They simply say "check this field against this file." The actual intelligence — which IPs, domains, and hashes are malicious — lives entirely in the CDB files:

```
urlhaus-ips       ← generated by update_cdb.py from abuse_stream.jsonl
urlhaus-domains   ← generated by update_cdb.py from abuse_stream.jsonl
malwarebazaar-hashes  ← (planned) generated by update_cdb.py from malwarebazaar_recent.jsonl
```

These files are regenerated automatically every time the STIX ingestion pipeline runs. So the rules never change, but the intelligence they check against updates continuously. Adding a new malicious IP to the feed automatically makes Rule 100020 detect it — no rule editing required.

---

### The Full Detection Chain

```
Sysmon (kernel driver on Windows endpoint)
    │  Watches: network connections, DNS queries, process launches
    │  Writes structured XML to Windows Event Log
    ▼
Wazuh Agent
    │  Polls Windows Event Log every ~1 second
    │  Ships raw event XML to Wazuh Manager on port 1514
    ▼
Wazuh Manager — Decoder
    │  Parses raw XML into named fields
    │  e.g. XML tag <DestinationIp> → field win.eventdata.destinationIp
    ▼
Wazuh Manager — Rule Engine
    │  Checks every active rule against the decoded fields
    │  Rule 100020: is win.eventdata.destinationIp in urlhaus-ips? → match
    │  Rule 100021: is win.eventdata.queryName in urlhaus-domains? → match
    │  Rule 100022: is win.eventdata.hashes in malwarebazaar-hashes? → match
    ▼
Alert fires → wazuh_n8n_integration.py (webhook)
    ▼
n8n workflow → enrichment.py
    │  Scores the matched IOC against local STIX database
    │  Outputs: final_score, confidence level, scoring breakdown, tags
    ▼
enrichment_results.jsonl → Analyst Dashboard (dashboard/app.py)
```

---

### Does Adding More Event Types Require More Rules?

Yes — one rule per event type/field combination. But this is not a design weakness. It is explicit, auditable, and exactly how every production Wazuh deployment works. Wazuh's own built-in ruleset contains over 3,000 rules structured this way.

If you wanted to add detection for, say, Windows Firewall drops (a different log source entirely), you would write one new rule pointing at the relevant field and the same CDB lists. The CDB lists and the enrichment engine require zero changes.

This is what makes the architecture **source-agnostic**: the intelligence layer (CDB + enrichment) stays constant, only the event-specific trigger rules vary.

---

### What Enabling Hash Detection (Rule 100022) Requires

Three changes, none of them touching the existing rules or enrichment engine:

1. **`sysmon_config.xml`** — add a `<ProcessCreate>` block to enable Sysmon Event 1 logging
2. **`update_cdb.py`** — extract SHA256 hashes from `malwarebazaar_recent.jsonl` and write a `malwarebazaar-hashes` CDB file
3. **`wazuh_custom_rules.xml`** — add rule 100022 pointing at `win.eventdata.hashes` against the new CDB

The enrichment engine already handles hash scoring (MalwareBazaar hash match = +60 points). No changes to `enrichment.py` are needed.
