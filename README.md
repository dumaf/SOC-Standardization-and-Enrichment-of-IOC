# SOC IOC Standardization & Enrichment

Pipeline for ingesting threat intelligence from URLhaus and MalwareBazaar, standardizing it as STIX 2.1, and enriching incoming IOCs with a composite threat score.

## Scripts

### `stix ingest.py` — URLhaus Ingestion

Polls URLhaus recent URLs every 60 seconds, deduplicates entries by content hash, converts each to a STIX 2.1 `Indicator`, and appends to `abuse_stream.jsonl`.

```bash
python "stix ingest.py"
```

- Runs in an infinite loop (Ctrl+C to stop)
- Output: `abuse_stream.jsonl` — one STIX Indicator per line
- Pattern format: `[url:value = '...']`
- Deduplication: in-memory SHA-256 of each raw entry

### `malwarebazaar_recent.py` — MalwareBazaar Ingestion

Fetches the 100 most recent malware samples from MalwareBazaar, converts each into three STIX 2.1 objects, and appends to `malwarebazaar_recent.jsonl`.

```bash
python malwarebazaar_recent.py
```

- Output: `malwarebazaar_recent.jsonl` — one STIX object per line
- Objects per sample:
  - `Malware` — represents the sample with full metadata
  - `Indicator` — contains file hash patterns (SHA-256, SHA-1, MD5, filename)
  - `Relationship` — links Indicator → Malware (`indicates`)
- Custom properties: `x_mb_sha256`, `x_mb_sha1`, `x_mb_md5`, `x_mb_tags`, `x_mb_first_seen`, `x_mb_reporter`, `x_mb_file_type`, `x_mb_delivery_method`, `x_mb_intelligence`
- Deduplication: skips SHA-256 hashes already present in the output file

### `enrichment.py` — IOC Enrichment Scoring Engine

Cross-references incoming IOC packets against the local JSONL databases. No external API calls — data is loaded into in-memory indices for fast lookups.

```python
from enrichment import Enricher, enrich_ioc, enrich_batch

# Class-based (load indices once, reuse)
enricher = Enricher()
result = enricher.enrich({"url": "http://evil.com/payload.exe"})
results = enricher.enrich_batch([{"url": "..."}, {"sha256": "abc..."}])

# Convenience wrappers (shared Enricher, lazy-loaded)
result = enrich_ioc({"url": "http://evil.com/payload.exe"})
results = enrich_batch(packets, output_file="enrichment_results.jsonl")
```

```bash
# CLI for testing
python enrichment.py "http://evil.com/payload.exe" --type url
python enrichment.py "abc123deadbeef..." --type hash
python enrichment.py "evil.com" --type domain
python enrichment.py "1.2.3.4" --type ip
python enrichment.py <ioc> --json              # raw JSON output
python enrichment.py <ioc> --output out.jsonl  # custom output file
```

#### Input Packet Format

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

#### Scoring Model

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

#### Temporal Multiplier

| Age | Multiplier |
|-----|------------|
| < 24h | x1.5 |
| 24-72h | x1.2 |
| 3-7 days | x1.0 |
| 7-30 days | x0.8 |
| > 30 days | x0.6 |

#### Confidence Levels

`final_score = raw_score * temporal_multiplier`

| Score | Level | Action |
|-------|-------|--------|
| >= 150 | CRITICAL | Confirmed active threat |
| 100-149 | HIGH | Prioritize investigation |
| 50-99 | MEDIUM | Investigate further |
| 20-49 | LOW | Informational |
| < 20 | MINIMAL | Likely benign or stale |

#### Output

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

## Environment Variables

Create a `.env` file with:

```
URLHAUS_API_KEY=your_key_here
MALWAREBAZAAR_API_KEY=your_key_here
```

## Pipeline Flow

```
URLhaus API  ──→  stix ingest.py  ──→  abuse_stream.jsonl  ──┐
                                                               ├──→  enrichment.py  ──→  enrichment_results.jsonl  ──→  n8n workflow
MalwareBazaar API  ──→  malwarebazaar_recent.py  ──→  malwarebazaar_recent.jsonl  ──┘
```
