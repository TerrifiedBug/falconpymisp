# falcon-misp

Import CrowdStrike Falcon threat intelligence into MISP. Pulls indicators, reports, and adversary profiles from the Falcon Intel API and pushes them into your MISP instance as structured events.

This is a ground-up rewrite of [CrowdStrike's misp-tools](https://github.com/CrowdStrike/misp-tools). The original worked, but it was slow, hard to configure, and the codebase had accumulated a lot of rough edges over time. This version replaces ~4,800 lines of threaded Python and INI config with ~1,200 lines of async Python and a single YAML file.

## What it imports

**Indicators** -- IPs, domains, hashes, URLs, email addresses, and about 20 other types. These get batched into per-type feed events in MISP (one event for MD5s, one for domains, etc.) rather than creating thousands of individual events.

**Reports** -- CrowdStrike threat analysis documents. Each becomes its own MISP event with the report description, tags, and linked galaxy clusters.

**Actors** -- Adversary profiles (BEAR, PANDA, SPIDER, etc.). One MISP event per actor with motivations, target industries, and galaxy links.

## How it works

The tool runs once and exits. Here's the sequence:

1. Reads a YAML config file
2. Loads previous state from `state.json` so it picks up where it left off
3. Connects to CrowdStrike and MISP, pre-loads galaxy clusters into memory
4. Runs all three importers -- indicators use async batching with `aiohttp`, reports and actors run sequentially per-event
5. Writes updated state back to disk with atomic file writes (write to temp file, rename -- crash-safe)

Indicators are the high-volume piece. The tool streams them from CrowdStrike using cursor-based pagination (the `_marker` field), buffers them by type, and flushes in configurable batches -- 2,000 attributes per API call by default. It never re-fetches indicators it already processed. The cursor handles that, and MISP's built-in duplicate rejection covers edge cases.

Reports and actors are simpler. The tool checks what already exists in MISP by name and skips duplicates. Galaxy clusters (threat actors, malware from malpedia, ATT&CK patterns) are matched automatically by name from a cache built at startup. No manual mapping file needed.

## How it differs from the original

The original CrowdStrike tool ([misp-tools](https://github.com/CrowdStrike/misp-tools)) has been around for a while. It works, but running it in production surfaces a few real problems.

The biggest is speed. The original checks every single indicator against MISP before importing it -- with 100K+ indicators, that's 100K+ individual API calls just for deduplication. This version uses CrowdStrike's cursor pagination to only fetch new data. MISP API calls drop from ~100,000 to roughly 50 (batches of 2,000).

Configuration is also more involved than it needs to be. Two INI files, 30+ settings, and a `galaxy.ini` mapping file you maintain by hand. This version is one YAML file. Galaxy mappings load automatically from your MISP instance at startup.

The original creates one MISP event per malware family for indicators, which tends to produce hundreds of events over time. This version creates one event per indicator type (MD5, domain, IP, etc.) -- about 20 events total.

Tags in the original were inconsistent across indicator types. This version standardizes to MISP taxonomy convention: `key="value"` (e.g., `crowdstrike:confidence="high"`, `kill-chain:phase="command-control"`). There's also a dry-run mode, which the original lacks.

| | Original | This version |
|---|---|---|
| Python | 3.6+ | 3.12+ |
| Config | 2 INI files, 30+ settings | 1 YAML file |
| Lines of code | ~4,800 | ~1,200 |
| Indicator dedup | Per-indicator MISP lookup | Cursor-based, no lookups |
| Galaxy mapping | Manual INI file | Auto-loaded from MISP |
| Event model | Per-malware-family | Per-indicator-type |
| Logging | Print statements | Structured JSON |
| State tracking | Multiple timestamp files | Single atomic JSON |
| Async | Threading | asyncio + aiohttp |
| Dry-run | No | Yes |
| Docker | Dockerfile only | Dockerfile + Compose |

## Setup

### Requirements

- Python 3.12+
- A CrowdStrike Falcon API key with READ access to Adversaries, Indicators, and Reports (Falcon Threat Intelligence)
- A MISP instance with an API key and a "CrowdStrike" organization created

### Install

```bash
pip install -r requirements.txt
```

Dependencies: `crowdstrike-falconpy` >= 1.0.0, `pymisp` >= 2.4.170, `aiohttp` >= 3.9.0, `pyyaml` >= 6.0.

### Configure

Copy the example configs and fill in your credentials:

```bash
cp config.example.yml config.yml
cp mappings.example.yml mappings.yml
```

At minimum you need to set `client_id`, `client_secret`, `misp.url`, `misp.api_key`, and `misp.org_uuid`. Everything else has sensible defaults.

The config looks like this:

```yaml
crowdstrike:
  client_id: ""
  client_secret: ""
  base_url: "auto"            # auto, us-1, us-2, eu-1, usgov-1
  request_limit: 5000

misp:
  url: "https://misp.example.com"
  api_key: ""
  verify_ssl: false
  org_uuid: ""                # UUID of CrowdStrike org in MISP
  distribution: 0             # 0=org only, 1=community, 2=connected, 3=all

import:
  indicators: true
  reports: true
  actors: true
  init_lookback_days: 30      # How far back on first run
  batch_size: 2000
  dry_run: false
  publish: true
  mappings_file: "/app/mappings.yml"

tags:
  tlp: "tlp:amber"
  confidence: true
  kill_chain: true

logging:
  level: "INFO"
  format: "json"

state_file: "/app/data/state.json"
```

See `config.example.yml` for the full list of options including proxy settings and taxonomy toggles.

### Mappings (optional)

The mappings file controls how CrowdStrike threat types and kill chain phases translate to MISP taxonomy tags. Without it, unmapped values fall back to `crowdstrike:threat-type="{raw}"`.

```yaml
threat_types:
  RANSOMWARE: 'malware-type="Ransomware"'
  PHISHING: 'incident-type="Phishing Activity"'
  RAT: 'malware-type="Remote Access Trojan"'
  # ...

kill_chain:
  actions_and_objectives: "action-on-objectives"
  command_and_control: "command-control"
```

See `mappings.example.yml` for the full set.

## Usage

### Run directly

```bash
python -m src config.yml
```

### Docker Compose

```bash
docker-compose up
```

Mounts `config.yml` and `mappings.yml` as read-only volumes, persists state to `./data/`.

### Dry-run

Set `dry_run: true` in the config to preview what would be imported. You can also log to a file for easier review:

```yaml
import:
  dry_run: true
  dry_run_max_items: 5

logging:
  file: "./dry_run.log"
```

Nothing gets written to MISP -- the tool just logs what it would have done.

## State and resumption

The tool tracks its position in `state.json`:

```json
{
  "indicators": {
    "last_marker": "abc123...",
    "last_run": "2025-01-15T10:30:00",
    "total_imported": 84521
  },
  "reports": {
    "last_timestamp": 1705312200,
    "last_run": "2025-01-15T10:30:00",
    "total_imported": 312
  },
  "actors": {
    "last_timestamp": 1705312200,
    "last_run": "2025-01-15T10:30:00",
    "total_imported": 187
  }
}
```

Next run picks up from where it stopped. Delete `state.json` to start fresh.

## Scheduling

The tool runs once and exits, so schedule it externally:

- **cron:** `0 */6 * * * cd /path/to/falcon-misp && python -m src config.yml`
- **Docker:** use `restart: always` in Compose, or a Kubernetes CronJob
- **systemd:** standard timer unit pointing at the Compose or Python command

## Project structure

```
src/
  __main__.py              # Entry point and orchestrator
  config.py                # YAML config loading and validation
  log.py                   # Structured JSON logging
  state.py                 # State persistence (atomic writes)
  normalization.py         # Tag mapping loader
  crowdstrike/
    client.py              # FalconPy wrapper with pagination
    models.py              # CSIndicator, CSReport, CSActor
  misp/
    client.py              # Async MISP client (aiohttp)
    models.py              # Event and attribute builders
    galaxy_cache.py        # Galaxy cluster pre-loader
  importers/
    indicators.py          # Async batching pipeline
    reports.py             # Per-report event creation
    actors.py              # Per-actor event creation
```
