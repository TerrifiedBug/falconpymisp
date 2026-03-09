# falcon-misp

Pulls CrowdStrike Falcon threat intel into MISP -- indicators, reports, and adversary profiles. You point it at both APIs, it does the rest.

Rewrite of [CrowdStrike's misp-tools](https://github.com/CrowdStrike/misp-tools). The original is ~4,800 lines of threaded Python with two INI config files. This is ~1,200 lines of async Python with one YAML file.

## What it imports

Indicators (IPs, domains, hashes, URLs, email addresses, ~20 types total), reports, and actors. Indicators go into per-type feed events in MISP -- one event for all MD5s, one for all domains, etc. Actor, family, and kill-chain context is in attribute tags, so you can filter with `restSearch` without needing a separate event for each grouping.

Reports each get their own MISP event with description, tags, and galaxy cluster links. Same for actors (BEAR, PANDA, SPIDER, etc.) -- one event per actor with motivations, targets, and galaxy links.

## How it works

Runs once and exits. Schedule it however you want.

1. Reads config YAML
2. Loads state from `state.json` (picks up where it left off)
3. Connects to CrowdStrike and MISP, pre-loads galaxy clusters into memory
4. Runs all three importers
5. Saves state back to disk (atomic write -- temp file then rename, won't corrupt on crash)

Indicators are the heavy part. Streams them from CrowdStrike using cursor pagination (`_marker` field), buffers by type, flushes in batches of 2,000 attributes per API call. Never re-fetches what it already processed -- the cursor handles that. MISP's duplicate rejection catches edge cases.

Reports and actors are lighter. Checks what's already in MISP by name, skips dupes. Galaxy clusters (threat actors, malpedia, ATT&CK patterns) match automatically by name from a cache built at startup -- no manual mapping file.

## How it differs from the original

[misp-tools](https://github.com/CrowdStrike/misp-tools) has been around for a while and it works. But if you've run it in production you've probably hit some of the same issues.

Speed is the big one. The original checks every indicator against MISP before importing. 100K+ indicators means 100K+ API calls just to deduplicate. This version uses CrowdStrike's cursor pagination -- only fetches new stuff. Total MISP API calls go from ~100,000 to about 50.

Config is also annoying in the original. Two INI files, 30+ settings between them, plus a `galaxy.ini` you maintain by hand for mapping malware families to MISP galaxies. Here it's one YAML file. Galaxies load from MISP automatically at startup.

The event model is where things really diverge. The original creates per-type feed events (like we do) *plus* per-malware-family events on top. Every indicator goes into both -- its type event and its family event. The intent was to let analysts pull up a single "Malware Family: Emotet" event and see everything related. Problem is, at scale this causes real MISP headaches: all your indicators are stored twice, correlation noise doubles (and MISP's over-correlation protection starts suppressing correlations past 20 matching attributes), and busy families like Cobalt Strike pile up thousands of attributes in one event that's painful to load or sync. MISP's own feed docs recommend a "fixed event" approach -- one event per feed, appended over time -- which is basically what our per-type model does. Want "all MD5s tied to Emotet"? Filter by tag in `restSearch`. No duplicated data needed.

Tags in the original are inconsistent. We standardize to MISP taxonomy: `key="value"` (like `crowdstrike:confidence="high"`, `kill-chain:phase="command-control"`).

There's also a dry-run mode now, which the original doesn't have.

| | Original | This version |
|---|---|---|
| Python | 3.6+ | 3.12+ |
| Config | 2 INI files, 30+ settings | 1 YAML file |
| Lines of code | ~4,800 | ~1,200 |
| Indicator dedup | Per-indicator MISP lookup | Cursor-based, no lookups |
| Galaxy mapping | Manual INI file | Auto-loaded from MISP |
| Event model | Per-type + per-family (duplicated) | Per-type only (tags for context) |
| Logging | Print statements | Structured JSON |
| State tracking | Multiple timestamp files | Single atomic JSON |
| Async | Threading | asyncio + aiohttp |
| Dry-run | No | Yes |
| Docker | Dockerfile only | Dockerfile + Compose |

## Setup

You need:

- Python 3.12+
- CrowdStrike Falcon API key with READ on Adversaries, Indicators, and Reports
- MISP instance with an API key and a "CrowdStrike" org

```bash
pip install -r requirements.txt
```

Dependencies: `crowdstrike-falconpy` >= 1.0.0, `pymisp` >= 2.4.170, `aiohttp` >= 3.9.0, `pyyaml` >= 6.0.

Copy the example configs:

```bash
cp config.example.yml config.yml
cp mappings.example.yml mappings.yml
```

You need to fill in `client_id`, `client_secret`, `misp.url`, `misp.api_key`, and `misp.org_uuid` at minimum. The rest has defaults that are fine to start with.

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

Full list of options (proxy, taxonomy toggles, etc.) is in `config.example.yml`.

### Mappings (optional)

Controls how CrowdStrike threat types and kill chain phases map to MISP taxonomy tags. If you skip it, unmapped values just become `crowdstrike:threat-type="{raw}"`.

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

Full set in `mappings.example.yml`.

## Usage

```bash
# run directly
python -m src config.yml

# or with docker
docker-compose up
```

Docker mounts `config.yml` and `mappings.yml` read-only and persists state to `./data/`.

### Dry-run

Set `dry_run: true` in config to see what would be imported without writing anything to MISP. Pair with file logging if you want to review it after:

```yaml
import:
  dry_run: true
  dry_run_max_items: 5

logging:
  file: "./dry_run.log"
```

## State

Tracks position in `state.json`:

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

Next run picks up where it left off. Delete `state.json` to start over.

## Scheduling

Runs once and exits. Use whatever scheduler you like:

- cron: `0 */6 * * * cd /path/to/falcon-misp && python -m src config.yml`
- Docker: `restart: always` or a Kubernetes CronJob
- systemd timer

## Project structure

```
src/
  __main__.py              # entry point, orchestrator
  config.py                # YAML config loading + validation
  log.py                   # structured JSON logging
  state.py                 # atomic state persistence
  normalization.py         # tag mapping loader
  crowdstrike/
    client.py              # FalconPy wrapper, pagination
    models.py              # CSIndicator, CSReport, CSActor
  misp/
    client.py              # async MISP client (aiohttp)
    models.py              # event + attribute builders
    galaxy_cache.py        # galaxy cluster pre-loader
  importers/
    indicators.py          # async batching pipeline
    reports.py             # per-report event creation
    actors.py              # per-actor event creation
```
