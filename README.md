# falcon-misp

Pulls CrowdStrike Falcon threat intel into MISP. Indicators, reports, adversary profiles. Point it at both APIs, it handles the rest.

This is a rewrite of [CrowdStrike's misp-tools](https://github.com/CrowdStrike/misp-tools). Their version is ~4,800 lines of threaded Python with two INI config files. This one is ~1,200 lines of async Python with one YAML file.

## What it imports

Indicators (IPs, domains, hashes, URLs, email addresses, about 20 types). These land in per-type feed events in MISP -- one event for all your MD5s, another for all domains, etc. Context like which actor or malware family an indicator is tied to lives in attribute-level tags. You filter with `restSearch` instead of needing a separate event per grouping.

Reports each get their own MISP event with a description, tags, and galaxy cluster links.

Actors (BEAR, PANDA, SPIDER, etc.) get one event each with motivations, targets, and galaxy links.

## How it works

Runs once and exits. Schedule it with cron, a k8s CronJob, whatever.

1. Reads your config YAML
2. Loads state from `state.json` so it picks up where it left off
3. Connects to CrowdStrike and MISP, pulls galaxy clusters into memory
4. Runs all three importers
5. Writes state back to disk (atomic write -- temp file then rename, won't corrupt if it crashes)

Indicators are the heavy part. Streams them from CrowdStrike using cursor pagination (`_marker` field), buffers by type, flushes in batches of 2,000 attributes per API call. Never re-fetches stuff it already processed. MISP's built-in duplicate rejection catches edge cases.

Reports and actors are lighter. Checks what's already in MISP by name, skips dupes. Galaxy clusters (threat actors, malpedia, ATT&CK patterns) match by name from a cache built at startup. No manual mapping file to maintain.

## Setup

You need:
- Python 3.12+
- A CrowdStrike Falcon API key with READ on Adversaries, Indicators, and Reports
- A MISP instance with an API key and a "CrowdStrike" org set up

```bash
pip install -r requirements.txt
```

Dependencies: `crowdstrike-falconpy` >= 1.0.0, `pymisp` >= 2.4.170, `aiohttp` >= 3.9.0, `pyyaml` >= 6.0.

Copy the example configs:

```bash
cp config.example.yml config.yml
cp mappings.example.yml mappings.yml
```

Fill in your CrowdStrike creds and MISP connection info. The rest works out of the box.

## Configuration

Only the CrowdStrike creds (`client_id`, `client_secret`) and MISP connection (`url`, `api_key`, `org_uuid`) are required. Everything else you can leave alone.

### CrowdStrike

```yaml
crowdstrike:
  client_id: ""
  client_secret: ""
  base_url: "auto"
  request_limit: 5000
```

| Field | Default | What it does |
|-------|---------|-------------|
| `client_id` | *(required)* | OAuth2 client ID. Grab it from the CrowdStrike console under Support > API Clients. |
| `client_secret` | *(required)* | OAuth2 client secret. Treat it like a password. |
| `base_url` | `"auto"` | Which CrowdStrike cloud to talk to. `"auto"` figures it out from your API key. If that doesn't work, set it yourself: `us-1`, `us-2`, `eu-1`, or `usgov-1`. |
| `request_limit` | `5000` | How many indicators to grab per API page. US-1 handles 5000, other clouds cap at 2500. Getting errors on EU-1 or US-2? Lower this. |

### MISP

```yaml
misp:
  url: "https://misp.example.com"
  api_key: ""
  verify_ssl: false
  org_uuid: ""
  distribution: 0
```

| Field | Default | What it does |
|-------|---------|-------------|
| `url` | *(required)* | Your MISP instance URL, with `https://`. |
| `api_key` | *(required)* | MISP auth key. Make one in MISP under Administration > Auth Keys. Needs permission to create events and add attributes. |
| `verify_ssl` | `false` | Check MISP's TLS cert. Turn on if you have a real cert. `false` is fine for self-signed certs in lab setups. |
| `org_uuid` | *(required)* | UUID of the org in MISP that owns the imported events. Find it under Administration > List Organisations, click your CrowdStrike org, UUID is in the URL or on the page. |
| `distribution` | `0` | Controls who sees events you create. `0` = your org only (good default), `1` = everyone on your MISP server, `2` = syncs to peered MISP instances (data leaves your server), `3` = syncs everywhere (careful with commercial intel). |

### Import

```yaml
import:
  indicators: true
  reports: true
  actors: true
  init_lookback_days: 30
  batch_size: 2000
  dry_run: false
  dry_run_max_items: 5
  publish: true
  mappings_file: "/app/mappings.yml"
```

| Field | Default | What it does |
|-------|---------|-------------|
| `indicators` | `true` | Pull in indicators (IPs, hashes, domains, etc.). |
| `reports` | `true` | Pull in CrowdStrike intel reports. |
| `actors` | `true` | Pull in threat actor profiles. |
| `init_lookback_days` | `30` | First run only: how far back to go. `0` grabs everything CrowdStrike has. After the first run this doesn't matter, it picks up from the saved cursor. |
| `batch_size` | `2000` | Indicator attributes per MISP API call. Bigger = faster but more memory. 2000 works well. |
| `dry_run` | `false` | Set `true` to see what _would_ be imported without writing to MISP. Good for testing your config. |
| `dry_run_max_items` | `5` | In dry-run mode, only process this many items per type. Keeps the output short. |
| `publish` | `true` | Mark events as "published" when created. Published events show up in feeds and correlations. Set `false` if you want to eyeball them first. |
| `mappings_file` | `"/app/mappings.yml"` | Path to the threat type / kill chain mappings file. Change this if you're not using Docker. |

### Tags

```yaml
tags:
  tlp: "tlp:amber"
  confidence: true
  kill_chain: true
  taxonomies:
    iep: false
    iep2: false
    workflow: false
```

`tlp` is the TLP (Traffic Light Protocol) marking on every event. It tells people what they can do with the data:

- `"tlp:red"` -- named recipients only. Don't share beyond whoever it was sent to.
- `"tlp:amber"` -- your org only. Share inside your org, not outside. This is the default and makes sense for commercial intel like CrowdStrike.
- `"tlp:amber+strict"` -- like amber but need-to-know only, even inside your org.
- `"tlp:green"` -- share with your community (ISAC, sector peers, etc.), just not publicly.
- `"tlp:clear"` -- no restrictions, fully public. Probably not appropriate for CrowdStrike data given licensing.

`confidence` tags indicators with their CrowdStrike confidence level (e.g. `crowdstrike:confidence="high"`). `kill_chain` tags them with their kill chain phase when CrowdStrike provides one (e.g. `kill-chain:phase="command-control"`). Both default to on.

The `taxonomies` section is for extra MISP taxonomy tags ([IEP](https://www.first.org/iep/), IEP v2, workflow). All off by default. Turn them on if your MISP setup uses them.

### Logging

```yaml
logging:
  level: "INFO"
  format: "json"
  file: null
```

`level` controls verbosity: `DEBUG` shows every API call and attribute, `INFO` is normal, `WARNING` and `ERROR` are quieter.

`format` is either `"json"` (structured JSON lines, good if you pipe logs somewhere) or `"text"` (human-readable).

`file` writes logs to a file too, not just stdout. Handy with `dry_run: true` -- set it to something like `"./dry_run.log"` and review later.

### Other

```yaml
state_file: "/app/data/state.json"

proxy:
  http: null
  https: null
```

`state_file` is where import progress gets saved. Change it if you're not running in Docker -- `"./data/state.json"` works for local dev.

`proxy.http` and `proxy.https` are for corporate proxies. Set them to something like `"http://proxy.corp:8080"` if you need to.

## Mappings (optional)

`mappings.yml` controls how CrowdStrike's threat type and kill chain labels get translated into MISP taxonomy tags. You can skip it entirely -- unmapped stuff just shows up as `crowdstrike:threat-type="{whatever CrowdStrike called it}"`.

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

CrowdStrike labels indicators with types like `RANSOMWARE` or `RAT`. The mappings turn those into standard MISP taxonomy tags. So instead of `crowdstrike:threat-type="RANSOMWARE"` (which only means something to people using this tool), you get `malware-type="Ransomware"` (which other MISP tools and sharing communities understand).

Kill chain is the same idea. CrowdStrike says `command_and_control`, MISP taxonomy says `command-control`. The mapping fixes that up.

Full set is in `mappings.example.yml`.

## Usage

```bash
# run it
python -m src config.yml

# or with docker
docker compose up
```

Docker mounts `config.yml` and `mappings.yml` read-only, persists state to `./data/`.

### Dry run

Flip `dry_run: true` to see what would happen without touching MISP:

```yaml
import:
  dry_run: true
  dry_run_max_items: 5

logging:
  file: "./dry_run.log"
```

Logs what each indicator, report, and actor event would look like, capped at 5 per type. Set `logging.file` to save it somewhere you can read after.

## State

Progress lives in `state.json`:

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

It runs once and quits. Put it on a schedule:

- cron: `0 */6 * * * cd /path/to/falcon-misp && python -m src config.yml`
- Docker: `restart: always` or a Kubernetes CronJob
- systemd timer

## vs. the original

[misp-tools](https://github.com/CrowdStrike/misp-tools) works fine. It's been around a while. But if you've run it in production you probably know the pain points.

Speed is the big one. The original checks every single indicator against MISP before importing it. 100K+ indicators means 100K+ API calls just for dedup. This version uses CrowdStrike's cursor pagination and only grabs new stuff. MISP API calls go from ~100,000 to about 50.

Config is also a pain. Two INI files, 30+ settings, plus a `galaxy.ini` you maintain by hand to map malware families to MISP galaxies. Here it's one YAML file. Galaxies load from MISP automatically.

The event model is where it really diverges. The original creates per-type feed events (same as us) _and_ per-malware-family events on top. Every indicator ends up in both. The idea was that analysts could open a "Malware Family: Emotet" event and see everything related. In practice it causes problems at scale -- indicators stored twice, correlation noise doubled (MISP's over-correlation protection kicks in past 20 matching attributes and starts hiding stuff), and popular families like Cobalt Strike end up with thousands of attributes in one event that's painful to load. MISP's own feed docs actually recommend a "fixed event" approach (one event per feed, append over time), which is what the per-type model does. Need "all MD5s tied to Emotet"? Filter by tag with `restSearch`. Same result, no duplication.

Tags in the original are inconsistent too. We stick to MISP taxonomy format: `key="value"` (like `crowdstrike:confidence="high"`, `kill-chain:phase="command-control"`).

Oh, and dry-run mode. The original doesn't have that.

| | Original | This one |
|---|---|---|
| Python | 3.6+ | 3.12+ |
| Config | 2 INI files, 30+ settings | 1 YAML file |
| Code | ~4,800 lines | ~1,200 lines |
| Indicator dedup | Per-indicator MISP lookup | Cursor-based, no lookups |
| Galaxy mapping | Manual INI file | Auto-loaded from MISP |
| Event model | Per-type + per-family (duplicated) | Per-type only (tags for context) |
| Logging | Print statements | Structured JSON |
| State | Multiple timestamp files | Single atomic JSON |
| Async | Threading | asyncio + aiohttp |
| Dry run | No | Yes |
| Docker | Dockerfile only | Dockerfile + Compose |

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
