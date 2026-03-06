import dataclasses as _dc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


class ConfigError(Exception):
    pass


@dataclass
class CrowdStrikeConfig:
    client_id: str
    client_secret: str
    base_url: str = "auto"
    request_limit: int = 5000


@dataclass
class MISPConfig:
    url: str
    api_key: str
    verify_ssl: bool = False
    org_uuid: str = ""
    distribution: int = 0


@dataclass
class ImportConfig:
    indicators: bool = True
    reports: bool = True
    actors: bool = True
    init_lookback_days: int = 30
    batch_size: int = 2000
    dry_run: bool = False
    dry_run_max_items: int = 5


@dataclass
class TaxonomiesConfig:
    iep: bool = False
    iep2: bool = False
    workflow: bool = False


@dataclass
class TagsConfig:
    tlp: str = "tlp:amber"
    confidence: bool = True
    kill_chain: bool = True
    taxonomies: TaxonomiesConfig = field(default_factory=TaxonomiesConfig)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"


@dataclass
class ProxyConfig:
    http: Optional[str] = None
    https: Optional[str] = None


@dataclass
class AppConfig:
    crowdstrike: CrowdStrikeConfig
    misp: MISPConfig
    import_: ImportConfig = field(default_factory=ImportConfig)
    tags: TagsConfig = field(default_factory=TagsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    state_file: str = "/app/data/state.json"
    proxy: ProxyConfig = field(default_factory=ProxyConfig)


_NESTED_TYPES = {
    "CrowdStrikeConfig": CrowdStrikeConfig,
    "MISPConfig": MISPConfig,
    "ImportConfig": ImportConfig,
    "TaxonomiesConfig": TaxonomiesConfig,
    "TagsConfig": TagsConfig,
    "LoggingConfig": LoggingConfig,
    "ProxyConfig": ProxyConfig,
}


def _build(cls, data: dict, path: str = ""):
    if data is None:
        data = {}
    kwargs = {}
    for f in _dc.fields(cls):
        value = data.get(f.name)
        if value is None:
            if f.default is _dc.MISSING and f.default_factory is _dc.MISSING:
                raise ConfigError(f"Missing required config field: {path}{f.name}")
            continue
        actual_type = f.type
        if isinstance(actual_type, str):
            actual_type = _NESTED_TYPES.get(actual_type)
        if actual_type and _dc.is_dataclass(actual_type) and isinstance(value, dict):
            value = _build(actual_type, value, path=f"{path}{f.name}.")
        kwargs[f.name] = value
    return cls(**kwargs)


def load_config(path: str) -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {path}")

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError("Config file must be a YAML mapping")

    if "import" in raw:
        raw["import_"] = raw.pop("import")

    return _build(AppConfig, raw)
