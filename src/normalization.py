from pathlib import Path
from typing import Optional

import yaml

from src.log import get_logger

log = get_logger(__name__)


class Mappings:
    def __init__(self, threat_types: dict[str, str] = None, kill_chain: dict[str, str] = None):
        self._threat_types = {k.upper(): v for k, v in (threat_types or {}).items()}
        self._kill_chain = dict(kill_chain or {})

    def threat_type(self, cs_value: str) -> Optional[str]:
        return self._threat_types.get(cs_value.upper())

    def threat_type_tag(self, cs_value: str) -> str:
        mapped = self.threat_type(cs_value)
        if mapped:
            return mapped
        return f'crowdstrike:threat-type="{cs_value}"'

    def kill_chain(self, cs_phase: str) -> str:
        return self._kill_chain.get(cs_phase, cs_phase)


def load_mappings(path: Optional[str]) -> Mappings:
    if not path:
        return Mappings()
    p = Path(path)
    if not p.exists():
        log.warning("mappings_file_not_found", extra={"path": path})
        return Mappings()
    try:
        with open(p) as f:
            raw = yaml.safe_load(f) or {}
        return Mappings(
            threat_types=raw.get("threat_types", {}),
            kill_chain=raw.get("kill_chain", {}),
        )
    except Exception as e:
        log.error("mappings_load_error", extra={"path": path, "error": str(e)})
        return Mappings()
