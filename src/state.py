import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.log import get_logger

log = get_logger(__name__)


@dataclass
class IndicatorState:
    last_marker: Optional[str] = None
    last_run: Optional[str] = None
    total_imported: int = 0


@dataclass
class TimestampState:
    last_timestamp: Optional[int] = None
    last_run: Optional[str] = None
    total_imported: int = 0


class ImportState:
    def __init__(self, path: str):
        self._path = path
        self.indicators = IndicatorState()
        self.reports = TimestampState()
        self.actors = TimestampState()
        self._load()

    def _load(self):
        path = Path(self._path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            log.warning("state_file_corrupted", extra={"path": self._path})
            return

        if ind := data.get("indicators"):
            self.indicators = IndicatorState(**{
                k: v for k, v in ind.items()
                if k in IndicatorState.__dataclass_fields__
            })
        if rep := data.get("reports"):
            self.reports = TimestampState(**{
                k: v for k, v in rep.items()
                if k in TimestampState.__dataclass_fields__
            })
        if act := data.get("actors"):
            self.actors = TimestampState(**{
                k: v for k, v in act.items()
                if k in TimestampState.__dataclass_fields__
            })

    def save(self):
        data = {
            "indicators": asdict(self.indicators),
            "reports": asdict(self.reports),
            "actors": asdict(self.actors),
        }
        path = Path(self._path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self._path)
        except Exception:
            os.unlink(tmp_path)
            raise

    def update_run_time(self, section: str):
        state = getattr(self, section)
        state.last_run = datetime.now(timezone.utc).isoformat()
