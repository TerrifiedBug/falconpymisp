import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    _DEFAULT_ATTRS = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())
    _SKIP_ATTRS = _DEFAULT_ATTRS | {"message", "msg", "args"}

    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._SKIP_ATTRS:
                entry[key] = value
        return json.dumps(entry, default=str)


def setup_logging(level: str = "INFO", fmt: str = "json"):
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
