import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


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


class MessageAllowlistFilter(logging.Filter):
    def __init__(self, allowlist: set[str]):
        super().__init__()
        self._allowlist = allowlist

    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage() in self._allowlist


def setup_logging(
    level: str = "INFO",
    fmt: str = "json",
    log_file: str = None,
    file_msg_allowlist: set[str] | None = None,
):
    root = logging.getLogger()
    root.handlers.clear()
    formatter = JSONFormatter() if fmt == "json" else logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    if log_file:
        log_path = Path(log_file)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path)
        except OSError:
            root.warning("log_file_unavailable", extra={"path": str(log_path)})
        else:
            file_handler.setFormatter(formatter)
            if file_msg_allowlist:
                file_handler.addFilter(MessageAllowlistFilter(file_msg_allowlist))
            root.addHandler(file_handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
