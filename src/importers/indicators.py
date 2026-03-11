import asyncio
from collections import defaultdict
from itertools import islice
from typing import Optional

from pymisp import MISPAttribute

from src.crowdstrike.client import CrowdStrikeClient
from src.misp.client import MISPClient
from src.misp.models import build_feed_event, build_indicator_attribute
from src.state import ImportState
from src.log import get_logger

log = get_logger(__name__)
PROGRESS_INTERVAL = 5000
STREAM_CHUNK_SIZE = 500


def _next_chunk(items, size: int):
    return list(islice(items, size))


class IndicatorImporter:
    def __init__(self, cs_client: CrowdStrikeClient, misp_client: MISPClient,
                 state: ImportState, batch_size: int = 2000, org_uuid: str = "",
                 tlp_tag: str = "tlp:amber", distribution: int = 0, tags_config=None,
                 dry_run: bool = False, max_items: int = 0, init_lookback_days: int = 30,
                 mappings=None, publish: bool = True, no_hashes: bool = False):
        self._cs = cs_client
        self._misp = misp_client
        self._state = state
        self._batch_size = batch_size
        self._org_uuid = org_uuid
        self._tlp_tag = tlp_tag
        self._distribution = distribution
        self._tags_config = tags_config
        self._dry_run = dry_run
        self._max_items = max_items
        self._init_lookback_days = init_lookback_days
        self._mappings = mappings
        self._publish = publish
        self._no_hashes = no_hashes
        self._feed_events: dict[str, str] = {}
        self._unpublished_feed_events: set[str] = set()
        self._buffers: dict[str, list[MISPAttribute]] = defaultdict(list)
        self._last_marker: Optional[str] = None
        self._count = 0

    async def run(self) -> int:
        log.info("indicator_import_start", extra={
            "from_marker": self._state.indicators.last_marker, "dry_run": self._dry_run,
        })
        if not self._dry_run:
            await self._discover_feed_events()
        from_marker = self._state.indicators.last_marker
        published_filter = None
        if from_marker is None and self._init_lookback_days:
            from datetime import datetime, timezone, timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._init_lookback_days)
            published_filter = int(cutoff.timestamp())
        indicators = self._cs.get_indicators(
            from_marker=from_marker, published_filter=published_filter,
        )
        scanned = 0
        try:
            while True:
                chunk = await asyncio.to_thread(_next_chunk, indicators, STREAM_CHUNK_SIZE)
                if not chunk:
                    break
                for indicator in chunk:
                    scanned += 1
                    if self._no_hashes and indicator.cs_type in {"hash_md5", "hash_sha1", "hash_sha256"}:
                        continue
                    if self._max_items and self._count >= self._max_items:
                        log.info("dry_run_limit_reached", extra={"max_items": self._max_items})
                        break
                    attr = build_indicator_attribute(indicator, self._tags_config, mappings=self._mappings)
                    if attr is None:
                        continue
                    if self._dry_run:
                        self._last_marker = indicator.marker
                        log.info("dry_run_indicator", extra={
                            "type": indicator.cs_type, "value": indicator.value,
                            "confidence": indicator.malicious_confidence,
                        })
                        self._count += 1
                        if self._count % PROGRESS_INTERVAL == 0:
                            log.info("indicator_progress", extra={
                                "processed": self._count,
                                "scanned": scanned,
                                "marker": self._last_marker,
                            })
                        continue
                    self._buffers[indicator.cs_type].append(attr)
                    self._last_marker = indicator.marker
                    self._count += 1
                    if len(self._buffers[indicator.cs_type]) >= self._batch_size:
                        await self._flush_buffer(indicator.cs_type)
                    if self._count % PROGRESS_INTERVAL == 0:
                        log.info("indicator_progress", extra={
                            "processed": self._count,
                            "scanned": scanned,
                            "marker": self._last_marker,
                        })
                if self._max_items and self._count >= self._max_items:
                    break
            if not self._dry_run:
                for cs_type in list(self._buffers.keys()):
                    if self._buffers[cs_type]:
                        await self._flush_buffer(cs_type)
                if self._last_marker:
                    self._state.indicators.last_marker = self._last_marker
                self._state.indicators.total_imported += self._count
                self._state.update_run_time("indicators")
                self._state.save()
        finally:
            self._buffers.clear()
        log.info("indicator_import_complete", extra={"total": self._count, "marker": self._last_marker, "dry_run": self._dry_run})
        return self._count

    async def _discover_feed_events(self):
        events = await self._misp.search_events(eventinfo="CrowdStrike:%Indicators", org=self._org_uuid)
        for event_wrapper in events:
            event = event_wrapper.get("Event", event_wrapper)
            info = event.get("info", "")
            event_id = str(event.get("id", ""))
            if "CrowdStrike:" in info and "Indicators" in info:
                type_part = info.replace("CrowdStrike:", "").replace("Indicators", "").strip()
                cs_type = type_part.lower().replace(" ", "_").strip()
                if cs_type:
                    self._feed_events[cs_type] = event_id
                    log.info("feed_event_found", extra={"type": cs_type, "event_id": event_id})

    async def _get_or_create_feed_event(self, cs_type: str) -> str:
        if cs_type in self._feed_events:
            return self._feed_events[cs_type]
        event = build_feed_event(indicator_type=cs_type, org_uuid=self._org_uuid,
            tlp_tag=self._tlp_tag, distribution=self._distribution, publish=False)
        result = await self._misp.create_event(event)
        event_id = str(result.get("Event", {}).get("id", ""))
        if not event_id:
            raise RuntimeError(f"Failed to create feed event for type '{cs_type}': unexpected response")
        self._feed_events[cs_type] = event_id
        self._unpublished_feed_events.add(event_id)
        log.info("feed_event_created", extra={"type": cs_type, "event_id": event_id})
        return event_id

    async def _flush_buffer(self, cs_type: str):
        attrs = self._buffers[cs_type]
        if not attrs:
            return
        event_id = await self._get_or_create_feed_event(cs_type)
        await self._misp.add_attributes_batch(event_id, attrs)
        if self._publish and event_id in self._unpublished_feed_events:
            await self._misp.publish_event(event_id)
            self._unpublished_feed_events.remove(event_id)
            log.info("feed_event_published", extra={"type": cs_type, "event_id": event_id})
        log.info("batch_flushed", extra={"type": cs_type, "count": len(attrs), "event_id": event_id})
        self._buffers[cs_type] = []
