import asyncio
from itertools import islice
from src.crowdstrike.client import CrowdStrikeClient
from src.misp.client import MISPClient
from src.misp.models import build_report_event
from src.state import ImportState
from src.log import get_logger

log = get_logger(__name__)
STREAM_CHUNK_SIZE = 200


def _next_chunk(items, size: int):
    return list(islice(items, size))


class ReportImporter:
    def __init__(self, cs_client: CrowdStrikeClient, misp_client: MISPClient,
                 state: ImportState, org_uuid: str = "", tlp_tag: str = "tlp:amber",
                 distribution: int = 0, galaxy_cache=None, dry_run: bool = False,
                 max_items: int = 0, init_lookback_ts: int = None,
                 attach_galaxies: bool = True,
                 publish: bool = True):
        self._cs = cs_client
        self._misp = misp_client
        self._state = state
        self._org_uuid = org_uuid
        self._tlp_tag = tlp_tag
        self._distribution = distribution
        self._galaxy_cache = galaxy_cache
        self._dry_run = dry_run
        self._max_items = max_items
        self._init_lookback_ts = init_lookback_ts
        self._attach_galaxies = attach_galaxies
        self._publish = publish

    async def run(self) -> int:
        log.info("report_import_start", extra={
            "from_timestamp": self._state.reports.last_timestamp, "dry_run": self._dry_run,
        })
        from_timestamp = self._state.reports.last_timestamp
        if from_timestamp is None and self._init_lookback_ts:
            from_timestamp = self._init_lookback_ts
            log.info("using_lookback", extra={"from_timestamp": from_timestamp})
        reports = self._cs.get_reports(from_timestamp=from_timestamp)
        count = 0
        last_timestamp = self._state.reports.last_timestamp
        while True:
            chunk = await asyncio.to_thread(_next_chunk, reports, STREAM_CHUNK_SIZE)
            if not chunk:
                break
            for report in chunk:
                if self._max_items and count >= self._max_items:
                    log.info("dry_run_limit_reached", extra={"max_items": self._max_items})
                    break
                if not self._dry_run and await self._report_exists(report.name):
                    log.info("report_skipped", extra={"report_name": report.name, "reason": "exists"})
                    continue
                if self._dry_run:
                    log.info("dry_run_report", extra={
                        "report_name": report.name, "type": report.report_type,
                        "actors": report.actors, "families": report.malware_families,
                    })
                    count += 1
                    continue
                event = build_report_event(report, self._org_uuid, self._tlp_tag, self._distribution, publish=self._publish)
                try:
                    result = await self._misp.create_event(event)
                    event_id = str(result.get("Event", {}).get("id", ""))
                    if not event_id:
                        raise RuntimeError(f"Failed to create event for report '{report.name}': unexpected response")
                    count += 1
                    if report.created_date and report.created_date > (last_timestamp or 0):
                        last_timestamp = report.created_date
                    await self._attach_report_galaxies(event_id, report)
                    log.info("report_imported", extra={"report_name": report.name, "event_id": event_id})
                except Exception as e:
                    log.error("report_import_failed", extra={"report_name": report.name, "error": str(e)})
            if self._max_items and count >= self._max_items:
                break
        if not self._dry_run:
            if last_timestamp:
                self._state.reports.last_timestamp = last_timestamp
            self._state.reports.total_imported += count
            self._state.update_run_time("reports")
            self._state.save()
        log.info("report_import_complete", extra={"total": count, "dry_run": self._dry_run})
        return count

    async def _report_exists(self, report_name: str) -> bool:
        events = await self._misp.search_events(
            org=self._org_uuid,
            eventinfo=report_name,
            limit=1,
            page=1,
        )
        for event_wrapper in events:
            event = event_wrapper.get("Event", event_wrapper)
            if event.get("info", "") == report_name:
                return True
        return False

    async def _attach_report_galaxies(self, event_id: str, report):
        if not self._attach_galaxies or not self._galaxy_cache:
            return
        for actor in report.actors:
            cluster = self._galaxy_cache.find(actor)
            if not cluster:
                continue
            try:
                await self._misp.attach_galaxy_cluster(event_id, cluster["id"])
            except Exception as e:
                log.warning("report_galaxy_attach_failed", extra={
                    "report_name": report.name,
                    "event_id": event_id,
                    "cluster_id": cluster.get("id"),
                    "cluster_name": cluster.get("value"),
                    "error": str(e),
                })
        for family in report.malware_families:
            cluster = self._galaxy_cache.find(family)
            if not cluster:
                continue
            try:
                await self._misp.attach_galaxy_cluster(event_id, cluster["id"])
            except Exception as e:
                log.warning("report_galaxy_attach_failed", extra={
                    "report_name": report.name,
                    "event_id": event_id,
                    "cluster_id": cluster.get("id"),
                    "cluster_name": cluster.get("value"),
                    "error": str(e),
                })

