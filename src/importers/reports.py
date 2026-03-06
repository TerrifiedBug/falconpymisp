import asyncio
from src.crowdstrike.client import CrowdStrikeClient
from src.misp.client import MISPClient
from src.misp.models import build_report_event
from src.state import ImportState
from src.log import get_logger

log = get_logger(__name__)


class ReportImporter:
    def __init__(self, cs_client: CrowdStrikeClient, misp_client: MISPClient,
                 state: ImportState, org_uuid: str = "", tlp_tag: str = "tlp:amber",
                 distribution: int = 0, galaxy_cache=None):
        self._cs = cs_client
        self._misp = misp_client
        self._state = state
        self._org_uuid = org_uuid
        self._tlp_tag = tlp_tag
        self._distribution = distribution
        self._galaxy_cache = galaxy_cache
        self._existing_reports: set[str] = set()

    async def run(self) -> int:
        log.info("report_import_start", extra={"from_timestamp": self._state.reports.last_timestamp})
        await self._discover_existing()
        from_timestamp = self._state.reports.last_timestamp
        reports = await asyncio.to_thread(
            lambda: list(self._cs.get_reports(from_timestamp=from_timestamp))
        )
        count = 0
        last_timestamp = from_timestamp
        for report in reports:
            if report.name in self._existing_reports:
                log.info("report_skipped", extra={"report_name": report.name, "reason": "exists"})
                continue
            event = build_report_event(report, self._org_uuid, self._tlp_tag, self._distribution)
            try:
                result = await self._misp.create_event(event)
                event_id = str(result.get("Event", {}).get("id", ""))
                if not event_id:
                    raise RuntimeError(f"Failed to create event for report '{report.name}': unexpected response")
                count += 1
                if self._galaxy_cache:
                    for actor in report.actors:
                        cluster = self._galaxy_cache.find(actor)
                        if cluster:
                            await self._misp.attach_galaxy_cluster(event_id, cluster["id"])
                    for family in report.malware_families:
                        cluster = self._galaxy_cache.find(family)
                        if cluster:
                            await self._misp.attach_galaxy_cluster(event_id, cluster["id"])
                if report.created_date and report.created_date > (last_timestamp or 0):
                    last_timestamp = report.created_date
                log.info("report_imported", extra={"report_name": report.name, "event_id": event_id})
            except Exception as e:
                log.error("report_import_failed", extra={"report_name": report.name, "error": str(e)})
        if last_timestamp:
            self._state.reports.last_timestamp = last_timestamp
        self._state.reports.total_imported += count
        self._state.update_run_time("reports")
        self._state.save()
        log.info("report_import_complete", extra={"total": count})
        return count

    async def _discover_existing(self):
        events = await self._misp.search_events(org=self._org_uuid, tags=["crowdstrike:report-type:%"])
        for event_wrapper in events:
            event = event_wrapper.get("Event", event_wrapper)
            self._existing_reports.add(event.get("info", ""))
