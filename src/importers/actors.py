import asyncio
from src.crowdstrike.client import CrowdStrikeClient
from src.misp.client import MISPClient
from src.misp.models import build_actor_event
from src.misp.galaxy_cache import GalaxyCache
from src.state import ImportState
from src.log import get_logger

log = get_logger(__name__)


class ActorImporter:
    def __init__(self, cs_client: CrowdStrikeClient, misp_client: MISPClient,
                 state: ImportState, org_uuid: str = "", tlp_tag: str = "tlp:amber",
                 distribution: int = 0, galaxy_cache: GalaxyCache = None, dry_run: bool = False,
                 max_items: int = 0, init_lookback_ts: int = None,
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
        self._publish = publish
        self._existing_actors: set[str] = set()

    async def run(self) -> int:
        log.info("actor_import_start", extra={
            "from_timestamp": self._state.actors.last_timestamp, "dry_run": self._dry_run,
        })
        if not self._dry_run:
            await self._discover_existing()
        from_timestamp = self._state.actors.last_timestamp
        if from_timestamp is None and self._init_lookback_ts:
            from_timestamp = self._init_lookback_ts
            log.info("using_lookback", extra={"from_timestamp": from_timestamp})
        actors = await asyncio.to_thread(
            lambda: list(self._cs.get_actors(from_timestamp=from_timestamp))
        )
        count = 0
        last_timestamp = self._state.actors.last_timestamp
        for actor in actors:
            if self._max_items and count >= self._max_items:
                log.info("dry_run_limit_reached", extra={"max_items": self._max_items})
                break
            if actor.name in self._existing_actors:
                log.info("actor_skipped", extra={"actor_name": actor.name, "reason": "exists"})
                continue
            if self._dry_run:
                log.info("dry_run_actor", extra={
                    "actor_name": actor.name, "motivations": actor.motivations,
                    "target_industries": actor.target_industries,
                })
                count += 1
                continue
            event = build_actor_event(actor, self._org_uuid, self._tlp_tag, self._distribution, publish=self._publish)
            try:
                result = await self._misp.create_event(event)
                event_id = str(result.get("Event", {}).get("id", ""))
                if not event_id:
                    raise RuntimeError(f"Failed to create event for actor '{actor.name}': unexpected response")
                count += 1
                if self._galaxy_cache:
                    cluster = self._galaxy_cache.find(actor.name)
                    if cluster:
                        await self._misp.attach_galaxy_cluster(event_id, cluster["id"])
                        log.info("galaxy_attached", extra={"actor_name": actor.name, "cluster": cluster.get("value")})
                if actor.last_modified_date and actor.last_modified_date > (last_timestamp or 0):
                    last_timestamp = actor.last_modified_date
                log.info("actor_imported", extra={"actor_name": actor.name, "event_id": event_id})
            except Exception as e:
                log.error("actor_import_failed", extra={"actor_name": actor.name, "error": str(e)})
        if not self._dry_run:
            if last_timestamp:
                self._state.actors.last_timestamp = last_timestamp
            self._state.actors.total_imported += count
            self._state.update_run_time("actors")
            self._state.save()
        log.info("actor_import_complete", extra={"total": count, "dry_run": self._dry_run})
        return count

    async def _discover_existing(self):
        events = await self._misp.search_events(org=self._org_uuid, tags=["crowdstrike:actor"])
        for event_wrapper in events:
            event = event_wrapper.get("Event", event_wrapper)
            info = event.get("info", "")
            if "CrowdStrike Actor:" in info:
                self._existing_actors.add(info.replace("CrowdStrike Actor:", "").strip())
