import asyncio
import sys
from datetime import datetime, timezone

from src.config import AppConfig, ConfigError, load_config
from src.log import setup_logging, get_logger
from src.state import ImportState
from src.crowdstrike.client import CrowdStrikeClient
from src.misp.client import MISPClient
from src.misp.galaxy_cache import GalaxyCache
from src.importers.indicators import IndicatorImporter
from src.importers.reports import ReportImporter
from src.importers.actors import ActorImporter

log = get_logger(__name__)


async def run_import(config: AppConfig):
    cs_client = CrowdStrikeClient(
        client_id=config.crowdstrike.client_id,
        client_secret=config.crowdstrike.client_secret,
        base_url=config.crowdstrike.base_url,
        request_limit=config.crowdstrike.request_limit,
        proxy={"http": config.proxy.http, "https": config.proxy.https}
        if config.proxy.http or config.proxy.https else None,
    )
    misp_client = MISPClient(
        url=config.misp.url, api_key=config.misp.api_key, verify_ssl=config.misp.verify_ssl,
    )
    await misp_client.connect()
    try:
        if not await misp_client.test_connection():
            log.error("misp_connection_failed")
            return
        state = ImportState(config.state_file)
        galaxy_cache = GalaxyCache()
        await galaxy_cache.load(misp_client)
        start_time = datetime.now(timezone.utc)
        totals = {}
        if config.import_.indicators:
            importer = IndicatorImporter(
                cs_client=cs_client, misp_client=misp_client, state=state,
                batch_size=config.import_.batch_size, org_uuid=config.misp.org_uuid,
                tlp_tag=config.tags.tlp, distribution=config.misp.distribution,
                tags_config=config.tags,
            )
            totals["indicators"] = await importer.run()
        if config.import_.reports:
            importer = ReportImporter(
                cs_client=cs_client, misp_client=misp_client, state=state,
                org_uuid=config.misp.org_uuid, tlp_tag=config.tags.tlp,
                distribution=config.misp.distribution, galaxy_cache=galaxy_cache,
            )
            totals["reports"] = await importer.run()
        if config.import_.actors:
            importer = ActorImporter(
                cs_client=cs_client, misp_client=misp_client, state=state,
                org_uuid=config.misp.org_uuid, tlp_tag=config.tags.tlp,
                distribution=config.misp.distribution, galaxy_cache=galaxy_cache,
            )
            totals["actors"] = await importer.run()
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        log.info("import_complete", extra={"totals": totals, "elapsed_seconds": round(elapsed, 1)})
    finally:
        await misp_client.close()


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "/app/config.yml"
    try:
        config = load_config(config_path)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    setup_logging(level=config.logging.level, fmt=config.logging.format)
    log.info("falcon_misp_import_start", extra={"config_path": config_path})
    asyncio.run(run_import(config))


if __name__ == "__main__":
    main()
