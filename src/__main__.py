import asyncio
import sys
from datetime import datetime, timezone, timedelta

from src.config import AppConfig, ConfigError, load_config
from src.log import setup_logging, get_logger
from src.state import ImportState
from src.crowdstrike.client import CrowdStrikeClient
from src.misp.client import MISPClient
from src.misp.galaxy_cache import GalaxyCache
from src.importers.indicators import IndicatorImporter
from src.importers.reports import ReportImporter
from src.importers.actors import ActorImporter
from src.normalization import load_mappings

log = get_logger(__name__)


def _lookback_timestamp(days: int) -> int:
    """Calculate Unix timestamp for N days ago."""
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())


async def run_import(config: AppConfig):
    dry_run = config.import_.dry_run
    if dry_run:
        log.info("dry_run_enabled", extra={"max_items": config.import_.dry_run_max_items})

    mappings = load_mappings(config.import_.mappings_file)
    publish = config.import_.publish
    log.info("config_loaded", extra={"publish": publish, "mappings_file": config.import_.mappings_file})

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
        lookback_ts = _lookback_timestamp(config.import_.init_lookback_days)
        galaxy_cache = GalaxyCache()
        await galaxy_cache.load(misp_client)
        start_time = datetime.now(timezone.utc)
        totals = {}
        if config.import_.indicators:
            importer = IndicatorImporter(
                cs_client=cs_client, misp_client=misp_client, state=state,
                batch_size=config.import_.batch_size, org_uuid=config.misp.org_uuid,
                tlp_tag=config.tags.tlp, distribution=config.misp.distribution,
                tags_config=config.tags, dry_run=dry_run,
                max_items=config.import_.dry_run_max_items if dry_run else 0,
                init_lookback_days=config.import_.init_lookback_days,
                mappings=mappings, publish=publish,
            )
            totals["indicators"] = await importer.run()
        if config.import_.reports:
            importer = ReportImporter(
                cs_client=cs_client, misp_client=misp_client, state=state,
                org_uuid=config.misp.org_uuid, tlp_tag=config.tags.tlp,
                distribution=config.misp.distribution, galaxy_cache=galaxy_cache,
                dry_run=dry_run,
                max_items=config.import_.dry_run_max_items if dry_run else 0,
                init_lookback_ts=lookback_ts if not state.reports.last_timestamp else None,
                publish=publish,
            )
            totals["reports"] = await importer.run()
        if config.import_.actors:
            importer = ActorImporter(
                cs_client=cs_client, misp_client=misp_client, state=state,
                org_uuid=config.misp.org_uuid, tlp_tag=config.tags.tlp,
                distribution=config.misp.distribution, galaxy_cache=galaxy_cache,
                dry_run=dry_run,
                max_items=config.import_.dry_run_max_items if dry_run else 0,
                init_lookback_ts=lookback_ts if not state.actors.last_timestamp else None,
                publish=publish,
            )
            totals["actors"] = await importer.run()
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        log.info("import_complete", extra={"totals": totals, "elapsed_seconds": round(elapsed, 1), "dry_run": dry_run})
    finally:
        await misp_client.close()


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "/app/config.yml"
    try:
        config = load_config(config_path)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    setup_logging(level=config.logging.level, fmt=config.logging.format, log_file=config.logging.file)
    log.info("falcon_misp_import_start", extra={"config_path": config_path})
    asyncio.run(run_import(config))


if __name__ == "__main__":
    main()
