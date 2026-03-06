from typing import Generator, Optional

from falconpy import Intel

from src.crowdstrike.models import CSIndicator, CSReport, CSActor
from src.log import get_logger

log = get_logger(__name__)

BASE_URL_MAP = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "usgov-1": "https://api.laggar.gcw.crowdstrike.com",
}


class CrowdStrikeClient:
    def __init__(self, client_id: str, client_secret: str, base_url: str = "auto",
                 request_limit: int = 5000, proxy: Optional[dict] = None):
        kwargs = {"client_id": client_id, "client_secret": client_secret}
        if base_url != "auto" and base_url in BASE_URL_MAP:
            kwargs["base_url"] = BASE_URL_MAP[base_url]
        elif base_url != "auto":
            kwargs["base_url"] = base_url
        if proxy:
            kwargs["proxy"] = proxy
        self._falcon = Intel(**kwargs)
        self._limit = min(request_limit, 5000)

    def get_indicators(self, from_marker: Optional[str] = None,
                       published_filter: Optional[int] = None) -> Generator[CSIndicator, None, None]:
        filters = []
        if from_marker:
            filters.append(f"_marker:>='{from_marker}'")
        if published_filter:
            filters.append(f"published_date:>={published_filter}")
        marker_filter = "+".join(filters)
        total = 1
        while total > 0:
            response = self._falcon.query_indicator_entities(
                filter=marker_filter, limit=self._limit, sort="_marker.asc", include_deleted=False,
            )
            if response["status_code"] != 200:
                for err in response.get("body", {}).get("errors", []):
                    log.error("cs_api_error", extra={"code": err.get("code"), "message": err.get("message")})
                break
            resources = response["body"].get("resources", [])
            total = response["body"]["meta"]["pagination"].get("total", 0)
            for raw in resources:
                yield CSIndicator.from_api(raw)
            if resources:
                last_marker = resources[-1].get("_marker", "")
                marker_filter = f"_marker:>'{last_marker}'"
            else:
                break

    def get_reports(self, from_timestamp: Optional[int] = None) -> Generator[CSReport, None, None]:
        fql_filter = f"created_date:>={from_timestamp}" if from_timestamp else ""
        offset = 0
        while True:
            response = self._falcon.query_report_entities(
                filter=fql_filter, limit=self._limit, offset=offset, sort="created_date|asc", fields="__full__",
            )
            if response["status_code"] != 200:
                for err in response.get("body", {}).get("errors", []):
                    log.error("cs_api_error", extra={"code": err.get("code"), "message": err.get("message")})
                break
            resources = response["body"].get("resources", [])
            if not resources:
                break
            for raw in resources:
                yield CSReport.from_api(raw)
            pagination = response["body"]["meta"]["pagination"]
            offset += len(resources)
            if offset >= pagination.get("total", 0):
                break

    def get_actors(self, from_timestamp: Optional[int] = None) -> Generator[CSActor, None, None]:
        fql_filter = f"last_modified_date:>={from_timestamp}" if from_timestamp else ""
        offset = 0
        while True:
            response = self._falcon.query_actor_entities(
                filter=fql_filter, limit=self._limit, offset=offset, sort="last_modified_date|asc", fields="__full__",
            )
            if response["status_code"] != 200:
                for err in response.get("body", {}).get("errors", []):
                    log.error("cs_api_error", extra={"code": err.get("code"), "message": err.get("message")})
                break
            resources = response["body"].get("resources", [])
            if not resources:
                break
            for raw in resources:
                yield CSActor.from_api(raw)
            pagination = response["body"]["meta"]["pagination"]
            offset += len(resources)
            if offset >= pagination.get("total", 0):
                break
