import asyncio
import json
import random
from typing import Any, Optional

import aiohttp
from pymisp import MISPEvent, MISPAttribute

from src.log import get_logger

log = get_logger(__name__)

MAX_RETRIES = 3
BASE_DELAY = 1.0


class MISPClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = False):
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._verify_ssl = verify_ssl
        self._session: Optional[aiohttp.ClientSession] = None

    async def connect(self):
        ssl = None if self._verify_ssl else False
        connector = aiohttp.TCPConnector(ssl=ssl, limit=20)
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={"Authorization": self._api_key, "Accept": "application/json", "Content-Type": "application/json"},
        )

    async def close(self):
        if self._session:
            await self._session.close()

    async def _request(self, method: str, path: str, data: Any = None) -> dict:
        url = f"{self._base_url}{path}"
        body = json.dumps(data) if data else None
        for attempt in range(MAX_RETRIES):
            try:
                if method == "GET":
                    request_cm = self._session.get(url)
                elif method == "POST":
                    request_cm = self._session.post(url, data=body)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                async with request_cm as resp:
                    if resp.status == 200:
                        return await resp.json()
                    error_text = await resp.text()
                log.warning("misp_api_error", extra={"status": resp.status, "path": path, "attempt": attempt + 1, "error": error_text[:200]})
            except aiohttp.ClientError as e:
                log.warning("misp_connection_error", extra={"path": path, "attempt": attempt + 1, "error": str(e)})
            if attempt < MAX_RETRIES - 1:
                delay = BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
                await asyncio.sleep(delay)
        raise RuntimeError(f"MISP API request failed after {MAX_RETRIES} retries: {path}")

    async def test_connection(self) -> bool:
        try:
            result = await self._request("GET", "/servers/getVersion")
            log.info("misp_connected", extra={"version": result.get("version", "unknown")})
            return True
        except Exception as e:
            log.error("misp_connection_failed", extra={"error": str(e)})
            return False

    async def create_event(self, event: MISPEvent) -> dict:
        return await self._request("POST", "/events/add", {"Event": event.to_dict()})

    async def update_event(self, event_id: str, event: MISPEvent) -> dict:
        return await self._request("POST", f"/events/edit/{event_id}", {"Event": event.to_dict()})

    async def search_events(self, **kwargs) -> list:
        result = await self._request("POST", "/events/restSearch", kwargs)
        return result.get("response", [])

    async def add_attributes_batch(self, event_id: str, attributes: list[MISPAttribute]) -> dict:
        data = [attr.to_dict() for attr in attributes]
        return await self._request("POST", f"/attributes/add/{event_id}", data)

    async def get_galaxies(self) -> list:
        return await self._request("GET", "/galaxies")

    async def get_galaxy_clusters(self, galaxy_id: str) -> list:
        result = await self._request("GET", f"/galaxy_clusters/index/{galaxy_id}")
        if isinstance(result, list):
            return result
        return result.get("response", [])

    async def search_galaxy_clusters(self, search_term: str) -> list:
        result = await self._request("POST", "/galaxy_clusters/restSearch", {"value": search_term})
        if isinstance(result, list):
            return result
        return result.get("response", [])

    async def attach_galaxy_cluster(self, event_id: str, galaxy_cluster_id: str) -> dict:
        return await self._request("POST", "/galaxies/attachCluster",
            {"Galaxy": {"target_id": event_id, "cluster_ids": [galaxy_cluster_id]}})
