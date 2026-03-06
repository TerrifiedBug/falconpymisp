from typing import Optional

from src.log import get_logger

log = get_logger(__name__)

GALAXY_TYPES = ["threat-actor", "malpedia", "mitre-attack-pattern"]


class GalaxyCache:
    def __init__(self):
        self._clusters: dict[str, dict] = {}
        self._galaxy_ids: dict[str, str] = {}

    async def load(self, misp_client):
        galaxies = await misp_client.get_galaxies()
        for galaxy in galaxies:
            g = galaxy.get("Galaxy", galaxy)
            if g.get("type") in GALAXY_TYPES:
                self._galaxy_ids[g["type"]] = str(g["id"])
        for galaxy_type, galaxy_id in self._galaxy_ids.items():
            clusters = await misp_client.get_galaxy_clusters(galaxy_id)
            for cluster in clusters:
                c = cluster.get("GalaxyCluster", cluster)
                name = c.get("value", "").lower()
                if name:
                    self._clusters[name] = c
        log.info("galaxy_cache_loaded", extra={"count": len(self._clusters)})

    def find(self, name: str) -> Optional[dict]:
        return self._clusters.get(name.lower())

    @property
    def count(self) -> int:
        return len(self._clusters)
