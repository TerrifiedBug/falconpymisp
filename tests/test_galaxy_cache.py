import pytest
from unittest.mock import AsyncMock
from src.misp.galaxy_cache import GalaxyCache


@pytest.fixture
def mock_misp_client():
    client = AsyncMock()
    client.get_galaxies.return_value = [
        {"Galaxy": {"id": "1", "type": "threat-actor", "name": "Threat Actor"}},
        {"Galaxy": {"id": "2", "type": "malpedia", "name": "Malpedia"}},
        {"Galaxy": {"id": "3", "type": "mitre-attack-pattern", "name": "MITRE ATT&CK"}},
    ]
    client.get_galaxy_clusters.side_effect = lambda gid: {
        "1": [
            {"id": "c1", "value": "FANCY BEAR", "tag_name": "misp-galaxy:threat-actor=\"FANCY BEAR\""},
            {"id": "c2", "value": "COZY BEAR", "tag_name": "misp-galaxy:threat-actor=\"COZY BEAR\""},
        ],
        "2": [{"id": "c3", "value": "njRAT", "tag_name": "misp-galaxy:malpedia=\"NjRAT\""}],
        "3": [],
    }.get(gid, [])
    return client


class TestGalaxyCache:
    @pytest.mark.asyncio
    async def test_load_caches_clusters(self, mock_misp_client):
        cache = GalaxyCache()
        await cache.load(mock_misp_client)
        assert cache.find("FANCY BEAR") is not None
        assert cache.find("njRAT") is not None

    @pytest.mark.asyncio
    async def test_case_insensitive_lookup(self, mock_misp_client):
        cache = GalaxyCache()
        await cache.load(mock_misp_client)
        assert cache.find("fancy bear") is not None
        assert cache.find("FANCY BEAR") is not None
        assert cache.find("Fancy Bear") is not None

    @pytest.mark.asyncio
    async def test_returns_none_for_unknown(self, mock_misp_client):
        cache = GalaxyCache()
        await cache.load(mock_misp_client)
        assert cache.find("UNKNOWN ACTOR") is None

    @pytest.mark.asyncio
    async def test_get_tag_name(self, mock_misp_client):
        cache = GalaxyCache()
        await cache.load(mock_misp_client)
        cluster = cache.find("FANCY BEAR")
        assert "threat-actor" in cluster["tag_name"]

    @pytest.mark.asyncio
    async def test_cluster_count(self, mock_misp_client):
        cache = GalaxyCache()
        await cache.load(mock_misp_client)
        assert cache.count == 3
