import pytest
from unittest.mock import AsyncMock, MagicMock
from src.importers.actors import ActorImporter
from src.crowdstrike.models import CSActor
from src.misp.galaxy_cache import GalaxyCache
from src.state import ImportState


@pytest.fixture
def mock_cs_client():
    client = MagicMock()
    client.get_actors.return_value = iter([
        CSActor(id=1, name="FANCY BEAR", description="Russian threat actor",
            short_description="APT28", created_date=1709712000,
            last_modified_date=1709712000, first_activity_date=1609459200,
            motivations=["Espionage"], target_industries=["Government"],
            target_countries=["United States"]),
    ])
    return client


@pytest.fixture
def mock_misp_client():
    client = AsyncMock()
    client.search_events.return_value = []
    client.create_event.return_value = {"Event": {"id": "300"}}
    client.attach_galaxy_cluster.return_value = {}
    return client


@pytest.fixture
def mock_galaxy_cache():
    cache = MagicMock(spec=GalaxyCache)
    cache.find.return_value = {"id": "c1", "value": "FANCY BEAR",
        "tag_name": "misp-galaxy:threat-actor=\"FANCY BEAR\""}
    return cache


@pytest.fixture
def state(tmp_state_file):
    return ImportState(str(tmp_state_file))


class TestActorImporter:
    @pytest.mark.asyncio
    async def test_imports_actors(self, mock_cs_client, mock_misp_client, mock_galaxy_cache, state):
        importer = ActorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, org_uuid="test-uuid", tlp_tag="tlp:amber", galaxy_cache=mock_galaxy_cache)
        count = await importer.run()
        assert count == 1
        assert mock_misp_client.create_event.call_count == 1

    @pytest.mark.asyncio
    async def test_attaches_galaxy_cluster(self, mock_cs_client, mock_misp_client, mock_galaxy_cache, state):
        importer = ActorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, org_uuid="test-uuid", tlp_tag="tlp:amber", galaxy_cache=mock_galaxy_cache)
        await importer.run()
        mock_misp_client.attach_galaxy_cluster.assert_called_once_with("300", "c1")

    @pytest.mark.asyncio
    async def test_updates_state(self, mock_cs_client, mock_misp_client, mock_galaxy_cache, state):
        importer = ActorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, org_uuid="test-uuid", tlp_tag="tlp:amber", galaxy_cache=mock_galaxy_cache)
        await importer.run()
        assert state.actors.last_timestamp == 1709712000
        assert state.actors.total_imported == 1

    @pytest.mark.asyncio
    async def test_dry_run_skips_misp_writes(self, mock_cs_client, mock_misp_client, mock_galaxy_cache, state):
        importer = ActorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, org_uuid="test-uuid", tlp_tag="tlp:amber", galaxy_cache=mock_galaxy_cache,
            dry_run=True, max_items=1)
        count = await importer.run()
        assert count == 1
        mock_misp_client.create_event.assert_not_called()
        assert state.actors.last_timestamp is None
