import pytest
from unittest.mock import AsyncMock, MagicMock
from src.importers.indicators import IndicatorImporter
from src.crowdstrike.models import CSIndicator
from src.state import ImportState


@pytest.fixture
def mock_cs_client():
    client = MagicMock()
    client.get_indicators.return_value = iter([
        CSIndicator(id="1", value="evil.com", cs_type="domain",
            malicious_confidence="high", published_date=1709712000,
            last_updated=1709712000, marker="100.abc"),
        CSIndicator(id="2", value="bad.org", cs_type="domain",
            malicious_confidence="medium", published_date=1709712000,
            last_updated=1709712000, marker="200.def"),
        CSIndicator(id="3", value="abc123", cs_type="hash_md5",
            malicious_confidence="high", published_date=1709712000,
            last_updated=1709712000, marker="300.ghi"),
    ])
    return client


@pytest.fixture
def mock_misp_client():
    client = AsyncMock()
    client.search_events.return_value = []
    client.create_event.return_value = {"Event": {"id": "100"}}
    client.add_attributes_batch.return_value = {"Attribute": []}
    return client


@pytest.fixture
def state(tmp_state_file):
    return ImportState(str(tmp_state_file))


class TestIndicatorImporter:
    @pytest.mark.asyncio
    async def test_imports_indicators_grouped_by_type(self, mock_cs_client, mock_misp_client, state):
        importer = IndicatorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, batch_size=100, org_uuid="test-uuid", tlp_tag="tlp:amber")
        count = await importer.run()
        assert count == 3
        assert mock_misp_client.create_event.call_count == 2

    @pytest.mark.asyncio
    async def test_updates_state_marker(self, mock_cs_client, mock_misp_client, state):
        importer = IndicatorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, batch_size=100, org_uuid="test-uuid", tlp_tag="tlp:amber")
        await importer.run()
        assert state.indicators.last_marker == "300.ghi"
        assert state.indicators.total_imported == 3

    @pytest.mark.asyncio
    async def test_resumes_from_existing_event(self, mock_cs_client, mock_misp_client, state):
        mock_misp_client.search_events.return_value = [
            {"Event": {"id": "50", "info": "CrowdStrike: Domain Indicators"}}
        ]
        importer = IndicatorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, batch_size=100, org_uuid="test-uuid", tlp_tag="tlp:amber")
        await importer.run()
        assert mock_misp_client.create_event.call_count == 1

    @pytest.mark.asyncio
    async def test_batch_flushing(self, mock_misp_client, state):
        indicators = [
            CSIndicator(id=str(i), value=f"domain{i}.com", cs_type="domain",
                malicious_confidence="high", published_date=0, last_updated=0, marker=f"{i}.x")
            for i in range(5)
        ]
        cs_client = MagicMock()
        cs_client.get_indicators.return_value = iter(indicators)
        mock_misp_client.search_events.return_value = []
        mock_misp_client.create_event.return_value = {"Event": {"id": "100"}}
        importer = IndicatorImporter(cs_client=cs_client, misp_client=mock_misp_client,
            state=state, batch_size=2, org_uuid="test-uuid", tlp_tag="tlp:amber")
        count = await importer.run()
        assert count == 5
        assert mock_misp_client.add_attributes_batch.call_count == 3

    @pytest.mark.asyncio
    async def test_dry_run_skips_misp_writes(self, mock_cs_client, mock_misp_client, state):
        importer = IndicatorImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, batch_size=100, org_uuid="test-uuid", tlp_tag="tlp:amber",
            dry_run=True, max_items=2)
        count = await importer.run()
        assert count == 2
        mock_misp_client.create_event.assert_not_called()
        mock_misp_client.add_attributes_batch.assert_not_called()
        assert state.indicators.last_marker is None
