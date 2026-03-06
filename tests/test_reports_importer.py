import pytest
from unittest.mock import AsyncMock, MagicMock
from src.importers.reports import ReportImporter
from src.crowdstrike.models import CSReport
from src.state import ImportState


@pytest.fixture
def mock_cs_client():
    client = MagicMock()
    client.get_reports.return_value = iter([
        CSReport(id=1, name="Report One", description="Details", short_description="Short",
            created_date=1709712000, last_modified_date=1709712000, report_type="Intelligence Report"),
        CSReport(id=2, name="Report Two", description="More details", short_description="Short 2",
            created_date=1709713000, last_modified_date=1709713000, report_type="Alert"),
    ])
    return client


@pytest.fixture
def mock_misp_client():
    client = AsyncMock()
    client.search_events.return_value = []
    client.create_event.return_value = {"Event": {"id": "200"}}
    return client


@pytest.fixture
def state(tmp_state_file):
    return ImportState(str(tmp_state_file))


class TestReportImporter:
    @pytest.mark.asyncio
    async def test_imports_reports(self, mock_cs_client, mock_misp_client, state):
        importer = ReportImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, org_uuid="test-uuid", tlp_tag="tlp:amber")
        count = await importer.run()
        assert count == 2
        assert mock_misp_client.create_event.call_count == 2

    @pytest.mark.asyncio
    async def test_updates_state_timestamp(self, mock_cs_client, mock_misp_client, state):
        importer = ReportImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, org_uuid="test-uuid", tlp_tag="tlp:amber")
        await importer.run()
        assert state.reports.last_timestamp == 1709713000
        assert state.reports.total_imported == 2

    @pytest.mark.asyncio
    async def test_skips_existing_reports(self, mock_cs_client, mock_misp_client, state):
        mock_misp_client.search_events.return_value = [{"Event": {"id": "50", "info": "Report One"}}]
        importer = ReportImporter(cs_client=mock_cs_client, misp_client=mock_misp_client,
            state=state, org_uuid="test-uuid", tlp_tag="tlp:amber")
        count = await importer.run()
        assert mock_misp_client.create_event.call_count == 1
