import pytest
from unittest.mock import MagicMock, patch
from src.crowdstrike.client import CrowdStrikeClient
from src.crowdstrike.models import CSIndicator, CSReport, CSActor


@pytest.fixture
def mock_falcon():
    return MagicMock()


@pytest.fixture
def cs_client(mock_falcon):
    with patch("src.crowdstrike.client.Intel", return_value=mock_falcon):
        client = CrowdStrikeClient(
            client_id="test-id", client_secret="test-secret",
            base_url="auto", request_limit=5000,
        )
        client._falcon = mock_falcon
        return client


class TestIndicatorStreaming:
    def test_yields_indicators_from_single_page(self, cs_client, mock_falcon):
        mock_falcon.query_indicator_entities.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "1", "indicator": "evil.com", "type": "domain",
                     "malicious_confidence": "high", "published_date": 1709712000,
                     "last_updated": 1709712000, "_marker": "1709712000.abc"}
                ],
                "meta": {"pagination": {"total": 0}},
            },
        }
        indicators = list(cs_client.get_indicators())
        assert len(indicators) == 1
        assert isinstance(indicators[0], CSIndicator)
        assert indicators[0].value == "evil.com"

    def test_paginates_with_marker(self, cs_client, mock_falcon):
        page1 = {"status_code": 200, "body": {
            "resources": [{"id": "1", "indicator": "a.com", "type": "domain",
                "malicious_confidence": "high", "published_date": 0,
                "last_updated": 0, "_marker": "100.abc"}],
            "meta": {"pagination": {"total": 2}},
        }}
        page2 = {"status_code": 200, "body": {
            "resources": [{"id": "2", "indicator": "b.com", "type": "domain",
                "malicious_confidence": "high", "published_date": 0,
                "last_updated": 0, "_marker": "200.def"}],
            "meta": {"pagination": {"total": 0}},
        }}
        mock_falcon.query_indicator_entities.side_effect = [page1, page2]
        indicators = list(cs_client.get_indicators())
        assert len(indicators) == 2
        assert mock_falcon.query_indicator_entities.call_count == 2

    def test_resumes_from_marker(self, cs_client, mock_falcon):
        mock_falcon.query_indicator_entities.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }
        list(cs_client.get_indicators(from_marker="500.xyz"))
        call_args = mock_falcon.query_indicator_entities.call_args
        assert "500.xyz" in call_args.kwargs.get("filter", "")

    def test_published_filter_applied(self, cs_client, mock_falcon):
        mock_falcon.query_indicator_entities.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }
        list(cs_client.get_indicators(published_filter=1709712000))
        call_args = mock_falcon.query_indicator_entities.call_args
        assert "published_date:>=1709712000" in call_args.kwargs.get("filter", "")


class TestReports:
    def test_get_reports(self, cs_client, mock_falcon):
        mock_falcon.query_report_entities.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": 1, "name": "Report 1", "description": "", "short_description": "",
                     "created_date": 1709712000, "last_modified_date": 1709712000}
                ],
                "meta": {"pagination": {"total": 1, "offset": 0}},
            },
        }
        reports = list(cs_client.get_reports())
        assert len(reports) == 1
        assert isinstance(reports[0], CSReport)


class TestActors:
    def test_get_actors(self, cs_client, mock_falcon):
        mock_falcon.query_actor_entities.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": 1, "name": "FANCY BEAR", "description": "", "short_description": "",
                     "created_date": 1709712000, "last_modified_date": 1709712000,
                     "first_activity_date": 1609459200}
                ],
                "meta": {"pagination": {"total": 1, "offset": 0}},
            },
        }
        actors = list(cs_client.get_actors())
        assert len(actors) == 1
        assert isinstance(actors[0], CSActor)
