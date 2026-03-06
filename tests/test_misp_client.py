import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pymisp import MISPEvent, MISPAttribute
from src.misp.client import MISPClient


@pytest_asyncio.fixture
async def misp_client():
    client = MISPClient(url="https://misp.example.com", api_key="test-key", verify_ssl=False)
    client._session = AsyncMock()
    return client


class TestMISPClient:
    @pytest.mark.asyncio
    async def test_create_event(self, misp_client):
        event = MISPEvent()
        event.info = "Test Event"
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"Event": {"id": "123", "info": "Test Event"}})
        misp_client._session.post = AsyncMock(return_value=mock_response)
        result = await misp_client.create_event(event)
        assert result["Event"]["id"] == "123"

    @pytest.mark.asyncio
    async def test_search_events(self, misp_client):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"response": []})
        misp_client._session.post = AsyncMock(return_value=mock_response)
        result = await misp_client.search_events(eventinfo="CrowdStrike%")
        assert result == []

    @pytest.mark.asyncio
    async def test_add_attributes_batch(self, misp_client):
        attrs = []
        for i in range(3):
            attr = MISPAttribute()
            attr.type = "domain"
            attr.value = f"evil{i}.com"
            attrs.append(attr)
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"Attribute": []})
        misp_client._session.post = AsyncMock(return_value=mock_response)
        await misp_client.add_attributes_batch("123", attrs)
        misp_client._session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_on_failure(self, misp_client):
        fail_resp = AsyncMock()
        fail_resp.status = 500
        fail_resp.text = AsyncMock(return_value="Server Error")
        ok_resp = AsyncMock()
        ok_resp.status = 200
        ok_resp.json = AsyncMock(return_value={"Event": {"id": "1"}})
        misp_client._session.post = AsyncMock(side_effect=[fail_resp, ok_resp])
        event = MISPEvent()
        event.info = "Retry Test"
        result = await misp_client.create_event(event)
        assert result["Event"]["id"] == "1"
        assert misp_client._session.post.call_count == 2
