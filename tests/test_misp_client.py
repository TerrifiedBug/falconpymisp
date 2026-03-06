import json
from contextlib import asynccontextmanager
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pymisp import MISPEvent, MISPAttribute
from src.misp.client import MISPClient


def _mock_response(status=200, json_data=None, text_data=""):
    """Create a mock that works as both an async context manager and a response."""
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data)
    resp.text = AsyncMock(return_value=text_data)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _mock_session_method(*responses):
    """Return a callable that yields context-manager-compatible mock responses."""
    mocks = [_mock_response(**r) if isinstance(r, dict) else r for r in responses]
    mock = MagicMock(side_effect=mocks)
    return mock


@pytest_asyncio.fixture
async def misp_client():
    client = MISPClient(url="https://misp.example.com", api_key="test-key", verify_ssl=False)
    client._session = MagicMock()
    return client


class TestMISPClient:
    @pytest.mark.asyncio
    async def test_create_event(self, misp_client):
        event = MISPEvent()
        event.info = "Test Event"
        resp = _mock_response(200, {"Event": {"id": "123", "info": "Test Event"}})
        misp_client._session.post = MagicMock(return_value=resp)
        result = await misp_client.create_event(event)
        assert result["Event"]["id"] == "123"

    @pytest.mark.asyncio
    async def test_search_events(self, misp_client):
        resp = _mock_response(200, {"response": []})
        misp_client._session.post = MagicMock(return_value=resp)
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
        resp = _mock_response(200, {"Attribute": []})
        misp_client._session.post = MagicMock(return_value=resp)
        await misp_client.add_attributes_batch("123", attrs)
        misp_client._session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_on_failure(self, misp_client):
        fail_resp = _mock_response(500, text_data="Server Error")
        ok_resp = _mock_response(200, {"Event": {"id": "1"}})
        misp_client._session.post = MagicMock(side_effect=[fail_resp, ok_resp])
        event = MISPEvent()
        event.info = "Retry Test"
        result = await misp_client.create_event(event)
        assert result["Event"]["id"] == "1"
        assert misp_client._session.post.call_count == 2
