import pytest
from pathlib import Path


@pytest.fixture
def tmp_state_file(tmp_path):
    return tmp_path / "state.json"


@pytest.fixture
def sample_config():
    return {
        "crowdstrike": {
            "client_id": "test-id",
            "client_secret": "test-secret",
            "base_url": "auto",
            "request_limit": 5000,
        },
        "misp": {
            "url": "https://misp.example.com",
            "api_key": "test-key",
            "verify_ssl": False,
            "org_uuid": "test-org-uuid",
            "distribution": 0,
        },
        "import": {
            "indicators": True,
            "reports": True,
            "actors": True,
            "init_lookback_days": 30,
            "batch_size": 2000,
        },
        "tags": {
            "tlp": "tlp:amber",
            "confidence": True,
            "kill_chain": True,
            "taxonomies": {
                "iep": False,
                "iep2": False,
                "workflow": False,
            },
        },
        "logging": {
            "level": "INFO",
            "format": "json",
        },
        "state_file": "/tmp/test_state.json",
        "proxy": {
            "http": None,
            "https": None,
        },
    }
