import json
import pytest
from src.state import ImportState


class TestImportState:
    def test_load_empty_state(self, tmp_state_file):
        state = ImportState(str(tmp_state_file))
        assert state.indicators.last_marker is None
        assert state.reports.last_timestamp is None
        assert state.actors.last_timestamp is None

    def test_save_and_reload(self, tmp_state_file):
        state = ImportState(str(tmp_state_file))
        state.indicators.last_marker = "1709712000.abc123"
        state.indicators.total_imported = 5000
        state.save()

        reloaded = ImportState(str(tmp_state_file))
        assert reloaded.indicators.last_marker == "1709712000.abc123"
        assert reloaded.indicators.total_imported == 5000

    def test_atomic_write(self, tmp_state_file):
        state = ImportState(str(tmp_state_file))
        state.indicators.last_marker = "test"
        state.save()
        parent = tmp_state_file.parent
        assert not list(parent.glob("*.tmp"))

    def test_load_existing_state(self, tmp_state_file):
        data = {
            "indicators": {
                "last_marker": "12345.xyz",
                "last_run": "2026-03-06T10:00:00Z",
                "total_imported": 100,
            },
            "reports": {
                "last_timestamp": 1709712000,
                "last_run": "2026-03-06T10:00:00Z",
                "total_imported": 50,
            },
            "actors": {
                "last_timestamp": 1709712000,
                "last_run": "2026-03-06T10:00:00Z",
                "total_imported": 10,
            },
        }
        tmp_state_file.write_text(json.dumps(data))
        state = ImportState(str(tmp_state_file))
        assert state.indicators.last_marker == "12345.xyz"
        assert state.reports.last_timestamp == 1709712000
        assert state.actors.total_imported == 10

    def test_corrupted_file_starts_fresh(self, tmp_state_file):
        tmp_state_file.write_text("not valid json{{{")
        state = ImportState(str(tmp_state_file))
        assert state.indicators.last_marker is None
