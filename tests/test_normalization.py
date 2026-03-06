import pytest
from pathlib import Path
from src.normalization import Mappings, load_mappings


@pytest.fixture
def mappings_file(tmp_path):
    content = """
threat_types:
  RANSOMWARE: 'malware-type="Ransomware"'
  PHISHING: 'incident-type="Phishing Activity"'

kill_chain:
  command_and_control: "command-control"
"""
    p = tmp_path / "mappings.yml"
    p.write_text(content)
    return str(p)


class TestLoadMappings:
    def test_loads_from_file(self, mappings_file):
        m = load_mappings(mappings_file)
        assert isinstance(m, Mappings)
        assert m.threat_type("RANSOMWARE") == 'malware-type="Ransomware"'

    def test_returns_empty_on_missing_file(self):
        m = load_mappings("/nonexistent/mappings.yml")
        assert m.threat_type("RANSOMWARE") is None

    def test_returns_empty_on_none_path(self):
        m = load_mappings(None)
        assert m.threat_type("RANSOMWARE") is None


class TestMappings:
    def test_threat_type_lookup(self, mappings_file):
        m = load_mappings(mappings_file)
        assert m.threat_type("RANSOMWARE") == 'malware-type="Ransomware"'
        assert m.threat_type("PHISHING") == 'incident-type="Phishing Activity"'

    def test_threat_type_case_insensitive(self, mappings_file):
        m = load_mappings(mappings_file)
        assert m.threat_type("ransomware") == 'malware-type="Ransomware"'

    def test_threat_type_returns_none_for_unknown(self, mappings_file):
        m = load_mappings(mappings_file)
        assert m.threat_type("UNKNOWN_TYPE") is None

    def test_kill_chain_lookup(self, mappings_file):
        m = load_mappings(mappings_file)
        assert m.kill_chain("command_and_control") == "command-control"

    def test_kill_chain_passthrough_unmapped(self, mappings_file):
        m = load_mappings(mappings_file)
        assert m.kill_chain("reconnaissance") == "reconnaissance"

    def test_threat_type_tag_with_mapped(self, mappings_file):
        m = load_mappings(mappings_file)
        assert m.threat_type_tag("RANSOMWARE") == 'malware-type="Ransomware"'

    def test_threat_type_tag_with_unmapped(self, mappings_file):
        m = load_mappings(mappings_file)
        assert m.threat_type_tag("UNKNOWN_XYZ") == 'crowdstrike:threat-type="UNKNOWN_XYZ"'
