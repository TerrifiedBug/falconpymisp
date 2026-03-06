import pytest
from src.crowdstrike.models import (
    CSIndicator, CSReport, CSActor,
    CS_TO_MISP_TYPE, cs_type_to_misp_type, cs_type_to_misp_category,
)


class TestCSToMISPTypeMapping:
    def test_hash_md5_maps_to_md5(self):
        assert cs_type_to_misp_type("hash_md5") == "md5"

    def test_domain_maps_to_domain(self):
        assert cs_type_to_misp_type("domain") == "domain"

    def test_ip_address_maps_to_ip_dst(self):
        assert cs_type_to_misp_type("ip_address") == "ip-dst"

    def test_url_maps_to_url(self):
        assert cs_type_to_misp_type("url") == "url"

    def test_unknown_type_returns_none(self):
        assert cs_type_to_misp_type("unknown_type_xyz") is None

    def test_all_mapped_types_have_categories(self):
        for cs_type in CS_TO_MISP_TYPE:
            assert cs_type_to_misp_category(cs_type) is not None


class TestCSIndicator:
    def test_from_api_response(self):
        raw = {
            "id": "ind_123", "indicator": "evil.com", "type": "domain",
            "malicious_confidence": "high", "published_date": 1709712000,
            "last_updated": 1709712000, "_marker": "1709712000.abc",
            "actors": ["FANCY BEAR"], "malware_families": ["njRAT"],
            "kill_chains": ["C0005"],
            "labels": [{"name": "MaliciousConfidence/High"}],
        }
        ind = CSIndicator.from_api(raw)
        assert ind.value == "evil.com"
        assert ind.cs_type == "domain"
        assert ind.malicious_confidence == "high"
        assert ind.marker == "1709712000.abc"
        assert "FANCY BEAR" in ind.actors
        assert "njRAT" in ind.malware_families


class TestCSReport:
    def test_from_api_response(self):
        raw = {
            "id": 12345, "name": "Test Report", "description": "A test report",
            "short_description": "Short desc", "created_date": 1709712000,
            "last_modified_date": 1709712000,
            "sub_type": {"name": "Intelligence Report"},
            "target_industries": [{"value": "Finance"}],
            "target_countries": [{"value": "United States"}],
            "actors": [{"name": "FANCY BEAR", "slug": "fancy-bear"}],
            "malware": [{"family_name": "njRAT"}],
            "kill_chains": [{"rich_text_name": "Reconnaissance"}],
        }
        report = CSReport.from_api(raw)
        assert report.name == "Test Report"
        assert report.report_type == "Intelligence Report"
        assert report.created_date == 1709712000


class TestCSActor:
    def test_from_api_response(self):
        raw = {
            "id": 456, "name": "FANCY BEAR", "description": "Russian threat actor",
            "short_description": "APT28", "created_date": 1709712000,
            "last_modified_date": 1709712000, "first_activity_date": 1609459200,
            "motivations": [{"value": "Espionage"}],
            "target_industries": [{"value": "Government"}],
            "target_countries": [{"value": "United States"}],
            "kill_chains": [{"rich_text_name": "Delivery"}],
        }
        actor = CSActor.from_api(raw)
        assert actor.name == "FANCY BEAR"
        assert "Espionage" in actor.motivations
