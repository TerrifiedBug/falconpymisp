import pytest
from src.misp.models import build_feed_event, build_indicator_attribute, build_report_event, build_actor_event
from src.crowdstrike.models import CSIndicator, CSReport, CSActor
from src.normalization import Mappings


class TestBuildFeedEvent:
    def test_creates_event_with_correct_info(self):
        event = build_feed_event(indicator_type="domain", org_uuid="test-uuid", tlp_tag="tlp:amber")
        assert "CrowdStrike" in event.info
        assert "domain" in event.info.lower()
        assert event.distribution == 0

    def test_has_tlp_tag(self):
        event = build_feed_event("domain", "test-uuid", "tlp:amber")
        tag_names = [t.name for t in event.tags]
        assert "tlp:amber" in tag_names


class TestBuildIndicatorAttribute:
    def test_creates_attribute_from_indicator(self):
        ind = CSIndicator(id="1", value="evil.com", cs_type="domain",
            malicious_confidence="high", published_date=0, last_updated=0, marker="")
        attr = build_indicator_attribute(ind, tags_config=None)
        assert attr.value == "evil.com"
        assert attr.type == "domain"
        assert attr.category == "Network activity"
        assert attr.to_ids is True

    def test_returns_none_for_unmapped_type(self):
        ind = CSIndicator(id="1", value="something", cs_type="unknown_xyz",
            malicious_confidence="high", published_date=0, last_updated=0, marker="")
        attr = build_indicator_attribute(ind, tags_config=None)
        assert attr is None


class TestBuildReportEvent:
    def test_creates_event_from_report(self):
        report = CSReport(id=1, name="Test Report", description="<p>Details</p>",
            short_description="Short", created_date=1709712000,
            last_modified_date=1709712000, report_type="Intelligence Report")
        event = build_report_event(report, org_uuid="test-uuid", tlp_tag="tlp:amber")
        assert event.info == "Test Report"
        assert event.distribution == 0


class TestBuildActorEvent:
    def test_creates_event_from_actor(self):
        actor = CSActor(id=1, name="FANCY BEAR", description="Russian threat actor",
            short_description="APT28", created_date=1709712000,
            last_modified_date=1709712000, first_activity_date=1609459200,
            motivations=["Espionage"])
        event = build_actor_event(actor, org_uuid="test-uuid", tlp_tag="tlp:amber")
        assert "FANCY BEAR" in event.info


class TestEventPublishing:
    def test_feed_event_published_when_true(self):
        event = build_feed_event("domain", "test-uuid", "tlp:amber", publish=True)
        assert event.published is True

    def test_feed_event_unpublished_when_false(self):
        event = build_feed_event("domain", "test-uuid", "tlp:amber", publish=False)
        assert event.published is False

    def test_report_event_published(self):
        report = CSReport(id=1, name="Test", description="", short_description="",
            created_date=0, last_modified_date=0, report_type="Alert")
        event = build_report_event(report, "test-uuid", "tlp:amber", publish=True)
        assert event.published is True

    def test_actor_event_published(self):
        actor = CSActor(id=1, name="TEST BEAR", description="", short_description="",
            created_date=0, last_modified_date=0, first_activity_date=0)
        event = build_actor_event(actor, "test-uuid", "tlp:amber", publish=True)
        assert event.published is True


class TestIndicatorEnrichedTagging:
    def _make_indicator(self, **kwargs):
        defaults = dict(id="1", value="evil.com", cs_type="domain",
            malicious_confidence="high", published_date=0, last_updated=0, marker="")
        defaults.update(kwargs)
        return CSIndicator(**defaults)

    def _make_mappings(self):
        return Mappings(
            threat_types={"RANSOMWARE": 'malware-type="Ransomware"'},
            kill_chain={"command_and_control": "command-control"},
        )

    def test_actor_tags_applied(self):
        ind = self._make_indicator(actors=["FANCY BEAR", "COZY BEAR"])
        attr = build_indicator_attribute(ind, tags_config=None)
        tag_names = [t.name for t in attr.tags]
        assert 'crowdstrike:actor="FANCY BEAR"' in tag_names
        assert 'crowdstrike:actor="COZY BEAR"' in tag_names

    def test_family_tags_applied(self):
        ind = self._make_indicator(malware_families=["Emotet"])
        attr = build_indicator_attribute(ind, tags_config=None)
        tag_names = [t.name for t in attr.tags]
        assert 'crowdstrike:malware-family="Emotet"' in tag_names

    def test_threat_type_tags_with_mappings(self):
        ind = self._make_indicator(threat_types=["RANSOMWARE"])
        mappings = self._make_mappings()
        attr = build_indicator_attribute(ind, tags_config=None, mappings=mappings)
        tag_names = [t.name for t in attr.tags]
        assert 'malware-type="Ransomware"' in tag_names

    def test_threat_type_fallback_without_mappings(self):
        ind = self._make_indicator(threat_types=["UNKNOWN_TYPE"])
        attr = build_indicator_attribute(ind, tags_config=None)
        tag_names = [t.name for t in attr.tags]
        assert 'crowdstrike:threat-type="UNKNOWN_TYPE"' in tag_names

    def test_kill_chain_tags_applied(self):
        ind = self._make_indicator(kill_chains=["command_and_control", "reconnaissance"])
        mappings = self._make_mappings()
        from src.config import TagsConfig
        tags_config = TagsConfig(kill_chain=True)
        attr = build_indicator_attribute(ind, tags_config=tags_config, mappings=mappings)
        tag_names = [t.name for t in attr.tags]
        assert 'kill-chain:phase="command-control"' in tag_names
        assert 'kill-chain:phase="reconnaissance"' in tag_names

    def test_kill_chain_tags_skipped_when_disabled(self):
        ind = self._make_indicator(kill_chains=["reconnaissance"])
        from src.config import TagsConfig
        tags_config = TagsConfig(kill_chain=False)
        attr = build_indicator_attribute(ind, tags_config=tags_config)
        tag_names = [t.name for t in attr.tags]
        assert not any("kill-chain" in t for t in tag_names)
