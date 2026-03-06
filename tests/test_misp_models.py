import pytest
from src.misp.models import build_feed_event, build_indicator_attribute, build_report_event, build_actor_event
from src.crowdstrike.models import CSIndicator, CSReport, CSActor


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
