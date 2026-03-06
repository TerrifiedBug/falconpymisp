from datetime import datetime, timezone
from typing import Optional

from pymisp import MISPEvent, MISPAttribute, MISPTag

from src.crowdstrike.models import CSIndicator, CSReport, CSActor, cs_type_to_misp_type, cs_type_to_misp_category


def _make_tag(name: str) -> MISPTag:
    tag = MISPTag()
    tag.name = name
    return tag


def _timestamp_to_date(ts: int) -> str:
    if ts <= 0:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def build_feed_event(indicator_type: str, org_uuid: str, tlp_tag: str, distribution: int = 0, publish: bool = False) -> MISPEvent:
    event = MISPEvent()
    event.info = f"CrowdStrike: {indicator_type.replace('_', ' ').title()} Indicators"
    event.distribution = distribution
    event.orgc_uuid = org_uuid
    event.analysis = 2
    event.threat_level_id = 2
    event.add_tag(_make_tag(tlp_tag))
    event.add_tag(_make_tag("crowdstrike:feed"))
    event.published = publish
    return event


def build_indicator_attribute(indicator: CSIndicator, tags_config, mappings=None) -> Optional[MISPAttribute]:
    misp_type = cs_type_to_misp_type(indicator.cs_type)
    if misp_type is None:
        return None
    category = cs_type_to_misp_category(indicator.cs_type)
    attr = MISPAttribute()
    attr.type = misp_type
    attr.category = category
    attr.value = indicator.value
    attr.to_ids = True
    attr.comment = f"CrowdStrike confidence: {indicator.malicious_confidence}"
    if indicator.malicious_confidence:
        attr.add_tag(_make_tag(f"crowdstrike:confidence:{indicator.malicious_confidence}"))
    for actor in indicator.actors:
        attr.add_tag(_make_tag(f'crowdstrike:actor="{actor}"'))
    for family in indicator.malware_families:
        attr.add_tag(_make_tag(f'crowdstrike:malware-family="{family}"'))
    for threat_type in indicator.threat_types:
        if mappings:
            attr.add_tag(_make_tag(mappings.threat_type_tag(threat_type)))
        else:
            attr.add_tag(_make_tag(f'crowdstrike:threat-type="{threat_type}"'))
    if tags_config and getattr(tags_config, "kill_chain", False):
        for phase in indicator.kill_chains:
            normalized = mappings.kill_chain(phase) if mappings else phase
            attr.add_tag(_make_tag(f'kill-chain:phase="{normalized}"'))
    return attr


def build_report_event(report: CSReport, org_uuid: str, tlp_tag: str, distribution: int = 0, publish: bool = False) -> MISPEvent:
    event = MISPEvent()
    event.info = report.name
    event.date = _timestamp_to_date(report.created_date)
    event.distribution = distribution
    event.orgc_uuid = org_uuid
    event.analysis = 2
    event.threat_level_id = 2
    event.add_tag(_make_tag(tlp_tag))
    event.add_tag(_make_tag(f"crowdstrike:report-type:{report.report_type}"))
    if report.description:
        attr = MISPAttribute()
        attr.type = "text"
        attr.category = "External analysis"
        attr.value = report.short_description or report.description[:500]
        attr.to_ids = False
        attr.comment = "CrowdStrike report description"
        event.add_attribute(**attr)
    for industry in report.target_industries:
        event.add_tag(_make_tag(f"crowdstrike:target-industry:{industry}"))
    for country in report.target_countries:
        event.add_tag(_make_tag(f"crowdstrike:target-country:{country}"))
    for actor in report.actors:
        event.add_tag(_make_tag(f"crowdstrike:actor:{actor}"))
    event.published = publish
    return event


def build_actor_event(actor: CSActor, org_uuid: str, tlp_tag: str, distribution: int = 0, publish: bool = False) -> MISPEvent:
    event = MISPEvent()
    event.info = f"CrowdStrike Actor: {actor.name}"
    event.date = _timestamp_to_date(actor.created_date)
    event.distribution = distribution
    event.orgc_uuid = org_uuid
    event.analysis = 2
    event.threat_level_id = 2
    event.add_tag(_make_tag(tlp_tag))
    event.add_tag(_make_tag("crowdstrike:actor"))
    for motivation in actor.motivations:
        event.add_tag(_make_tag(f"crowdstrike:motivation:{motivation}"))
    if actor.description:
        attr = MISPAttribute()
        attr.type = "text"
        attr.category = "External analysis"
        attr.value = actor.short_description or actor.description[:500]
        attr.to_ids = False
        attr.comment = f"CrowdStrike actor: {actor.name}"
        event.add_attribute(**attr)
    event.published = publish
    return event
