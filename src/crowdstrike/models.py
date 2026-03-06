from dataclasses import dataclass, field
from typing import Optional


CS_TO_MISP_TYPE = {
    "hash_md5": "md5", "hash_sha256": "sha256", "hash_sha1": "sha1",
    "hash_imphash": "imphash", "domain": "domain", "ip_address": "ip-dst",
    "ip_address_block": "ip-dst", "url": "url", "email_address": "email-dst",
    "email_subject": "email-subject", "file_name": "filename", "filepath": "filename",
    "mutex_name": "mutex", "password": "text", "username": "text",
    "persona_name": "text", "bitcoin_address": "btc", "coin_address": "btc",
    "device_name": "text", "campaign_id": "campaign-id",
    "service_name": "windows-service-name", "registry": "regkey",
    "user_agent": "user-agent", "x509_serial": "x509-fingerprint-sha1",
    "x509_subject": "text", "port": "port",
}

CS_TO_MISP_CATEGORY = {
    "hash_md5": "Payload delivery", "hash_sha256": "Payload delivery",
    "hash_sha1": "Payload delivery", "hash_imphash": "Payload delivery",
    "domain": "Network activity", "ip_address": "Network activity",
    "ip_address_block": "Network activity", "url": "Network activity",
    "email_address": "Payload delivery", "email_subject": "Payload delivery",
    "file_name": "Payload delivery", "filepath": "Payload delivery",
    "mutex_name": "Artifacts dropped", "password": "Payload delivery",
    "username": "Payload delivery", "persona_name": "Attribution",
    "bitcoin_address": "Financial fraud", "coin_address": "Financial fraud",
    "device_name": "Targeting data", "campaign_id": "Attribution",
    "service_name": "Artifacts dropped", "registry": "Persistence mechanism",
    "user_agent": "Network activity", "x509_serial": "Network activity",
    "x509_subject": "Network activity", "port": "Network activity",
}


def cs_type_to_misp_type(cs_type: str) -> Optional[str]:
    return CS_TO_MISP_TYPE.get(cs_type)


def cs_type_to_misp_category(cs_type: str) -> Optional[str]:
    return CS_TO_MISP_CATEGORY.get(cs_type)


@dataclass
class CSIndicator:
    id: str
    value: str
    cs_type: str
    malicious_confidence: str
    published_date: int
    last_updated: int
    marker: str
    actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    kill_chains: list[str] = field(default_factory=list)
    threat_types: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)

    @classmethod
    def from_api(cls, raw: dict) -> "CSIndicator":
        return cls(
            id=str(raw.get("id", "")),
            value=raw.get("indicator", ""),
            cs_type=raw.get("type", ""),
            malicious_confidence=raw.get("malicious_confidence", "unverified"),
            published_date=raw.get("published_date", 0),
            last_updated=raw.get("last_updated", 0),
            marker=raw.get("_marker", ""),
            actors=raw.get("actors", []) or [],
            malware_families=raw.get("malware_families", []) or [],
            kill_chains=raw.get("kill_chains", []) or [],
            threat_types=raw.get("threat_types", []) or [],
            labels=[lb.get("name", "") for lb in (raw.get("labels") or [])],
        )


@dataclass
class CSReport:
    id: int
    name: str
    description: str
    short_description: str
    created_date: int
    last_modified_date: int
    report_type: str
    target_industries: list[str] = field(default_factory=list)
    target_countries: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    kill_chains: list[str] = field(default_factory=list)

    @classmethod
    def from_api(cls, raw: dict) -> "CSReport":
        return cls(
            id=raw.get("id", 0), name=raw.get("name", ""),
            description=raw.get("description", ""),
            short_description=raw.get("short_description", ""),
            created_date=raw.get("created_date", 0),
            last_modified_date=raw.get("last_modified_date", 0),
            report_type=(raw.get("sub_type") or {}).get("name", ""),
            target_industries=[i.get("value", "") for i in (raw.get("target_industries") or [])],
            target_countries=[c.get("value", "") for c in (raw.get("target_countries") or [])],
            actors=[a.get("name", "") for a in (raw.get("actors") or [])],
            malware_families=[m.get("family_name", "") for m in (raw.get("malware") or [])],
            kill_chains=[k.get("rich_text_name", "") for k in (raw.get("kill_chains") or [])],
        )


@dataclass
class CSActor:
    id: int
    name: str
    description: str
    short_description: str
    created_date: int
    last_modified_date: int
    first_activity_date: int
    motivations: list[str] = field(default_factory=list)
    target_industries: list[str] = field(default_factory=list)
    target_countries: list[str] = field(default_factory=list)
    kill_chains: list[str] = field(default_factory=list)

    @classmethod
    def from_api(cls, raw: dict) -> "CSActor":
        return cls(
            id=raw.get("id", 0), name=raw.get("name", ""),
            description=raw.get("description", ""),
            short_description=raw.get("short_description", ""),
            created_date=raw.get("created_date", 0),
            last_modified_date=raw.get("last_modified_date", 0),
            first_activity_date=raw.get("first_activity_date", 0),
            motivations=[m.get("value", "") for m in (raw.get("motivations") or [])],
            target_industries=[i.get("value", "") for i in (raw.get("target_industries") or [])],
            target_countries=[c.get("value", "") for c in (raw.get("target_countries") or [])],
            kill_chains=[k.get("rich_text_name", "") for k in (raw.get("kill_chains") or [])],
        )
