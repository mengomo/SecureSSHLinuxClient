from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class MtlsMaterial:
    client_certificate_path: Path
    client_key_path: Path
    ca_certificate_path: Optional[Path]


@dataclass(frozen=True)
class InstalledBundle:
    bundle_id: str
    broker_url: str
    mtls: MtlsMaterial
    host_patterns: list[str]
    default_principals: list[str]
    default_profile: str
    allowed_profiles: list[str]
    key_id: str
    requester: str
    reason: Optional[str]


@dataclass(frozen=True)
class CertificateInfo:
    valid_after: str
    valid_before: str
    principals: list[str]
    raw_output: str
