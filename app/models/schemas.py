from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class CallerInfo(BaseModel):
    requester: str = Field(..., min_length=1, max_length=128)
    source_ip: Optional[str] = Field(default=None, max_length=64)
    reason: Optional[str] = Field(default=None, max_length=256)


class CertPermissionOverrides(BaseModel):
    """Caller-specified extensions and critical options for the ``custom`` profile."""

    extensions: Optional[List[str]] = Field(
        default=None,
        description="SSH extensions, e.g. ['permit-pty', 'permit-port-forwarding']",
    )
    critical_options: Optional[Dict[str, str]] = Field(
        default=None,
        description="Critical options, e.g. {'force-command': '/usr/bin/rsync'}",
    )


class SignUserRequest(BaseModel):
    public_key: str = Field(..., min_length=32)
    key_id: str = Field(..., min_length=1, max_length=128)
    requested_principals: Optional[List[str]] = None
    ttl: Optional[str] = Field(default=None, description="Examples: 24h, 12h, 30m")
    caller: CallerInfo
    profile: Optional[str] = Field(
        default=None,
        description="Lifecycle profile: zf_production, development, oem_production, "
        "field_operation, claims_warranty, end_of_life, custom",
    )
    permissions: Optional[CertPermissionOverrides] = Field(
        default=None,
        description="Only used when profile is 'custom'",
    )
    source_address: Optional[str] = Field(
        default=None,
        description="CIDR for source-address critical option, e.g. '10.0.0.0/8'",
    )
    force_command: Optional[str] = Field(
        default=None,
        description="Forced command for automation certs",
    )


class SignHostRequest(BaseModel):
    public_key: str = Field(..., min_length=32)
    key_id: str = Field(..., min_length=1, max_length=128)
    requested_principals: List[str]
    ttl: Optional[str] = Field(default=None, description="Examples: 1095d, 8760h, 24h")
    caller: CallerInfo


class SignResponse(BaseModel):
    success: bool = True
    cert_type: Literal["user", "host"]
    key_id: str
    principals: List[str]
    ttl: str
    certificate: str
    idempotent_reused: bool = False
    profile: Optional[str] = None


class ErrorResponse(BaseModel):
    success: bool = False
    error_code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class VersionResponse(BaseModel):
    app_name: str
    version: str
    broker_bind: str
    public_base_url: str
    default_user_ttl_hours: int
    max_user_ttl_hours: int
    default_host_ttl_hours: int
    max_host_ttl_hours: int
    allowed_user_principals: List[str]
    default_user_profile: str


class HealthResponse(BaseModel):
    status: Literal["ok"]
    timestamp: datetime


class PubKeyResponse(BaseModel):
    key_type: Literal["user", "host"]
    public_key: str


class UiBootstrapResponse(BaseModel):
    app_name: str
    version: str
    broker_bind: str
    public_base_url: str
    allowed_user_principals: List[str]
    default_user_ttl_hours: int
    max_user_ttl_hours: int
    default_host_ttl_hours: int
    max_host_ttl_hours: int
    default_user_profile: str
    available_profiles: List[str]
    user_ca_pubkey_endpoint: str
    host_ca_pubkey_endpoint: str
    sign_user_endpoint: str
    sign_host_endpoint: str
    inspect_cert_endpoint: str
    example_caller: CallerInfo


class InspectCertRequest(BaseModel):
    certificate: str = Field(..., min_length=32)


class InspectCertResponse(BaseModel):
    cert_type: str
    key_id: str
    serial: str
    valid_after: str
    valid_before: str
    principals: List[str]
    critical_options: Dict[str, str] = Field(default_factory=dict)
    extensions: List[str] = Field(default_factory=list)
    signing_ca_fingerprint: str
    raw_output: str


class DemoPublicKeyResponse(BaseModel):
    key_type: str
    public_key: str
    comment: str
