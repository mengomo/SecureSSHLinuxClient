import base64
import ipaddress
import re
from typing import Dict, List, Literal, Optional

from fastapi import HTTPException, status

from app.config import Settings

SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}
TTL_PATTERN = re.compile(r"^(?P<value>\d+)(?P<unit>[mhd])$")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:@/-]{1,128}$")


def api_error(
    status_code: int, error_code: str, message: str, details: Optional[Dict] = None
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"error_code": error_code, "message": message, "details": details},
    )


def validate_key_id(key_id: str) -> str:
    if not KEY_ID_PATTERN.fullmatch(key_id):
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "KEY_ID_INVALID",
            "key_id contains unsupported characters",
        )
    return key_id


def validate_ssh_public_key(public_key: str) -> str:
    parts = public_key.strip().split()
    if len(parts) < 2 or len(parts) > 3:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "PUBLIC_KEY_INVALID",
            "public_key must be a valid OpenSSH public key line",
        )
    key_type, key_material = parts[0], parts[1]
    if key_type not in SSH_KEY_TYPES:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "PUBLIC_KEY_INVALID",
            f"Unsupported key type: {key_type}",
        )
    try:
        base64.b64decode(key_material.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "PUBLIC_KEY_INVALID",
            "public_key base64 payload is invalid",
        ) from exc
    return public_key.strip()


def normalize_ttl(
    ttl: Optional[str],
    *,
    default_hours: int,
    max_hours: int,
    cert_type: Literal["user", "host"],
) -> str:
    if ttl is None or ttl == "":
        ttl = f"{default_hours}h"
    match = TTL_PATTERN.fullmatch(ttl)
    if not match:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "TTL_INVALID",
            "ttl must look like 30m, 12h, or 7d",
        )
    value = int(match.group("value"))
    unit = match.group("unit")
    ttl_hours = value / 60 if unit == "m" else value if unit == "h" else value * 24
    if ttl_hours <= 0:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "TTL_INVALID",
            "ttl must be positive",
        )
    if ttl_hours > max_hours:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "TTL_TOO_LARGE",
            f"{cert_type} ttl exceeds max allowed {max_hours}h",
        )
    return ttl


def validate_user_principals(requested: Optional[List[str]], settings: Settings) -> List[str]:
    allowed = set(settings.user_allowed_principal_list)
    principals = requested or settings.user_allowed_principal_list
    normalized: List[str] = []
    for principal in principals:
        if principal not in allowed:
            raise api_error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "PRINCIPAL_NOT_ALLOWED",
                f"User principal {principal} is not allowed",
            )
        if principal not in normalized:
            normalized.append(principal)
    if not normalized:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "PRINCIPAL_REQUIRED",
            "At least one user principal is required",
        )
    return normalized


def validate_host_principals(requested: List[str]) -> List[str]:
    if not requested:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "PRINCIPAL_REQUIRED",
            "Host principals cannot be empty",
        )
    normalized: List[str] = []
    for principal in requested:
        value = principal.strip()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
            normalized.append(value)
            continue
        except ValueError:
            pass
        if HOSTNAME_PATTERN.fullmatch(value):
            normalized.append(value.lower())
            continue
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "PRINCIPAL_INVALID",
            f"Host principal {principal} is not a valid IP or hostname",
        )
    if not normalized:
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "PRINCIPAL_REQUIRED",
            "Host principals cannot be empty",
        )
    return list(dict.fromkeys(normalized))


# ── extension and critical-option validators ─────────────────────────────────

def validate_extensions(extensions: List[str]) -> List[str]:
    """Whitelist-check SSH certificate extensions."""
    from app.services.extension_profiles import KNOWN_EXTENSIONS

    normalized: List[str] = []
    for ext in extensions:
        ext = ext.strip()
        if ext not in KNOWN_EXTENSIONS:
            raise api_error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "EXTENSION_UNKNOWN",
                f"Unknown SSH extension: {ext}. "
                f"Allowed: {', '.join(sorted(KNOWN_EXTENSIONS))}",
            )
        if ext not in normalized:
            normalized.append(ext)
    return normalized


def validate_critical_options(options: Dict[str, str]) -> Dict[str, str]:
    """Validate critical-option keys and value formats."""
    from app.services.extension_profiles import KNOWN_CRITICAL_OPTION_KEYS

    validated: Dict[str, str] = {}
    for key, value in options.items():
        key = key.strip()
        if key not in KNOWN_CRITICAL_OPTION_KEYS:
            raise api_error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "CRITICAL_OPTION_UNKNOWN",
                f"Unknown critical option: {key}. "
                f"Allowed: {', '.join(sorted(KNOWN_CRITICAL_OPTION_KEYS))}",
            )
        if key == "source-address":
            _validate_source_address(value)
        elif key == "force-command":
            if not value or not value.strip():
                raise api_error(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "CRITICAL_OPTION_INVALID",
                    "force-command value must be non-empty",
                )
        validated[key] = value.strip()
    return validated


def _validate_source_address(value: str) -> None:
    """Validate that *value* is a comma-separated list of valid CIDRs or IPs."""
    if not value or not value.strip():
        raise api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "CRITICAL_OPTION_INVALID",
            "source-address value must be non-empty",
        )
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                ipaddress.ip_network(part, strict=False)
            else:
                ipaddress.ip_address(part)
        except ValueError:
            raise api_error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "CRITICAL_OPTION_INVALID",
                f"source-address contains invalid CIDR or IP: {part}",
            )


def validate_source_address(value: str) -> str:
    """Validate a source-address CIDR string."""
    _validate_source_address(value)
    return value.strip()

