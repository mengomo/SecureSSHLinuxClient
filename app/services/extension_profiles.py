"""SSH certificate extension profiles mapped to ZF product lifecycle stages.

Each lifecycle stage defines which SSH extensions and critical options are
embedded into user certificates.  The ``resolve_profile`` helper merges a
named profile with optional caller overrides, and ``build_keygen_options``
translates the result into ``-O`` flags for ``ssh-keygen -s``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.utils.validators import api_error

# ── known SSH certificate extensions ────────────────────────────────────────
KNOWN_EXTENSIONS = frozenset(
    {
        "permit-pty",
        "permit-port-forwarding",
        "permit-agent-forwarding",
        "permit-X11-forwarding",
        "permit-user-rc",
        "no-touch-required",
    }
)

# ── known critical-option keys ──────────────────────────────────────────────
KNOWN_CRITICAL_OPTION_KEYS = frozenset(
    {
        "force-command",
        "source-address",
        "verify-required",
    }
)


# ── data structures ─────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CertificatePermissions:
    """Resolved set of extensions and critical options for a certificate."""

    extensions: List[str] = field(default_factory=list)
    critical_options: Dict[str, str] = field(default_factory=dict)


# ── built-in lifecycle profiles ─────────────────────────────────────────────
BUILTIN_PROFILES: Dict[str, CertificatePermissions] = {
    # ZF Production – production line setup & flash
    "zf_production": CertificatePermissions(
        extensions=["permit-pty"],
        critical_options={},
    ),
    # Development – debug & development access
    "development": CertificatePermissions(
        extensions=["permit-pty", "permit-port-forwarding", "permit-agent-forwarding"],
        critical_options={},
    ),
    # OEM Production – OEM partner production access
    "oem_production": CertificatePermissions(
        extensions=["permit-pty"],
        critical_options={},
    ),
    # Field Operation (DEFAULT) – standard field diagnostics
    "field_operation": CertificatePermissions(
        extensions=["permit-pty", "permit-port-forwarding"],
        critical_options={},
    ),
    # Claims / Warranty – read-only diagnostic access
    "claims_warranty": CertificatePermissions(
        extensions=["permit-pty"],
        critical_options={},
    ),
    # End of Life – decommission & data wipe
    "end_of_life": CertificatePermissions(
        extensions=["permit-pty"],
        critical_options={},
    ),
}

PROFILE_NAMES = frozenset(BUILTIN_PROFILES.keys()) | {"custom"}

# ── diagnostic role → allowed profiles ──────────────────────────────────────
ROLE_ALLOWED_PROFILES: Dict[str, frozenset] = {
    "dev": frozenset({"development", "zf_production"}),
    "prod": frozenset({"zf_production", "oem_production", "field_operation", "end_of_life"}),
    "claims": frozenset({"claims_warranty", "field_operation"}),
    "OEMprod": frozenset({"oem_production", "field_operation"}),
    "admin": frozenset(PROFILE_NAMES),
    # server role is for host certs only – no user profiles
    "server": frozenset(),
}


def check_role_profile_access(role: str, profile: str) -> None:
    """Raise 403 if *role* may not issue certificates with *profile*."""
    allowed = ROLE_ALLOWED_PROFILES.get(role, frozenset())
    if profile not in allowed:
        raise api_error(
            403,
            "PROFILE_FORBIDDEN",
            f"Role '{role}' is not allowed to issue profile '{profile}'",
        )


def resolve_profile(
    *,
    profile_name: Optional[str],
    default_profile: str,
    extensions_override: Optional[List[str]] = None,
    critical_options_override: Optional[Dict[str, str]] = None,
    source_address: Optional[str] = None,
    force_command: Optional[str] = None,
) -> CertificatePermissions:
    """Resolve a lifecycle profile, merging overrides and convenience fields.

    Parameters
    ----------
    profile_name:
        Name of a built-in profile or ``"custom"``.  Falls back to
        *default_profile* when ``None``.
    default_profile:
        The server-configured default (e.g. ``"field_operation"``).
    extensions_override / critical_options_override:
        Only honoured for the ``"custom"`` profile.
    source_address:
        Convenience shorthand – added as ``source-address`` critical option
        for any profile.
    force_command:
        Convenience shorthand – added as ``force-command`` critical option
        for any profile.
    """
    name = profile_name or default_profile

    if name not in PROFILE_NAMES:
        raise api_error(
            422,
            "PROFILE_UNKNOWN",
            f"Unknown profile: {name}. Allowed: {', '.join(sorted(PROFILE_NAMES))}",
        )

    if name == "custom":
        extensions = list(extensions_override or [])
        critical_options = dict(critical_options_override or {})
    else:
        base = BUILTIN_PROFILES[name]
        extensions = list(base.extensions)
        critical_options = dict(base.critical_options)

    # convenience overrides applicable to every profile
    if source_address:
        critical_options["source-address"] = source_address
    if force_command:
        critical_options["force-command"] = force_command

    return CertificatePermissions(extensions=extensions, critical_options=critical_options)


def build_keygen_options(permissions: CertificatePermissions) -> List[str]:
    """Convert *permissions* into ``ssh-keygen -O`` flag pairs.

    Strategy: emit ``-O clear`` first to strip all default extensions, then
    explicitly re-add the desired ones.  This ensures deny-by-default.
    """
    flags: List[str] = ["-O", "clear"]

    for ext in permissions.extensions:
        flags.extend(["-O", f"extension:{ext}"])

    for key, value in permissions.critical_options.items():
        if value:
            flags.extend(["-O", f"critical:{key}={value}"])
        else:
            # boolean critical option (e.g. verify-required)
            flags.extend(["-O", f"critical:{key}"])

    return flags
