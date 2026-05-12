import pytest
from fastapi import HTTPException

from app.services.extension_profiles import (
    BUILTIN_PROFILES,
    CertificatePermissions,
    PROFILE_NAMES,
    ROLE_ALLOWED_PROFILES,
    build_keygen_options,
    check_role_profile_access,
    resolve_profile,
)


# ── profile resolution ──────────────────────────────────────────────────────


def test_resolve_builtin_field_operation() -> None:
    perms = resolve_profile(profile_name="field_operation", default_profile="field_operation")
    assert perms.extensions == ["permit-pty", "permit-port-forwarding"]
    assert perms.critical_options == {}


def test_resolve_builtin_development() -> None:
    perms = resolve_profile(profile_name="development", default_profile="field_operation")
    assert "permit-agent-forwarding" in perms.extensions
    assert "permit-pty" in perms.extensions


def test_resolve_default_when_none() -> None:
    perms = resolve_profile(profile_name=None, default_profile="field_operation")
    assert perms == BUILTIN_PROFILES["field_operation"]


def test_resolve_custom_with_overrides() -> None:
    perms = resolve_profile(
        profile_name="custom",
        default_profile="field_operation",
        extensions_override=["permit-pty"],
        critical_options_override={"force-command": "/bin/true"},
    )
    assert perms.extensions == ["permit-pty"]
    assert perms.critical_options == {"force-command": "/bin/true"}


def test_resolve_unknown_profile_raises() -> None:
    with pytest.raises(HTTPException) as exc_info:
        resolve_profile(profile_name="nonexistent", default_profile="field_operation")
    assert exc_info.value.status_code == 422


def test_resolve_with_source_address() -> None:
    perms = resolve_profile(
        profile_name="zf_production",
        default_profile="field_operation",
        source_address="10.0.0.0/8",
    )
    assert perms.critical_options["source-address"] == "10.0.0.0/8"
    assert perms.extensions == ["permit-pty"]


def test_resolve_with_force_command() -> None:
    perms = resolve_profile(
        profile_name="claims_warranty",
        default_profile="field_operation",
        force_command="/usr/local/bin/diag-tool",
    )
    assert perms.critical_options["force-command"] == "/usr/local/bin/diag-tool"


# ── keygen option generation ────────────────────────────────────────────────


def test_build_keygen_options_minimal() -> None:
    perms = CertificatePermissions(extensions=["permit-pty"], critical_options={})
    flags = build_keygen_options(perms)
    assert flags == ["-O", "clear", "-O", "extension:permit-pty"]


def test_build_keygen_options_with_force_command() -> None:
    perms = CertificatePermissions(
        extensions=["permit-pty"],
        critical_options={"force-command": "/usr/bin/rsync"},
    )
    flags = build_keygen_options(perms)
    assert "-O" in flags
    assert "clear" in flags
    assert "extension:permit-pty" in flags
    assert "critical:force-command=/usr/bin/rsync" in flags


def test_build_keygen_options_with_source_address() -> None:
    perms = CertificatePermissions(
        extensions=["permit-pty", "permit-port-forwarding"],
        critical_options={"source-address": "192.168.0.0/16"},
    )
    flags = build_keygen_options(perms)
    assert "critical:source-address=192.168.0.0/16" in flags
    assert "extension:permit-pty" in flags
    assert "extension:permit-port-forwarding" in flags


# ── role → profile access control ───────────────────────────────────────────


def test_dev_role_can_sign_development() -> None:
    check_role_profile_access("dev", "development")  # should not raise


def test_dev_role_can_sign_zf_production() -> None:
    check_role_profile_access("dev", "zf_production")  # should not raise


def test_dev_role_cannot_sign_field_operation() -> None:
    with pytest.raises(HTTPException) as exc_info:
        check_role_profile_access("dev", "field_operation")
    assert exc_info.value.status_code == 403


def test_prod_role_can_sign_field_operation() -> None:
    check_role_profile_access("prod", "field_operation")  # should not raise


def test_prod_role_can_sign_end_of_life() -> None:
    check_role_profile_access("prod", "end_of_life")  # should not raise


def test_claims_role_can_sign_claims_warranty() -> None:
    check_role_profile_access("claims", "claims_warranty")  # should not raise


def test_claims_role_cannot_sign_development() -> None:
    with pytest.raises(HTTPException) as exc_info:
        check_role_profile_access("claims", "development")
    assert exc_info.value.status_code == 403


def test_oemprod_role_can_sign_oem_production() -> None:
    check_role_profile_access("OEMprod", "oem_production")  # should not raise


def test_admin_can_sign_all_profiles() -> None:
    for profile in PROFILE_NAMES:
        check_role_profile_access("admin", profile)  # should not raise


def test_server_role_cannot_sign_any_user_profile() -> None:
    for profile in BUILTIN_PROFILES:
        with pytest.raises(HTTPException):
            check_role_profile_access("server", profile)


# ── profile coverage ────────────────────────────────────────────────────────


def test_all_builtin_profiles_have_permit_pty() -> None:
    """Every lifecycle profile should grant at least permit-pty."""
    for name, perms in BUILTIN_PROFILES.items():
        assert "permit-pty" in perms.extensions, f"{name} is missing permit-pty"
