from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from zfcssh_client.models import InstalledBundle, MtlsMaterial
from zfcssh_client.paths import ClientPaths, ensure_directories


class BundleError(ValueError):
    pass


def import_bundle(bundle_path: Path, paths: ClientPaths) -> InstalledBundle:
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    ensure_directories(paths)

    bundle_id = _required_text(payload, "bundle_id")
    broker_url = _validate_broker_url(_required_text(payload, "broker_url"))
    mtls = payload.get("mtls")
    if not isinstance(mtls, dict):
        raise BundleError("mtls must be an object")

    client_certificate = _resolve_pem_value(
        bundle_path,
        mtls,
        inline_key="client_certificate_pem",
        path_key="client_certificate_path",
    )
    client_key = _resolve_pem_value(
        bundle_path,
        mtls,
        inline_key="client_key_pem",
        path_key="client_key_path",
    )
    ca_certificate = _resolve_optional_pem_value(
        bundle_path,
        mtls,
        inline_key="ca_certificate_pem",
        path_key="ca_certificate_path",
    )

    paths.client_certificate_path.write_text(client_certificate, encoding="utf-8")
    paths.client_key_path.write_text(client_key, encoding="utf-8")
    paths.client_certificate_path.chmod(0o600)
    paths.client_key_path.chmod(0o600)

    ca_path: Path | None = None
    if ca_certificate:
        paths.ca_certificate_path.write_text(ca_certificate, encoding="utf-8")
        paths.ca_certificate_path.chmod(0o600)
        ca_path = paths.ca_certificate_path
    elif paths.ca_certificate_path.exists():
        paths.ca_certificate_path.unlink()

    ssh = payload.get("ssh")
    if not isinstance(ssh, dict):
        raise BundleError("ssh must be an object")

    host_patterns = _validate_string_list(ssh.get("host_patterns"), "ssh.host_patterns")
    default_principals = _validate_string_list(
        ssh.get("default_principals"), "ssh.default_principals"
    )
    default_profile = _required_text(ssh, "default_profile", prefix="ssh.")
    allowed_profiles = _validate_string_list(
        ssh.get("allowed_profiles") or [default_profile], "ssh.allowed_profiles"
    )
    if default_profile not in allowed_profiles:
        raise BundleError("ssh.default_profile must be listed in ssh.allowed_profiles")

    identity = payload.get("identity") if isinstance(payload.get("identity"), dict) else {}
    requester = _required_text(identity or {"requester": bundle_id}, "requester", prefix="identity.")
    reason = identity.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise BundleError("identity.reason must be a string")

    installed = InstalledBundle(
        bundle_id=bundle_id,
        broker_url=broker_url,
        mtls=MtlsMaterial(
            client_certificate_path=paths.client_certificate_path,
            client_key_path=paths.client_key_path,
            ca_certificate_path=ca_path,
        ),
        host_patterns=host_patterns,
        default_principals=default_principals,
        default_profile=default_profile,
        allowed_profiles=allowed_profiles,
        key_id=str(ssh.get("key_id") or bundle_id),
        requester=requester,
        reason=reason,
    )
    paths.bundle_metadata_path.write_text(
        json.dumps(_bundle_to_dict(installed), indent=2) + "\n",
        encoding="utf-8",
    )
    paths.bundle_metadata_path.chmod(0o600)
    return installed


def load_installed_bundle(paths: ClientPaths) -> InstalledBundle:
    if not paths.bundle_metadata_path.is_file():
        raise BundleError("No bundle imported. Run 'zfcssh bundle import <bundle.json>' first")
    payload = json.loads(paths.bundle_metadata_path.read_text(encoding="utf-8"))
    mtls_payload = payload["mtls"]
    ca_path = mtls_payload.get("ca_certificate_path")
    return InstalledBundle(
        bundle_id=payload["bundle_id"],
        broker_url=payload["broker_url"],
        mtls=MtlsMaterial(
            client_certificate_path=Path(mtls_payload["client_certificate_path"]),
            client_key_path=Path(mtls_payload["client_key_path"]),
            ca_certificate_path=Path(ca_path) if ca_path else None,
        ),
        host_patterns=list(payload["host_patterns"]),
        default_principals=list(payload["default_principals"]),
        default_profile=payload["default_profile"],
        allowed_profiles=list(payload["allowed_profiles"]),
        key_id=payload["key_id"],
        requester=payload["requester"],
        reason=payload.get("reason"),
    )


def _bundle_to_dict(bundle: InstalledBundle) -> dict[str, Any]:
    return {
        "bundle_id": bundle.bundle_id,
        "broker_url": bundle.broker_url,
        "mtls": {
            "client_certificate_path": str(bundle.mtls.client_certificate_path),
            "client_key_path": str(bundle.mtls.client_key_path),
            "ca_certificate_path": str(bundle.mtls.ca_certificate_path)
            if bundle.mtls.ca_certificate_path
            else None,
        },
        "host_patterns": bundle.host_patterns,
        "default_principals": bundle.default_principals,
        "default_profile": bundle.default_profile,
        "allowed_profiles": bundle.allowed_profiles,
        "key_id": bundle.key_id,
        "requester": bundle.requester,
        "reason": bundle.reason,
    }


def _required_text(payload: dict[str, Any], key: str, *, prefix: str = "") -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BundleError(f"{prefix}{key} is required")
    return value.strip()


def _validate_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise BundleError(f"{label} must be a non-empty array")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise BundleError(f"{label} must only contain non-empty strings")
        stripped = item.strip()
        if stripped not in normalized:
            normalized.append(stripped)
    return normalized


def _validate_broker_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise BundleError("broker_url must be an https URL")
    return value


def _resolve_pem_value(
    bundle_path: Path,
    payload: dict[str, Any],
    *,
    inline_key: str,
    path_key: str,
) -> str:
    inline = payload.get(inline_key)
    path_value = payload.get(path_key)
    if inline and path_value:
        raise BundleError(f"Only one of mtls.{inline_key} or mtls.{path_key} may be set")
    if isinstance(inline, str) and inline.strip():
        return inline.strip() + "\n"
    if isinstance(path_value, str) and path_value.strip():
        resolved = (bundle_path.parent / path_value).resolve()
        return resolved.read_text(encoding="utf-8")
    raise BundleError(f"One of mtls.{inline_key} or mtls.{path_key} is required")


def _resolve_optional_pem_value(
    bundle_path: Path,
    payload: dict[str, Any],
    *,
    inline_key: str,
    path_key: str,
) -> str | None:
    inline = payload.get(inline_key)
    path_value = payload.get(path_key)
    if inline and path_value:
        raise BundleError(f"Only one of mtls.{inline_key} or mtls.{path_key} may be set")
    if isinstance(inline, str) and inline.strip():
        return inline.strip() + "\n"
    if isinstance(path_value, str) and path_value.strip():
        resolved = (bundle_path.parent / path_value).resolve()
        return resolved.read_text(encoding="utf-8")
    return None
