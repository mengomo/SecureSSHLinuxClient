from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from zfcssh_client.broker import BrokerClient, BrokerError
from zfcssh_client.bundle import BundleError, import_bundle, load_installed_bundle
from zfcssh_client.certificates import (
    CertificateError,
    ensure_ssh_tools,
    ensure_user_key,
    inspect_installed_certificate,
    install_host_ca,
    install_user_certificate,
    load_public_key,
    needs_renewal,
)
from zfcssh_client.logging_utils import configure_logging
from zfcssh_client.paths import default_paths, ensure_directories
from zfcssh_client.ssh import run_ssh

LOGGER = logging.getLogger("zfcssh.client")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zfcssh")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    bundle_parser = subparsers.add_parser("bundle")
    bundle_subparsers = bundle_parser.add_subparsers(dest="bundle_command", required=True)
    bundle_import_parser = bundle_subparsers.add_parser("import")
    bundle_import_parser.add_argument("bundle_path", type=Path)

    enroll_parser = subparsers.add_parser("enroll")
    enroll_parser.add_argument("--profile")
    enroll_parser.add_argument("--principal", action="append", dest="principals")
    enroll_parser.add_argument("--ttl")

    renew_parser = subparsers.add_parser("renew")
    renew_parser.add_argument("--force", action="store_true")
    renew_parser.add_argument("--if-needed", action="store_true")
    renew_parser.add_argument("--profile")
    renew_parser.add_argument("--principal", action="append", dest="principals")

    subparsers.add_parser("status")
    subparsers.add_parser("verify")

    ssh_parser = subparsers.add_parser("ssh")
    ssh_parser.add_argument("target")
    ssh_parser.add_argument("remote_command", nargs=argparse.REMAINDER)
    ssh_parser.add_argument("--skip-renew", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    paths = default_paths()
    ensure_directories(paths)
    configure_logging(paths.log_path, verbose=args.verbose)

    try:
        if args.command == "bundle" and args.bundle_command == "import":
            bundle = import_bundle(args.bundle_path, paths)
            print(f"Imported bundle '{bundle.bundle_id}' for broker {bundle.broker_url}")
            return 0
        if args.command == "status":
            return _status(paths)
        if args.command == "verify":
            return _verify(paths)
        if args.command == "enroll":
            _enroll(paths, profile=args.profile, principals=args.principals, ttl=args.ttl)
            return 0
        if args.command == "renew":
            return _renew(
                paths,
                force=args.force,
                if_needed=args.if_needed,
                profile=args.profile,
                principals=args.principals,
            )
        if args.command == "ssh":
            return _ssh(paths, target=args.target, remote_command=args.remote_command, skip_renew=args.skip_renew)
    except (BundleError, BrokerError, CertificateError, FileNotFoundError) as exc:
        LOGGER.error("command_failed error=%s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def _status(paths) -> int:
    bundle = load_installed_bundle(paths)
    certificate = inspect_installed_certificate(paths)
    payload = {
        "bundle_id": bundle.bundle_id,
        "broker_url": bundle.broker_url,
        "key_path": str(paths.user_key_path),
        "certificate_path": str(paths.user_cert_path),
        "host_ca_path": str(paths.host_ca_path),
        "certificate_present": certificate is not None,
        "certificate_principals": certificate.principals if certificate else [],
        "certificate_valid_before": certificate.valid_before if certificate else None,
        "renewal_needed": needs_renewal(certificate) if certificate else True,
    }
    print(json.dumps(payload, indent=2))
    return 0


def _verify(paths) -> int:
    bundle = load_installed_bundle(paths)
    ensure_ssh_tools()
    ensure_user_key(paths, comment=bundle.key_id)
    certificate = inspect_installed_certificate(paths)
    if certificate is None:
        raise CertificateError("No installed SSH user certificate")
    if paths.host_ca_path.read_text(encoding="utf-8").strip() == "":
        raise CertificateError("Host CA trust file is empty")
    print("Verification passed")
    return 0


def _enroll(paths, *, profile: str | None, principals: list[str] | None, ttl: str | None) -> None:
    bundle = load_installed_bundle(paths)
    selected_profile = profile or bundle.default_profile
    if selected_profile not in bundle.allowed_profiles:
        raise BundleError(f"Profile '{selected_profile}' is not permitted by the imported bundle")
    ensure_ssh_tools()
    ensure_user_key(paths, comment=bundle.key_id)
    client = BrokerClient(bundle)
    host_ca_public_key = client.get_host_ca_public_key()
    install_host_ca(paths, host_patterns=bundle.host_patterns, public_key=host_ca_public_key)
    public_key = load_public_key(paths)
    certificate = client.request_user_certificate(
        public_key=public_key,
        key_id=bundle.key_id,
        principals=principals or bundle.default_principals,
        profile=selected_profile,
        ttl=ttl,
    )
    install_user_certificate(paths, certificate)
    LOGGER.info("enrollment_complete profile=%s principals=%s", selected_profile, principals or bundle.default_principals)
    print(f"Installed SSH certificate for profile '{selected_profile}'")


def _renew(
    paths,
    *,
    force: bool,
    if_needed: bool,
    profile: str | None,
    principals: list[str] | None,
) -> int:
    certificate = inspect_installed_certificate(paths)
    if if_needed and not force and not needs_renewal(certificate):
        print("Certificate is still outside the renewal window")
        return 0
    _enroll(paths, profile=profile, principals=principals, ttl=None)
    return 0


def _ssh(paths, *, target: str, remote_command: list[str], skip_renew: bool) -> int:
    if not skip_renew:
        _renew(paths, force=False, if_needed=True, profile=None, principals=None)
    return run_ssh(
        target=target,
        paths=paths,
        remote_command=remote_command if remote_command else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
