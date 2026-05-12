from __future__ import annotations

import logging
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from zfcssh_client.models import CertificateInfo
from zfcssh_client.paths import ClientPaths

LOGGER = logging.getLogger("zfcssh.client.certs")

MANAGED_KNOWN_HOSTS_BEGIN = "# >>> zfcssh managed host ca >>>"
MANAGED_KNOWN_HOSTS_END = "# <<< zfcssh managed host ca <<<"


class CertificateError(RuntimeError):
    pass


def ensure_ssh_tools() -> None:
    for command in ("ssh", "ssh-keygen"):
        if shutil.which(command) is None:
            raise CertificateError(f"{command} must be installed and available in PATH")


def ensure_user_key(paths: ClientPaths, *, comment: str) -> Path:
    if paths.user_key_path.is_file() and paths.user_key_path.with_suffix(".pub").is_file():
        return paths.user_key_path
    result = subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            comment,
            "-f",
            str(paths.user_key_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise CertificateError(f"ssh-keygen failed to create a user key: {result.stderr.strip()}")
    paths.user_key_path.chmod(0o600)
    paths.user_key_path.with_suffix(".pub").chmod(0o644)
    return paths.user_key_path


def load_public_key(paths: ClientPaths) -> str:
    public_key_path = paths.user_key_path.with_suffix(".pub")
    if not public_key_path.is_file():
        raise CertificateError(f"Missing public key: {public_key_path}")
    return public_key_path.read_text(encoding="utf-8").strip()


def install_user_certificate(paths: ClientPaths, certificate: str) -> None:
    paths.user_cert_path.write_text(certificate.strip() + "\n", encoding="utf-8")
    paths.user_cert_path.chmod(0o600)


def install_host_ca(paths: ClientPaths, *, host_patterns: list[str], public_key: str) -> None:
    paths.host_ca_path.write_text(public_key.strip() + "\n", encoding="utf-8")
    paths.host_ca_path.chmod(0o644)

    managed_lines = [MANAGED_KNOWN_HOSTS_BEGIN]
    managed_lines.extend(
        f"@cert-authority {pattern} {public_key.strip()}" for pattern in host_patterns
    )
    managed_lines.append(MANAGED_KNOWN_HOSTS_END)

    existing_lines = []
    if paths.known_hosts_path.is_file():
        existing_lines = paths.known_hosts_path.read_text(encoding="utf-8").splitlines()

    output_lines: list[str] = []
    skip = False
    for line in existing_lines:
        if line == MANAGED_KNOWN_HOSTS_BEGIN:
            skip = True
            continue
        if line == MANAGED_KNOWN_HOSTS_END:
            skip = False
            continue
        if not skip:
            output_lines.append(line)
    if output_lines and output_lines[-1] != "":
        output_lines.append("")
    output_lines.extend(managed_lines)
    paths.known_hosts_path.write_text("\n".join(output_lines).rstrip() + "\n", encoding="utf-8")
    paths.known_hosts_path.chmod(0o600)


def inspect_installed_certificate(paths: ClientPaths) -> CertificateInfo | None:
    if not paths.user_cert_path.is_file():
        return None
    result = subprocess.run(
        ["ssh-keygen", "-Lf", str(paths.user_cert_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise CertificateError(f"ssh-keygen failed to inspect certificate: {result.stderr.strip()}")
    return parse_inspection_output(result.stdout)


def parse_inspection_output(output: str) -> CertificateInfo:
    valid_after = ""
    valid_before = ""
    principals: list[str] = []
    in_principals = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("Valid: from "):
            valid_range = line[len("Valid: from ") :]
            if " to " not in valid_range:
                raise CertificateError("Certificate inspection output was missing validity information")
            valid_after, valid_before = valid_range.split(" to ", 1)
            in_principals = False
        elif line == "Principals:":
            in_principals = True
        elif in_principals and line:
            if line.endswith(":"):
                in_principals = False
            else:
                principals.append(line)
    if not valid_before:
        raise CertificateError("Certificate inspection output was incomplete")
    return CertificateInfo(
        valid_after=valid_after,
        valid_before=valid_before,
        principals=principals,
        raw_output=output.strip(),
    )


def needs_renewal(certificate: CertificateInfo | None, *, now: datetime | None = None) -> bool:
    if certificate is None:
        return True
    if certificate.valid_before == "forever":
        return False
    now = now or datetime.now(timezone.utc)
    valid_after = _parse_ssh_time(certificate.valid_after)
    valid_before = _parse_ssh_time(certificate.valid_before)
    lifetime = valid_before - valid_after
    renewal_window = max(timedelta(minutes=15), lifetime / 4)
    remaining = valid_before - now
    LOGGER.info(
        "certificate_renewal_check valid_before=%s remaining_seconds=%s renewal_window_seconds=%s",
        certificate.valid_before,
        int(remaining.total_seconds()),
        int(renewal_window.total_seconds()),
    )
    return remaining <= renewal_window


def _parse_ssh_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
