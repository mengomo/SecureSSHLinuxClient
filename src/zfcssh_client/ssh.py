from __future__ import annotations

import subprocess

from zfcssh_client.paths import ClientPaths


def build_ssh_command(
    *,
    target: str,
    paths: ClientPaths,
    remote_command: list[str] | None = None,
) -> list[str]:
    command = [
        "ssh",
        "-i",
        str(paths.user_key_path),
        "-o",
        f"CertificateFile={paths.user_cert_path}",
        "-o",
        f"UserKnownHostsFile={paths.known_hosts_path}",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "IdentitiesOnly=yes",
        target,
    ]
    if remote_command:
        command.extend(remote_command)
    return command


def run_ssh(
    *,
    target: str,
    paths: ClientPaths,
    remote_command: list[str] | None = None,
) -> int:
    return subprocess.call(build_ssh_command(target=target, paths=paths, remote_command=remote_command))
