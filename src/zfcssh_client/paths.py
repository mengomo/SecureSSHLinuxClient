from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClientPaths:
    config_dir: Path
    mtls_dir: Path
    state_dir: Path
    ssh_dir: Path
    bundle_metadata_path: Path
    client_certificate_path: Path
    client_key_path: Path
    ca_certificate_path: Path
    user_key_path: Path
    user_cert_path: Path
    host_ca_path: Path
    known_hosts_path: Path
    log_path: Path


def default_paths(home: Path | None = None) -> ClientPaths:
    home = home or Path.home()
    config_dir = home / ".config" / "zfcssh"
    mtls_dir = config_dir / "mtls"
    state_dir = home / ".local" / "state" / "zfcssh"
    ssh_dir = home / ".ssh"
    return ClientPaths(
        config_dir=config_dir,
        mtls_dir=mtls_dir,
        state_dir=state_dir,
        ssh_dir=ssh_dir,
        bundle_metadata_path=config_dir / "bundle.json",
        client_certificate_path=mtls_dir / "client.crt",
        client_key_path=mtls_dir / "client.key",
        ca_certificate_path=mtls_dir / "ca.crt",
        user_key_path=ssh_dir / "zfcssh_id_ed25519",
        user_cert_path=ssh_dir / "zfcssh_id_ed25519-cert.pub",
        host_ca_path=ssh_dir / "zfcssh_host_ca.pub",
        known_hosts_path=ssh_dir / "known_hosts",
        log_path=state_dir / "client.log",
    )


def ensure_directories(paths: ClientPaths) -> None:
    for directory in (paths.config_dir, paths.mtls_dir, paths.state_dir, paths.ssh_dir):
        directory.mkdir(parents=True, exist_ok=True)
    paths.config_dir.chmod(0o700)
    paths.mtls_dir.chmod(0o700)
    paths.state_dir.chmod(0o700)
    paths.ssh_dir.chmod(0o700)
