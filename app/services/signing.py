import logging
import os
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings
from app.services.extension_profiles import CertificatePermissions, build_keygen_options
from app.services.idempotency import IdempotencyStore
from app.utils.validators import api_error

LOGGER = logging.getLogger("zfcssh.signing")


class SigningService:
    def __init__(self, settings: Settings, store: IdempotencyStore) -> None:
        self.settings = settings
        self.store = store
        Path(settings.temp_dir).mkdir(parents=True, exist_ok=True)
        Path(settings.temp_dir).chmod(0o700)

    def sign_certificate(
        self,
        *,
        cert_type: str,
        key_id: str,
        principals: list[str],
        ttl: str,
        public_key: str,
        permissions: CertificatePermissions | None = None,
    ) -> tuple[str, bool]:
        request_hash = self.store.build_hash(
            {
                "cert_type": cert_type,
                "key_id": key_id,
                "principals": principals,
                "ttl": ttl,
                "public_key": public_key,
                "extensions": permissions.extensions if permissions else [],
                "critical_options": permissions.critical_options if permissions else {},
            }
        )
        existing = self.store.get(request_hash)
        if existing:
            return existing["certificate"], True

        certificate = self._run_ssh_keygen(
            cert_type=cert_type,
            key_id=key_id,
            principals=principals,
            ttl=ttl,
            public_key=public_key,
            permissions=permissions,
        )
        self.store.put(
            request_hash=request_hash,
            cert_type=cert_type,
            key_id=key_id,
            principals=principals,
            ttl=ttl,
            certificate=certificate,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        return certificate, False

    def _run_ssh_keygen(
        self,
        *,
        cert_type: str,
        key_id: str,
        principals: list[str],
        ttl: str,
        public_key: str,
        permissions: CertificatePermissions | None = None,
    ) -> str:
        ca_private_key = (
            self.settings.user_ca_private_key if cert_type == "user" else self.settings.host_ca_private_key
        )
        ca_key_passphrase = (
            self.settings.user_ca_key_passphrase
            if cert_type == "user"
            else self.settings.host_ca_key_passphrase
        )
        command = [
            "ssh-keygen",
            "-s",
            ca_private_key,
            "-I",
            key_id,
            "-n",
            ",".join(principals),
            "-V",
            f"+{ttl}",
            "-z",
            str(secrets.randbits(31)),
        ]
        if cert_type == "host":
            command.append("-h")

        # inject extension / critical-option flags for user certs
        if cert_type == "user" and permissions:
            command.extend(build_keygen_options(permissions))

        with tempfile.TemporaryDirectory(dir=self.settings.temp_dir) as temp_dir:
            temp_path = Path(temp_dir)
            pubkey_path = temp_path / "subject_key.pub"
            cert_path = temp_path / "subject_key-cert.pub"
            askpass_path = temp_path / "askpass.sh"
            pubkey_path.write_text(public_key.strip() + "\n", encoding="utf-8")
            pubkey_path.chmod(0o600)
            command.append(str(pubkey_path))
            env = os.environ.copy()
            if ca_key_passphrase:
                askpass_path.write_text(
                    "#!/bin/sh\n"
                    "printf '%s' \"$ZFCS_CA_KEY_PASSPHRASE\"\n",
                    encoding="utf-8",
                )
                askpass_path.chmod(0o700)
                env.update(
                    {
                        "SSH_ASKPASS": str(askpass_path),
                        "SSH_ASKPASS_REQUIRE": "force",
                        "ZFCS_CA_KEY_PASSPHRASE": ca_key_passphrase,
                        "DISPLAY": "broker:0",
                    }
                )

            LOGGER.info(
                "sign_command cert_type=%s key_id=%s principals=%s temp_dir=%s",
                cert_type,
                key_id,
                ",".join(principals),
                temp_dir,
            )
            try:
                result = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                )
            except FileNotFoundError as exc:
                raise api_error(500, "SSH_KEYGEN_NOT_FOUND", "ssh-keygen is not installed") from exc

            if result.returncode != 0:
                raise api_error(
                    500,
                    "SIGNING_FAILED",
                    "ssh-keygen failed to sign certificate",
                    {"stderr": result.stderr.strip()},
                )
            if not cert_path.exists():
                raise api_error(
                    500,
                    "CERTIFICATE_MISSING",
                    "Certificate file was not produced by ssh-keygen",
                )
            return cert_path.read_text(encoding="utf-8").strip()

    def inspect_certificate(self, certificate: str) -> dict:
        with tempfile.TemporaryDirectory(dir=self.settings.temp_dir) as temp_dir:
            temp_path = Path(temp_dir)
            cert_path = temp_path / "inspect-cert.pub"
            cert_path.write_text(certificate.strip() + "\n", encoding="utf-8")
            cert_path.chmod(0o600)
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-Lf", str(cert_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as exc:
                raise api_error(500, "SSH_KEYGEN_NOT_FOUND", "ssh-keygen is not installed") from exc
            if result.returncode != 0:
                raise api_error(
                    422,
                    "CERT_PARSE_FAILED",
                    "ssh-keygen could not parse the certificate",
                    {"stderr": result.stderr.strip()},
                )
            return self._parse_certificate_inspection(result.stdout)

    @staticmethod
    def _parse_certificate_inspection(output: str) -> dict:
        cert_type = ""
        key_id = ""
        serial = ""
        valid_after = ""
        valid_before = ""
        principals: list[str] = []
        signing_ca_fingerprint = ""
        critical_options: dict[str, str] = {}
        extensions: list[str] = []

        # parser state
        section = ""  # "", "principals", "critical_options", "extensions"

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if line.startswith("Type: "):
                cert_type = line[len("Type: ") :]
                section = ""
            elif line.startswith('Key ID: "'):
                key_id = line[len('Key ID: "') : -1]
                section = ""
            elif line.startswith("Serial: "):
                serial = line[len("Serial: ") :]
                section = ""
            elif line.startswith("Valid: from "):
                valid_range = line[len("Valid: from ") :]
                if " to " in valid_range:
                    valid_after, valid_before = valid_range.split(" to ", 1)
                section = ""
            elif line.startswith("Signing CA: "):
                signing_ca_fingerprint = line[len("Signing CA: ") :]
                section = ""
            elif line == "Principals:":
                section = "principals"
            elif line.startswith("Critical Options:"):
                section = "critical_options" if line == "Critical Options:" else ""
            elif line.startswith("Extensions:"):
                section = "extensions" if line == "Extensions:" else ""
            elif section == "principals" and line:
                principals.append(line)
            elif section == "critical_options" and line:
                # format: "force-command /usr/bin/rsync" or "source-address 10.0.0.0/8"
                parts = line.split(None, 1)
                if len(parts) == 2:
                    critical_options[parts[0]] = parts[1]
                elif len(parts) == 1:
                    critical_options[parts[0]] = ""
            elif section == "extensions" and line:
                extensions.append(line)

        if not cert_type:
            raise api_error(422, "CERT_PARSE_FAILED", "Certificate inspection output was incomplete")

        return {
            "cert_type": cert_type,
            "key_id": key_id,
            "serial": serial,
            "valid_after": valid_after,
            "valid_before": valid_before,
            "principals": principals,
            "critical_options": critical_options,
            "extensions": extensions,
            "signing_ca_fingerprint": signing_ca_fingerprint,
            "raw_output": output.strip(),
        }

    def generate_demo_public_key(self, *, comment: str) -> dict:
        with tempfile.TemporaryDirectory(dir=self.settings.temp_dir) as temp_dir:
            temp_path = Path(temp_dir)
            key_path = temp_path / "demo_ed25519"
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as exc:
                raise api_error(500, "SSH_KEYGEN_NOT_FOUND", "ssh-keygen is not installed") from exc
            if result.returncode != 0:
                raise api_error(
                    500,
                    "DEMO_KEYGEN_FAILED",
                    "ssh-keygen failed to generate a demo public key",
                    {"stderr": result.stderr.strip()},
                )
            public_key = key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()
            return {
                "key_type": "user",
                "public_key": public_key,
                "comment": comment,
            }

    def generate_demo_host_public_key(self, *, comment: str) -> dict:
        with tempfile.TemporaryDirectory(dir=self.settings.temp_dir) as temp_dir:
            temp_path = Path(temp_dir)
            key_path = temp_path / "demo_host_ed25519"
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as exc:
                raise api_error(500, "SSH_KEYGEN_NOT_FOUND", "ssh-keygen is not installed") from exc
            if result.returncode != 0:
                raise api_error(
                    500,
                    "DEMO_KEYGEN_FAILED",
                    "ssh-keygen failed to generate a demo host public key",
                    {"stderr": result.stderr.strip()},
                )
            public_key = key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()
            return {
                "key_type": "host",
                "public_key": public_key,
                "comment": comment,
            }
