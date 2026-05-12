from __future__ import annotations

import json
import ssl
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import urljoin

from zfcssh_client.models import InstalledBundle
from zfcssh_client.profiles import default_ttl_for_profile


class BrokerError(RuntimeError):
    pass


class BrokerClient:
    def __init__(self, bundle: InstalledBundle, *, timeout: int = 15, max_bytes: int = 65536) -> None:
        self.bundle = bundle
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.context = self._build_ssl_context(bundle)

    def request_user_certificate(
        self,
        *,
        public_key: str,
        key_id: str,
        principals: list[str],
        profile: str,
        ttl: str | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "public_key": public_key,
            "key_id": key_id,
            "requested_principals": principals,
            "profile": profile,
            "caller": {
                "requester": self.bundle.requester,
                "reason": self.bundle.reason or "linux pc endpoint certificate enrollment",
            },
        }
        payload["ttl"] = ttl or default_ttl_for_profile(profile)
        response = self._request_json("POST", "/v1/sign/user", payload)
        certificate = response.get("certificate")
        if not isinstance(certificate, str) or not certificate.strip():
            raise BrokerError("Broker response did not include a certificate")
        return certificate.strip()

    def get_host_ca_public_key(self) -> str:
        response = self._request_json("GET", "/v1/ca/host/pubkey")
        public_key = response.get("public_key")
        if not isinstance(public_key, str) or not public_key.strip():
            raise BrokerError("Broker response did not include host CA public key")
        return public_key.strip()

    def _request_json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(urljoin(self.bundle.broker_url, path), data=body, headers=headers, method=method)
        opener = request.build_opener(request.HTTPSHandler(context=self.context))
        try:
            with opener.open(req, timeout=self.timeout) as response:
                data = response.read(self.max_bytes + 1)
        except error.HTTPError as exc:
            details = exc.read(self.max_bytes).decode("utf-8", errors="replace")
            raise BrokerError(f"Broker request failed with HTTP {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise BrokerError(f"Broker request failed: {exc.reason}") from exc
        if len(data) > self.max_bytes:
            raise BrokerError("Broker response exceeded maximum allowed size")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise BrokerError("Broker response was not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise BrokerError("Broker response was not a JSON object")
        return parsed

    @staticmethod
    def _build_ssl_context(bundle: InstalledBundle) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if bundle.mtls.ca_certificate_path and bundle.mtls.ca_certificate_path.is_file():
            context.load_verify_locations(cafile=str(bundle.mtls.ca_certificate_path))
        context.load_cert_chain(
            certfile=str(bundle.mtls.client_certificate_path),
            keyfile=str(bundle.mtls.client_key_path),
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
