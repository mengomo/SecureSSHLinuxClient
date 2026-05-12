from app.api.routes import build_application
from app.config import Settings
from app.security.auth import AuthContext, require_host_sign_role, require_user_sign_role
from app.services.signing import SigningService
from app.services.idempotency import IdempotencyStore


def build_settings() -> Settings:
    return Settings(
        TOKEN_DEV="dev-token",
        TOKEN_PROD="prod-token",
        TOKEN_CLAIMS="claims-token",
        TOKEN_OEMPROD="oemprod-token",
        TOKEN_SERVER="server-token",
        TOKEN_ADMIN="admin-token",
        USER_ALLOWED_PRINCIPALS="rocky,root",
        IDEMPOTENCY_DB_PATH="/tmp/zfcssh-broker-test.db",
        TEMP_DIR="/tmp/zfcssh-broker-test",
        USER_CA_PUBLIC_KEY="/tmp/user_ca.pub",
        HOST_CA_PUBLIC_KEY="/tmp/host_ca.pub",
    )


def test_expected_routes_are_registered() -> None:
    settings = build_settings()
    app = build_application(settings)
    paths = {route.path for route in app.routes}
    assert "/ui" in paths
    assert "/healthz" in paths
    assert "/v1/version" in paths
    assert "/v1/ui/bootstrap" in paths
    assert "/v1/ui/demo-user-pubkey" in paths
    assert "/v1/ui/demo-host-pubkey" in paths
    assert "/v1/ui/inspect-cert" in paths
    assert "/v1/ca/user/pubkey" in paths
    assert "/v1/ca/host/pubkey" in paths
    assert "/v1/sign/user" in paths
    assert "/v1/sign/host" in paths


def test_user_sign_role_accepts_dev() -> None:
    auth = AuthContext(role="dev", token_hint="dev:abc123")
    assert require_user_sign_role(auth) == auth


def test_user_sign_role_accepts_prod() -> None:
    auth = AuthContext(role="prod", token_hint="prod:abc123")
    assert require_user_sign_role(auth) == auth


def test_user_sign_role_accepts_claims() -> None:
    auth = AuthContext(role="claims", token_hint="claims:abc12")
    assert require_user_sign_role(auth) == auth


def test_user_sign_role_accepts_oemprod() -> None:
    auth = AuthContext(role="OEMprod", token_hint="OEMprod:abc")
    assert require_user_sign_role(auth) == auth


def test_host_sign_role_accepts_server() -> None:
    auth = AuthContext(role="server", token_hint="server:abc123")
    assert require_host_sign_role(auth) == auth


def test_parse_certificate_inspection_output() -> None:
    settings = build_settings()
    service = SigningService(settings, IdempotencyStore(settings.idempotency_db_path))
    output = """
/tmp/id-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:test
        Signing CA: ECDSA SHA256:ca-fingerprint (using ecdsa-sha2-nistp256)
        Key ID: "blooze@192.168.131.128"
        Serial: 12345
        Valid: from 2026-03-16T22:28:00 to 2026-03-17T22:29:57
        Principals:
                rocky
                root
        Critical Options:
                force-command /usr/local/bin/diag-tool --read-only
                source-address 192.168.131.0/24
        Extensions:
                permit-port-forwarding
                permit-pty
"""
    parsed = service._parse_certificate_inspection(output)
    assert parsed["cert_type"] == "ssh-ed25519-cert-v01@openssh.com user certificate"
    assert parsed["key_id"] == "blooze@192.168.131.128"
    assert parsed["serial"] == "12345"
    assert parsed["principals"] == ["rocky", "root"]
    assert parsed["extensions"] == ["permit-port-forwarding", "permit-pty"]
    assert parsed["critical_options"] == {
        "force-command": "/usr/local/bin/diag-tool --read-only",
        "source-address": "192.168.131.0/24",
    }


def test_parse_certificate_no_critical_options() -> None:
    settings = build_settings()
    service = SigningService(settings, IdempotencyStore(settings.idempotency_db_path))
    output = """
/tmp/id-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:test
        Signing CA: ECDSA SHA256:ca-fingerprint (using ecdsa-sha2-nistp256)
        Key ID: "dev@workstation"
        Serial: 99999
        Valid: from 2026-03-16T22:28:00 to 2026-03-17T22:29:57
        Principals:
                rocky
        Critical Options: (none)
        Extensions:
                permit-pty
"""
    parsed = service._parse_certificate_inspection(output)
    assert parsed["key_id"] == "dev@workstation"
    assert parsed["principals"] == ["rocky"]
    assert parsed["critical_options"] == {}
    assert parsed["extensions"] == ["permit-pty"]
