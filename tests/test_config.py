from pathlib import Path

from app.config import Settings


def build_settings(tmp_path: Path, **overrides: str) -> Settings:
    ca_paths = {
        "USER_CA_PRIVATE_KEY": str(tmp_path / "user_ca"),
        "USER_CA_PUBLIC_KEY": str(tmp_path / "user_ca.pub"),
        "HOST_CA_PRIVATE_KEY": str(tmp_path / "host_ca"),
        "HOST_CA_PUBLIC_KEY": str(tmp_path / "host_ca.pub"),
    }
    for raw_path in ca_paths.values():
        Path(raw_path).write_text("test-key\n", encoding="utf-8")

    values = {
        "BROKER_PUBLIC_BASE_URL": "https://broker.example.internal",
        "AUDIT_LOG_PATH": str(tmp_path / "logs" / "audit.log"),
        "IDEMPOTENCY_DB_PATH": str(tmp_path / "state" / "idempotency.db"),
        "TEMP_DIR": str(tmp_path / "tmp"),
        "TOKEN_DEV": "dev-real-token",
        "TOKEN_SERVER": "server-real-token",
        "TOKEN_ADMIN": "admin-real-token",
        "DEFAULT_USER_PROFILE": "field_operation",
        **ca_paths,
    }
    values.update(overrides)
    return Settings(**values)


def test_startup_validation_accepts_https_deployment_settings(tmp_path: Path) -> None:
    settings = build_settings(tmp_path)

    result = settings.startup_validation(check_commands=False)

    assert result.ok


def test_startup_validation_allows_local_http_for_development(tmp_path: Path) -> None:
    settings = build_settings(tmp_path, BROKER_PUBLIC_BASE_URL="http://localhost:8443")

    result = settings.startup_validation(check_commands=False)

    assert result.ok


def test_startup_validation_rejects_non_tls_remote_url(tmp_path: Path) -> None:
    settings = build_settings(tmp_path, BROKER_PUBLIC_BASE_URL="http://192.168.131.135:8443")

    result = settings.startup_validation(check_commands=False)

    assert not result.ok
    assert any("must use https" in error for error in result.errors)


def test_startup_validation_rejects_placeholder_tokens(tmp_path: Path) -> None:
    settings = build_settings(tmp_path, TOKEN_DEV="change-me-dev-token")

    result = settings.startup_validation(check_commands=False)

    assert not result.ok
    assert any("TOKEN_DEV" in error for error in result.errors)


def test_startup_validation_rejects_unknown_default_profile(tmp_path: Path) -> None:
    settings = build_settings(tmp_path, DEFAULT_USER_PROFILE="unknown-profile")

    result = settings.startup_validation(check_commands=False)

    assert not result.ok
    assert any("DEFAULT_USER_PROFILE" in error for error in result.errors)


def test_startup_validation_requires_server_and_user_tokens(tmp_path: Path) -> None:
    settings = build_settings(
        tmp_path,
        TOKEN_DEV="",
        TOKEN_PROD="",
        TOKEN_CLAIMS="",
        TOKEN_OEMPROD="",
        TOKEN_ADMIN="",
        TOKEN_SERVER="",
    )

    result = settings.startup_validation(check_commands=False)

    assert not result.ok
    assert any("TOKEN_SERVER" in error for error in result.errors)
    assert any("user-signing role token" in error for error in result.errors)


def test_host_certificate_defaults_are_three_years(tmp_path: Path) -> None:
    settings = build_settings(tmp_path)

    assert settings.host_default_ttl_hours == 26280
    assert settings.host_max_ttl_hours == 26280