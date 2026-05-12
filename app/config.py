from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
import shutil
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDER_TOKEN_PREFIXES = ("change-me-",)
PLACEHOLDER_TOKEN_VALUES = frozenset(
    {
        "admin-token-123",
        "client-token-123",
        "server-token-123",
    }
)
LOCAL_BROKER_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class StartupValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class Settings(BaseSettings):
    app_name: str = Field(default="zfcssh-broker", alias="APP_NAME")
    app_version: str = Field(default="0.2.0", alias="APP_VERSION")
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8443, alias="PORT")
    broker_public_base_url: str = Field(
        default="http://192.168.131.135:8443", alias="BROKER_PUBLIC_BASE_URL"
    )
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    audit_log_path: str = Field(
        default="/var/log/zfcssh-broker/audit.log", alias="AUDIT_LOG_PATH"
    )
    idempotency_db_path: str = Field(
        default="/var/lib/zfcssh-broker/idempotency.db", alias="IDEMPOTENCY_DB_PATH"
    )
    temp_dir: str = Field(default="/var/tmp/zfcssh-broker", alias="TEMP_DIR")
    user_ca_private_key: str = Field(
        default="/root/.step/secrets/ssh_user_ca_key", alias="USER_CA_PRIVATE_KEY"
    )
    user_ca_public_key: str = Field(
        default="/root/.step/certs/ssh_user_ca_key.pub", alias="USER_CA_PUBLIC_KEY"
    )
    user_ca_key_passphrase: str = Field(default="", alias="USER_CA_KEY_PASSPHRASE")
    host_ca_private_key: str = Field(
        default="/root/.step/secrets/ssh_host_ca_key", alias="HOST_CA_PRIVATE_KEY"
    )
    host_ca_public_key: str = Field(
        default="/root/.step/certs/ssh_host_ca_key.pub", alias="HOST_CA_PUBLIC_KEY"
    )
    host_ca_key_passphrase: str = Field(default="", alias="HOST_CA_KEY_PASSPHRASE")
    user_allowed_principals: str = Field(
        default="rocky,root", alias="USER_ALLOWED_PRINCIPALS"
    )
    user_default_ttl_hours: int = Field(default=24, alias="USER_DEFAULT_TTL_HOURS")
    user_max_ttl_hours: int = Field(default=168, alias="USER_MAX_TTL_HOURS")
    host_default_ttl_hours: int = Field(default=26280, alias="HOST_DEFAULT_TTL_HOURS")
    host_max_ttl_hours: int = Field(default=26280, alias="HOST_MAX_TTL_HOURS")

    # ── lifecycle diagnostic role tokens ─────────────────────────────────────
    token_dev: str = Field(default="", alias="TOKEN_DEV")
    token_prod: str = Field(default="", alias="TOKEN_PROD")
    token_claims: str = Field(default="", alias="TOKEN_CLAIMS")
    token_oemprod: str = Field(default="", alias="TOKEN_OEMPROD")
    token_server: str = Field(default="", alias="TOKEN_SERVER")
    token_admin: str = Field(default="", alias="TOKEN_ADMIN")

    # ── extension profile defaults ───────────────────────────────────────────
    default_user_profile: str = Field(default="field_operation", alias="DEFAULT_USER_PROFILE")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def user_allowed_principal_list(self) -> list[str]:
        return [item.strip() for item in self.user_allowed_principals.split(",") if item.strip()]

    def token_map(self) -> dict[str, str]:
        values = {
            "dev": self.token_dev,
            "prod": self.token_prod,
            "claims": self.token_claims,
            "OEMprod": self.token_oemprod,
            "server": self.token_server,
            "admin": self.token_admin,
        }
        return {role: token for role, token in values.items() if token}

    def startup_validation(
        self,
        *,
        check_files: bool = True,
        check_commands: bool = True,
    ) -> StartupValidationResult:
        from app.services.extension_profiles import BUILTIN_PROFILES

        errors: list[str] = []
        warnings: list[str] = []

        if self.default_user_profile not in BUILTIN_PROFILES:
            errors.append(
                "DEFAULT_USER_PROFILE must be one of: "
                f"{', '.join(sorted(BUILTIN_PROFILES))}"
            )

        if not self.user_allowed_principal_list:
            errors.append("USER_ALLOWED_PRINCIPALS must define at least one principal")

        if self.user_default_ttl_hours <= 0 or self.user_max_ttl_hours <= 0:
            errors.append("USER_DEFAULT_TTL_HOURS and USER_MAX_TTL_HOURS must be positive")
        elif self.user_default_ttl_hours > self.user_max_ttl_hours:
            errors.append("USER_DEFAULT_TTL_HOURS must be less than or equal to USER_MAX_TTL_HOURS")

        if self.host_default_ttl_hours <= 0 or self.host_max_ttl_hours <= 0:
            errors.append("HOST_DEFAULT_TTL_HOURS and HOST_MAX_TTL_HOURS must be positive")
        elif self.host_default_ttl_hours > self.host_max_ttl_hours:
            errors.append("HOST_DEFAULT_TTL_HOURS must be less than or equal to HOST_MAX_TTL_HOURS")

        parsed_base_url = urlparse(self.broker_public_base_url)
        if not parsed_base_url.scheme or not parsed_base_url.netloc:
            errors.append("BROKER_PUBLIC_BASE_URL must be a fully qualified URL")
        else:
            hostname = parsed_base_url.hostname or ""
            if parsed_base_url.scheme != "https" and hostname not in LOCAL_BROKER_HOSTS:
                errors.append(
                    "BROKER_PUBLIC_BASE_URL must use https outside localhost to align "
                    "with the commercial X.509 TLS boundary"
                )
            if hostname and self._is_ip_literal(hostname):
                warnings.append(
                    "BROKER_PUBLIC_BASE_URL uses an IP literal; prefer a DNS name backed "
                    "by the commercial X.509 PKI"
                )

        token_values = {
            "TOKEN_DEV": self.token_dev,
            "TOKEN_PROD": self.token_prod,
            "TOKEN_CLAIMS": self.token_claims,
            "TOKEN_OEMPROD": self.token_oemprod,
            "TOKEN_SERVER": self.token_server,
            "TOKEN_ADMIN": self.token_admin,
        }
        placeholder_tokens = [
            name for name, value in token_values.items() if self._is_placeholder_token(value)
        ]
        if placeholder_tokens:
            errors.append(
                "Replace placeholder tokens before startup: "
                f"{', '.join(sorted(placeholder_tokens))}"
            )

        if not self.token_server.strip():
            errors.append(
                "TOKEN_SERVER must be configured for host certificate bootstrap and host signing"
            )

        user_signing_tokens = [
            self.token_dev,
            self.token_prod,
            self.token_claims,
            self.token_oemprod,
            self.token_admin,
        ]
        if not any(token.strip() for token in user_signing_tokens):
            errors.append(
                "Configure at least one user-signing role token "
                "(TOKEN_DEV/TOKEN_PROD/TOKEN_CLAIMS/TOKEN_OEMPROD/TOKEN_ADMIN)"
            )

        temp_dir_path = Path(self.temp_dir)
        if temp_dir_path.exists() and not temp_dir_path.is_dir():
            errors.append(f"TEMP_DIR must be a directory path: {temp_dir_path}")

        if check_files:
            required_paths = {
                "USER_CA_PRIVATE_KEY": self.user_ca_private_key,
                "USER_CA_PUBLIC_KEY": self.user_ca_public_key,
                "HOST_CA_PRIVATE_KEY": self.host_ca_private_key,
                "HOST_CA_PUBLIC_KEY": self.host_ca_public_key,
            }
            for label, raw_path in required_paths.items():
                candidate = Path(raw_path)
                if not candidate.is_file():
                    errors.append(f"{label} does not point to a readable file: {candidate}")

        if check_commands and shutil.which("ssh-keygen") is None:
            errors.append("ssh-keygen must be installed and available in PATH")

        return StartupValidationResult(errors=errors, warnings=warnings)

    def ensure_startup_ready(
        self,
        *,
        check_files: bool = True,
        check_commands: bool = True,
    ) -> StartupValidationResult:
        result = self.startup_validation(
            check_files=check_files,
            check_commands=check_commands,
        )
        if result.errors:
            formatted_errors = "\n- ".join(result.errors)
            raise RuntimeError(f"Startup validation failed:\n- {formatted_errors}")
        return result

    @staticmethod
    def _is_placeholder_token(token: str) -> bool:
        value = token.strip()
        if not value:
            return False
        return value.startswith(PLACEHOLDER_TOKEN_PREFIXES) or value in PLACEHOLDER_TOKEN_VALUES

    @staticmethod
    def _is_ip_literal(hostname: str) -> bool:
        return all(char.isdigit() or char in ".:" for char in hostname)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
