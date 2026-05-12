from app.config import Settings
from app.utils.validators import normalize_ttl, validate_host_principals, validate_user_principals


def test_validate_user_principals_defaults() -> None:
    settings = Settings(USER_ALLOWED_PRINCIPALS="rocky,root")
    assert validate_user_principals(None, settings) == ["rocky", "root"]


def test_validate_host_principals_ip_and_hostname() -> None:
    assert validate_host_principals(["192.168.131.134", "soc-host"]) == ["192.168.131.134", "soc-host"]


def test_normalize_ttl_default() -> None:
    assert normalize_ttl(None, default_hours=24, max_hours=168, cert_type="user") == "24h"


def test_normalize_ttl_accepts_three_year_host_ttl() -> None:
    assert normalize_ttl("1095d", default_hours=26280, max_hours=26280, cert_type="host") == "1095d"
