from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException, status

from app.config import Settings, get_settings


@dataclass(frozen=True)
class AuthContext:
    role: str
    token_hint: str


def _bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "AUTH_REQUIRED", "message": "Missing Authorization header"},
        )
    prefix = "bearer "
    if not authorization.lower().startswith(prefix):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "AUTH_INVALID", "message": "Expected Bearer token"},
        )
    token = authorization[len(prefix) :].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "AUTH_INVALID", "message": "Empty Bearer token"},
        )
    return token


def require_auth(
    authorization: Optional[str] = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> AuthContext:
    token = _bearer_token(authorization)
    token_map = settings.token_map()
    for role, expected in token_map.items():
        if token == expected:
            return AuthContext(role=role, token_hint=f"{role}:{token[:6]}")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error_code": "AUTH_FORBIDDEN", "message": "Token is not allowed"},
    )


def require_user_sign_role(auth: AuthContext = Depends(require_auth)) -> AuthContext:
    """Roles that can sign user certificates (lifecycle roles + admin)."""
    if auth.role not in {"dev", "prod", "claims", "OEMprod", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "AUTH_FORBIDDEN", "message": "Role cannot sign user certs"},
        )
    return auth


def require_host_sign_role(auth: AuthContext = Depends(require_auth)) -> AuthContext:
    if auth.role not in {"server", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "AUTH_FORBIDDEN", "message": "Role cannot sign host certs"},
        )
    return auth
