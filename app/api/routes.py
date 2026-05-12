import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import Settings, get_settings
from app.models.schemas import (
    CertPermissionOverrides,
    DemoPublicKeyResponse,
    ErrorResponse,
    HealthResponse,
    InspectCertRequest,
    InspectCertResponse,
    PubKeyResponse,
    SignHostRequest,
    SignResponse,
    SignUserRequest,
    UiBootstrapResponse,
    VersionResponse,
)
from app.security.auth import AuthContext, require_auth, require_host_sign_role, require_user_sign_role
from app.services.extension_profiles import (
    PROFILE_NAMES,
    check_role_profile_access,
    resolve_profile,
)
from app.services.idempotency import IdempotencyStore
from app.services.signing import SigningService
from app.utils.validators import (
    normalize_ttl,
    validate_critical_options,
    validate_extensions,
    validate_host_principals,
    validate_key_id,
    validate_source_address,
    validate_ssh_public_key,
    validate_user_principals,
)

LOGGER = logging.getLogger("zfcssh.api")
UI_INDEX = Path(__file__).resolve().parents[1] / "ui" / "index.html"


def create_router(service: SigningService, settings: Settings) -> APIRouter:
    router = APIRouter()

    def audit(
        *,
        request: Request,
        action: str,
        auth: Optional[AuthContext],
        key_id: Optional[str],
        principals: Optional[List[str]],
        result: str,
        error_code: Optional[str] = None,
        caller: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> None:
        LOGGER.info(
            "audit action=%s remote_ip=%s auth_role=%s token_hint=%s caller=%s key_id=%s principals=%s profile=%s result=%s error_code=%s",
            action,
            request.client.host if request.client else "-",
            auth.role if auth else "-",
            auth.token_hint if auth else "-",
            caller or "-",
            key_id or "-",
            ",".join(principals or []),
            profile or "-",
            result,
            error_code or "-",
        )

    @router.get("/healthz", response_model=HealthResponse)
    def healthz() -> HealthResponse:
        return HealthResponse(status="ok", timestamp=datetime.now(timezone.utc))

    @router.get("/ui", response_class=HTMLResponse)
    def ui() -> HTMLResponse:
        return HTMLResponse(UI_INDEX.read_text(encoding="utf-8"))

    @router.get("/v1/version", response_model=VersionResponse)
    def version(auth: AuthContext = Depends(require_auth)) -> VersionResponse:
        return VersionResponse(
            app_name=settings.app_name,
            version=settings.app_version,
            broker_bind=f"{settings.host}:{settings.port}",
            public_base_url=settings.broker_public_base_url,
            default_user_ttl_hours=settings.user_default_ttl_hours,
            max_user_ttl_hours=settings.user_max_ttl_hours,
            default_host_ttl_hours=settings.host_default_ttl_hours,
            max_host_ttl_hours=settings.host_max_ttl_hours,
            allowed_user_principals=settings.user_allowed_principal_list,
            default_user_profile=settings.default_user_profile,
        )

    @router.get("/v1/ui/bootstrap", response_model=UiBootstrapResponse)
    def ui_bootstrap(auth: AuthContext = Depends(require_auth)) -> UiBootstrapResponse:
        return UiBootstrapResponse(
            app_name=settings.app_name,
            version=settings.app_version,
            broker_bind=f"{settings.host}:{settings.port}",
            public_base_url=settings.broker_public_base_url,
            allowed_user_principals=settings.user_allowed_principal_list,
            default_user_ttl_hours=settings.user_default_ttl_hours,
            max_user_ttl_hours=settings.user_max_ttl_hours,
            default_host_ttl_hours=settings.host_default_ttl_hours,
            max_host_ttl_hours=settings.host_max_ttl_hours,
            default_user_profile=settings.default_user_profile,
            available_profiles=sorted(PROFILE_NAMES),
            user_ca_pubkey_endpoint="/v1/ca/user/pubkey",
            host_ca_pubkey_endpoint="/v1/ca/host/pubkey",
            sign_user_endpoint="/v1/sign/user",
            sign_host_endpoint="/v1/sign/host",
            inspect_cert_endpoint="/v1/ui/inspect-cert",
            example_caller={"requester": "manual-ui", "source_ip": None, "reason": "manual workflow step"},
        )

    @router.get("/v1/ca/user/pubkey", response_model=PubKeyResponse)
    def user_ca_pubkey(auth: AuthContext = Depends(require_auth)) -> PubKeyResponse:
        public_key = Path(settings.user_ca_public_key).read_text(encoding="utf-8").strip()
        return PubKeyResponse(key_type="user", public_key=public_key)

    @router.get("/v1/ca/host/pubkey", response_model=PubKeyResponse)
    def host_ca_pubkey(auth: AuthContext = Depends(require_auth)) -> PubKeyResponse:
        public_key = Path(settings.host_ca_public_key).read_text(encoding="utf-8").strip()
        return PubKeyResponse(key_type="host", public_key=public_key)

    @router.post(
        "/v1/ui/demo-user-pubkey",
        response_model=DemoPublicKeyResponse,
        responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    )
    def demo_user_pubkey(
        auth: AuthContext = Depends(require_auth),
    ) -> DemoPublicKeyResponse:
        del auth
        return DemoPublicKeyResponse(**service.generate_demo_public_key(comment="demo-ui-user"))

    @router.post(
        "/v1/ui/demo-host-pubkey",
        response_model=DemoPublicKeyResponse,
        responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    )
    def demo_host_pubkey(
        auth: AuthContext = Depends(require_auth),
    ) -> DemoPublicKeyResponse:
        del auth
        return DemoPublicKeyResponse(**service.generate_demo_host_public_key(comment="demo-ui-host"))

    @router.post(
        "/v1/sign/user",
        response_model=SignResponse,
        responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    )
    def sign_user(
        payload: SignUserRequest,
        request: Request,
        auth: AuthContext = Depends(require_user_sign_role),
    ) -> SignResponse:
        validate_key_id(payload.key_id)
        public_key = validate_ssh_public_key(payload.public_key)
        principals = validate_user_principals(payload.requested_principals, settings)
        ttl = normalize_ttl(
            payload.ttl,
            default_hours=settings.user_default_ttl_hours,
            max_hours=settings.user_max_ttl_hours,
            cert_type="user",
        )

        # ── resolve lifecycle profile ────────────────────────────────────
        profile_name = payload.profile or settings.default_user_profile

        # validate caller-provided permission overrides
        ext_override = None
        crit_override = None
        if payload.permissions:
            if payload.permissions.extensions:
                ext_override = validate_extensions(payload.permissions.extensions)
            if payload.permissions.critical_options:
                crit_override = validate_critical_options(payload.permissions.critical_options)
        if payload.source_address:
            validate_source_address(payload.source_address)

        permissions = resolve_profile(
            profile_name=profile_name,
            default_profile=settings.default_user_profile,
            extensions_override=ext_override,
            critical_options_override=crit_override,
            source_address=payload.source_address,
            force_command=payload.force_command,
        )

        # enforce role → profile authorization
        check_role_profile_access(auth.role, profile_name)

        try:
            certificate, reused = service.sign_certificate(
                cert_type="user",
                key_id=payload.key_id,
                principals=principals,
                ttl=ttl,
                public_key=public_key,
                permissions=permissions,
            )
        except HTTPException as exc:
            audit(
                request=request,
                action="sign_user",
                auth=auth,
                key_id=payload.key_id,
                principals=principals,
                result="failed",
                error_code=exc.detail.get("error_code"),
                caller=payload.caller.requester,
                profile=profile_name,
            )
            raise
        audit(
            request=request,
            action="sign_user",
            auth=auth,
            key_id=payload.key_id,
            principals=principals,
            result="ok",
            caller=payload.caller.requester,
            profile=profile_name,
        )
        return SignResponse(
            cert_type="user",
            key_id=payload.key_id,
            principals=principals,
            ttl=ttl,
            certificate=certificate,
            idempotent_reused=reused,
            profile=profile_name,
        )

    @router.post(
        "/v1/sign/host",
        response_model=SignResponse,
        responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    )
    def sign_host(
        payload: SignHostRequest,
        request: Request,
        auth: AuthContext = Depends(require_host_sign_role),
    ) -> SignResponse:
        validate_key_id(payload.key_id)
        public_key = validate_ssh_public_key(payload.public_key)
        principals = validate_host_principals(payload.requested_principals)
        ttl = normalize_ttl(
            payload.ttl,
            default_hours=settings.host_default_ttl_hours,
            max_hours=settings.host_max_ttl_hours,
            cert_type="host",
        )
        try:
            certificate, reused = service.sign_certificate(
                cert_type="host",
                key_id=payload.key_id,
                principals=principals,
                ttl=ttl,
                public_key=public_key,
            )
        except HTTPException as exc:
            audit(
                request=request,
                action="sign_host",
                auth=auth,
                key_id=payload.key_id,
                principals=principals,
                result="failed",
                error_code=exc.detail.get("error_code"),
                caller=payload.caller.requester,
            )
            raise
        audit(
            request=request,
            action="sign_host",
            auth=auth,
            key_id=payload.key_id,
            principals=principals,
            result="ok",
            caller=payload.caller.requester,
        )
        return SignResponse(
            cert_type="host",
            key_id=payload.key_id,
            principals=principals,
            ttl=ttl,
            certificate=certificate,
            idempotent_reused=reused,
        )

    @router.post(
        "/v1/ui/inspect-cert",
        response_model=InspectCertResponse,
        responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    )
    def inspect_cert(
        payload: InspectCertRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> InspectCertResponse:
        del auth
        return InspectCertResponse(**service.inspect_certificate(payload.certificate))

    return router


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
        return JSONResponse(status_code=exc.status_code, content={"success": False, **detail})

    @app.exception_handler(Exception)
    async def generic_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("unhandled_exception error=%s", exc)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error_code": "INTERNAL_ERROR",
                "message": "Unexpected server error",
            },
        )


def build_application(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()
    store = IdempotencyStore(settings.idempotency_db_path)
    service = SigningService(settings, store)
    app = FastAPI(title=settings.app_name, version=settings.app_version)
    app.include_router(create_router(service, settings))
    register_exception_handlers(app)
    return app
