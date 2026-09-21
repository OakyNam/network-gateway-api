"""Local administrative API. Mount this router without an additional prefix."""

import logging
import threading
from urllib.parse import urlsplit

from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.api.schemas.management import (
    BatchWrite, Capabilities, ConnectionCollection, ConnectionTestWrite, ConnectionWrite,
    ProxyCollection, ProxyWrite, PublicConnection, PublicJob, PublicProxy,
    PublicRoleAccount, RoleAccountCollection, RoleAccountWrite, SETTINGS_MODELS,
    SettingsName, SettingsPayload, TestResult,
)
from app.bl.services.batches import BatchService
from app.bl.services.management import ManagementError, ManagementService, capabilities
from app.common.identity import AuthenticatedUser, require_administrator, require_operator, require_viewer

_worker_lock = threading.Lock()
logger = logging.getLogger(__name__)


def _origin(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def _check_browser_mutation(request):
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    origin = request.headers.get("origin")
    target = _origin(str(request.base_url))
    if request.headers.get("sec-fetch-site", "").lower() in {"cross-site", "same-site"}:
        raise HTTPException(403, "Cross-origin administrative requests are not allowed.")
    if origin is not None and (_origin(origin) is None or _origin(origin) != target):
        raise HTTPException(403, "Cross-origin administrative requests are not allowed.")
    if request.method in {"POST", "PUT", "PATCH"}:
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        # Reject browser form/simple requests, including empty test POSTs.
        if content_type != "application/json":
            raise HTTPException(415, "Administrative requests require application/json.")


class SafeManagementRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe_handler(request):
            try:
                _check_browser_mutation(request)
                return await handler(request)
            except RequestValidationError:
                # Neither arbitrary field names, invalid values, validator ctx,
                # nor malformed JSON bodies are reflected back to the caller.
                return JSONResponse(status_code=422, content={"detail": "Invalid request fields."})
            except ResponseValidationError:
                return JSONResponse(status_code=500, content={"detail": "Invalid management response."})
            except ManagementError as exc:
                return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

        return safe_handler


router = APIRouter(prefix="/api/v1", route_class=SafeManagementRoute, tags=["management"])


def get_store(request: Request):
    try:
        from app.dal.db.store import get_store as configured_store

        store = configured_store()
        request.app.state.management_store = store
        return store
    except Exception:
        logger.error("Management storage could not be initialized.")
        raise ManagementError("Management storage is unavailable.", 503) from None


def get_management_service(request: Request, store=Depends(get_store)):
    return ManagementService(
        store,
        demo_mode=getattr(request.app.state, "demo_mode", False),
        device_data_provider=getattr(request.app.state, "device_data_provider", "disabled"),
    )


def get_batch_service(request: Request, management=Depends(get_management_service)):
    with _worker_lock:
        service = getattr(request.app.state, "management_batches", None)
        if service is None:
            service = BatchService(management)
            request.app.state.management_batches = service
        else:
            service.management.device_data_provider = management.device_data_provider
        return service


async def shutdown_management(app):
    """Await in the application's lifespan shutdown BEFORE closing its store."""
    service = getattr(app.state, "management_batches", None)
    if service is not None:
        await run_in_threadpool(service.shutdown)


@router.get("/capabilities", response_model=Capabilities)
def get_capabilities(viewer: Annotated[AuthenticatedUser, Depends(require_viewer)]):
    return capabilities()


@router.get("/connections", response_model=ConnectionCollection)
def list_connections(viewer: Annotated[AuthenticatedUser, Depends(require_viewer)], service=Depends(get_management_service)):
    return service.list("connections")


@router.get("/connections/{item_id}", response_model=PublicConnection)
def get_connection(item_id: str, viewer: Annotated[AuthenticatedUser, Depends(require_viewer)], service=Depends(get_management_service)):
    return service.get("connections", item_id)


@router.post("/connections", response_model=PublicConnection, status_code=201)
def create_connection(payload: ConnectionWrite, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    return service.save("connections", payload.model_dump(exclude_unset=True))


@router.put("/connections/{item_id}", response_model=PublicConnection)
def update_connection(item_id: str, payload: ConnectionWrite, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    return service.save("connections", payload.model_dump(exclude_unset=True), item_id)


@router.delete("/connections/{item_id}", status_code=204)
def delete_connection(item_id: str, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    service.delete("connections", item_id)
    return Response(status_code=204)


@router.post("/connections/{item_id}/test", response_model=TestResult)
def test_connection(
    item_id: str,
    operator: Annotated[AuthenticatedUser, Depends(require_operator)],
    payload: ConnectionTestWrite = Body(
        default=ConnectionTestWrite(),
        openapi_examples={"empty": {"summary": "Test the saved profile", "value": {}}},
    ),
    service=Depends(get_management_service),
):
    return service.test(item_id)


@router.get("/proxies", response_model=ProxyCollection)
def list_proxies(viewer: Annotated[AuthenticatedUser, Depends(require_viewer)], service=Depends(get_management_service)):
    return service.list("proxies")


@router.get("/proxies/{item_id}", response_model=PublicProxy)
def get_proxy(item_id: str, viewer: Annotated[AuthenticatedUser, Depends(require_viewer)], service=Depends(get_management_service)):
    return service.get("proxies", item_id)


@router.post("/proxies", response_model=PublicProxy, status_code=201)
def create_proxy(payload: ProxyWrite, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    return service.save("proxies", payload.model_dump(exclude_unset=True))


@router.put("/proxies/{item_id}", response_model=PublicProxy)
def update_proxy(item_id: str, payload: ProxyWrite, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    return service.save("proxies", payload.model_dump(exclude_unset=True), item_id)


@router.delete("/proxies/{item_id}", status_code=204)
def delete_proxy(item_id: str, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    service.delete("proxies", item_id)
    return Response(status_code=204)


@router.get("/role-accounts", response_model=RoleAccountCollection)
def list_roles(viewer: Annotated[AuthenticatedUser, Depends(require_viewer)], service=Depends(get_management_service)):
    return service.list("role_accounts")


@router.get("/role-accounts/{item_id}", response_model=PublicRoleAccount)
def get_role(item_id: str, viewer: Annotated[AuthenticatedUser, Depends(require_viewer)], service=Depends(get_management_service)):
    return service.get("role_accounts", item_id)


@router.post("/role-accounts", response_model=PublicRoleAccount, status_code=201)
def create_role(payload: RoleAccountWrite, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    return service.save("role_accounts", payload.model_dump(exclude_unset=True))


@router.put("/role-accounts/{item_id}", response_model=PublicRoleAccount)
def update_role(item_id: str, payload: RoleAccountWrite, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    return service.save("role_accounts", payload.model_dump(exclude_unset=True), item_id)


@router.delete("/role-accounts/{item_id}", status_code=204)
def delete_role(item_id: str, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    service.delete("role_accounts", item_id)
    return Response(status_code=204)


@router.post("/connection-tests", response_model=PublicJob, status_code=202)
def create_batch(payload: BatchWrite, operator: Annotated[AuthenticatedUser, Depends(require_operator)], service=Depends(get_batch_service)):
    return service.start(payload.connection_ids)


@router.get("/connection-tests/{job_id}", response_model=PublicJob)
def get_batch(job_id: str, operator: Annotated[AuthenticatedUser, Depends(require_operator)], service=Depends(get_batch_service)):
    return service.get(job_id)


@router.get("/connection-tests/{job_id}/export")
def export_batch(job_id: str, operator: Annotated[AuthenticatedUser, Depends(require_operator)], format: str = "csv", service=Depends(get_batch_service)):
    content, media_type, filename = service.export(job_id, format)
    return Response(content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


def _public_settings(name, payload):
    try:
        return SETTINGS_MODELS[name].model_validate(payload)
    except ValidationError:
        raise ManagementError("Invalid stored management configuration.", 500) from None


@router.get("/mappings/{name}", response_model=SettingsPayload)
def get_settings(name: SettingsName, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    return _public_settings(name, service.get_config(name))


@router.put(
    "/mappings/{name}",
    response_model=SettingsPayload,
    description=(
        "Replace one credential-free configuration. Use table/search_column for device_lookup; "
        "key_columns/map for client_mapping or proxy_mapping. Client map values must be supported "
        "gateway class paths; proxy map values are hostnames/IP addresses or null for direct access. "
        "Database URLs, credentials, and arbitrary import paths are not accepted."
    ),
)
def update_settings(name: SettingsName, payload: SettingsPayload, admin: Annotated[AuthenticatedUser, Depends(require_administrator)], service=Depends(get_management_service)):
    try:
        validated = SETTINGS_MODELS[name].model_validate(payload.model_dump())
    except ValidationError:
        raise HTTPException(422, "Invalid settings fields for the selected configuration.") from None
    return _public_settings(name, service.save_config(name, validated.model_dump()))
