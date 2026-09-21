"""Simulated device inventory and persistent route management."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.api.routes.management import SafeManagementRoute, get_store
from app.api.schemas.device_data import (
    DeviceInventory, StaticRouteCollection, StaticRouteItem, StaticRouteWrite,
)
from app.bl.services.device_data import DeviceDataService
from app.bl.services.management import resolve_correlation_id
from app.common.identity import AuthenticatedUser, require_operator, require_viewer

router = APIRouter(prefix="/api/v1", route_class=SafeManagementRoute, tags=["device data"])


def get_device_data_service(request: Request, store=Depends(get_store)):
    return DeviceDataService(
        store, provider=getattr(request.app.state, "device_data_provider", "disabled"),
    )


@router.get("/connections/{connection_id}/inventory", response_model=DeviceInventory)
def get_inventory(
    connection_id: str,
    viewer: Annotated[AuthenticatedUser, Depends(require_viewer)],
    service=Depends(get_device_data_service),
):
    return service.inventory(connection_id)


@router.get("/connections/{connection_id}/static-routes", response_model=StaticRouteCollection)
def list_static_routes(
    connection_id: str,
    viewer: Annotated[AuthenticatedUser, Depends(require_viewer)],
    service=Depends(get_device_data_service),
):
    return service.list_static_routes(connection_id)


@router.post(
    "/connections/{connection_id}/static-routes", response_model=StaticRouteItem, status_code=201,
)
def create_static_route(
    connection_id: str,
    payload: StaticRouteWrite,
    request: Request,
    response: Response,
    operator: Annotated[AuthenticatedUser, Depends(require_operator)],
    service=Depends(get_device_data_service),
):
    correlation_id = resolve_correlation_id(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return service.create_static_route(
        connection_id, payload.model_dump(), actor=operator, correlation_id=correlation_id,
        request_method=request.method, request_path=request.url.path,
    )


@router.put(
    "/connections/{connection_id}/static-routes/{route_id}", response_model=StaticRouteItem,
)
def update_static_route(
    connection_id: str,
    route_id: str,
    payload: StaticRouteWrite,
    request: Request,
    response: Response,
    operator: Annotated[AuthenticatedUser, Depends(require_operator)],
    service=Depends(get_device_data_service),
):
    correlation_id = resolve_correlation_id(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return service.update_static_route(
        connection_id, route_id, payload.model_dump(), actor=operator, correlation_id=correlation_id,
        request_method=request.method, request_path=request.url.path,
    )


@router.delete("/connections/{connection_id}/static-routes/{route_id}", status_code=204)
def delete_static_route(
    connection_id: str,
    route_id: str,
    request: Request,
    response: Response,
    operator: Annotated[AuthenticatedUser, Depends(require_operator)],
    service=Depends(get_device_data_service),
):
    correlation_id = resolve_correlation_id(request)
    service.delete_static_route(
        connection_id, route_id, actor=operator, correlation_id=correlation_id,
        request_method=request.method, request_path=request.url.path,
    )
    return Response(status_code=204, headers={"X-Correlation-ID": correlation_id})