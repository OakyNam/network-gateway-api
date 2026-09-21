
"""
Root API router for the NETCONF Gateway.

This module aggregates all domain-specific routers (routers, interfaces, protocols, MPLS)
under a single FastAPI APIRouter instance for modularity and maintainability.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from app.common.identity import AuthenticatedUser, has_role, require_viewer
from app.api.routes.legacy.router_controller import router as router_controller
from app.api.routes.legacy.interface_controller import router as interface_controller
from app.api.routes.legacy.protocol_controller import router as protocol_controller
from app.api.routes.legacy.mpls_controller import router as mpls_controller
from app.api.routes.legacy.device_controller import router as device_controller

def require_legacy_read_only(
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_viewer)],
):
    if request.method in {"GET", "HEAD"}:
        return user
    if not has_role(user, "Administrator"):
        raise HTTPException(status_code=403, detail="Insufficient role.")
    raise HTTPException(
        status_code=501,
        detail="Legacy configuration mutations are disabled until they use the audited service boundary.",
    )


router = APIRouter(dependencies=[Depends(require_legacy_read_only)])
router.include_router(router_controller, prefix="/routers", tags=["Routers"])
router.include_router(interface_controller, prefix="/interfaces", tags=["Interfaces"])
router.include_router(protocol_controller, prefix="/protocols", tags=["Protocols"])
router.include_router(mpls_controller, prefix="/mpls", tags=["MPLS"])
router.include_router(device_controller, prefix="/devices", tags=["Devices"])
