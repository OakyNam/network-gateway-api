"""Immutable transaction (audit) read API. No PUT/POST/DELETE endpoints exist."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query

from app.api.routes.management import SafeManagementRoute, get_store
from app.api.schemas.transactions import TransactionCollection
from app.bl.services.transactions import TransactionsService
from app.common.identity import AuthenticatedUser, require_viewer

router = APIRouter(prefix="/api/v1", route_class=SafeManagementRoute, tags=["transactions"])


def get_transactions_service(store=Depends(get_store)):
    return TransactionsService(store)


@router.get("/transactions", response_model=TransactionCollection)
def list_transactions(
    viewer: Annotated[AuthenticatedUser, Depends(require_viewer)],
    connection_id: str | None = Query(default=None, max_length=128),
    action: str | None = Query(default=None, max_length=128),
    actor_subject: str | None = Query(default=None, max_length=255),
    outcome: Literal["succeeded", "failed"] | None = Query(default=None),
    from_time: str | None = Query(default=None, max_length=64),
    to_time: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service=Depends(get_transactions_service),
):
    return service.list(
        connection_id=connection_id, action=action, actor_subject=actor_subject, outcome=outcome,
        from_time=from_time, to_time=to_time, limit=limit, offset=offset,
    )