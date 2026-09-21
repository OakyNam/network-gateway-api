"""Immutable, read-only transaction (audit) API contracts."""

from typing import Literal

from pydantic import BaseModel, Field

Outcome = Literal["succeeded", "failed"]


class TransactionRecord(BaseModel):
    id: str
    timestamp_utc: str
    correlation_id: str
    actor_subject: str
    actor_tenant_id: str | None = None
    actor_name: str
    actor_email: str | None = None
    actor_roles: list[str]
    auth_mode: Literal["entra", "demo"]
    action: str
    resource_type: str
    resource_id: str | None = None
    connection_id: str | None = None
    outcome: Outcome
    before_state: dict | list | str | int | float | bool | None = None
    after_state: dict | list | str | int | float | bool | None = None
    detail: str | None = None
    request_method: str | None = None
    request_path: str | None = None


class TransactionCollection(BaseModel):
    items: list[TransactionRecord]
    total: int = Field(ge=0)
