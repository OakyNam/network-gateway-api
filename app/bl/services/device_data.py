"""Explicit fake-only device operations through the persisted access graph."""

import logging

from app.bl.services.management import ManagementError, store_call

logger = logging.getLogger(__name__)


class DeviceDataService:
    def __init__(self, store, *, provider="disabled"):
        self.store = store
        self.provider = provider

    def _client(self, connection_id):
        if self.provider != "fake":
            raise ManagementError("Simulated device access is disabled.", 503)
        profile = store_call(self.store, "get", "connections", connection_id)
        if profile.get("client_type", "network") != "fake":
            raise ManagementError("Device data is unsupported for network profiles.", 501)
        from app.dal.device.fake_client import FakeDeviceClient

        return FakeDeviceClient(self.store, connection_id)

    @staticmethod
    def _audit_context(*, actor, correlation_id, action, request_method, request_path):
        """Actor/correlation metadata only -- resource_type/resource_id/connection_id/
        outcome/before_state/after_state are filled in by the store's atomic
        *_static_route_audited methods and must not be supplied here.
        """
        return {
            "correlation_id": correlation_id,
            "actor_subject": actor.subject,
            "actor_tenant_id": actor.tenant_id,
            "actor_name": actor.name,
            "actor_email": actor.email,
            "actor_roles": sorted(actor.roles),
            "auth_mode": actor.auth_mode,
            "action": action,
            "request_method": request_method,
            "request_path": request_path,
        }

    def _record_failure(self, audit, *, resource_id, connection_id, detail):
        """Best-effort failed-attempt audit row via the separate, non-atomic
        append_transaction call; never masks the original mutation error.
        """
        try:
            store_call(self.store, "append_transaction", {
                **audit, "resource_type": "static_route", "resource_id": resource_id,
                "connection_id": connection_id, "outcome": "failed", "detail": detail,
                "before_state": None, "after_state": None,
            })
        except ManagementError:
            logger.error("Failed static-route attempt could not be audited.")

    def inventory(self, connection_id):
        return store_call(self._client(connection_id), "inventory")

    def list_static_routes(self, connection_id):
        items = store_call(self._client(connection_id), "list_static_routes")
        return {"provider": "fake", "simulated": True, "items": items}

    def create_static_route(self, connection_id, payload, *, actor, correlation_id, request_method, request_path):
        audit = self._audit_context(
            actor=actor, correlation_id=correlation_id, action="static_route.create",
            request_method=request_method, request_path=request_path,
        )
        try:
            client = self._client(connection_id)
            item = store_call(
                client, "create_static_route", payload,
                audit={**audit, "detail": "Static route created."},
            )
        except ManagementError as exc:
            self._record_failure(
                audit, resource_id=None, connection_id=connection_id, detail=str(exc),
            )
            raise
        return {"provider": "fake", "simulated": True, "item": item}

    def update_static_route(self, connection_id, route_id, payload, *, actor, correlation_id, request_method, request_path):
        audit = self._audit_context(
            actor=actor, correlation_id=correlation_id, action="static_route.update",
            request_method=request_method, request_path=request_path,
        )
        try:
            client = self._client(connection_id)
            item = store_call(
                client, "update_static_route", route_id, payload,
                audit={**audit, "detail": "Static route updated."},
            )
        except ManagementError as exc:
            self._record_failure(
                audit, resource_id=route_id, connection_id=connection_id, detail=str(exc),
            )
            raise
        return {"provider": "fake", "simulated": True, "item": item}

    def delete_static_route(self, connection_id, route_id, *, actor, correlation_id, request_method, request_path):
        audit = self._audit_context(
            actor=actor, correlation_id=correlation_id, action="static_route.delete",
            request_method=request_method, request_path=request_path,
        )
        try:
            client = self._client(connection_id)
            store_call(
                client, "delete_static_route", route_id,
                audit={**audit, "detail": "Static route deleted."},
            )
        except ManagementError as exc:
            self._record_failure(
                audit, resource_id=route_id, connection_id=connection_id, detail=str(exc),
            )
            raise