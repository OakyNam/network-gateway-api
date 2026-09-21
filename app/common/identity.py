"""Authentication primitives and reusable FastAPI authorization dependencies."""

from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request

GatewayRole = Literal["Viewer", "Operator", "Administrator"]
_ROLE_RANK = {"Viewer": 1, "Operator": 2, "Administrator": 3}


@dataclass(frozen=True)
class AuthenticatedUser:
    subject: str
    tenant_id: str | None
    name: str
    email: str | None
    roles: frozenset[GatewayRole]
    auth_mode: Literal["entra", "demo"]

    def public(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "email": self.email,
            "roles": sorted(self.roles),
            "auth_mode": self.auth_mode,
        }


def has_role(user: AuthenticatedUser, required: GatewayRole) -> bool:
    return any(_ROLE_RANK[role] >= _ROLE_RANK[required] for role in user.roles)


def current_user(request: Request) -> AuthenticatedUser:
    from app.bl.services.auth import AuthenticationService

    try:
        return AuthenticationService.from_request(request).authenticate_request(request)
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=401, detail="Authentication is unavailable.") from None


def require_role(required: GatewayRole):
    def dependency(user: Annotated[AuthenticatedUser, Depends(current_user)]) -> AuthenticatedUser:
        if not has_role(user, required):
            raise HTTPException(status_code=403, detail="Insufficient role.")
        return user
    return dependency


require_viewer = require_role("Viewer")
require_operator = require_role("Operator")
require_administrator = require_role("Administrator")
