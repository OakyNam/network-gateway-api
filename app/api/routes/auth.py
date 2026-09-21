"""Public browser authentication and session endpoints."""

import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.bl.services.auth import AuthenticationService
from app.common.identity import current_user
from config.settings import auth_settings

router = APIRouter(prefix="/api/v1", tags=["authentication"])


def _secure_cookie(request: Request) -> bool:
    return request.url.hostname not in {"localhost", "127.0.0.1", "::1"}


@router.get("/session")
def session(request: Request):
    try:
        return {"user": current_user(request).public()}
    except HTTPException as exc:
        if exc.status_code == 401:
            return {"user": None}
        raise


@router.get("/login")
def login(request: Request):
    service = AuthenticationService.from_request(request)
    redirect_uri = str(request.url_for("oidc_callback"))
    started = service.start_login(redirect_uri)
    response = RedirectResponse(started.authorization_url, status_code=302)
    response.set_cookie(
        "gateway_oidc_flow", started.state_cookie, httponly=True, secure=_secure_cookie(request),
        samesite="lax", max_age=600, path="/api/v1",
    )
    return response


@router.get("/callback", name="oidc_callback")
def callback(request: Request, code: str = Query(...), state: str = Query(...)):
    service = AuthenticationService.from_request(request)
    user = service.complete_login(code, state, request.cookies.get("gateway_oidc_flow"))
    response = RedirectResponse("/ui", status_code=302)
    response.delete_cookie("gateway_oidc_flow", path="/api/v1")
    response.set_cookie(
        "gateway_session", service.session_cookie(user, time.time() + 3600),
        httponly=True, secure=_secure_cookie(request), samesite="lax", max_age=3600, path="/",
    )
    return response


@router.get("/logout")
def logout(request: Request):
    settings = auth_settings()
    response = JSONResponse({"detail": "Signed out."})
    response.delete_cookie("gateway_session", path="/")
    if settings.mode == "entra" and settings.post_logout_redirect_uri:
        response = RedirectResponse(settings.post_logout_redirect_uri, status_code=302)
        response.delete_cookie("gateway_session", path="/")
    return response
