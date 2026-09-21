"""Serve the API-driven administrative UI without device or database logic."""
import mimetypes
from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
router = APIRouter()


@router.get("/ui", response_class=FileResponse, include_in_schema=False)
@router.get("/ui/", response_class=FileResponse, include_in_schema=False)
def index():
    return FileResponse(ROOT / "templates" / "index.html")


def register_ui(app: FastAPI) -> None:
    mimetypes.add_type("text/javascript", ".mjs")
    app.mount("/ui/static", StaticFiles(directory=ROOT / "static"), name="ui-static")
    app.include_router(router)
