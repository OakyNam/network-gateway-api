"""Network Gateway API composition root: routes, UI and worker lifecycle."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

from app.api.routes.management import router as management_router, shutdown_management
from app.api.routes.device_data import router as device_data_router
from app.api.routes.auth import router as auth_router
from app.api.routes.transactions import router as transactions_router
from app.routes import router
from config.logger import setup_logging
from config.settings import device_data_provider
from app.ui.routes import register_ui


@asynccontextmanager
async def lifespan(application: FastAPI):
    try:
        yield
    finally:
        try:
            await shutdown_management(application)
        finally:
            store = getattr(application.state, "management_store", None)
            if store is not None:
                await run_in_threadpool(store.close)
            application.state.management_batches = None
            application.state.management_store = None

setup_logging()

app = FastAPI(
    title="Network Gateway API",
    description="API-first device profiles, reusable credentials, proxy paths and connection tests.",
    lifespan=lifespan,
)
app.state.demo_mode = False
app.state.device_data_provider = device_data_provider()
app.include_router(router)
app.include_router(auth_router)
app.include_router(management_router)
app.include_router(device_data_router)
app.include_router(transactions_router)
register_ui(app)


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse("/ui")
