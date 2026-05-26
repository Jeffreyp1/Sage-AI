"""FastAPI application entrypoint."""

from fastapi import FastAPI

from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_health import router as health_router
from app.api.routes_remediation import router as remediation_router
from app.api.routes_repos import router as repos_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="VulnSage AI API",
        description="Agentic vulnerability triage and remediation backend.",
        version="0.1.0",
    )
    app.include_router(health_router)
    app.include_router(repos_router)
    app.include_router(remediation_router)
    app.include_router(dashboard_router)
    return app


app = create_app()
