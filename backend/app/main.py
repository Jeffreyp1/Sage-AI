"""FastAPI application entrypoint."""

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_health import router as health_router
from app.api.routes_remediation import router as remediation_router
from app.api.routes_repos import router as repos_router


def sanitized_validation_errors(exc: RequestValidationError) -> list[dict[str, object]]:
    details = []
    for error in exc.errors():
        loc = error.get("loc", ())
        location = str(loc[0]) if loc else "request"
        details.append(
            {
                "type": str(error.get("type", "value_error")),
                "loc": [location],
                "msg": "Invalid request field.",
            }
        )
    return details


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sage AI API",
        description="Agentic vulnerability triage and remediation backend.",
        version="0.1.0",
    )

    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(
        _request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": sanitized_validation_errors(exc)},
        )

    app.include_router(health_router)
    app.include_router(repos_router)
    app.include_router(remediation_router)
    app.include_router(dashboard_router)
    return app


app = create_app()
