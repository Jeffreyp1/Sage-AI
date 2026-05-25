"""Health routes."""

from fastapi import APIRouter

from app import __version__

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "vulnsage-ai-backend",
        "version": __version__,
    }

