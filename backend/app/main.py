from pathlib import Path

from fastapi import FastAPI

from .api.routes import auth, reports, scans
from .core.config import settings
from .core.database import Base, engine

app = FastAPI(title="SQLHawk API", version="0.1.0")


@app.on_event("startup")
def on_startup() -> None:
    _ensure_sqlite_dir()
    _ensure_reports_dir()
    Base.metadata.create_all(bind=engine)


def _ensure_sqlite_dir() -> None:
    if settings.api_database_url.startswith("sqlite:///"):
        path = settings.api_database_url.replace("sqlite:///", "", 1)
        Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def _ensure_reports_dir() -> None:
    Path(settings.reports_dir).expanduser().resolve().mkdir(parents=True, exist_ok=True)


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(reports.router)
