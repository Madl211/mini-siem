from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import alerts, events, exports, logs
from app.database import SessionLocal, init_db
from app.detection.rules import load_rules, sync_rules_to_db

RULES_CONFIG_PATH = "app/detection/config.yaml"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        rules = load_rules(RULES_CONFIG_PATH)
        sync_rules_to_db(db, rules)
    finally:
        db.close()
    yield


app = FastAPI(title="Mini-SIEM", lifespan=lifespan)

app.include_router(events.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(exports.router, prefix="/api")

app.mount("/", StaticFiles(directory="app/static", html=True), name="static")