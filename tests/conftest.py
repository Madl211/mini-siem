import os

# WICHTIG: muss VOR dem Import von app.database gesetzt werden, da DATABASE_URL
# beim Modul-Import einmalig ausgewertet wird.
os.environ["MINI_SIEM_DATABASE_URL"] = "sqlite:///./test_mini_siem.db"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app


@pytest.fixture(autouse=True)
def reset_database():
    """Sorgt fuer eine frische, leere Datenbank vor jedem einzelnen Test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture()
def db_session():
    """Direkter DB-Zugriff fuer Tests ohne HTTP-Ebene (Parser, Detection Engine)."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client():
    """FastAPI-TestClient fuer Tests der API-Endpunkte."""
    with TestClient(app) as test_client:
        yield test_client
