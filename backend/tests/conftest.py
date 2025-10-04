from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pytest
from fastapi.testclient import TestClient
from backend.main import app, get_db
from backend.database import Base

import uuid

# Use in-memory SQLite for full isolation
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test_test.db" 
engine = create_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override FastAPI dependency
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db


# Fixture: create fresh database before tests
@pytest.fixture(scope="session", autouse=True)
def create_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client():
    # Create tables before each test
    Base.metadata.create_all(bind=engine)
    yield TestClient(app)
    # Drop tables after each test
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_user(client):
    unique_id = uuid.uuid4().hex[:6]
    user_data = {
        "username": f"testuser_{unique_id}",
        "email": f"test_{unique_id}@example.com",
        "password": "password123"
    }
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 200, f"User registration failed: {response.json()}"

    # login to get token
    login_resp = client.post("/auth/login", data={"username": user_data["username"], "password": user_data["password"]})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    return {"user": user_data, "token": token, "headers": {"Authorization": f"Bearer {token}"}}

@pytest.fixture(autouse=True)
def clear_db():
    yield
    from backend.models import User, Recipe, Favorite  # adjust imports
    db = TestingSessionLocal()
    db.query(Favorite).delete()
    db.query(Recipe).delete()
    db.query(User).delete()
    db.commit()
    db.close()

def test_create_recipe(client, test_user):
    headers = test_user["headers"]
    response = client.post(
        "/recipes",
        json={"title": "My Recipe", "ingredients": "Eggs", "instructions": "Cook it"},
        headers=headers
    )
    assert response.status_code == 200
