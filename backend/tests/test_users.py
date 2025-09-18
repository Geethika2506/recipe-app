import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ..database import Base, get_db
from ..main import app

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

def test_register_user():
    response = client.post(
        "/auth/register",
        json={
            "username": "geethika",
            "email": "geethikareddy@example.com",
            "password": "test_123#"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "geethika"
    assert data["email"]== "geethikareddy@example.com"
    assert data["password"] == "test_123#"

def test_login_user():
    # First register a user
    client.post(
        "/auth/register",
        json={
            "username": "logintest",
            "email": "login@example.com",
            "password": "testpassword123"
        }
    )
    
    # Then try to login
    response = client.post(
        "/auth/login",
        data={
            "username": "logintest",
            "password": "testpassword123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"