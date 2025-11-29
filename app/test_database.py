
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .database import Base

# Use in-memory SQLite database for testing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_test_db():
    """Get test database session"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

def setup_test_db():
    """Create all tables for testing"""
    Base.metadata.create_all(bind=engine)

def teardown_test_db():
    """Drop all tables after testing"""
    Base.metadata.drop_all(bind=engine)


# ============================================================
# STEP 3: Create Test Configuration File
# ============================================================
# Create a new file: tests/conftest.py

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
import sys
import os

# Add parent directory to path so we can import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.main import app
from app.test_database import get_test_db, setup_test_db, teardown_test_db
from app.database import get_db
from app import models, schemas, crud

# Override the database dependency
app.dependency_overrides[get_db] = get_test_db

@pytest.fixture(scope="session")
def test_client():
    """Create a test client for the FastAPI app"""
    setup_test_db()
    client = TestClient(app)
    yield client
    teardown_test_db()

@pytest.fixture(scope="function")
def db_session():
    """Create a fresh database session for each test"""
    setup_test_db()
    db = next(get_test_db())
    yield db
    db.close()
    teardown_test_db()

@pytest.fixture(scope="function")
def test_user(db_session: Session):
    """Create a test user"""
    user_data = schemas.UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpassword123"
    )
    user = crud.create_user(db=db_session, user=user_data)
    return user

@pytest.fixture(scope="function")
def test_recipe(db_session: Session, test_user):
    """Create a test recipe"""
    recipe_data = schemas.RecipeCreate(
        title="Test Recipe",
        description="A test recipe description",
        ingredients="1 cup flour\n2 eggs\n1 cup milk",
        instructions="Mix all ingredients and bake at 350°F for 30 minutes",
        prep_time=10,
        cook_time=30,
        servings=4,
        difficulty="easy",
        image_url="https://example.com/image.jpg"
    )
    recipe = crud.create_recipe(db=db_session, recipe=recipe_data, user_id=test_user.id)
    return recipe

@pytest.fixture(scope="function")
def auth_token(test_client, test_user):
    """Get authentication token for test user"""
    response = test_client.post(
        "/auth/login",
        data={"username": test_user.username, "password": "testpassword123"}
    )
    return response.json()["access_token"]