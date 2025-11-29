# tests/conftest.py - REPLACE your current conftest.py with this

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.main import app
from app.database import Base, get_db
from app import models, schemas, crud

# Test database setup
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Fixtures
@pytest.fixture(scope="function")
def create_test_db():
    """Create test database tables"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(create_test_db):
    """Create a fresh database session for each test"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def clear_db(create_test_db):
    """Clear database between tests"""
    db = TestingSessionLocal()
    try:
        # Clear all tables
        db.query(models.Favorite).delete()
        db.query(models.Recipe).delete()
        db.query(models.User).delete()
        db.commit()
        yield db
    finally:
        db.close()


def override_get_db():
    """Override database dependency for testing"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# Override the dependency
app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
def test_client(create_test_db):
    """Create a test client for the FastAPI app"""
    client = TestClient(app)
    yield client


@pytest.fixture(scope="function")
def client(create_test_db):
    """Alias for test_client - some tests use 'client' instead"""
    client = TestClient(app)
    yield client


@pytest.fixture(scope="function")
def test_user(db_session: Session):
    """Create a test user"""
    user_data = schemas.UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpassword123"
    )
    user = crud.create_user(db=db_session, user=user_data)
    # Store the plain password for login tests
    user.plain_password = "testpassword123"
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
        data={
            "username": test_user.username,
            "password": test_user.plain_password
        }
    )
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        raise Exception(f"Failed to get auth token: {response.json()}")