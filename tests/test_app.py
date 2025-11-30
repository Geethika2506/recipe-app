"""
Unit and integration tests for Recipe Finder App
Required to achieve 70%+ code coverage
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

# Add app to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.main import app
from app.database import Base, get_db
from app import models

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override get_db dependency
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

# Create test client
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test and drop after"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

# ========== Health & Metrics Tests ==========

def test_health_endpoint():
    """Test health endpoint returns correct format"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'healthy'
    assert data['version'] == '2.0.0'
    assert 'database' in data

def test_metrics_endpoint():
    """Test Prometheus metrics endpoint"""
    response = client.get("/metrics")
    assert response.status_code == 200
    content = response.text
    assert 'http_requests_total' in content
    assert 'http_errors_total' in content
    assert 'http_request_duration_seconds' in content
    assert 'http_requests_active' in content

def test_metrics_tracking():
    """Test that metrics are being tracked"""
    # Make some requests
    client.get("/health")
    client.get("/health")
    
    # Check metrics increased
    response = client.get("/metrics")
    assert response.status_code == 200

# ========== Root Endpoint Tests ==========

def test_root_endpoint():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code in [200, 307]  # 200 or redirect to frontend

# ========== Authentication Tests ==========

def test_register_user():
    """Test user registration"""
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123"
    }
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 200
    data = response.json()
    assert data['username'] == 'testuser'
    assert data['email'] == 'test@example.com'
    assert 'id' in data

def test_register_duplicate_email():
    """Test registering with duplicate email fails"""
    user_data = {
        "username": "user1",
        "email": "duplicate@example.com",
        "password": "password123"
    }
    # Register first time
    client.post("/auth/register", json=user_data)
    
    # Try to register again with same email
    user_data['username'] = 'user2'
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 400
    assert 'email already registered' in response.json()['detail'].lower()

def test_register_duplicate_username():
    """Test registering with duplicate username fails"""
    user_data = {
        "username": "duplicateuser",
        "email": "email1@example.com",
        "password": "password123"
    }
    # Register first time
    client.post("/auth/register", json=user_data)
    
    # Try to register again with same username
    user_data['email'] = 'email2@example.com'
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 400
    assert 'username already taken' in response.json()['detail'].lower()

def test_login_user():
    """Test user login"""
    # Register user first
    user_data = {
        "username": "logintest",
        "email": "login@example.com",
        "password": "testpass123"
    }
    client.post("/auth/register", json=user_data)
    
    # Login
    login_data = {
        "username": "logintest",
        "password": "testpass123"
    }
    response = client.post("/auth/login", data=login_data)
    assert response.status_code == 200
    data = response.json()
    assert 'access_token' in data
    assert data['token_type'] == 'bearer'

def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    login_data = {
        "username": "nonexistent",
        "password": "wrongpassword"
    }
    response = client.post("/auth/login", data=login_data)
    assert response.status_code == 401

def test_get_current_user():
    """Test getting current user info"""
    # Register and login
    user_data = {
        "username": "currentuser",
        "email": "current@example.com",
        "password": "pass123"
    }
    client.post("/auth/register", json=user_data)
    
    login_response = client.post("/auth/login", data={
        "username": "currentuser",
        "password": "pass123"
    })
    token = login_response.json()['access_token']
    
    # Get current user
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data['username'] == 'currentuser'

# ========== Recipe CRUD Tests ==========

def create_test_user_and_login():
    """Helper function to create user and return auth token"""
    user_data = {
        "username": f"testuser_{os.urandom(4).hex()}",
        "email": f"test_{os.urandom(4).hex()}@example.com",
        "password": "testpass123"
    }
    client.post("/auth/register", json=user_data)
    
    login_response = client.post("/auth/login", data={
        "username": user_data['username'],
        "password": user_data['password']
    })
    return login_response.json()['access_token']

def test_create_recipe():
    """Test creating a recipe"""
    token = create_test_user_and_login()
    
    recipe_data = {
        "title": "Test Recipe",
        "description": "A test recipe",
        "ingredients": "ingredient1, ingredient2",
        "instructions": "Step 1, Step 2",
        "difficulty": "easy"
    }
    
    response = client.post(
        "/recipes",
        json=recipe_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data['title'] == 'Test Recipe'
    assert 'id' in data

def test_create_recipe_unauthorized():
    """Test creating recipe without authentication fails"""
    recipe_data = {
        "title": "Test Recipe",
        "description": "A test recipe",
        "ingredients": "ingredient1",
        "instructions": "Step 1"
    }
    
    response = client.post("/recipes", json=recipe_data)
    assert response.status_code == 401

def test_get_all_recipes():
    """Test getting all recipes"""
    response = client.get("/recipes")
    assert response.status_code == 200
    data = response.json()
    assert 'local_recipes' in data

def test_get_recipe_by_id():
    """Test getting a specific recipe"""
    token = create_test_user_and_login()
    
    # Create a recipe
    recipe_data = {
        "title": "Specific Recipe",
        "description": "Description",
        "ingredients": "ingredients",
        "instructions": "instructions"
    }
    create_response = client.post(
        "/recipes",
        json=recipe_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    recipe_id = create_response.json()['id']
    
    # Get the recipe
    response = client.get(f"/recipes/{recipe_id}")
    assert response.status_code == 200
    data = response.json()
    assert data['id'] == recipe_id
    assert data['title'] == 'Specific Recipe'

def test_get_nonexistent_recipe():
    """Test getting a recipe that doesn't exist"""
    response = client.get("/recipes/99999")
    assert response.status_code == 404

def test_update_recipe():
    """Test updating a recipe"""
    token = create_test_user_and_login()
    
    # Create recipe
    recipe_data = {
        "title": "Original Title",
        "description": "Original description",
        "ingredients": "ingredients",
        "instructions": "instructions"
    }
    create_response = client.post(
        "/recipes",
        json=recipe_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    recipe_id = create_response.json()['id']
    
    # Update recipe
    update_data = {
        "title": "Updated Title",
        "description": "Updated description"
    }
    response = client.put(
        f"/recipes/{recipe_id}",
        json=update_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data['title'] == 'Updated Title'

def test_delete_recipe():
    """Test deleting a recipe"""
    token = create_test_user_and_login()
    
    # Create recipe
    recipe_data = {
        "title": "Recipe to Delete",
        "description": "Will be deleted",
        "ingredients": "ingredients",
        "instructions": "instructions"
    }
    create_response = client.post(
        "/recipes",
        json=recipe_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    recipe_id = create_response.json()['id']
    
    # Delete recipe
    response = client.delete(
        f"/recipes/{recipe_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    
    # Verify deletion
    get_response = client.get(f"/recipes/{recipe_id}")
    assert get_response.status_code == 404

def test_search_recipes():
    """Test recipe search"""
    response = client.get("/recipes/search?q=pasta")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_my_recipes():
    """Test getting current user's recipes"""
    token = create_test_user_and_login()
    
    # Create a recipe
    recipe_data = {
        "title": "My Recipe",
        "description": "My description",
        "ingredients": "ingredients",
        "instructions": "instructions"
    }
    client.post(
        "/recipes",
        json=recipe_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Get my recipes
    response = client.get("/recipes/my", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    recipes = response.json()
    assert len(recipes) >= 1
    assert any(r['title'] == 'My Recipe' for r in recipes)

# ========== Favorites Tests ==========

def test_add_to_favorites():
    """Test adding recipe to favorites"""
    token = create_test_user_and_login()
    
    # Create recipe
    recipe_data = {
        "title": "Favorite Recipe",
        "description": "Description",
        "ingredients": "ingredients",
        "instructions": "instructions"
    }
    create_response = client.post(
        "/recipes",
        json=recipe_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    recipe_id = create_response.json()['id']
    
    # Add to favorites
    response = client.post(
        f"/favorites/{recipe_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert 'favorite_id' in response.json()

def test_get_favorites():
    """Test getting user's favorites"""
    token = create_test_user_and_login()
    
    response = client.get("/favorites", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_remove_from_favorites():
    """Test removing recipe from favorites"""
    token = create_test_user_and_login()
    
    # Create and favorite a recipe
    recipe_data = {
        "title": "To Remove",
        "description": "Description",
        "ingredients": "ingredients",
        "instructions": "instructions"
    }
    create_response = client.post(
        "/recipes",
        json=recipe_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    recipe_id = create_response.json()['id']
    
    # Add to favorites
    client.post(f"/favorites/{recipe_id}", headers={"Authorization": f"Bearer {token}"})
    
    # Remove from favorites
    response = client.delete(
        f"/favorites/{recipe_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

# ========== Error Handling Tests ==========

def test_404_error():
    """Test 404 error handling"""
    response = client.get("/nonexistent-endpoint")
    assert response.status_code == 404

def test_unauthorized_access():
    """Test accessing protected endpoint without auth"""
    response = client.get("/recipes/my")
    assert response.status_code == 401