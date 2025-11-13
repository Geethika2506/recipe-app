import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import uuid

from backend.database import Base, get_db
from backend.main import app
from backend import models, crud, schemas


# Use in-memory database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db():
    """Create fresh database for each test"""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db):
    """Create test client with database override"""
    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture
def test_user(client):
    """Create and return test user with token"""
    # Generate unique credentials for each test
    unique_id = str(uuid.uuid4())[:8]
    user_data = {
        "username": f"testuser_{unique_id}",
        "email": f"test_{unique_id}@example.com",
        "password": "password123"
    }
    
    # Register user
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 200, f"Registration failed: {response.json()}"
    
    # Login to get token
    login_data = {
        "username": user_data["username"],
        "password": "password123"
    }
    response = client.post("/auth/login", data=login_data)
    assert response.status_code == 200, f"Login failed: {response.json()}"
    token = response.json()["access_token"]
    
    return {
        "token": token, 
        "user": user_data,
        "username": user_data["username"],
        "email": user_data["email"]
    }


class TestAuthenticationRoutes:
    """Test authentication endpoints"""
    
    def test_register_user(self, client):
        """Test user registration"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "newpassword123"
        }
        response = client.post("/auth/register", json=user_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert "id" in data
    
    def test_register_duplicate_email(self, client, test_user):
        """Test registering with duplicate email fails"""
        user_data = {
            "username": "differentuser",
            "email": test_user["email"],  # Use existing email
            "password": "password123"
        }
        response = client.post("/auth/register", json=user_data)
        
        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]
    
    def test_register_duplicate_username(self, client, test_user):
        """Test registering with duplicate username fails"""
        user_data = {
            "username": test_user["username"],  # Use existing username
            "email": "different@example.com",
            "password": "password123"
        }
        response = client.post("/auth/register", json=user_data)
        
        assert response.status_code == 400
        assert "Username already taken" in response.json()["detail"]
    
    def test_login_success(self, client, test_user):
        """Test successful login"""
        login_data = {
            "username": test_user["username"],
            "password": "password123"
        }
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_wrong_password(self, client, test_user):
        """Test login with wrong password"""
        login_data = {
            "username": test_user["username"],
            "password": "wrongpassword"
        }
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 401
    
    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent username"""
        login_data = {
            "username": "nonexistent",
            "password": "password123"
        }
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 401
    
    def test_get_current_user(self, client, test_user):
        """Test getting current user info"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        response = client.get("/auth/me", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == test_user["username"]
        assert data["email"] == test_user["email"]
    
    def test_get_current_user_no_token(self, client):
        """Test getting current user without token fails"""
        response = client.get("/auth/me")
        assert response.status_code == 401


class TestRecipeRoutes:
    """Test recipe endpoints"""
    
    def test_create_recipe(self, client, test_user):
        """Test creating a recipe"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        recipe_data = {
            "title": "Test Recipe",
            "description": "A delicious recipe",
            "ingredients": "flour, eggs, milk",
            "instructions": "Mix and bake",
            "prep_time": 15,
            "cook_time": 30,
            "servings": 4,
            "difficulty": "easy"
        }
        response = client.post("/recipes", json=recipe_data, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Test Recipe"
        assert "id" in data
    
    def test_create_recipe_unauthorized(self, client):
        """Test creating recipe without authentication"""
        recipe_data = {
            "title": "Test Recipe",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        response = client.post("/recipes", json=recipe_data)
        
        assert response.status_code == 401
    
    def test_get_recipe(self, client, test_user):
        """Test getting a recipe by ID"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create recipe
        recipe_data = {
            "title": "Test Recipe",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        create_response = client.post("/recipes", json=recipe_data, headers=headers)
        recipe_id = create_response.json()["id"]
        
        # Get recipe
        response = client.get(f"/recipes/{recipe_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == recipe_id
    
    def test_get_nonexistent_recipe(self, client):
        """Test getting nonexistent recipe returns 404"""
        response = client.get("/recipes/99999")
        assert response.status_code == 404
    
    def test_get_all_recipes(self, client, test_user):
        """Test getting all recipes"""
        response = client.get("/recipes")
        
        assert response.status_code == 200
        data = response.json()
        assert "local_recipes" in data
        assert "external_recipes" in data
    
    def test_get_my_recipes(self, client, test_user):
        """Test getting current user's recipes"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create recipes
        for i in range(3):
            recipe_data = {
                "title": f"My Recipe {i}",
                "ingredients": "ingredients",
                "instructions": "instructions"
            }
            client.post("/recipes", json=recipe_data, headers=headers)
        
        # Get my recipes
        response = client.get("/recipes/my", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
    
    def test_search_recipes(self, client, test_user):
        """Test searching recipes"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create test recipes
        recipes = [
            {"title": "Chocolate Cake", "ingredients": "chocolate", "instructions": "bake"},
            {"title": "Vanilla Cookies", "ingredients": "vanilla", "instructions": "bake"}
        ]
        for recipe_data in recipes:
            client.post("/recipes", json=recipe_data, headers=headers)
        
        # Search
        response = client.get("/recipes/search", params={"q": "chocolate"})
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any("chocolate" in r["title"].lower() for r in data)
    
    def test_update_recipe(self, client, test_user):
        """Test updating a recipe"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create recipe
        recipe_data = {
            "title": "Original Title",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        create_response = client.post("/recipes", json=recipe_data, headers=headers)
        recipe_id = create_response.json()["id"]
        
        # Update recipe
        update_data = {"title": "Updated Title"}
        response = client.put(f"/recipes/{recipe_id}", json=update_data, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Updated Title"
    
    def test_update_recipe_unauthorized(self, client, test_user):
        """Test updating recipe without proper authorization"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create recipe
        recipe_data = {
            "title": "Recipe",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        create_response = client.post("/recipes", json=recipe_data, headers=headers)
        recipe_id = create_response.json()["id"]
        
        # Try to update without token
        update_data = {"title": "Hacked"}
        response = client.put(f"/recipes/{recipe_id}", json=update_data)
        
        assert response.status_code == 401
    
    def test_delete_recipe(self, client, test_user):
        """Test deleting a recipe"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create recipe
        recipe_data = {
            "title": "To Delete",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        create_response = client.post("/recipes", json=recipe_data, headers=headers)
        recipe_id = create_response.json()["id"]
        
        # Delete recipe
        response = client.delete(f"/recipes/{recipe_id}", headers=headers)
        assert response.status_code == 200
        
        # Verify deleted
        get_response = client.get(f"/recipes/{recipe_id}")
        assert get_response.status_code == 404
    
    def test_delete_recipe_unauthorized(self, client, test_user):
        """Test deleting recipe without authorization"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create recipe
        recipe_data = {
            "title": "Recipe",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        create_response = client.post("/recipes", json=recipe_data, headers=headers)
        recipe_id = create_response.json()["id"]
        
        # Try to delete without token
        response = client.delete(f"/recipes/{recipe_id}")
        assert response.status_code == 401


class TestFavoriteRoutes:
    """Test favorite endpoints"""
    
    def test_add_favorite(self, client, test_user):
        """Test adding recipe to favorites"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create recipe
        recipe_data = {
            "title": "Favorite Recipe",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        create_response = client.post("/recipes", json=recipe_data, headers=headers)
        recipe_id = create_response.json()["id"]
        
        # Add to favorites
        response = client.post(f"/favorites/{recipe_id}", headers=headers)
        assert response.status_code == 200
        assert "message" in response.json()
    
    def test_add_nonexistent_recipe_to_favorites(self, client, test_user):
        """Test adding nonexistent recipe to favorites"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        response = client.post("/favorites/99999", headers=headers)
        assert response.status_code == 404
    
    def test_get_favorites(self, client, test_user):
        """Test getting user's favorites"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create and favorite recipes
        for i in range(3):
            recipe_data = {
                "title": f"Recipe {i}",
                "ingredients": "ingredients",
                "instructions": "instructions"
            }
            create_response = client.post("/recipes", json=recipe_data, headers=headers)
            recipe_id = create_response.json()["id"]
            client.post(f"/favorites/{recipe_id}", headers=headers)
        
        # Get favorites
        response = client.get("/favorites", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
    
    def test_remove_favorite(self, client, test_user):
        """Test removing recipe from favorites"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        
        # Create and favorite recipe
        recipe_data = {
            "title": "Recipe",
            "ingredients": "ingredients",
            "instructions": "instructions"
        }
        create_response = client.post("/recipes", json=recipe_data, headers=headers)
        recipe_id = create_response.json()["id"]
        client.post(f"/favorites/{recipe_id}", headers=headers)
        
        # Remove from favorites
        response = client.delete(f"/favorites/{recipe_id}", headers=headers)
        assert response.status_code == 200
        
        # Verify removed
        favorites_response = client.get("/favorites", headers=headers)
        assert len(favorites_response.json()) == 0
    
    def test_remove_nonexistent_favorite(self, client, test_user):
        """Test removing nonexistent favorite"""
        headers = {"Authorization": f"Bearer {test_user['token']}"}
        response = client.delete("/favorites/99999", headers=headers)
        assert response.status_code == 404


class TestRootRoute:
    """Test root endpoint"""
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns expected response"""
        response = client.get("/")
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])