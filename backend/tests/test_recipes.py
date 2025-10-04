import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ..database import Base, get_db
from ..main import app
from .. import models, crud, schemas

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_recipes.db"
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

# Helper function to create and login a user, return auth header
def create_auth_user(username="testuser", email="test@example.com", password="testpass123"):
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password}
    )
    response = client.post("/auth/login", data={"username": username, "password": password})
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

class TestRecipeCreation:
    """Test recipe creation functionality"""
    
    def test_create_recipe_success(self):
        """Test successful recipe creation"""
        headers = create_auth_user("creator1", "creator1@test.com")
        response = client.post(
            "/recipes",
            json={
                "title": "Test Recipe",
                "description": "A delicious test recipe",
                "ingredients": "flour, sugar, eggs",
                "instructions": "Mix and bake",
                "prep_time": 15,
                "cook_time": 30,
                "servings": 4,
                "difficulty": "easy"
            },
            headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Test Recipe"
        assert data["prep_time"] == 15
        assert "id" in data
    
    def test_create_recipe_minimal(self):
        """Test creating recipe with minimal fields"""
        headers = create_auth_user("creator2", "creator2@test.com")
        response = client.post(
            "/recipes",
            json={
                "title": "Simple Recipe",
                "ingredients": "ingredient1, ingredient2",
                "instructions": "Mix and cook"
            },
            headers=headers
        )
        assert response.status_code == 200
        assert response.json()["title"] == "Simple Recipe"
    
    def test_create_recipe_unauthorized(self):
        """Test creating recipe without authentication"""
        response = client.post(
            "/recipes",
            json={
                "title": "Unauthorized Recipe",
                "ingredients": "test",
                "instructions": "test"
            }
        )
        assert response.status_code == 401

class TestRecipeRetrieval:
    """Test recipe retrieval"""
    
    def test_get_all_recipes(self):
        """Test getting all recipes"""
        response = client.get("/recipes")
        assert response.status_code == 200
        data = response.json()
        assert "local_recipes" in data or isinstance(data, list)
    
    def test_get_my_recipes(self):
        """Test getting current user's recipes"""
        headers = create_auth_user("owner1", "owner1@test.com")
        
        # Create recipe
        client.post(
            "/recipes",
            json={"title": "My Recipe", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        
        # Get my recipes
        response = client.get("/recipes/my", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
    
    def test_get_recipe_by_id(self):
        """Test getting specific recipe"""
        headers = create_auth_user("getter1", "getter1@test.com")
        
        # Create recipe
        create_resp = client.post(
            "/recipes",
            json={"title": "Get Me", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        
        # Get recipe
        response = client.get(f"/recipes/{recipe_id}")
        assert response.status_code == 200
        assert response.json()["id"] == recipe_id
    
    def test_get_nonexistent_recipe(self):
        """Test getting non-existent recipe"""
        response = client.get("/recipes/99999")
        assert response.status_code == 404

class TestRecipeSearch:
    """Test recipe search"""
    
    def test_search_by_title(self):
        """Test searching recipes by title"""
        headers = create_auth_user("searcher1", "searcher1@test.com")
        
        # Create test recipe
        client.post(
            "/recipes",
            json={
                "title": "Chocolate Cake",
                "ingredients": "chocolate, flour",
                "instructions": "bake"
            },
            headers=headers
        )
        
        # Search
        response = client.get("/recipes/search?q=chocolate")
        assert response.status_code == 200
        results = response.json()
        assert len(results) >= 1
    
    def test_search_by_ingredients(self):
        """Test searching by ingredients"""
        headers = create_auth_user("searcher2", "searcher2@test.com")
        
        client.post(
            "/recipes",
            json={
                "title": "Chicken Dish",
                "ingredients": "chicken, garlic, onions",
                "instructions": "cook"
            },
            headers=headers
        )
        
        response = client.get("/recipes/search?q=chicken")
        assert response.status_code == 200
        assert len(response.json()) >= 1

class TestRecipeUpdate:
    """Test recipe updates"""
    
    def test_update_recipe(self):
        """Test updating a recipe"""
        headers = create_auth_user("updater1", "updater1@test.com")
        
        # Create recipe
        create_resp = client.post(
            "/recipes",
            json={
                "title": "Original",
                "ingredients": "original",
                "instructions": "original"
            },
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        
        # Update
        response = client.put(
            f"/recipes/{recipe_id}",
            json={"title": "Updated Title"},
            headers=headers
        )
        assert response.status_code == 200
        assert response.json()["title"] == "Updated Title"
    
    def test_update_unauthorized(self):
        """Test updating without auth"""
        headers = create_auth_user("updater2", "updater2@test.com")
        
        create_resp = client.post(
            "/recipes",
            json={"title": "Recipe", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        
        # Try update without auth
        response = client.put(
            f"/recipes/{recipe_id}",
            json={"title": "Hacked"}
        )
        assert response.status_code == 401

class TestRecipeDeletion:
    """Test recipe deletion"""
    
    def test_delete_recipe(self):
        """Test deleting a recipe"""
        headers = create_auth_user("deleter1", "deleter1@test.com")
        
        # Create recipe
        create_resp = client.post(
            "/recipes",
            json={"title": "Delete Me", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        
        # Delete
        response = client.delete(f"/recipes/{recipe_id}", headers=headers)
        assert response.status_code == 200
        
        # Verify deleted
        get_resp = client.get(f"/recipes/{recipe_id}")
        assert get_resp.status_code == 404
    
    def test_delete_unauthorized(self):
        """Test deleting without auth"""
        headers = create_auth_user("deleter2", "deleter2@test.com")
        
        create_resp = client.post(
            "/recipes",
            json={"title": "Recipe", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        
        # Try delete without auth
        response = client.delete(f"/recipes/{recipe_id}")
        assert response.status_code == 401

class TestFavorites:
    """Test favorite functionality"""
    
    def test_add_favorite(self):
        """Test adding recipe to favorites"""
        headers = create_auth_user("fav1", "fav1@test.com")
        
        # Create recipe
        create_resp = client.post(
            "/recipes",
            json={"title": "Favorite Recipe", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        
        # Add to favorites
        response = client.post(f"/favorites/{recipe_id}", headers=headers)
        assert response.status_code == 200
    
    def test_remove_favorite(self):
        """Test removing from favorites"""
        headers = create_auth_user("fav2", "fav2@test.com")
        
        # Create and favorite
        create_resp = client.post(
            "/recipes",
            json={"title": "Recipe", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        client.post(f"/favorites/{recipe_id}", headers=headers)
        
        # Remove favorite
        response = client.delete(f"/favorites/{recipe_id}", headers=headers)
        assert response.status_code == 200
    
    def test_get_favorites(self):
        """Test getting user favorites"""
        headers = create_auth_user("fav3", "fav3@test.com")
        
        # Create and favorite recipe
        create_resp = client.post(
            "/recipes",
            json={"title": "Fav Recipe", "ingredients": "test", "instructions": "test"},
            headers=headers
        )
        recipe_id = create_resp.json()["id"]
        client.post(f"/favorites/{recipe_id}", headers=headers)
        
        # Get favorites
        response = client.get("/favorites", headers=headers)
        assert response.status_code == 200
        assert len(response.json()) >= 1