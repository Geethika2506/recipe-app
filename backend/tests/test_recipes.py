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

# Helper function to create and login a user, return auth header
def create_auth_user(username="testuser", email="test@example.com", password="testpass123"):
    # Register user
    client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password
        }
    )
    
    # Login to get token
    response = client.post(
        "/auth/login",
        data={
            "username": username,
            "password": password
        }
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_create_recipe():
    headers = create_auth_user()
    
    response = client.post(
        "/recipes/",
        json={
            "title": "Test Recipe",
            "description": "A delicious test recipe",
            "ingredients": "flour, sugar, eggs",
            "instructions": "Mix ingredients and bake",
            "prep_time": 15,
            "cook_time": 30,
            "servings": 4,
            "difficulty": "easy",
            "is_public": True
        },
        headers=headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Test Recipe"
    assert data["description"] == "A delicious test recipe"
    assert data["ingredients"] == "flour, sugar, eggs"
    assert data["prep_time"] == 15
    assert data["cook_time"] == 30
    assert data["servings"] == 4
    assert data["difficulty"] == "easy"
    assert data["is_public"] == True

def test_create_recipe_unauthorized():
    response = client.post(
        "/recipes/",
        json={
            "title": "Test Recipe",
            "description": "A delicious test recipe",
            "ingredients": "flour, sugar, eggs",
            "instructions": "Mix ingredients and bake",
            "prep_time": 15,
            "cook_time": 30,
            "servings": 4,
            "difficulty": "easy",
            "is_public": True
        }
    )
    
    assert response.status_code == 401

def test_read_public_recipes():
    headers = create_auth_user("recipeuser", "recipe@example.com")
    
    # Create a public recipe
    client.post(
        "/recipes/",
        json={
            "title": "Public Recipe",
            "description": "A public recipe",
            "ingredients": "ingredients",
            "instructions": "instructions",
            "prep_time": 10,
            "cook_time": 20,
            "servings": 2,
            "difficulty": "easy",
            "is_public": True
        },
        headers=headers
    )
    
    # Read recipes without auth (should work for public recipes)
    response = client.get("/recipes/")
    
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert data[0]["title"] == "Public Recipe"
    assert data[0]["is_public"] == True

def test_read_my_recipes():
    headers = create_auth_user("myrecipeuser", "myrecipe@example.com")
    
    # Create a recipe
    client.post(
        "/recipes/",
        json={
            "title": "My Recipe",
            "description": "My personal recipe",
            "ingredients": "secret ingredients",
            "instructions": "secret instructions",
            "prep_time": 5,
            "cook_time": 10,
            "servings": 1,
            "difficulty": "medium",
            "is_public": False
        },
        headers=headers
    )
    
    # Read my recipes
    response = client.get("/recipes/my", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert data[0]["title"] == "My Recipe"
    assert data[0]["is_public"] == False

def test_read_specific_recipe():
    headers = create_auth_user("specificuser", "specific@example.com")
    
    # Create a recipe
    create_response = client.post(
        "/recipes/",
        json={
            "title": "Specific Recipe",
            "description": "A specific recipe to test",
            "ingredients": "specific ingredients",
            "instructions": "specific instructions",
            "prep_time": 12,
            "cook_time": 25,
            "servings": 3,
            "difficulty": "hard",
            "is_public": True
        },
        headers=headers
    )
    
    recipe_id = create_response.json()["id"]
    
    # Read the specific recipe
    response = client.get(f"/recipes/{recipe_id}")
    
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Specific Recipe"
    assert data["id"] == recipe_id

def test_read_private_recipe_forbidden():
    headers = create_auth_user("privateuser", "private@example.com")
    
    # Create a private recipe
    create_response = client.post(
        "/recipes/",
        json={
            "title": "Private Recipe",
            "description": "A private recipe",
            "ingredients": "private ingredients",
            "instructions": "private instructions",
            "prep_time": 8,
            "cook_time": 15,
            "servings": 2,
            "difficulty": "easy",
            "is_public": False
        },
        headers=headers
    )
    
    recipe_id = create_response.json()["id"]
    
    # Try to read the private recipe without auth
    response = client.get(f"/recipes/{recipe_id}")
    
    assert response.status_code == 403

def test_update_recipe():
    headers = create_auth_user("updateuser", "update@example.com")
    
    # Create a recipe
    create_response = client.post(
        "/recipes/",
        json={
            "title": "Original Recipe",
            "description": "Original description",
            "ingredients": "original ingredients",
            "instructions": "original instructions",
            "prep_time": 10,
            "cook_time": 20,
            "servings": 2,
            "difficulty": "easy",
            "is_public": True
        },
        headers=headers
    )
    
    recipe_id = create_response.json()["id"]
    
    # Update the recipe
    response = client.put(
        f"/recipes/{recipe_id}",
        json={
            "title": "Updated Recipe",
            "description": "Updated description",
            "ingredients": "updated ingredients",
            "instructions": "updated instructions",
            "prep_time": 15,
            "cook_time": 25,
            "servings": 4,
            "difficulty": "medium",
            "is_public": False
        },
        headers=headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Updated Recipe"
    assert data["description"] == "Updated description"
    assert data["prep_time"] == 15
    assert data["servings"] == 4
    assert data["difficulty"] == "medium"
    assert data["is_public"] == False

def test_delete_recipe():
    headers = create_auth_user("deleteuser", "delete@example.com")
    
    # Create a recipe
    create_response = client.post(
        "/recipes/",
        json={
            "title": "Recipe to Delete",
            "description": "This recipe will be deleted",
            "ingredients": "temporary ingredients",
            "instructions": "temporary instructions",
            "prep_time": 5,
            "cook_time": 10,
            "servings": 1,
            "difficulty": "easy",
            "is_public": True
        },
        headers=headers
    )
    
    recipe_id = create_response.json()["id"]
    
    # Delete the recipe
    response = client.delete(f"/recipes/{recipe_id}", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["message"] == "Recipe deleted successfully"
    
    # Try to read the deleted recipe
    get_response = client.get(f"/recipes/{recipe_id}")
    assert get_response.status_code == 404

def test_search_recipes():
    headers = create_auth_user("searchuser", "search@example.com")
    
    # Create a recipe with specific ingredients
    client.post(
        "/recipes/",
        json={
            "title": "Chocolate Cake",
            "description": "Delicious chocolate cake",
            "ingredients": "chocolate, flour, eggs, sugar",
            "instructions": "Mix and bake",
            "prep_time": 20,
            "cook_time": 40,
            "servings": 8,
            "difficulty": "medium",
            "is_public": True
        },
        headers=headers
    )
    
    # Search for recipes containing "chocolate"
    response = client.get("/recipes/?search=chocolate")
    
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    found_recipe = next((r for r in data if "chocolate" in r["title"].lower() or 
                        "chocolate" in r["ingredients"].lower()), None)
    assert found_recipe is not None

def test_favorite_recipe():
    headers = create_auth_user("favoriteuser", "favorite@example.com")
    
    # Create a recipe
    create_response = client.post(
        "/recipes/",
        json={
            "title": "Favorite Recipe",
            "description": "A recipe to favorite",
            "ingredients": "favorite ingredients",
            "instructions": "favorite instructions",
            "prep_time": 10,
            "cook_time": 15,
            "servings": 2,
            "difficulty": "easy",
            "is_public": True
        },
        headers=headers
    )
    
    recipe_id = create_response.json()["id"]
    
    # Favorite the recipe
    response = client.post(f"/recipes/{recipe_id}/favorite", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["message"] == "Recipe added to favorites"
    
    # Try to favorite again (should fail)
    response = client.post(f"/recipes/{recipe_id}/favorite", headers=headers)
    assert response.status_code == 400

def test_unfavorite_recipe():
    headers = create_auth_user("unfavoriteuser", "unfavorite@example.com")
    
    # Create and favorite a recipe
    create_response = client.post(
        "/recipes/",
        json={
            "title": "Unfavorite Recipe",
            "description": "A recipe to unfavorite",
            "ingredients": "unfavorite ingredients",
            "instructions": "unfavorite instructions",
            "prep_time": 8,
            "cook_time": 12,
            "servings": 1,
            "difficulty": "easy",
            "is_public": True
        },
        headers=headers
    )
    
    recipe_id = create_response.json()["id"]
    
    # Favorite first
    client.post(f"/recipes/{recipe_id}/favorite", headers=headers)
    
    # Then unfavorite
    response = client.delete(f"/recipes/{recipe_id}/favorite", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["message"] == "Recipe removed from favorites"