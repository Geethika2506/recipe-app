
import pytest
from fastapi.testclient import TestClient

class TestAuthenticationEndpoints:
    """Test authentication API endpoints"""
    
    def test_register_new_user(self, test_client):
        """Test user registration"""
        response = test_client.post(
            "/auth/register",
            json={
                "username": "integrationuser",
                "email": "integration@example.com",
                "password": "securepassword123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "integrationuser"
        assert data["email"] == "integration@example.com"
        assert "id" in data
    
    def test_register_duplicate_email(self, test_client, test_user):
        """Test registering with duplicate email returns error"""
        response = test_client.post(
            "/auth/register",
            json={
                "username": "newusername",
                "email": test_user.email,  # Duplicate email
                "password": "password123"
            }
        )
        
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()
    
    def test_login_success(self, test_client, test_user):
        """Test successful login"""
        response = test_client.post(
            "/auth/login",
            data={
                "username": test_user.username,
                "password": "testpassword123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_wrong_password(self, test_client, test_user):
        """Test login with wrong password"""
        response = test_client.post(
            "/auth/login",
            data={
                "username": test_user.username,
                "password": "wrongpassword"
            }
        )
        
        assert response.status_code == 401
    
    def test_get_current_user(self, test_client, auth_token):
        """Test getting current user info"""
        response = test_client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "username" in data
        assert "email" in data
    
    def test_get_current_user_no_token(self, test_client):
        """Test accessing protected route without token"""
        response = test_client.get("/auth/me")
        
        assert response.status_code == 401


class TestRecipeEndpoints:
    """Test recipe API endpoints"""
    
    def test_create_recipe(self, test_client, auth_token):
        """Test creating a recipe via API"""
        response = test_client.post(
            "/recipes",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={
                "title": "API Test Recipe",
                "description": "Created via API test",
                "ingredients": "ingredient 1\ningredient 2",
                "instructions": "Step 1\nStep 2",
                "prep_time": 15,
                "cook_time": 30,
                "servings": 4,
                "difficulty": "medium"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "API Test Recipe"
        assert "id" in data
    
    def test_create_recipe_unauthorized(self, test_client):
        """Test creating recipe without authentication"""
        response = test_client.post(
            "/recipes",
            json={
                "title": "Unauthorized Recipe",
                "ingredients": "test",
                "instructions": "test",
                "difficulty": "easy"
            }
        )
        
        assert response.status_code == 401
    
    def test_get_all_recipes(self, test_client):
        """Test retrieving all recipes"""
        response = test_client.get("/recipes")
        
        assert response.status_code == 200
        data = response.json()
        assert "local_recipes" in data or isinstance(data, list)
    
    def test_get_recipe_by_id(self, test_client, test_recipe):
        """Test retrieving a specific recipe"""
        response = test_client.get(f"/recipes/{test_recipe.id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_recipe.id
        assert data["title"] == test_recipe.title
    
    def test_get_nonexistent_recipe(self, test_client):
        """Test retrieving non-existent recipe"""
        response = test_client.get("/recipes/99999")
        
        assert response.status_code == 404
    
    def test_update_recipe(self, test_client, auth_token, test_recipe):
        """Test updating a recipe"""
        response = test_client.put(
            f"/recipes/{test_recipe.id}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={
                "title": "Updated Title",
                "description": "Updated description"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Updated Title"
    
    def test_delete_recipe(self, test_client, auth_token, test_recipe):
        """Test deleting a recipe"""
        response = test_client.delete(
            f"/recipes/{test_recipe.id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        
        # Verify it's deleted
        get_response = test_client.get(f"/recipes/{test_recipe.id}")
        assert get_response.status_code == 404
    
    def test_search_recipes(self, test_client, test_user):
        """Test recipe search endpoint"""
        response = test_client.get("/recipes/search?q=test")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_my_recipes(self, test_client, auth_token):
        """Test getting current user's recipes"""
        response = test_client.get(
            "/recipes/my",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestFavoritesEndpoints:
    """Test favorites API endpoints"""
    
    def test_add_to_favorites(self, test_client, auth_token, test_recipe):
        """Test adding recipe to favorites"""
        response = test_client.post(
            f"/favorites/{test_recipe.id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "favorite_id" in data
    
    def test_add_to_favorites_with_recipe_data(self, test_client, auth_token):
        """Test adding external recipe to favorites"""
        response = test_client.post(
            "/favorites/add",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={
                "title": "External Recipe",
                "description": "From external source",
                "ingredients": "ingredient 1\ningredient 2",
                "instructions": "Do this and that",
                "difficulty": "easy"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "recipe_id" in data
        assert "favorite_id" in data
    
    def test_get_favorites(self, test_client, auth_token, test_recipe):
        """Test retrieving user's favorites"""
        # Add to favorites first
        test_client.post(
            f"/favorites/{test_recipe.id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Get favorites
        response = test_client.get(
            "/favorites",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
    
    def test_remove_from_favorites(self, test_client, auth_token, test_recipe):
        """Test removing recipe from favorites"""
        # Add to favorites first
        test_client.post(
            f"/favorites/{test_recipe.id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Remove from favorites
        response = test_client.delete(
            f"/favorites/{test_recipe.id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        assert "removed" in response.json()["message"].lower()
    
    def test_favorites_unauthorized(self, test_client):
        """Test accessing favorites without authentication"""
        response = test_client.get("/favorites")
        
        assert response.status_code == 401


class TestHealthEndpoints:
    """Test system health endpoints"""
    
    def test_health_check(self, test_client):
        """Test health check endpoint"""
        response = test_client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_root_endpoint(self, test_client):
        """Test root endpoint"""
        response = test_client.get("/")
        
        assert response.status_code == 200