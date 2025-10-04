import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ..database import Base, get_db
from ..main import app
from .. import models, crud, schemas, auth

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_users.db"
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

class TestUserRegistration:
    """Test user registration"""
    
    def test_register_valid_user(self):
        """Test registering a valid user"""
        response = client.post(
            "/auth/register",
            json={
                "username": "newuser1",
                "email": "newuser1@example.com",
                "password": "password123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "newuser1"
        assert data["email"] == "newuser1@example.com"
        assert "id" in data
        assert "hashed_password" not in data
        assert data["is_active"] is True
    
    def test_register_duplicate_email(self):
        """Test duplicate email fails"""
        client.post(
            "/auth/register",
            json={
                "username": "user1",
                "email": "duplicate@example.com",
                "password": "password123"
            }
        )
        response = client.post(
            "/auth/register",
            json={
                "username": "user2",
                "email": "duplicate@example.com",
                "password": "password456"
            }
        )
        assert response.status_code == 400
        assert "email" in response.json()["detail"].lower()
    
    def test_register_duplicate_username(self):
        """Test duplicate username fails"""
        client.post(
            "/auth/register",
            json={
                "username": "sameuser",
                "email": "user1@example.com",
                "password": "password123"
            }
        )
        response = client.post(
            "/auth/register",
            json={
                "username": "sameuser",
                "email": "user2@example.com",
                "password": "password456"
            }
        )
        assert response.status_code == 400
        assert "username" in response.json()["detail"].lower()
    
    def test_register_short_username(self):
        """Test short username validation"""
        response = client.post(
            "/auth/register",
            json={
                "username": "ab",
                "email": "test@example.com",
                "password": "password123"
            }
        )
        assert response.status_code == 422
    
    def test_register_short_password(self):
        """Test short password validation"""
        response = client.post(
            "/auth/register",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "12345"
            }
        )
        assert response.status_code == 422
    
    def test_register_invalid_username_chars(self):
        """Test invalid username characters"""
        response = client.post(
            "/auth/register",
            json={
                "username": "user@name!",
                "email": "test@example.com",
                "password": "password123"
            }
        )
        assert response.status_code == 422

class TestUserLogin:
    """Test user login"""
    
    def test_login_success(self):
        """Test successful login"""
        client.post(
            "/auth/register",
            json={
                "username": "loginuser",
                "email": "login@example.com",
                "password": "loginpass123"
            }
        )
        response = client.post(
            "/auth/login",
            data={
                "username": "loginuser",
                "password": "loginpass123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_wrong_password(self):
        """Test login with wrong password"""
        client.post(
            "/auth/register",
            json={
                "username": "wrongpass",
                "email": "wrong@example.com",
                "password": "correctpassword"
            }
        )
        response = client.post(
            "/auth/login",
            data={
                "username": "wrongpass",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401
    
    def test_login_nonexistent_user(self):
        """Test login with non-existent user"""
        response = client.post(
            "/auth/login",
            data={
                "username": "nonexistent",
                "password": "password123"
            }
        )
        assert response.status_code == 401

class TestUserAuthentication:
    """Test authentication and tokens"""
    
    def test_get_current_user(self):
        """Test getting current user info"""
        client.post(
            "/auth/register",
            json={
                "username": "authuser",
                "email": "auth@example.com",
                "password": "password123"
            }
        )
        login_resp = client.post(
            "/auth/login",
            data={"username": "authuser", "password": "password123"}
        )
        token = login_resp.json()["access_token"]
        
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "authuser"
        assert data["email"] == "auth@example.com"
    
    def test_get_current_user_no_token(self):
        """Test getting user without token"""
        response = client.get("/auth/me")
        assert response.status_code == 401
    
    def test_get_current_user_invalid_token(self):
        """Test with invalid token"""
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

class TestPasswordSecurity:
    """Test password security"""
    
    def test_password_is_hashed(self):
        """Test that passwords are hashed"""
        response = client.post(
            "/auth/register",
            json={
                "username": "hashtest",
                "email": "hash@example.com",
                "password": "mypassword123"
            }
        )
        # Password should not be in response
        assert "password" not in response.json()
        assert "hashed_password" not in response.json()
    
    def test_password_verification(self):
        """Test password hashing and verification"""
        password = "testpassword123"
        hashed = auth.get_password_hash(password)
        
        # Correct password verifies
        assert auth.verify_password(password, hashed) is True
        
        # Wrong password doesn't verify
        assert auth.verify_password("wrongpassword", hashed) is False
    
    def test_different_hashes_for_same_password(self):
        """Test that same password produces different hashes"""
        password = "samepassword"
        hash1 = auth.get_password_hash(password)
        hash2 = auth.get_password_hash(password)
        
        # Hashes should be different
        assert hash1 != hash2
        
        # But both should verify
        assert auth.verify_password(password, hash1)
        assert auth.verify_password(password, hash2)

class TestUserProfile:
    """Test user profile features"""
    
    def test_user_has_created_at(self):
        """Test user has timestamp"""
        response = client.post(
            "/auth/register",
            json={
                "username": "timestamp",
                "email": "timestamp@example.com",
                "password": "password123"
            }
        )
        assert "created_at" in response.json()
    
    def test_user_is_active_by_default(self):
        """Test new users are active"""
        response = client.post(
            "/auth/register",
            json={
                "username": "activeuser",
                "email": "active@example.com",
                "password": "password123"
            }
        )
        assert response.json()["is_active"] is True

class TestUserRecipeRelationship:
    """Test user-recipe relationships"""
    
    def test_user_can_create_recipes(self):
        """Test user can create recipes"""
        # Register and login
        client.post(
            "/auth/register",
            json={
                "username": "recipeowner",
                "email": "recipeowner@example.com",
                "password": "password123"
            }
        )
        login_resp = client.post(
            "/auth/login",
            data={"username": "recipeowner", "password": "password123"}
        )
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Create recipe
        response = client.post(
            "/recipes",
            json={
                "title": "User's Recipe",
                "ingredients": "test",
                "instructions": "test"
            },
            headers=headers
        )
        assert response.status_code == 200
        assert response.json()["title"] == "User's Recipe"
    
    def test_user_can_view_own_recipes(self):
        """Test user can view their own recipes"""
        # Register and login
        client.post(
            "/auth/register",
            json={
                "username": "viewer",
                "email": "viewer@example.com",
                "password": "password123"
            }
        )
        login_resp = client.post(
            "/auth/login",
            data={"username": "viewer", "password": "password123"}
        )
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Create recipes
        for i in range(3):
            client.post(
                "/recipes",
                json={
                    "title": f"Recipe {i}",
                    "ingredients": "test",
                    "instructions": "test"
                },
                headers=headers
            )
        
        # Get user's recipes
        response = client.get("/recipes/my", headers=headers)
        assert response.status_code == 200
        assert len(response.json()) == 3

class TestMultipleUsers:
    """Test multiple user scenarios"""
    
    def test_users_have_separate_recipes(self):
        """Test users have separate recipe collections"""
        # User 1
        client.post(
            "/auth/register",
            json={
                "username": "user1sep",
                "email": "user1sep@example.com",
                "password": "password123"
            }
        )
        login1 = client.post(
            "/auth/login",
            data={"username": "user1sep", "password": "password123"}
        )
        token1 = login1.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}
        
        # User 2
        client.post(
            "/auth/register",
            json={
                "username": "user2sep",
                "email": "user2sep@example.com",
                "password": "password123"
            }
        )
        login2 = client.post(
            "/auth/login",
            data={"username": "user2sep", "password": "password123"}
        )
        token2 = login2.json()["access_token"]
        headers2 = {"Authorization": f"Bearer {token2}"}
        
        # User 1 creates recipes
        for i in range(2):
            client.post(
                "/recipes",
                json={
                    "title": f"User1 Recipe {i}",
                    "ingredients": "test",
                    "instructions": "test"
                },
                headers=headers1
            )
        
        # User 2 creates recipes
        for i in range(3):
            client.post(
                "/recipes",
                json={
                    "title": f"User2 Recipe {i}",
                    "ingredients": "test",
                    "instructions": "test"
                },
                headers=headers2
            )
        
        # Verify separate collections
        recipes1 = client.get("/recipes/my", headers=headers1).json()
        recipes2 = client.get("/recipes/my", headers=headers2).json()
        
        assert len(recipes1) == 2
        assert len(recipes2) == 3
    
    def test_users_cannot_modify_others_recipes(self):
        """Test users can't modify other users' recipes"""
        # User 1 creates recipe
        client.post(
            "/auth/register",
            json={
                "username": "owner",
                "email": "owner@example.com",
                "password": "password123"
            }
        )
        login1 = client.post(
            "/auth/login",
            data={"username": "owner", "password": "password123"}
        )
        token1 = login1.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}
        
        recipe_resp = client.post(
            "/recipes",
            json={
                "title": "Owner's Recipe",
                "ingredients": "test",
                "instructions": "test"
            },
            headers=headers1
        )
        recipe_id = recipe_resp.json()["id"]
        
        # User 2 tries to modify
        client.post(
            "/auth/register",
            json={
                "username": "hacker",
                "email": "hacker@example.com",
                "password": "password123"
            }
        )
        login2 = client.post(
            "/auth/login",
            data={"username": "hacker", "password": "password123"}
        )
        token2 = login2.json()["access_token"]
        headers2 = {"Authorization": f"Bearer {token2}"}
        
        response = client.put(
            f"/recipes/{recipe_id}",
            json={"title": "Hacked Title"},
            headers=headers2
        )
        assert response.status_code == 404  # Not found (no permission)