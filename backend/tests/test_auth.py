import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import jwt
from datetime import timedelta
from backend.database import Base, get_db
from backend.main import app
from backend import models, crud, schemas, auth



# Make sure the backend package is importable
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)






# Add backend directory to path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)


# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture
def db():
    """Create a fresh database for each test"""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

class TestPasswordHandling:
    """Test password hashing and verification"""
    
    def test_password_hash_and_verify(self):
        """Test that password can be hashed and verified"""
        password = "mysecretpassword123"
        hashed = auth.get_password_hash(password)
        
        assert hashed != password
        assert auth.verify_password(password, hashed)
    
    def test_password_hash_different_each_time(self):
        """Test that same password produces different hashes"""
        password = "samepassword"
        hash1 = auth.get_password_hash(password)
        hash2 = auth.get_password_hash(password)
        
        assert hash1 != hash2
        assert auth.verify_password(password, hash1)
        assert auth.verify_password(password, hash2)
    
    def test_wrong_password_fails(self):
        """Test that wrong password doesn't verify"""
        password = "correctpassword"
        wrong_password = "wrongpassword"
        hashed = auth.get_password_hash(password)
        
        assert not auth.verify_password(wrong_password, hashed)
    
    def test_truncate_long_password(self):
        """Test that passwords longer than 72 bytes are truncated"""
        long_password = "a" * 100
        truncated = auth.truncate_password(long_password)
        
        assert len(truncated.encode('utf-8')) <= 72

class TestJWTTokens:
    """Test JWT token creation and validation"""
    
    def test_create_access_token(self):
        """Test access token creation"""
        data = {"sub": "testuser"}
        token = auth.create_access_token(data)
        
        assert token is not None
        assert isinstance(token, str)
    
    def test_token_contains_correct_data(self):
        """Test that token contains the encoded data"""
        username = "testuser123"
        data = {"sub": username}
        token = auth.create_access_token(data)
        
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        assert payload["sub"] == username
        assert "exp" in payload
    
    def test_token_with_custom_expiration(self):
        """Test token creation with custom expiration"""
        data = {"sub": "testuser"}
        expires_delta = timedelta(minutes=15)
        token = auth.create_access_token(data, expires_delta)
        
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        assert "exp" in payload

class TestUserQueries:
    """Test database user queries"""
    
    def test_get_user_by_username(self, db):
        """Test retrieving user by username"""
        # Create test user
        user = models.User(
            username="testuser",
            email="test@example.com",
            hashed_password=auth.get_password_hash("password123")
        )
        db.add(user)
        db.commit()
        
        # Query user
        found_user = auth.get_user_by_username(db, "testuser")
        assert found_user is not None
        assert found_user.username == "testuser"
        assert found_user.email == "test@example.com"
    
    def test_get_user_by_email(self, db):
        """Test retrieving user by email"""
        user = models.User(
            username="testuser",
            email="test@example.com",
            hashed_password=auth.get_password_hash("password123")
        )
        db.add(user)
        db.commit()
        
        found_user = auth.get_user_by_email(db, "test@example.com")
        assert found_user is not None
        assert found_user.email == "test@example.com"
    
    def test_get_nonexistent_user_returns_none(self, db):
        """Test that querying nonexistent user returns None"""
        user = auth.get_user_by_username(db, "nonexistent")
        assert user is None

class TestUserAuthentication:
    """Test user authentication"""
    
    def test_authenticate_user_success(self, db):
        """Test successful authentication"""
        password = "mypassword123"
        user = models.User(
            username="testuser",
            email="test@example.com",
            hashed_password=auth.get_password_hash(password)
        )
        db.add(user)
        db.commit()
        
        authenticated = auth.authenticate_user(db, "testuser", password)
        assert authenticated is not None
        assert authenticated.username == "testuser"
    
    def test_authenticate_user_wrong_password(self, db):
        """Test authentication with wrong password"""
        user = models.User(
            username="testuser",
            email="test@example.com",
            hashed_password=auth.get_password_hash("correctpassword")
        )
        db.add(user)
        db.commit()
        
        authenticated = auth.authenticate_user(db, "testuser", "wrongpassword")
        assert authenticated is None
    
    def test_authenticate_nonexistent_user(self, db):
        """Test authentication with nonexistent username"""
        authenticated = auth.authenticate_user(db, "nonexistent", "password")
        assert authenticated is None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])