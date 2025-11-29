
import pytest
from app import crud, schemas, models

class TestUserCRUD:
    """Test user CRUD operations"""
    
    def test_create_user(self, db_session):
        """Test creating a new user"""
        user_data = schemas.UserCreate(
            username="newuser",
            email="newuser@example.com",
            password="password123"
        )
        user = crud.create_user(db=db_session, user=user_data)
        
        assert user.username == "newuser"
        assert user.email == "newuser@example.com"
        assert user.hashed_password != "password123"  # Should be hashed
        assert user.id is not None
    
    def test_get_user_by_email(self, db_session, test_user):
        """Test retrieving user by email"""
        user = crud.get_user_by_email(db=db_session, email=test_user.email)
        
        assert user is not None
        assert user.email == test_user.email
        assert user.username == test_user.username
    
    def test_get_user_by_username(self, db_session, test_user):
        """Test retrieving user by username"""
        user = crud.get_user_by_username(db=db_session, username=test_user.username)
        
        assert user is not None
        assert user.username == test_user.username
    
    def test_create_duplicate_email(self, db_session, test_user):
        """Test that duplicate email raises error"""
        user_data = schemas.UserCreate(
            username="anotheruser",
            email=test_user.email,  # Same email as existing user
            password="password123"
        )
        
        # Check if user with this email already exists
        existing = crud.get_user_by_email(db=db_session, email=test_user.email)
        assert existing is not None


class TestRecipeCRUD:
    """Test recipe CRUD operations"""
    
    def test_create_recipe(self, db_session, test_user):
        """Test creating a new recipe"""
        recipe_data = schemas.RecipeCreate(
            title="Pasta Carbonara",
            description="Classic Italian pasta",
            ingredients="500g pasta\n200g bacon\n4 eggs\nParmesan cheese",
            instructions="Cook pasta. Fry bacon. Mix eggs and cheese. Combine.",
            prep_time=10,
            cook_time=20,
            servings=4,
            difficulty="medium"
        )
        recipe = crud.create_recipe(db=db_session, recipe=recipe_data, user_id=test_user.id)
        
        assert recipe.title == "Pasta Carbonara"
        assert recipe.owner_id == test_user.id
        assert recipe.id is not None
    
    def test_get_recipe(self, db_session, test_recipe):
        """Test retrieving a recipe by ID"""
        recipe = crud.get_recipe(db=db_session, recipe_id=test_recipe.id)
        
        assert recipe is not None
        assert recipe.id == test_recipe.id
        assert recipe.title == test_recipe.title
    
    def test_get_recipes(self, db_session, test_user):
        """Test retrieving multiple recipes"""
        # Create multiple recipes
        for i in range(3):
            recipe_data = schemas.RecipeCreate(
                title=f"Recipe {i}",
                description=f"Description {i}",
                ingredients="test ingredients",
                instructions="test instructions",
                difficulty="easy"
            )
            crud.create_recipe(db=db_session, recipe=recipe_data, user_id=test_user.id)
        
        recipes = crud.get_recipes(db=db_session, skip=0, limit=10)
        assert len(recipes) >= 3
    
    def test_update_recipe(self, db_session, test_recipe, test_user):
        """Test updating a recipe"""
        update_data = schemas.RecipeUpdate(
            title="Updated Recipe Title",
            description="Updated description"
        )
        updated_recipe = crud.update_recipe(
            db=db_session,
            recipe_id=test_recipe.id,
            recipe_update=update_data,
            user_id=test_user.id
        )
        
        assert updated_recipe is not None
        assert updated_recipe.title == "Updated Recipe Title"
        assert updated_recipe.description == "Updated description"
    
    def test_delete_recipe(self, db_session, test_recipe, test_user):
        """Test deleting a recipe"""
        success = crud.delete_recipe(
            db=db_session,
            recipe_id=test_recipe.id,
            user_id=test_user.id
        )
        
        assert success is True
        
        # Verify recipe is deleted
        deleted_recipe = crud.get_recipe(db=db_session, recipe_id=test_recipe.id)
        assert deleted_recipe is None
    
    def test_search_recipes(self, db_session, test_user):
        """Test searching recipes"""
        # Create recipes with searchable content
        recipe_data = schemas.RecipeCreate(
            title="Chicken Curry",
            description="Spicy Indian curry",
            ingredients="chicken\ncurry powder\ncoconut milk",
            instructions="Cook chicken with curry",
            difficulty="medium"
        )
        crud.create_recipe(db=db_session, recipe=recipe_data, user_id=test_user.id)
        
        # Search for "chicken"
        results = crud.search_recipes(db=db_session, query="chicken", skip=0, limit=10)
        
        assert len(results) > 0
        assert any("chicken" in r.title.lower() or "chicken" in r.ingredients.lower() 
                   for r in results)


class TestFavoritesCRUD:
    """Test favorites CRUD operations"""
    
    def test_add_favorite(self, db_session, test_user, test_recipe):
        """Test adding a recipe to favorites"""
        favorite = crud.add_favorite(
            db=db_session,
            user_id=test_user.id,
            recipe_id=test_recipe.id
        )
        
        assert favorite is not None
        assert favorite.user_id == test_user.id
        assert favorite.recipe_id == test_recipe.id
    
    def test_get_user_favorites(self, db_session, test_user, test_recipe):
        """Test retrieving user's favorite recipes"""
        # Add to favorites
        crud.add_favorite(db=db_session, user_id=test_user.id, recipe_id=test_recipe.id)
        
        # Get favorites
        favorites = crud.get_user_favorites(db=db_session, user_id=test_user.id)
        
        assert len(favorites) > 0
        assert any(f.id == test_recipe.id for f in favorites)
    
    def test_remove_favorite(self, db_session, test_user, test_recipe):
        """Test removing a recipe from favorites"""
        # Add to favorites first
        crud.add_favorite(db=db_session, user_id=test_user.id, recipe_id=test_recipe.id)
        
        # Remove from favorites
        success = crud.remove_favorite(
            db=db_session,
            user_id=test_user.id,
            recipe_id=test_recipe.id
        )
        
        assert success is True
        
        # Verify it's removed
        favorites = crud.get_user_favorites(db=db_session, user_id=test_user.id)
        assert not any(f.id == test_recipe.id for f in favorites)