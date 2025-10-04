from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import List, Optional
from . import models, schemas, auth

# ----------------- User CRUD -----------------
def create_user(db: Session, user: schemas.UserCreate) -> models.User:
    """Create a new user"""
    # Check for existing email or username
    if get_user_by_email(db, user.email) or get_user_by_username(db, user.username):
        raise ValueError("Email or username already registered")

    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user(db: Session, user_id: int) -> Optional[models.User]:
    """Get user by ID"""
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    """Get user by email"""
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    """Get user by username"""
    return db.query(models.User).filter(models.User.username == username).first()

# ----------------- Recipe CRUD -----------------
def create_recipe(db: Session, recipe: schemas.RecipeCreate, user_id: int) -> models.Recipe:
    """Create a new recipe"""
    db_recipe = models.Recipe(**recipe.model_dump(), owner_id=user_id)
    db.add(db_recipe)
    db.commit()
    db.refresh(db_recipe)
    return db_recipe

def get_recipe(db: Session, recipe_id: int) -> Optional[models.Recipe]:
    """Get recipe by ID"""
    return db.query(models.Recipe).filter(models.Recipe.id == recipe_id).first()

def get_recipes(db: Session, skip: int = 0, limit: int = 100) -> List[models.Recipe]:
    """Get all recipes with pagination"""
    return db.query(models.Recipe).offset(skip).limit(limit).all()

def get_user_recipes(db: Session, user_id: int, skip: int = 0, limit: int = 100) -> List[models.Recipe]:
    """Get recipes by user ID"""
    return (
        db.query(models.Recipe)
        .filter(models.Recipe.owner_id == user_id)
        .offset(skip)
        .limit(limit)
        .all()
    )

def update_recipe(db: Session, recipe_id: int, recipe_update: schemas.RecipeUpdate, user_id: int) -> Optional[models.Recipe]:
    """Update a recipe"""
    db_recipe = db.query(models.Recipe).filter(
        and_(models.Recipe.id == recipe_id, models.Recipe.owner_id == user_id)
    ).first()
    
    if not db_recipe:
        return None

    update_data = recipe_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_recipe, field, value)
    
    db.commit()
    db.refresh(db_recipe)
    return db_recipe

def delete_recipe(db: Session, recipe_id: int, user_id: int) -> bool:
    """Delete a recipe"""
    db_recipe = db.query(models.Recipe).filter(
        and_(models.Recipe.id == recipe_id, models.Recipe.owner_id == user_id)
    ).first()
    
    if not db_recipe:
        return False
    
    db.delete(db_recipe)
    db.commit()
    return True

def search_recipes(db: Session, query: str, skip: int = 0, limit: int = 100) -> List[models.Recipe]:
    """Search recipes by title, description, or ingredients"""
    return (
        db.query(models.Recipe)
        .filter(
            or_(
                models.Recipe.title.ilike(f"%{query}%"),
                models.Recipe.description.ilike(f"%{query}%"),
                models.Recipe.ingredients.ilike(f"%{query}%")
            )
        )
        .offset(skip)
        .limit(limit)
        .all()
    )

# ----------------- Favorite CRUD -----------------
def add_favorite(db: Session, user_id: int, recipe_id: int) -> models.Favorite:
    """Add recipe to favorites"""
    # Check if already favorited
    existing = db.query(models.Favorite).filter(
        and_(models.Favorite.user_id == user_id, models.Favorite.recipe_id == recipe_id)
    ).first()
    
    if existing:
        return existing
    
    db_favorite = models.Favorite(user_id=user_id, recipe_id=recipe_id)
    db.add(db_favorite)
    db.commit()
    db.refresh(db_favorite)
    return db_favorite

def remove_favorite(db: Session, user_id: int, recipe_id: int) -> bool:
    """Remove recipe from favorites"""
    db_favorite = db.query(models.Favorite).filter(
        and_(models.Favorite.user_id == user_id, models.Favorite.recipe_id == recipe_id)
    ).first()
    
    if not db_favorite:
        return False
    
    db.delete(db_favorite)
    db.commit()
    return True

def get_user_favorites(db: Session, user_id: int, skip: int = 0, limit: int = 100) -> List[models.Favorite]:
    """Get user's favorite recipes"""
    return (
        db.query(models.Favorite)
        .filter(models.Favorite.user_id == user_id)
        .offset(skip)
        .limit(limit)
        .all()
    )