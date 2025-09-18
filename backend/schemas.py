from pydantic import BaseModel, EmailStr, validator
from typing import List, Optional
from datetime import datetime
import re

# ----------------- Users -----------------
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

class User(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class UserWithRecipes(User):
    recipes: List['Recipe'] = []

# ----------------- Recipes -----------------
class RecipeBase(BaseModel):
    title: str
    description: Optional[str] = None
    ingredients: str
    instructions: str
    prep_time: Optional[int] = None
    cook_time: Optional[int] = None
    servings: Optional[int] = 1
    difficulty: Optional[str] = "easy"
    image_url: Optional[str] = None
    source_url: Optional[str] = None

class RecipeCreate(RecipeBase):
    pass

class RecipeUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    ingredients: Optional[str] = None
    instructions: Optional[str] = None
    prep_time: Optional[int] = None
    cook_time: Optional[int] = None
    servings: Optional[int] = None
    difficulty: Optional[str] = None
    image_url: Optional[str] = None
    source_url: Optional[str] = None

class Recipe(RecipeBase):
    id: int
    owner_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class RecipeWithOwner(Recipe):
    owner: User

# ----------------- Favorites -----------------
class FavoriteCreate(BaseModel):
    recipe_id: int

class Favorite(BaseModel):
    id: int
    user_id: int
    recipe_id: int
    created_at: datetime
    recipe: Recipe

    class Config:
        from_attributes = True

# ----------------- Auth -----------------
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# ----------------- Search -----------------
class RecipeSearch(BaseModel):
    query: str
    diet: Optional[str] = None
    cuisine: Optional[str] = None
    max_ready_time: Optional[int] = None

# Fix forward references
UserWithRecipes.model_rebuild()