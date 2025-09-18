from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from datetime import timedelta
import os
import httpx

from . import models, schemas, crud, auth
from .database import engine, get_db

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="Recipe Finder API",
    description="A recipe management system with user authentication and CRUD operations",
    version="1.0.0"
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (for frontend)
if os.path.exists("frontend"):
    app.mount("/static", StaticFiles(directory="frontend"), name="static")

# ----------------- Authentication Routes -----------------
@app.post("/auth/register", response_model=schemas.User)
async def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user already exists
    if crud.get_user_by_email(db, user.email):
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    if crud.get_user_by_username(db, user.username):
        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )
    
    return crud.create_user(db=db, user=user)

@app.post("/auth/login", response_model=schemas.Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login user and return access token"""
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=schemas.User)
async def read_current_user(current_user: models.User = Depends(auth.get_current_active_user)):
    """Get current user info"""
    return current_user

# ----------------- Recipe Routes -----------------
@app.get("/recipes", response_model=List[schemas.Recipe])
async def read_recipes(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all recipes"""
    return crud.get_recipes(db, skip=skip, limit=limit)

@app.get("/recipes/search", response_model=List[schemas.Recipe])
async def search_recipes(q: str, skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    """Search recipes by title, description, or ingredients"""
    return crud.search_recipes(db, query=q, skip=skip, limit=limit)

@app.get("/recipes/my", response_model=List[schemas.Recipe])
async def read_my_recipes(
    skip: int = 0, 
    limit: int = 100, 
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current user's recipes"""
    return crud.get_user_recipes(db, user_id=current_user.id, skip=skip, limit=limit)

@app.get("/recipes/{recipe_id}", response_model=schemas.Recipe)
async def read_recipe(recipe_id: int, db: Session = Depends(get_db)):
    """Get recipe by ID"""
    recipe = crud.get_recipe(db, recipe_id)
    if recipe is None:
        raise HTTPException(status_code=404, detail="Recipe not found")
    return recipe

@app.post("/recipes", response_model=schemas.Recipe)
async def create_recipe(
    recipe: schemas.RecipeCreate,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new recipe"""
    return crud.create_recipe(db=db, recipe=recipe, user_id=current_user.id)

@app.put("/recipes/{recipe_id}", response_model=schemas.Recipe)
async def update_recipe(
    recipe_id: int,
    recipe: schemas.RecipeUpdate,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update a recipe"""
    updated_recipe = crud.update_recipe(db, recipe_id, recipe, current_user.id)
    if updated_recipe is None:
        raise HTTPException(status_code=404, detail="Recipe not found or you don't have permission")
    return updated_recipe

@app.delete("/recipes/{recipe_id}")
async def delete_recipe(
    recipe_id: int,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a recipe"""
    success = crud.delete_recipe(db, recipe_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Recipe not found or you don't have permission")
    return {"message": "Recipe deleted successfully"}

# ----------------- Favorites Routes -----------------
@app.get("/favorites", response_model=List[schemas.Favorite])
async def read_favorites(
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current user's favorite recipes"""
    return crud.get_user_favorites(db, user_id=current_user.id, skip=skip, limit=limit)

@app.post("/favorites/{recipe_id}")
async def add_to_favorites(
    recipe_id: int,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Add recipe to favorites"""
    # Check if recipe exists
    recipe = crud.get_recipe(db, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    
    favorite = crud.add_favorite(db, current_user.id, recipe_id)
    return {"message": "Recipe added to favorites", "favorite_id": favorite.id}

@app.delete("/favorites/{recipe_id}")
async def remove_from_favorites(
    recipe_id: int,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Remove recipe from favorites"""
    success = crud.remove_favorite(db, current_user.id, recipe_id)
    if not success:
        raise HTTPException(status_code=404, detail="Favorite not found")
    return {"message": "Recipe removed from favorites"}

# ----------------- External API Integration -----------------
@app.get("/api/recipes/external")
async def search_external_recipes(q: str, number: int = 10):
    """Search recipes from external API (Spoonacular)"""
    api_key = os.getenv("SPOONACULAR_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="External API not configured")
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://api.spoonacular.com/recipes/complexSearch",
                params={
                    "query": q,
                    "number": number,
                    "apiKey": api_key,
                    "addRecipeInformation": True
                }
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(status_code=response.status_code, detail="External API error")
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="External API unavailable")

# ----------------- Root Route -----------------
@app.get("/")
async def read_root():
    """Root endpoint"""
    if os.path.exists("frontend/index.html"):
        return FileResponse("frontend/index.html")
    return {
        "message": "Recipe Finder API",
        "docs": "/docs",
        "version": "1.0.0"
    }

# ----------------- Health Check -----------------
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}