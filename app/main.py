from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session
from typing import List
from datetime import timedelta
import os
import httpx
import time

# Prometheus metrics imports
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from . import models, schemas, crud, auth
from .database import engine, get_db

# Prometheus metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

ERROR_COUNT = Counter(
    'http_errors_total',
    'Total HTTP errors',
    ['method', 'endpoint', 'status']
)

ACTIVE_REQUESTS = Gauge(
    'http_requests_active',
    'Number of active requests'
)

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="Recipe Finder API",
    description="A recipe management system with user authentication and CRUD operations",
    version="2.0.0"
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics tracking middleware
@app.middleware("http")
async def track_metrics(request, call_next):
    ACTIVE_REQUESTS.inc()
    start_time = time.time()
    
    try:
        response = await call_next(request)
        duration = time.time() - start_time
        
        # Track metrics
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)
        
        if response.status_code >= 400:
            ERROR_COUNT.labels(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code
            ).inc()
        
        return response
    except Exception as e:
        ERROR_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=500
        ).inc()
        raise e
    finally:
        ACTIVE_REQUESTS.dec()

# Prometheus metrics endpoint
@app.get("/metrics")
def metrics():
    """Expose Prometheus metrics"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Health check endpoint
@app.get("/health")
def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "database": "connected"
    }

# Mount static files (for frontend)
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")
else:
    print(f"Warning: Frontend directory not found at {frontend_path}")

# ----------------- Authentication Routes -----------------
@app.post("/auth/register", response_model=schemas.User)
async def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    if crud.get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if crud.get_user_by_username(db, user.username):
        raise HTTPException(status_code=400, detail="Username already taken")
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
@app.get("/recipes")
async def read_all_recipes(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Get all recipes (local + external API)"""
    local_recipes = crud.get_recipes(db, skip=skip, limit=limit)
    async with httpx.AsyncClient() as client:
        res = await client.get("https://www.themealdb.com/api/json/v1/1/search.php", params={"s": ""})
        data = res.json()
        external_recipes = data.get("meals", [])[:5] if data else []
    return {"local_recipes": local_recipes, "external_recipes": external_recipes}

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

@app.get("/recipes/search/ingredient")
async def search_recipes_by_ingredient(ingredient: str):
    """Search recipes from TheMealDB by ingredient"""
    async with httpx.AsyncClient() as client:
        res = await client.get(
            "https://www.themealdb.com/api/json/v1/1/filter.php",
            params={"i": ingredient}
        )
        data = res.json()
        if not data or not data.get("meals"):
            return {"meals": []}
        recipes = []
        for meal in data["meals"][:5]:
            lookup = await client.get(
                "https://www.themealdb.com/api/json/v1/1/lookup.php",
                params={"i": meal["idMeal"]}
            )
            recipes.append(lookup.json()["meals"][0])
        return {"meals": recipes}

@app.post("/recipes", response_model=schemas.Recipe)
async def create_recipe(
    recipe: schemas.RecipeCreate,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new recipe"""
    return crud.create_recipe(db=db, recipe=recipe, user_id=current_user.id)

@app.post("/recipes/external", response_model=schemas.Recipe)
async def save_external_recipe(
    recipe: schemas.RecipeCreate,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Save an external recipe without owner (for favorites only)"""
    existing = db.query(models.Recipe).filter(
        models.Recipe.title == recipe.title,
        models.Recipe.owner_id == None
    ).first()
    if existing:
        return existing
    return crud.create_external_recipe(db, recipe=recipe)

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

# Add these imports at the top of your main.py if not present:
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

# Replace your favorites routes with these improved versions:

# ----------------- Favorites Routes (FIXED WITH BETTER ERROR HANDLING) -----------------

@app.get("/favorites", response_model=List[schemas.Recipe])
async def read_favorites(
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current user's favorite recipes"""
    try:
        return crud.get_user_favorites(db, user_id=current_user.id, skip=skip, limit=limit)
    except Exception as e:
        print(f"Error loading favorites: {e}")
        raise HTTPException(status_code=500, detail=f"Error loading favorites: {str(e)}")


@app.post("/favorites/add")
async def add_to_favorites_with_recipe(
    recipe_data: schemas.RecipeCreate,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Add recipe to favorites. If recipe doesn't exist, create it first.
    This handles both local and external recipes in one operation.
    """
    try:
        print(f"=== Add to Favorites Request ===")
        print(f"User: {current_user.username}")
        print(f"Recipe data: {recipe_data.dict()}")
        
        # Validate required fields
        if not recipe_data.title or not recipe_data.title.strip():
            raise HTTPException(status_code=400, detail="Recipe title is required")
        
        if not recipe_data.ingredients or not recipe_data.ingredients.strip():
            raise HTTPException(status_code=400, detail="Recipe ingredients are required")
        
        if not recipe_data.instructions or not recipe_data.instructions.strip():
            raise HTTPException(status_code=400, detail="Recipe instructions are required")
        
        # Check if recipe already exists in database by title
        existing_recipe = db.query(models.Recipe).filter(
            models.Recipe.title == recipe_data.title
        ).first()
        
        if existing_recipe:
            print(f"Recipe exists with ID: {existing_recipe.id}")
            recipe_id = existing_recipe.id
        else:
            # Create the recipe without owner (external recipe)
            print("Creating new external recipe")
            try:
                new_recipe = crud.create_external_recipe(db, recipe=recipe_data)
                recipe_id = new_recipe.id
                print(f"Created recipe with ID: {recipe_id}")
            except Exception as e:
                print(f"Error creating recipe: {e}")
                raise HTTPException(status_code=500, detail=f"Error creating recipe: {str(e)}")
        
        # Check if already in favorites
        existing_favorite = db.query(models.Favorite).filter(
            models.Favorite.user_id == current_user.id,
            models.Favorite.recipe_id == recipe_id
        ).first()
        
        if existing_favorite:
            print("Recipe already in favorites")
            return {
                "message": "Recipe already in favorites",
                "favorite_id": existing_favorite.id,
                "recipe_id": recipe_id
            }
        
        # Add to favorites
        print("Adding to favorites")
        try:
            favorite = crud.add_favorite(db, current_user.id, recipe_id)
            print(f"Created favorite with ID: {favorite.id}")
            return {
                "message": "Recipe added to favorites",
                "favorite_id": favorite.id,
                "recipe_id": recipe_id
            }
        except Exception as e:
            print(f"Error adding favorite: {e}")
            raise HTTPException(status_code=500, detail=f"Error adding to favorites: {str(e)}")
            
    except HTTPException:
        raise
    except ValidationError as e:
        print(f"Validation error: {e}")
        raise HTTPException(status_code=422, detail=f"Invalid recipe data: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@app.post("/favorites/{recipe_id}")
async def add_to_favorites_by_id(
    recipe_id: int,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    try:
        recipe = crud.get_recipe(db, recipe_id)
        if not recipe:
            raise HTTPException(status_code=404, detail="Recipe not found")
        
        existing_favorite = db.query(models.Favorite).filter(
            models.Favorite.user_id == current_user.id,
            models.Favorite.recipe_id == recipe_id
        ).first()
        
        if existing_favorite:
            return {"message": "Recipe already in favorites"}
        
        favorite = crud.add_favorite(db, current_user.id, recipe_id)
        return {"message": "Recipe added to favorites"}
    except Exception as e:
        print(f"Error adding favorite by ID: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/favorites/{recipe_id}")
async def remove_from_favorites(
    recipe_id: int,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    try:
        success = crud.remove_favorite(db, current_user.id, recipe_id)
        if not success:
            raise HTTPException(status_code=404, detail="Favorite not found")
        return {"message": "Recipe removed from favorites"}
    except Exception as e:
        print(f"Error removing favorite: {e}")
        raise HTTPException(status_code=500, detail=str(e))
# ----------------- External API Integration -----------------
@app.get("/api/recipes/external", tags=["External"])
async def search_external_recipes(q: str, number: int = 10):
    """Search recipes from TheMealDB by ingredient"""
    async with httpx.AsyncClient() as client:
        try:
            filter_res = await client.get(
                "https://www.themealdb.com/api/json/v1/1/filter.php",
                params={"i": q},
                timeout=10.0
            )
            filter_data = filter_res.json()
            if not filter_data or not filter_data.get("meals"):
                return {"results": [], "total": 0}
            results = []
            for meal in filter_data["meals"][:number]:
                meal_id = meal["idMeal"]
                lookup_res = await client.get(
                    "https://www.themealdb.com/api/json/v1/1/lookup.php",
                    params={"i": meal_id},
                    timeout=10.0
                )
                meal_detail = lookup_res.json().get("meals", [{}])[0]
                ingredients = []
                for i in range(1, 21):
                    ingredient = meal_detail.get(f'strIngredient{i}')
                    measure = meal_detail.get(f'strMeasure{i}')
                    if ingredient and ingredient.strip():
                        ingredients.append(f"{measure} {ingredient}".strip())
                results.append({
                    'id': f"ext_{meal_detail['idMeal']}",
                    'title': meal_detail.get('strMeal', 'Unknown'),
                    'description': f"{meal_detail.get('strCategory', '')} - {meal_detail.get('strArea', '')}".strip(' - '),
                    'image_url': meal_detail.get('strMealThumb'),
                    'instructions': meal_detail.get('strInstructions', 'No instructions'),
                    'ingredients': '\n'.join(ingredients),
                    'difficulty': 'medium',
                    'external': True
                })
            return {'results': results, 'total': len(results)}
        except Exception as e:
            print(f"External API error: {e}")
            return {'results': [], 'total': 0}

@app.get("/api/recipes/category", tags=["External"])
async def get_recipes_by_category(c: str = "Seafood"):
    """Get recipes by category from TheMealDB"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"https://www.themealdb.com/api/json/v1/1/filter.php?c={c}",
                timeout=10.0
            )
            data = response.json()
            if not data or not data.get("meals"):
                return {"results": [], "total": 0}
            results = []
            for meal in data["meals"][:10]:
                results.append({
                    'id': f"ext_{meal['idMeal']}",
                    'title': meal.get('strMeal', 'Unknown'),
                    'image_url': meal.get('strMealThumb'),
                    'description': c,
                    'difficulty': 'medium',
                    'external': True
                })
            return {'results': results, 'total': len(results)}
        except Exception as e:
            print(f"Category API error: {e}")
            return {'results': [], 'total': 0}

# ----------------- Root Route -----------------
@app.get("/")
async def read_root():
    """Root endpoint"""
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "message": "Recipe Finder API - Version 2.0.0",
        "docs": "/docs",
        "health": "/health",
        "metrics": "/metrics",
        "version": "2.0.0"
    }