from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from . import models, schemas
from .database import get_db
from .users import get_current_user

router = APIRouter(
    prefix="/recipes",
    tags=["recipes"]
)

def get_recipe_by_id(db: Session, recipe_id: int):
    return db.query(models.Recipe).filter(models.Recipe.id == recipe_id).first()

def get_recipes(db: Session, skip: int = 0, limit: int = 100, search: Optional[str] = None):
    query = db.query(models.Recipe)
    if search:
        query = query.filter(models.Recipe.title.contains(search))
    return query.offset(skip).limit(limit).all()

def get_recipes_by_user(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(models.Recipe).filter(models.Recipe.owner_id == user_id).offset(skip).limit(limit).all()

def create_recipe(db: Session, recipe: schemas.RecipeCreate, user_id: int):
    db_recipe = models.Recipe(
        title=recipe.title,
        description=recipe.description,
        ingredients=recipe.ingredients,
        instructions=recipe.instructions,
        prep_time=recipe.prep_time,
        cook_time=recipe.cook_time,
        servings=recipe.servings,
        difficulty=recipe.difficulty,
        cuisine_type=recipe.cuisine_type,
        dietary_tags=recipe.dietary_tags,
        owner_id=user_id
    )
    db.add(db_recipe)
    db.commit()
    db.refresh(db_recipe)
    return db_recipe

def update_recipe(db: Session, recipe_id: int, recipe_update: schemas.RecipeUpdate, user_id: int):
    db_recipe = db.query(models.Recipe).filter(models.Recipe.id == recipe_id).first()
    if not db_recipe:
        return None
    if db_recipe.owner_id != user_id:
        return False
    
    update_data = recipe_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_recipe, field, value)
    
    db.commit()
    db.refresh(db_recipe)
    return db_recipe

def delete_recipe(db: Session, recipe_id: int, user_id: int):
    db_recipe = db.query(models.Recipe).filter(models.Recipe.id == recipe_id).first()
    if not db_recipe:
        return None
    if db_recipe.owner_id != user_id:
        return False
    
    db.delete(db_recipe)
    db.commit()
    return True

@router.post("/", response_model=schemas.Recipe)
def create_new_recipe(
    recipe: schemas.RecipeCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    return create_recipe(db=db, recipe=recipe, user_id=current_user.id)

@router.get("/", response_model=List[schemas.Recipe])
def read_recipes(
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = Query(None, description="Search recipes by title"),
    db: Session = Depends(get_db)
):
    recipes = get_recipes(db, skip=skip, limit=limit, search=search)
    return recipes

@router.get("/my-recipes", response_model=List[schemas.Recipe])
def read_my_recipes(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    recipes = get_recipes_by_user(db, user_id=current_user.id, skip=skip, limit=limit)
    return recipes

@router.get("/{recipe_id}", response_model=schemas.Recipe)
def read_recipe(recipe_id: int, db: Session = Depends(get_db)):
    db_recipe = get_recipe_by_id(db, recipe_id=recipe_id)
    if db_recipe is None:
        raise HTTPException(status_code=404, detail="Recipe not found")
    return db_recipe

@router.put("/{recipe_id}", response_model=schemas.Recipe)
def update_existing_recipe(
    recipe_id: int,
    recipe_update: schemas.RecipeUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    result = update_recipe(db, recipe_id=recipe_id, recipe_update=recipe_update, user_id=current_user.id)
    if result is None:
        raise HTTPException(status_code=404, detail="Recipe not found")
    if result is False:
        raise HTTPException(status_code=403, detail="Not authorized to update this recipe")
    return result

@router.delete("/{recipe_id}")
def delete_existing_recipe(
    recipe_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    result = delete_recipe(db, recipe_id=recipe_id, user_id=current_user.id)
    if result is None:
        raise HTTPException(status_code=404, detail="Recipe not found")
    if result is False:
        raise HTTPException(status_code=403, detail="Not authorized to delete this recipe")
    return {"message": "Recipe deleted successfully"}

@router.get("/cuisine/{cuisine_type}", response_model=List[schemas.Recipe])
def read_recipes_by_cuisine(
    cuisine_type: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    recipes = db.query(models.Recipe).filter(models.Recipe.cuisine_type == cuisine_type).offset(skip).limit(limit).all()
    return recipes

@router.get("/difficulty/{difficulty}", response_model=List[schemas.Recipe])
def read_recipes_by_difficulty(
    difficulty: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    recipes = db.query(models.Recipe).filter(models.Recipe.difficulty == difficulty).offset(skip).limit(limit).all()
    return recipes