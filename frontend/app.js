// Global variables
let currentUser = null;
let authToken = null;
let currentRecipes = [];
let currentPage = 0;
const recipesPerPage = 20;

// DOM elements
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const loginModal = document.getElementById('login-modal');
const recipeModal = document.getElementById('recipe-modal');
const addRecipeModal = document.getElementById('add-recipe-modal');
const searchInput = document.getElementById('search-input');
const searchBtn = document.getElementById('search-btn');

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    checkAuthToken();
});

// Initialize app
function initializeApp() {
    showSection('home');
    loadRecipes();
}

// Setup event listeners
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = e.target.getAttribute('href').substring(1);
            showSection(section);
            loadSectionData(section);
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    });

    // Authentication
    loginBtn.addEventListener('click', () => openModal('login-modal'));
    logoutBtn.addEventListener('click', logout);

    // Auth tabs
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabType = e.target.dataset.tab;
            switchAuthTab(tabType);
        });
    });

    // Auth forms
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    document.getElementById('add-recipe-form').addEventListener('submit', handleAddRecipe);

    // Search
    searchBtn.addEventListener('click', performSearch);
    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performSearch();
    });

    // Add recipe button
    document.getElementById('add-recipe-btn').addEventListener('click', () => {
        openModal('add-recipe-modal');
    });

    // Load more button
    document.getElementById('load-more').addEventListener('click', loadMoreRecipes);

    // Modal close buttons
    document.querySelectorAll('.close').forEach(closeBtn => {
        closeBtn.addEventListener('click', (e) => {
            const modal = e.target.closest('.modal');
            closeModal(modal.id);
        });
    });

    // Close modals when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            closeModal(e.target.id);
        }
    });
}

// Authentication functions
function checkAuthToken() {
    authToken = localStorage.getItem('authToken');
    if (authToken) {
        fetchCurrentUser();
    }
}

async function fetchCurrentUser() {
    try {
        const response = await fetch('/auth/me', {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            currentUser = await response.json();
            updateUIForLoggedInUser();
        } else {
            localStorage.removeItem('authToken');
            authToken = null;
        }
    } catch (error) {
        console.error('Error fetching user:', error);
    }
}

function updateUIForLoggedInUser() {
    loginBtn.style.display = 'none';
    logoutBtn.style.display = 'block';
    document.getElementById('favorites-link').style.display = 'block';
    document.getElementById('my-recipes-link').style.display = 'block';
}

function updateUIForLoggedOutUser() {
    loginBtn.style.display = 'block';
    logoutBtn.style.display = 'none';
    document.getElementById('favorites-link').style.display = 'none';
    document.getElementById('my-recipes-link').style.display = 'none';
    currentUser = null;
}

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    showLoading(true);
    try {
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        const response = await fetch('/auth/login', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            authToken = data.access_token;
            localStorage.setItem('authToken', authToken);
            await fetchCurrentUser();
            closeModal('login-modal');
            showToast('Login successful!', 'success');
            document.getElementById('login-form').reset();
        } else {
            showToast(data.detail || 'Login failed', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
        console.error('Login error:', error);
    } finally {
        showLoading(false);
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;

    showLoading(true);
    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });

        const data = await response.json();

        if (response.ok) {
            showToast('Registration successful! Please login.', 'success');
            switchAuthTab('login');
            document.getElementById('register-form').reset();
        } else {
            showToast(data.detail || 'Registration failed', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
        console.error('Register error:', error);
    } finally {
        showLoading(false);
    }
}

function logout() {
    localStorage.removeItem('authToken');
    authToken = null;
    updateUIForLoggedOutUser();
    showSection('home');
    showToast('Logged out successfully', 'success');
}

// Recipe functions
async function loadRecipes(reset = false) {
    if (reset) {
        currentRecipes = [];
        currentPage = 0;
    }

    showLoading(true);
    try {
        // Fetch local recipes
        const localResponse = await fetch(`/recipes?skip=${currentPage * recipesPerPage}&limit=${recipesPerPage}`);
        
        if (!localResponse.ok) {
            throw new Error('Failed to load local recipes');
        }
        
        const localData = await localResponse.json();
        
        // Check if localData is an array or an object with a recipes property
        const localRecipes = Array.isArray(localData) ? localData : (localData.recipes || []);
        
        let allRecipes = [...localRecipes];

        // On first load, fetch external recipes
        // On first load, fetch external recipes by category
if (currentPage === 0) {
    const categories = ['Pasta', 'Seafood', 'Chicken', 'Beef', 'Dessert', 'Vegetarian'];
    
    for (const category of categories) {
        try {
            const extResponse = await fetch(`/api/recipes/category?c=${category}`);
            if (extResponse.ok) {
                const extData = await extResponse.json();
                if (extData.results && Array.isArray(extData.results)) {
                    allRecipes.push(...extData.results);
                }
            }
        } catch (err) {
            console.log(`Skipping ${category}:`, err.message);
        }
    }
    
    // Remove duplicates by ID
    const seen = new Set();
    allRecipes = allRecipes.filter(recipe => {
        const id = recipe.id;
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    });
}
        currentRecipes = reset ? allRecipes : [...currentRecipes, ...allRecipes];
        displayRecipes(currentRecipes, 'recipe-grid');
        currentPage++;

        // Manage load more button
        const loadMoreBtn = document.getElementById('load-more');
        if (loadMoreBtn) {
            loadMoreBtn.style.display = localRecipes.length < recipesPerPage ? 'none' : 'block';
        }

    } catch (error) {
        console.error('Load recipes error:', error);
        showToast('Error loading recipes: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}
async function loadMyRecipes() {
    if (!authToken) {
        showToast('Please login to view your recipes', 'warning');
        return;
    }

    showLoading(true);
    try {
        const response = await fetch('/recipes/my', {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            const recipes = await response.json();
            displayMyRecipes(recipes, 'my-recipes-grid');
        } else {
            const error = await response.json();
            showToast(error.detail || 'Error loading your recipes', 'error');
        }
    } catch (error) {
        showToast('Network error loading your recipes', 'error');
        console.error('Load my recipes error:', error);
    } finally {
        showLoading(false);
    }
}

async function loadFavorites() {
    if (!authToken) {
        showToast('Please login to view favorites', 'warning');
        return;
    }

    showLoading(true);
    try {
        const response = await fetch('/favorites', {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const favorites = await response.json();

        if (response.ok) {
            const favoriteRecipes = favorites.map(fav => fav.recipe);
            displayFavoriteRecipes(favoriteRecipes, 'favorites-grid');
        } else {
            showToast('Error loading favorites', 'error');
        }
    } catch (error) {
        showToast('Network error loading favorites', 'error');
        console.error('Load favorites error:', error);
    } finally {
        showLoading(false);
    }
}
function displayFavoriteRecipes(recipes, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    if (recipes.length === 0) {
        container.innerHTML = '<div class="no-recipes"><p>No favorites yet. Add recipes to favorites to see them here!</p></div>';
        return;
    }

    recipes.forEach(recipe => {
        const card = document.createElement('div');
        card.className = 'recipe-card';
        
        const imageUrl = recipe.image_url || 'https://via.placeholder.com/300x200?text=No+Image';
        const prepTime = recipe.prep_time ? `${recipe.prep_time}min prep` : '';
        const cookTime = recipe.cook_time ? `${recipe.cook_time}min cook` : '';
        const timeInfo = [prepTime, cookTime].filter(t => t).join(' • ');

        card.innerHTML = `
            <img src="${imageUrl}" alt="${recipe.title}" class="recipe-image" onerror="this.src='https://via.placeholder.com/300x200?text=No+Image'">
            <div class="recipe-content">
                <h3 class="recipe-title">${recipe.title}</h3>
                <p class="recipe-description">${recipe.description || 'No description available'}</p>
                <div class="recipe-meta">
                    <span class="recipe-time">
                        <i class="fas fa-clock"></i>
                        ${timeInfo || 'Time not specified'}
                    </span>
                    <span class="recipe-difficulty">${recipe.difficulty || 'medium'}</span>
                </div>
                <div class="recipe-actions">
                    <button onclick="removeFavorite(${recipe.id}); event.stopPropagation();" class="btn btn-danger">
                        <i class="fas fa-heart-broken"></i> Remove
                    </button>
                </div>
            </div>
        `;

        card.addEventListener('click', (e) => {
            if (!e.target.closest('button')) {
                showRecipeDetails(recipe.id);
            }
        });

        container.appendChild(card);
    });
}
// Original function for home/recipes/search tabs
function displayRecipes(recipes, containerId, showActions = false) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    if (recipes.length === 0) {
        container.innerHTML = '<div class="no-recipes"><p>No recipes found.</p></div>';
        return;
    }

    recipes.forEach(recipe => {
        const recipeCard = createRecipeCard(recipe, showActions);
        container.appendChild(recipeCard);
    });
}

// Function for My Recipes tab with edit/delete buttons
function displayMyRecipes(recipes, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    if (recipes.length === 0) {
        container.innerHTML = '<div class="no-recipes"><p>No recipes found. Create your first recipe!</p></div>';
        return;
    }

    recipes.forEach(recipe => {
        const card = document.createElement('div');
        card.className = 'recipe-card';
        
        const imageUrl = recipe.image_url || 'https://via.placeholder.com/300x200?text=No+Image';
        const prepTime = recipe.prep_time ? `${recipe.prep_time}min prep` : '';
        const cookTime = recipe.cook_time ? `${recipe.cook_time}min cook` : '';
        const timeInfo = [prepTime, cookTime].filter(t => t).join(' • ');

        card.innerHTML = `
            <img src="${imageUrl}" alt="${recipe.title}" class="recipe-image" onerror="this.src='https://via.placeholder.com/300x200?text=No+Image'">
            <div class="recipe-content">
                <h3 class="recipe-title">${recipe.title}</h3>
                <p class="recipe-description">${recipe.description || 'No description available'}</p>
                <div class="recipe-meta">
                    <span class="recipe-time"><i class="fas fa-clock"></i> ${timeInfo || 'Time not specified'}</span>
                    <span class="recipe-difficulty">${recipe.difficulty || 'medium'}</span>
                </div>
                <div class="recipe-actions">
                    <button onclick="editRecipe(${recipe.id}); event.stopPropagation();" class="btn btn-secondary">
                        <i class="fas fa-edit"></i> Edit
                    </button>
                    <button onclick="deleteRecipe(${recipe.id}); event.stopPropagation();" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
        `;

        card.addEventListener('click', (e) => {
            if (!e.target.closest('button')) {
                showRecipeDetails(recipe.id);
            }
        });

        container.appendChild(card);
    });
}

async function removeFavorite(recipeId) {
    if (!authToken) {
        showToast('Please login', 'warning');
        return;
    }

    showLoading(true);
    try {
        const response = await fetch(`/favorites/${recipeId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            showToast('Removed from favorites', 'success');
            loadFavorites(); // Refresh the list
        } else {
            showToast('Error removing from favorites', 'error');
        }
    } catch (error) {
        showToast('Network error', 'error');
        console.error('Remove favorite error:', error);
    } finally {
        showLoading(false);
    }
}



function createRecipeCard(recipe, showActions = false) {
    const card = document.createElement('div');
    card.className = 'recipe-card';
    const isExternal = recipe.external || String(recipe.id).startsWith('ext_');
    
    const imageUrl = recipe.image_url || 'https://via.placeholder.com/300x200?text=No+Image';
    const prepTime = recipe.prep_time ? `${recipe.prep_time}min prep` : '';
    const cookTime = recipe.cook_time ? `${recipe.cook_time}min cook` : '';
    const timeInfo = [prepTime, cookTime].filter(t => t).join(' • ');

    card.innerHTML = `
        <img src="${imageUrl}" alt="${recipe.title}" class="recipe-image" onerror="this.src='https://via.placeholder.com/300x200?text=No+Image'">
        <div class="recipe-content">
            <h3 class="recipe-title">${recipe.title} ${isExternal ? '🌐' : ''}</h3>
            <p class="recipe-description">${recipe.description || 'No description available'}</p>
            <div class="recipe-meta">
                <span class="recipe-time">
                    <i class="fas fa-clock"></i>
                    ${timeInfo || 'Time not specified'}
                </span>
                <span class="recipe-difficulty">${recipe.difficulty || 'easy'}</span>
            </div>
            <div class="recipe-actions">
                <button class="btn btn-favorite" onclick="handleFavoriteClick('${recipe.id}', ${isExternal}, event)">
                    <i class="fas fa-heart"></i> ${isExternal ? 'Save' : ''}
                </button>
                ${showActions && !isExternal ? `
                    <button onclick="editRecipe(${recipe.id}); event.stopPropagation();" class="btn btn-secondary">
                        <i class="fas fa-edit"></i> Edit
                    </button>
                    <button onclick="deleteRecipe(${recipe.id}); event.stopPropagation();" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                ` : ''}
            </div>
        </div>
    `;

    card.addEventListener('click', (e) => {
        if (!e.target.closest('button')) {
            showRecipeDetails(recipe.id);
        }
    });
    if (isExternal) {
        card.dataset.recipeData = JSON.stringify(recipe);
    }
    return card;
}

async function handleFavoriteClick(recipeId, isExternal) {
    if (!authToken) {
        showToast('Please login to add favorites', 'warning');
        return;
    }

    showLoading(true);
    try {
        if (isExternal) {
            // Get the full recipe data from the card
            const card = event.target.closest('.recipe-card');
            const recipeData = JSON.parse(card.dataset.recipeData);
            
            // First save to database
            showToast('Saving recipe to your collection...', 'info');
            const savedId = await saveExternalRecipe(recipeData);
            
            if (savedId) {
                // Then add to favorites
                const response = await fetch(`/favorites/${savedId}`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    showToast('Recipe saved and added to favorites!', 'success');
                } else {
                    showToast('Recipe saved but could not add to favorites', 'warning');
                }
            } else {
                showToast('Error saving recipe', 'error');
            }
        } else {
            // Regular favorite toggle for your recipes
            await toggleFavorite(recipeId);
        }
    } catch (error) {
        showToast('Error processing favorite', 'error');
        console.error('Favorite error:', error);
    } finally {
        showLoading(false);
    }
}

async function showRecipeDetails(recipeId) {
    showLoading(true);
    try {
        // Check if external recipe (starts with "ext_")
        if (String(recipeId).startsWith('ext_')) {
            const mealId = String(recipeId).replace('ext_', '');
            const response = await fetch(`https://www.themealdb.com/api/json/v1/1/lookup.php?i=${mealId}`);
            const data = await response.json();
            const recipe = data.meals[0];
            
            // Build ingredients list
            const ingredients = [];
            for (let i = 1; i <= 20; i++) {
                const ingredient = recipe[`strIngredient${i}`];
                const measure = recipe[`strMeasure${i}`];
                if (ingredient && ingredient.trim()) {
                    ingredients.push(`${measure} ${ingredient}`.trim());
                }
            }
            
            const externalRecipe = {
                title: recipe.strMeal,
                image_url: recipe.strMealThumb,
                description: `${recipe.strCategory} - ${recipe.strArea}`,
                ingredients: ingredients.join('\n'),
                instructions: recipe.strInstructions,
                source_url: recipe.strYoutube
            };
            
            displayRecipeDetails(externalRecipe);
            openModal('recipe-modal');
        } else {
            // Local recipe
            const response = await fetch(`/recipes/${recipeId}`);
            const recipe = await response.json();

            if (response.ok) {
                displayRecipeDetails(recipe);
                openModal('recipe-modal');
            } else {
                showToast('Error loading recipe details', 'error');
            }
        }
    } catch (error) {
        showToast('Network error loading recipe details', 'error');
        console.error('Recipe details error:', error);
    } finally {
        showLoading(false);
    }
}
function displayRecipeDetails(recipe) {
    const detailsContainer = document.getElementById('recipe-details');
    const imageUrl = recipe.image_url || 'https://via.placeholder.com/400x250?text=No+Image';
    
    // Format ingredients (assuming they're stored as comma-separated or line-separated)
    const ingredients = recipe.ingredients.split(/[,\n]/).map(ing => ing.trim()).filter(ing => ing);
    const ingredientsList = ingredients.map(ing => `<li>${ing}</li>`).join('');

    // Format instructions
    const instructions = recipe.instructions.replace(/\n/g, '<br>');

    detailsContainer.innerHTML = `
        <div class="recipe-detail">
            <div class="recipe-detail-header">
                <h2 class="recipe-detail-title">${recipe.title}</h2>
                <img src="${imageUrl}" alt="${recipe.title}" class="recipe-detail-image" onerror="this.src='https://via.placeholder.com/400x250?text=No+Image'">
                <div class="recipe-detail-meta">
                    ${recipe.prep_time ? `<span><i class="fas fa-clock"></i> Prep: ${recipe.prep_time}min</span>` : ''}
                    ${recipe.cook_time ? `<span><i class="fas fa-fire"></i> Cook: ${recipe.cook_time}min</span>` : ''}
                    <span><i class="fas fa-users"></i> Serves: ${recipe.servings || 1}</span>
                    <span><i class="fas fa-signal"></i> ${recipe.difficulty || 'easy'}</span>
                </div>
            </div>
            
            ${recipe.description ? `
                <div class="recipe-detail-section">
                    <h4>Description</h4>
                    <p>${recipe.description}</p>
                </div>
            ` : ''}
            
            <div class="recipe-detail-section">
                <h4>Ingredients</h4>
                <ul class="ingredients-list">
                    ${ingredientsList}
                </ul>
            </div>
            
            <div class="recipe-detail-section">
                <h4>Instructions</h4>
                <div class="instructions-content">
                    ${instructions}
                </div>
            </div>
        </div>
    `;
}

async function handleAddRecipe(e) {
    e.preventDefault();
    
    if (!authToken) {
        showToast('Please login to add recipes', 'warning');
        return;
    }

    const recipeData = {
        title: document.getElementById('recipe-title').value,
        description: document.getElementById('recipe-description').value,
        ingredients: document.getElementById('recipe-ingredients').value,
        instructions: document.getElementById('recipe-instructions').value,
        prep_time: parseInt(document.getElementById('recipe-prep-time').value) || null,
        cook_time: parseInt(document.getElementById('recipe-cook-time').value) || null,
        servings: parseInt(document.getElementById('recipe-servings').value) || 1,
        difficulty: document.getElementById('recipe-difficulty').value,
        image_url: document.getElementById('recipe-image-url').value || null
    };

    showLoading(true);
    try {
        const response = await fetch('/recipes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(recipeData)
        });

        const data = await response.json();

        if (response.ok) {
            showToast('Recipe added successfully!', 'success');
            closeModal('add-recipe-modal');
            document.getElementById('add-recipe-form').reset();
            // Refresh recipes if we're on the my-recipes page
            const activeSection = document.querySelector('.section.active');
            if (activeSection.id === 'my-recipes') {
                loadMyRecipes();
            }
        } else {
            showToast(data.detail || 'Error adding recipe', 'error');
        }
    } catch (error) {
        showToast('Network error adding recipe', 'error');
        console.error('Add recipe error:', error);
    } finally {
        showLoading(false);
    }
}

async function deleteRecipe(recipeId) {
    if (!confirm('Are you sure you want to delete this recipe?')) {
        return;
    }

    showLoading(true);
    try {
        const response = await fetch(`/recipes/${recipeId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            showToast('Recipe deleted successfully', 'success');
            loadMyRecipes(); // Refresh the list
        } else {
            const data = await response.json();
            showToast(data.detail || 'Error deleting recipe', 'error');
        }
    } catch (error) {
        showToast('Network error deleting recipe', 'error');
        console.error('Delete recipe error:', error);
    } finally {
        showLoading(false);
    }
}

async function toggleFavorite(recipeId) {
    if (!authToken) {
        showToast('Please login to add favorites', 'warning');
        return;
    }

    try {
        // Try to add to favorites first
        const response = await fetch(`/favorites/${recipeId}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            showToast('Added to favorites!', 'success');
        } else if (response.status === 400) {
            // If already exists, try to remove
            const removeResponse = await fetch(`/favorites/${recipeId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
            
            if (removeResponse.ok) {
                showToast('Removed from favorites', 'success');
            }
        } else {
            showToast('Error updating favorites', 'error');
        }
    } catch (error) {
        showToast('Network error updating favorites', 'error');
        console.error('Toggle favorite error:', error);
    }
}
async function saveExternalRecipe(externalRecipe) {
    if (!authToken) {
        showToast('Please login to save recipes', 'warning');
        return null;
    }

    try {
        // Ensure ingredients is a string
        let ingredientsStr = '';
        if (typeof externalRecipe.ingredients === 'string') {
            ingredientsStr = externalRecipe.ingredients;
        } else if (Array.isArray(externalRecipe.ingredients)) {
            ingredientsStr = externalRecipe.ingredients.join('\n');
        }

        // Ensure instructions is a string
        let instructionsStr = externalRecipe.instructions || 'No instructions provided';
        if (typeof instructionsStr !== 'string') {
            instructionsStr = String(instructionsStr);
        }

        const recipeData = {
            title: externalRecipe.title || 'Untitled Recipe',
            description: externalRecipe.description || 'Recipe from TheMealDB',
            ingredients: ingredientsStr || 'No ingredients listed',
            instructions: instructionsStr,
            image_url: externalRecipe.image_url || null,
            difficulty: 'medium',
            servings: 4,
            prep_time: null,
            cook_time: null
        };

        console.log('Saving recipe:', recipeData); // Debug log

        const response = await fetch('/recipes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(recipeData)
        });

        if (response.ok) {
            const savedRecipe = await response.json();
            return savedRecipe.id;
        } else {
            const error = await response.json();
            console.error('Save recipe error:', error);
            showToast('Error: ' + (error.detail || 'Could not save recipe'), 'error');
            return null;
        }
    } catch (error) {
        console.error('Error saving external recipe:', error);
        showToast('Network error saving recipe', 'error');
        return null;
    }
}

async function performSearch() {
    const query = searchInput.value.trim().toLowerCase();
    if (!query) {
        showToast('Please enter a search term', 'warning');
        return;
    }

    showLoading(true);
    try {
        // Categories that should use category search instead of ingredient search
        const categories = [
            'pasta', 'dessert', 'seafood', 'vegetarian', 'vegan', 'breakfast', 
            'beef', 'chicken', 'lamb', 'pork', 'side', 'starter', 'goat',
            'miscellaneous', 'soup', 'curry', 'salad'
        ];
        
        const isCategory = categories.includes(query);

        // Search local database
        const localPromise = fetch(`/recipes/search?q=${encodeURIComponent(query)}&limit=20`).catch(() => null);
        
        // Search external API - use category or ingredient endpoint
        let externalPromise;
        if (isCategory) {
            externalPromise = fetch(`/api/recipes/category?c=${encodeURIComponent(query)}`).catch(() => null);
        } else {
            externalPromise = fetch(`/api/recipes/external?q=${encodeURIComponent(query)}`).catch(() => null);
        }

        const [localResponse, externalResponse] = await Promise.all([localPromise, externalPromise]);

        let localRecipes = [];
        let externalRecipes = [];

        if (localResponse && localResponse.ok) {
            localRecipes = await localResponse.json();
        }

        if (externalResponse && externalResponse.ok) {
            const externalData = await externalResponse.json();
            externalRecipes = externalData.results || [];
        }

        const allRecipes = [...localRecipes, ...externalRecipes];

        if (allRecipes.length > 0) {
            displayRecipes(allRecipes, 'recipe-grid');
            showSection('recipes');
            showToast(`Found ${allRecipes.length} recipes (${localRecipes.length} yours, ${externalRecipes.length} from web)`, 'success');
        } else {
            displayRecipes([], 'recipe-grid');
            showSection('recipes');
            showToast('No recipes found. Try ingredients like "chicken", "milk" or categories like "pasta", "dessert"', 'warning');
        }
    } catch (error) {
        showToast('Network error searching recipes', 'error');
        console.error('Search error:', error);
    } finally {
        showLoading(false);
    }
}

window.quickSearch = function(term) {
    searchInput.value = term;
    performSearch();
};
// UI Helper functions
function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(sectionId).classList.add('active');
}

function loadSectionData(sectionId) {
    switch (sectionId) {
        case 'recipes':
            loadRecipes(true);
            break;
        case 'favorites':
            loadFavorites();
            break;
        case 'my-recipes':
            loadMyRecipes();
            break;
    }
}

function loadMoreRecipes() {
    loadRecipes();
}

function openModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

function switchAuthTab(tabType) {
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabType}"]`).classList.add('active');

    document.querySelectorAll('.auth-form').forEach(form => {
        form.style.display = 'none';
    });
    document.getElementById(`${tabType}-form`).style.display = 'block';
}

function showLoading(show) {
    document.getElementById('loading').style.display = show ? 'flex' : 'none';
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    const container = document.getElementById('toast-container');
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}

async function editRecipe(recipeId) {
    if (!authToken) {
        showToast('Please login to edit recipes', 'warning');
        return;
    }

    try {
        // Get the recipe details first
        const response = await fetch(`/recipes/${recipeId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        const recipe = await response.json();

        if (!response.ok) {
            showToast(recipe.detail || 'Error loading recipe', 'error');
            return;
        }

        // Prefill form with existing recipe data
        document.getElementById('recipe-title').value = recipe.title;
        document.getElementById('recipe-description').value = recipe.description || '';
        document.getElementById('recipe-ingredients').value = recipe.ingredients || '';
        document.getElementById('recipe-instructions').value = recipe.instructions || '';
        document.getElementById('recipe-prep-time').value = recipe.prep_time || '';
        document.getElementById('recipe-cook-time').value = recipe.cook_time || '';
        document.getElementById('recipe-servings').value = recipe.servings || 1;
        document.getElementById('recipe-difficulty').value = recipe.difficulty || 'easy';
        document.getElementById('recipe-image-url').value = recipe.image_url || '';

        // Open the modal
        openModal('add-recipe-modal');

        // Replace form submit handler temporarily
        const form = document.getElementById('add-recipe-form');
        form.onsubmit = async function(e) {
            e.preventDefault();

            const updatedData = {
                title: document.getElementById('recipe-title').value,
                description: document.getElementById('recipe-description').value,
                ingredients: document.getElementById('recipe-ingredients').value,
                instructions: document.getElementById('recipe-instructions').value,
                prep_time: parseInt(document.getElementById('recipe-prep-time').value) || null,
                cook_time: parseInt(document.getElementById('recipe-cook-time').value) || null,
                servings: parseInt(document.getElementById('recipe-servings').value) || 1,
                difficulty: document.getElementById('recipe-difficulty').value,
                image_url: document.getElementById('recipe-image-url').value || null
            };

            try {
                const updateResponse = await fetch(`/recipes/${recipeId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(updatedData)
                });

                if (updateResponse.ok) {
                    showToast('Recipe updated successfully!', 'success');
                    closeModal('add-recipe-modal');
                    loadMyRecipes(); // refresh list
                } else {
                    const data = await updateResponse.json();
                    showToast(data.detail || 'Error updating recipe', 'error');
                }
            } catch (error) {
                showToast('Network error updating recipe', 'error');
                console.error('Edit recipe error:', error);
            }
        };
    } catch (error) {
        showToast('Error loading recipe for edit', 'error');
        console.error('Edit recipe fetch error:', error);
    }
}
