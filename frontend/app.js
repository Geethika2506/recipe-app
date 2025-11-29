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
            headers: { 'Authorization': `Bearer ${authToken}` }
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
            headers: { 'Content-Type': 'application/json' },
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
        const localResponse = await fetch(`/recipes?skip=${currentPage * recipesPerPage}&limit=${recipesPerPage}`);
        
        if (!localResponse.ok) throw new Error('Failed to load local recipes');
        
        const localData = await localResponse.json();
        const localRecipes = Array.isArray(localData) ? localData : (localData.recipes || []);
        
        let allRecipes = [...localRecipes];

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
            headers: { 'Authorization': `Bearer ${authToken}` }
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
    console.log('=== loadFavorites START ===');
    
    if (!authToken) {
        console.log('No auth token');
        showToast('Please login to view favorites', 'warning');
        return;
    }

    console.log('Auth token exists:', authToken ? 'yes' : 'no');
    showLoading(true);
    
    try {
        console.log('Fetching favorites from /favorites...');
        const response = await fetch('/favorites', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

<<<<<<< HEAD
        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);

        if (response.ok) {
            const favorites = await response.json();
            console.log('Parsed favorites:', JSON.stringify(favorites, null, 2));
            console.log('Favorites type:', typeof favorites);
            console.log('Is array:', Array.isArray(favorites));
            console.log('Length:', favorites ? favorites.length : 0);
            
            if (favorites && favorites.length > 0) {
                console.log('First favorite structure:', JSON.stringify(favorites[0], null, 2));
            }
            
            displayFavorites(favorites, 'favorites-grid');
=======
        if (response.ok) {
            const favoriteRecipes = await response.json();
            displayFavoriteRecipes(favoriteRecipes, 'favorites-grid');
>>>>>>> 0bdd4c4f2f34af6f3e8485687e625ca66f4df037
        } else {
            const errorText = await response.text();
            console.error('Error response:', errorText);
            showToast('Error loading favorites', 'error');
        }
    } catch (error) {
<<<<<<< HEAD
        console.error('Error loading favorites:', error);
        showToast('Network error loading favorites', 'error');
=======
        console.error('=== CATCH BLOCK ===');
        console.error('Error type:', error.name);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        showToast('Network error loading favorites: ' + error.message, 'error');
>>>>>>> origin/main
    } finally {
        console.log('=== loadFavorites END ===');
        showLoading(false);
    }
}
<<<<<<< HEAD

=======
<<<<<<< HEAD
=======
>>>>>>> origin/main
function displayFavoriteRecipes(recipes, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    const validRecipes = recipes.filter(recipe => recipe != null && typeof recipe === 'object' && recipe.id);

    if (validRecipes.length === 0) {
        container.innerHTML = '<div class="no-recipes"><p>No favorites yet. Add recipes to favorites to see them here!</p></div>';
        return;
    }

    validRecipes.forEach(recipe => {
        const card = createRecipeCard(recipe, false);
        // Modify button to be a remove button
        const actionBtn = card.querySelector('.btn-favorite');
        if(actionBtn) {
            actionBtn.className = 'btn btn-danger';
            actionBtn.innerHTML = '<i class="fas fa-heart-broken"></i> Remove';
            actionBtn.onclick = (e) => {
                e.stopPropagation();
                removeFavorite(recipe.id);
            };
        }
        container.appendChild(card);
    });
}
<<<<<<< HEAD

=======
// Original function for home/recipes/search tabs
>>>>>>> 0bdd4c4f2f34af6f3e8485687e625ca66f4df037
>>>>>>> origin/main
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

function displayMyRecipes(recipes, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    if (recipes.length === 0) {
        container.innerHTML = '<div class="no-recipes"><p>No recipes found. Create your first recipe!</p></div>';
        return;
    }

    recipes.forEach(recipe => {
        const card = createRecipeCard(recipe, true);
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
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        if (response.ok) {
            showToast('Removed from favorites', 'success');
            loadFavorites(); 
        } else {
            showToast('Error removing from favorites', 'error');
        }
    } catch (error) {
        showToast('Network error', 'error');
    } finally {
        showLoading(false);
    }
}

// ---------------------------------------------------------
//  Improved Handle Favorite / Save Logic (Fixes 500 Error)
// ---------------------------------------------------------
async function handleFavoriteClick(recipeId, isExternal, event) {
    event.stopPropagation();

    if (!authToken) {
        showToast('Please login to add favorites', 'warning');
        return;
    }

    const btn = event.currentTarget;
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    btn.disabled = true;

    try {
        if (isExternal) {
            const card = event.target.closest('.recipe-card');
            if (!card || !card.dataset.recipeData) throw new Error('Recipe data missing');

            let recipeData = JSON.parse(card.dataset.recipeData);

            // Fetch full details if ingredients are missing
            if (!recipeData.instructions || !recipeData.ingredients || recipeData.instructions === 'No instructions provided') {
                const extId = String(recipeData.id).replace('ext_', '');
                const lookupRes = await fetch(`https://www.themealdb.com/api/json/v1/1/lookup.php?i=${extId}`);
                const lookupData = await lookupRes.json();
                
                if (lookupData.meals && lookupData.meals[0]) {
                    const fullMeal = lookupData.meals[0];
                    const ingredients = [];
                    for (let i = 1; i <= 20; i++) {
                        const ingredient = fullMeal[`strIngredient${i}`];
                        const measure = fullMeal[`strMeasure${i}`];
                        if (ingredient && ingredient.trim()) {
                            ingredients.push(`${measure} ${ingredient}`.trim());
                        }
                    }
                    recipeData = {
                        ...recipeData,
                        instructions: fullMeal.strInstructions || 'No instructions',
                        ingredients: ingredients.join('\n'),
                        image_url: fullMeal.strMealThumb,
                    };
                    card.dataset.recipeData = JSON.stringify(recipeData); // Cache for next time
                }
            }

            // CONSTRUCTION OF PAYLOAD
            // IMPORTANT: Sending 0 instead of null prevents 500 errors
            const payload = {
                title: String(recipeData.title || 'Untitled').substring(0, 100),
                description: String(recipeData.description || 'External Recipe').substring(0, 500),
                ingredients: formatIngredients(recipeData.ingredients),
                instructions: String(recipeData.instructions || 'No instructions'),
                image_url: recipeData.image_url || '',
                difficulty: 'medium',
                servings: 4,
                prep_time: 0, // Explicitly 0
                cook_time: 0  // Explicitly 0
            };

            const response = await fetch('/favorites/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${authToken}`
                },
                body: JSON.stringify(payload)
            });

            // Robust JSON handling
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.indexOf("application/json") !== -1) {
                const result = await response.json();
                if (response.ok) {
                    showToast('Added to favorites!', 'success');
                    btn.innerHTML = '<i class="fas fa-heart"></i> Saved';
                    btn.classList.add('saved');
                } else {
                    if (result.message && result.message.includes('already')) {
                        showToast('Already in favorites', 'info');
                    } else {
                        showToast(result.detail || 'Failed to save', 'error');
                        btn.innerHTML = originalContent;
                        btn.disabled = false;
                    }
                }
            } else {
                // If response is not JSON (e.g. 500 HTML error), read as text
                const text = await response.text();
                console.error('Server Error:', text);
                showToast(`Server error (${response.status}). Check console.`, 'error');
                btn.innerHTML = originalContent;
                btn.disabled = false;
            }

        } else {
            // Local Recipe Toggle
            await toggleFavorite(recipeId);
            btn.innerHTML = originalContent;
            btn.disabled = false;
        }
    } catch (error) {
        console.error('Favorite error:', error);
        showToast('Error: ' + error.message, 'error');
        btn.innerHTML = originalContent;
        btn.disabled = false;
    }
}

async function toggleFavorite(recipeId) {
    try {
        const response = await fetch(`/favorites/${recipeId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        const data = await response.json();
        if (response.ok) {
            showToast(data.message.includes('already') ? 'Already in favorites' : 'Added to favorites', 'success');
        } else {
            showToast(data.detail || 'Error', 'error');
        }
    } catch (error) {
        console.error(error);
        showToast('Network error', 'error');
    }
}

async function showRecipeDetails(recipeId) {
    showLoading(true);
    try {
        if (String(recipeId).startsWith('ext_')) {
            const mealId = String(recipeId).replace('ext_', '');
            const response = await fetch(`https://www.themealdb.com/api/json/v1/1/lookup.php?i=${mealId}`);
            const data = await response.json();
            const recipe = data.meals[0];
            
            const ingredients = [];
            for (let i = 1; i <= 20; i++) {
                const ingredient = recipe[`strIngredient${i}`];
                const measure = recipe[`strMeasure${i}`];
                if (ingredient && ingredient.trim()) {
                    ingredients.push(`${measure} ${ingredient}`.trim());
                }
            }
            
            displayRecipeDetails({
                title: recipe.strMeal,
                image_url: recipe.strMealThumb,
                description: `${recipe.strCategory} - ${recipe.strArea}`,
                ingredients: ingredients.join('\n'),
                instructions: recipe.strInstructions,
                prep_time: 0,
                cook_time: 0
            });
            openModal('recipe-modal');
        } else {
            const response = await fetch(`/recipes/${recipeId}`);
            const recipe = await response.json();
            if (response.ok) {
                displayRecipeDetails(recipe);
                openModal('recipe-modal');
            } else {
                showToast('Error loading recipe', 'error');
            }
        }
    } catch (error) {
        showToast('Network error', 'error');
    } finally {
        showLoading(false);
    }
}

function displayRecipeDetails(recipe) {
    const detailsContainer = document.getElementById('recipe-details');
    const imageUrl = recipe.image_url || 'https://via.placeholder.com/400x250?text=No+Image';
    
    const ingredients = String(recipe.ingredients || '').split(/[,\n]/).map(ing => ing.trim()).filter(ing => ing);
    const ingredientsList = ingredients.map(ing => `<li>${ing}</li>`).join('');
    const instructions = String(recipe.instructions || '').replace(/\n/g, '<br>');

    detailsContainer.innerHTML = `
        <div class="recipe-detail">
            <div class="recipe-detail-header">
                <h2 class="recipe-detail-title">${recipe.title}</h2>
                <img src="${imageUrl}" alt="${recipe.title}" class="recipe-detail-image" onerror="this.src='https://via.placeholder.com/400x250?text=No+Image'">
                <div class="recipe-detail-meta">
                    ${recipe.prep_time ? `<span><i class="fas fa-clock"></i> Prep: ${recipe.prep_time}min</span>` : ''}
                    ${recipe.cook_time ? `<span><i class="fas fa-fire"></i> Cook: ${recipe.cook_time}min</span>` : ''}
                    <span><i class="fas fa-users"></i> Serves: ${recipe.servings || 4}</span>
                    <span><i class="fas fa-signal"></i> ${recipe.difficulty || 'medium'}</span>
                </div>
            </div>
            
            <div class="recipe-detail-section">
                <h4>Description</h4>
                <p>${recipe.description || ''}</p>
            </div>
            
            <div class="recipe-detail-section">
                <h4>Ingredients</h4>
                <ul class="ingredients-list">${ingredientsList}</ul>
            </div>
            
            <div class="recipe-detail-section">
                <h4>Instructions</h4>
                <div class="instructions-content">${instructions}</div>
            </div>
        </div>
    `;
}

async function handleAddRecipe(e) {
    e.preventDefault();
    if (!authToken) return showToast('Please login', 'warning');

    const recipeData = {
        title: document.getElementById('recipe-title').value,
        description: document.getElementById('recipe-description').value,
        ingredients: document.getElementById('recipe-ingredients').value,
        instructions: document.getElementById('recipe-instructions').value,
        prep_time: parseInt(document.getElementById('recipe-prep-time').value) || 0,
        cook_time: parseInt(document.getElementById('recipe-cook-time').value) || 0,
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

        if (response.ok) {
            showToast('Recipe added!', 'success');
            closeModal('add-recipe-modal');
            document.getElementById('add-recipe-form').reset();
            loadMyRecipes();
        } else {
            const data = await response.json();
            showToast(data.detail || 'Error adding recipe', 'error');
        }
    } catch (error) {
        showToast('Network error', 'error');
    } finally {
        showLoading(false);
    }
}

async function deleteRecipe(recipeId) {
    if (!confirm('Are you sure?')) return;

    showLoading(true);
    try {
        const response = await fetch(`/recipes/${recipeId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        if (response.ok) {
            showToast('Deleted', 'success');
            loadMyRecipes();
        } else {
            showToast('Error deleting', 'error');
        }
    } catch (error) {
        showToast('Network error', 'error');
    } finally {
        showLoading(false);
    }
}

async function performSearch() {
    const query = searchInput.value.trim().toLowerCase();
    if (!query) return showToast('Please enter a search term', 'warning');

    showLoading(true);
    try {
        const categories = ['pasta', 'dessert', 'seafood', 'vegetarian', 'vegan', 'breakfast', 'beef', 'chicken', 'lamb', 'pork'];
        const isCategory = categories.includes(query);

        const localPromise = fetch(`/recipes/search?q=${encodeURIComponent(query)}&limit=20`).catch(() => null);
        
        let externalPromise;
        if (isCategory) {
            externalPromise = fetch(`/api/recipes/category?c=${encodeURIComponent(query)}`).catch(() => null);
        } else {
            externalPromise = fetch(`/api/recipes/external?q=${encodeURIComponent(query)}`).catch(() => null);
        }

        const [localRes, extRes] = await Promise.all([localPromise, externalPromise]);
        
        let localRecipes = localRes && localRes.ok ? await localRes.json() : [];
        let extRecipes = extRes && extRes.ok ? (await extRes.json()).results || [] : [];

        const allRecipes = [...localRecipes, ...extRecipes];
        displayRecipes(allRecipes, 'recipe-grid');
        showSection('recipes');
        
        if (allRecipes.length === 0) showToast('No recipes found', 'warning');

    } catch (error) {
        console.error(error);
        showToast('Search failed', 'error');
    } finally {
        showLoading(false);
    }
}

// Helpers
function createRecipeCard(recipe, showActions = false) {
    const card = document.createElement('div');
    card.className = 'recipe-card';
    const isExternal = recipe.external || String(recipe.id).startsWith('ext_');
    
    const imageUrl = recipe.image_url || 'https://via.placeholder.com/300x200?text=No+Image';
    const timeInfo = (recipe.prep_time || recipe.cook_time) 
        ? `${recipe.prep_time || 0}m / ${recipe.cook_time || 0}m` 
        : 'Time varies';

    card.innerHTML = `
        <img src="${imageUrl}" alt="${recipe.title}" class="recipe-image" onerror="this.src='https://via.placeholder.com/300x200?text=No+Image'">
        <div class="recipe-content">
            <h3 class="recipe-title">${recipe.title} ${isExternal ? '🌐' : ''}</h3>
            <p class="recipe-description">${(recipe.description || '').substring(0, 100)}...</p>
            <div class="recipe-meta">
                <span class="recipe-time"><i class="fas fa-clock"></i> ${timeInfo}</span>
                <span class="recipe-difficulty">${recipe.difficulty || 'medium'}</span>
            </div>
            <div class="recipe-actions">
                <button class="btn btn-favorite" onclick="handleFavoriteClick('${recipe.id}', ${isExternal}, event)">
                    <i class="fas fa-heart"></i> ${isExternal ? 'Save' : 'Favorite'}
                </button>
                ${showActions && !isExternal ? `
                    <button onclick="editRecipe(${recipe.id}); event.stopPropagation();" class="btn btn-secondary"><i class="fas fa-edit"></i></button>
                    <button onclick="deleteRecipe(${recipe.id}); event.stopPropagation();" class="btn btn-danger"><i class="fas fa-trash"></i></button>
                ` : ''}
            </div>
        </div>
    `;

    card.addEventListener('click', (e) => {
        if (!e.target.closest('button')) showRecipeDetails(recipe.id);
    });

    if (isExternal) {
        // Store sanitized data
        const safeData = {
            id: recipe.id,
            title: recipe.title,
            description: recipe.description || '',
            ingredients: recipe.ingredients || '',
            instructions: recipe.instructions || '',
            image_url: recipe.image_url || '',
            difficulty: recipe.difficulty || 'medium',
            external: true
        };
        card.dataset.recipeData = JSON.stringify(safeData);
    }
    
    return card;
}

function formatIngredients(ing) {
    if (!ing) return 'No ingredients';
    if (Array.isArray(ing)) return ing.join('\n');
    return String(ing);
}

async function editRecipe(recipeId) {
    if (!authToken) return showToast('Login required', 'warning');

    try {
        const response = await fetch(`/recipes/${recipeId}`, {
             headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const recipe = await response.json();
        if (!response.ok) return showToast('Load failed', 'error');

        document.getElementById('recipe-title').value = recipe.title;
        document.getElementById('recipe-description').value = recipe.description || '';
        document.getElementById('recipe-ingredients').value = recipe.ingredients || '';
        document.getElementById('recipe-instructions').value = recipe.instructions || '';
        document.getElementById('recipe-prep-time').value = recipe.prep_time || 0;
        document.getElementById('recipe-cook-time').value = recipe.cook_time || 0;
        document.getElementById('recipe-servings').value = recipe.servings || 1;
        document.getElementById('recipe-difficulty').value = recipe.difficulty || 'easy';
        document.getElementById('recipe-image-url').value = recipe.image_url || '';

        openModal('add-recipe-modal');

        const form = document.getElementById('add-recipe-form');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const updatedData = {
                title: document.getElementById('recipe-title').value,
                description: document.getElementById('recipe-description').value,
                ingredients: document.getElementById('recipe-ingredients').value,
                instructions: document.getElementById('recipe-instructions').value,
                prep_time: parseInt(document.getElementById('recipe-prep-time').value) || 0,
                cook_time: parseInt(document.getElementById('recipe-cook-time').value) || 0,
                servings: parseInt(document.getElementById('recipe-servings').value) || 1,
                difficulty: document.getElementById('recipe-difficulty').value,
                image_url: document.getElementById('recipe-image-url').value || null
            };

            const putRes = await fetch(`/recipes/${recipeId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
                body: JSON.stringify(updatedData)
            });

            if (putRes.ok) {
                showToast('Updated', 'success');
                closeModal('add-recipe-modal');
                loadMyRecipes();
                // Restore original handler for new adds
                form.onsubmit = handleAddRecipe; 
            } else {
                showToast('Update failed', 'error');
            }
        };
    } catch (err) {
        console.error(err);
    }
}

function showLoading(show) {
    const el = document.getElementById('loading');
    if (el) el.style.display = show ? 'flex' : 'none';
}

function showToast(msg, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = msg;
    document.getElementById('toast-container').appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

function showSection(id) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById(id).classList.add('active');
}

function loadSectionData(id) {
    if (id === 'recipes') loadRecipes(true);
    else if (id === 'favorites') loadFavorites();
    else if (id === 'my-recipes') loadMyRecipes();
}

function openModal(id) { document.getElementById(id).style.display = 'block'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }

function switchAuthTab(type) {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-tab="${type}"]`).classList.add('active');
    document.querySelectorAll('.auth-form').forEach(f => f.style.display = 'none');
    document.getElementById(`${type}-form`).style.display = 'block';
}

window.quickSearch = function(term) {
    searchInput.value = term;
    performSearch();
};