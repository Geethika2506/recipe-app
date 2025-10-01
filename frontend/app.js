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
        const response = await fetch(`/recipes?skip=${currentPage * recipesPerPage}&limit=${recipesPerPage}`);
        const recipes = await response.json();

        if (response.ok) {
            currentRecipes = reset ? recipes : [...currentRecipes, ...recipes];
            displayRecipes(currentRecipes, 'recipe-grid');
            currentPage++;

            // Hide load more button if no more recipes
            const loadMoreBtn = document.getElementById('load-more');
            if (recipes.length < recipesPerPage) {
                loadMoreBtn.style.display = 'none';
            } else {
                loadMoreBtn.style.display = 'block';
            }
        } else {
            showToast('Error loading recipes', 'error');
        }
    } catch (error) {
        showToast('Network error loading recipes', 'error');
        console.error('Load recipes error:', error);
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

        const recipes = await response.json();

        if (response.ok) {
            displayRecipes(recipes, 'my-recipes-grid', true);
        } else {
            showToast('Error loading your recipes', 'error');
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
            displayRecipes(favoriteRecipes, 'favorites-grid');
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

function createRecipeCard(recipe, showActions = false) {
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
                <span class="recipe-difficulty">${recipe.difficulty || 'easy'}</span>
            </div>
            <div class="recipe-actions">
                ${authToken ? `<button onclick="toggleFavorite(${recipe.id})" class="btn btn-favorite">
                    <i class="fas fa-heart"></i>
                </button>` : ''}
                ${showActions ? `
                    <button onclick="editRecipe(${recipe.id})" class="btn btn-secondary">
                        <i class="fas fa-edit"></i> Edit
                    </button>
                    <button onclick="deleteRecipe(${recipe.id})" class="btn btn-danger">
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

    return card;
}

async function showRecipeDetails(recipeId) {
    showLoading(true);
    try {
        const response = await fetch(`/recipes/${recipeId}`);
        const recipe = await response.json();

        if (response.ok) {
            displayRecipeDetails(recipe);
            openModal('recipe-modal');
        } else {
            showToast('Error loading recipe details', 'error');
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

async function performSearch() {
    const query = searchInput.value.trim();
    if (!query) {
        showToast('Please enter a search term', 'warning');
        return;
    }

    showLoading(true);
    try {
        const response = await fetch(`/recipes/search?q=${encodeURIComponent(query)}&limit=50`);
        const recipes = await response.json();

        if (response.ok) {
            displayRecipes(recipes, 'recipe-grid');
            showSection('recipes');
            showToast(`Found ${recipes.length} recipes for "${query}"`, 'success');
        } else {
            showToast('Error searching recipes', 'error');
        }
    } catch (error) {
        showToast('Network error searching recipes', 'error');
        console.error('Search error:', error);
    } finally {
        showLoading(false);
    }
}

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
