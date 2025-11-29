#!/bin/bash

# IMPORTANT: Replace YOUR_NAME with your actual name
YOUR_NAME="Geethika"  # CHANGE THIS!

# Variables
RESOURCE_GROUP="${YOUR_NAME}-recipe-rg"
LOCATION="westeurope"
ACR_NAME="${YOUR_NAME}recipeacr"  # No hyphens, lowercase only
APP_SERVICE_PLAN="${YOUR_NAME}-recipe-plan"
WEB_APP_STAGING="${YOUR_NAME}-recipe-app-staging"
WEB_APP_PROD="${YOUR_NAME}-recipe-app-prod"

echo "Creating resources for: $YOUR_NAME"
echo "=================================="

# Login to Azure (use Service Principal from Blackboard)
az login --service-principal \
  --username <APP_ID_FROM_BLACKBOARD> \
  --password <PASSWORD_FROM_BLACKBOARD> \
  --tenant <TENANT_ID_FROM_BLACKBOARD>

# Create Resource Group
echo "Creating resource group..."
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION

# Create Azure Container Registry
echo "Creating container registry..."
az acr create \
  --name $ACR_NAME \
  --resource-group $RESOURCE_GROUP \
  --sku Basic \
  --admin-enabled true

# Create App Service Plan (Linux)
echo "Creating App Service Plan..."
az appservice plan create \
  --name $APP_SERVICE_PLAN \
  --resource-group $RESOURCE_GROUP \
  --is-linux \
  --sku B1

# Create Web App for Staging
echo "Creating staging web app..."
az webapp create \
  --name $WEB_APP_STAGING \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_SERVICE_PLAN \
  --deployment-container-image-name $ACR_NAME.azurecr.io/recipe-finder:latest

# Create Web App for Production
echo "Creating production web app..."
az webapp create \
  --name $WEB_APP_PROD \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_SERVICE_PLAN \
  --deployment-container-image-name $ACR_NAME.azurecr.io/recipe-finder:latest

# Configure continuous deployment
echo "Configuring continuous deployment..."
az webapp deployment container config \
  --name $WEB_APP_STAGING \
  --resource-group $RESOURCE_GROUP \
  --enable-cd true

az webapp deployment container config \
  --name $WEB_APP_PROD \
  --resource-group $RESOURCE_GROUP \
  --enable-cd true

# Set environment variables
echo "Setting environment variables..."
az webapp config appsettings set \
  --name $WEB_APP_STAGING \
  --resource-group $RESOURCE_GROUP \
  --settings \
    DATABASE_URL="sqlite:///./recipes.db" \
    SECRET_KEY="your-secret-key-here" \
    ENVIRONMENT="staging"

az webapp config appsettings set \
  --name $WEB_APP_PROD \
  --resource-group $RESOURCE_GROUP \
  --settings \
    DATABASE_URL="sqlite:///./recipes.db" \
    SECRET_KEY="your-secret-key-here" \
    ENVIRONMENT="production"

echo "=================================="
echo "✅ Setup complete!"
echo "Staging URL: https://$WEB_APP_STAGING.azurewebsites.net"
echo "Production URL: https://$WEB_APP_PROD.azurewebsites.net"