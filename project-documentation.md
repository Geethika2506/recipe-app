# Recipe Finder App - Code Documentation
**Student:** Geethika  
**Date:** November 30, 2024

## Project Overview
FastAPI-based recipe finder application with CI/CD pipeline

---

## Main Application Code

### app/main.py
```python
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import app.models as models
import app.schemas as schemas
from app.database import engine, get_db

app = FastAPI(title="Recipe Finder API")

@app.get("/health")
def health_check():
    return {"status": "healthy"}

# ... rest of your code
```

---

## CI/CD Pipeline Configuration

### .github/workflows/ci-cd.yml
```yaml
name: CI/CD Pipeline with Azure Deployment

on:
  push:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    # ... rest of your workflow
```

---

## Dockerfile
```dockerfile
FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libffi-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Requirements

### requirements.txt
```
fastapi==0.104.1
uvicorn==0.24.0
sqlalchemy==2.0.23
pydantic==2.9.2
# ... rest of requirements
```

---

## Test Results

- **Total Tests:** 72
- **Passed:** 72 (100%)
- **Code Coverage:** 72%
- **Status:** ✅ All tests passing

---

## Deployment Information

- **GitHub Repository:** https://github.com/Geethika2506/recipe-app
- **Staging URL:** https://geethika-recipe-app-staging.azurewebsites.net
- **Production URL:** https://geethika-recipe-app-prod.azurewebsites.net

---

## Screenshots

### GitHub Actions - Successful Build
![GitHub Actions](path/to/screenshot.png)

### Application Running
![App Running](path/to/screenshot.png)