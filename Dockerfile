FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies including build tools for argon2
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# Copy application code
COPY . .


# Set Python path so imports work correctly
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run application - IMPORTANT: Run from /app directory
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]