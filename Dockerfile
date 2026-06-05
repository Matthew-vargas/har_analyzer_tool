FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY backend.py .
COPY app.py .

# Copy static assets
RUN mkdir -p static
COPY static/index.html static/index.html
COPY static/bulk.html static/bulk.html
COPY static/history.html static/history.html

# Expose port (Render overrides with PORT env var)
EXPOSE 5000

ENV FLASK_ENV=production

# Use gunicorn for production (handles concurrency and SSE properly)
CMD gunicorn --bind 0.0.0.0:$PORT --timeout 300 --worker-class sync --workers 1 app:app
