# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install Flask
RUN pip install --no-cache-dir Flask==3.0.0

# Copy all files from repository root
COPY . .

# Create static directory if it doesn't exist and ensure frontend is there
RUN mkdir -p static && \
    if [ -f har_analyzer_tool_frontend.html ]; then \
        cp har_analyzer_tool_frontend.html static/har_analyzer_tool_frontend.html; \
    fi

# Expose port (Render will override with PORT env var)
EXPOSE 5000

# Set environment variable for production
ENV FLASK_ENV=production

# Run the application
CMD ["python", "har_analyzer_tool_backend.py"]
