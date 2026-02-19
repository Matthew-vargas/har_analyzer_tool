# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install Flask
RUN pip install --no-cache-dir Flask==3.0.0

# Copy backend file
COPY har_analyzer_tool_backend.py .

# Create static directory and copy frontend
RUN mkdir -p static
COPY har_analyzer_tool_frontend.html static/har_analyzer_tool_frontend.html

# Expose port (Render will override with PORT env var)
EXPOSE 5000

# Set environment variable for production
ENV FLASK_ENV=production

# Run the application
CMD ["python", "har_analyzer_tool_backend.py"]
