FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY src/ ./src/
COPY static/ ./static/
COPY models/ ./models/
COPY data/ ./data/

# Create reports directory
RUN mkdir -p reports

# Expose dashboard port
EXPOSE 8000

# Start the dashboard
CMD ["python", "src/dashboard.py"]
