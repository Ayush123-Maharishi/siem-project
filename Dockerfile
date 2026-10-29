# Base lightweight Python image
FROM python:3.11-slim

# Prevent Python from writing .pyc and buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Generate initial logs and seed SQLite database
RUN python collectors/generator.py && python core/engine.py

# Expose Streamlit default port
EXPOSE 8501

# Healthcheck to ensure container is alive
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Launch Streamlit app
ENTRYPOINT ["python", "-m", "streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
