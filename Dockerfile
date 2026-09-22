# Dockerfile
# Base image for the Python pipeline (worker + dashboard share this image,
# with the actual command overridden per-service in docker-compose.yml)

FROM python:3.13-slim

WORKDIR /app

# Install OS-level dependencies Playwright's Chromium needs to actually run
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Installs Chromium plus its OS-level dependencies (fonts, libs, etc.)
RUN playwright install --with-deps chromium

COPY . .

# Default command (overridden by docker-compose for the dashboard service)
CMD ["python", "-m", "src.ingest.ct_stream_client"]
