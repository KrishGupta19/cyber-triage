FROM python:3.11-slim

WORKDIR /app

# System build deps for C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# ── 1. Install PyTorch CPU-only first (pinned to match dev environment) ───────
RUN pip install --no-cache-dir \
    torch==2.10.0 \
    --index-url https://download.pytorch.org/whl/cpu

# ── 2. Install PyTorch Geometric (pinned) ────────────────────────────────────
RUN pip install --no-cache-dir torch-geometric==2.7.0

# ── 3. Install remaining dependencies ────────────────────────────────────────
RUN pip install --no-cache-dir \
    psutil \
    fastapi \
    "uvicorn[standard]" \
    networkx \
    python-multipart \
    requests \
    anthropic

# ── 4. Copy application files ─────────────────────────────────────────────────
COPY src/     ./src/
COPY static/  ./static/
COPY models/  ./models/
COPY data/    ./data/

RUN mkdir -p reports

EXPOSE 8000

# ── NOTE: Run with --pid=host on Linux to monitor real host processes ─────────
CMD ["python", "src/dashboard.py"]
