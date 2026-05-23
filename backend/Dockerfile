FROM python:3.11-slim

LABEL maintainer="AutonomSOC Team"
LABEL description="AutonomSOC Backend — FastAPI + LangGraph + Ollama"

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc libpq-dev git \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Non-root user
RUN useradd -m -u 1000 autonomsoc && chown -R autonomsoc:autonomsoc /app
USER autonomsoc

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# BUG FIXED: original was `backend.api.routes:app` which assumed the
# Docker context was the repo root. Since WORKDIR=/app and we COPY .
# from inside backend/, the correct module path is api.routes:app
CMD ["uvicorn", "api.routes:app", "--host", "0.0.0.0", "--port", "8000"]
