# === Stage 1: Build React frontend ===
FROM node:20-alpine AS frontend-builder
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install
COPY frontend/ .
RUN npm run build

# === Stage 2: Install Python deps ===
FROM python:3.11-slim AS backend-builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# === Stage 3: Runtime ===
FROM python:3.11-slim AS runtime
WORKDIR /app

RUN groupadd -r aegis && useradd -r -g aegis -m aegis
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY --from=backend-builder /install /usr/local
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .
COPY --from=frontend-builder /frontend/dist ./static

RUN chown -R aegis:aegis /app
USER aegis

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--loop", "uvloop", "--http", "httptools"]
