# syntax=docker/dockerfile:1
# PROJECT SENTINEL - multi-stage image (builds the dashboard, ships agent + API).

# ---- stage 1: build the frontend ----
FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- stage 2: python runtime ----
FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN groupadd --system sentinel && useradd --system --gid sentinel --home /var/lib/sentinel sentinel \
    && mkdir -p /var/lib/sentinel /var/log/sentinel && chown -R sentinel:sentinel /var/lib/sentinel /var/log/sentinel

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY agent/ ./agent/
COPY backend/ ./backend/
COPY config/ ./config/
COPY --from=frontend /app/frontend/dist ./frontend/dist

ENV SENTINEL_DATA_DIR=/var/lib/sentinel \
    SENTINEL_CONFIG=/app/config/sentinel.yaml \
    SENTINEL_API_HOST=0.0.0.0 \
    SENTINEL_API_PORT=8443
EXPOSE 8443
USER sentinel
# Default: run the control plane / dashboard API. Run the agent with:
#   docker run ... python -m agent run
CMD ["python", "-m", "backend", "run"]
