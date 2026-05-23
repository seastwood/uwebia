# syntax=docker/dockerfile:1.7

# Stage 1: build a virtualenv with all Python deps. Using a separate
# stage keeps the final image small (no compilers / build headers).
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build deps for psycopg2-binary (libpq), Pillow (zlib, jpeg, freetype),
# cryptography (libffi, openssl), and others.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libjpeg-dev \
        zlib1g-dev \
        libfreetype6-dev \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && pip install -r requirements.txt


# Stage 2: runtime image. Only the venv + app code, plus the runtime
# shared libs Pillow/psycopg2 need at import time.
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    FLASK_APP=main.py \
    # Bind gunicorn to all interfaces inside the container.
    GUNICORN_BIND=0.0.0.0:5772 \
    GUNICORN_WORKERS=3 \
    GUNICORN_TIMEOUT=120

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        libjpeg62-turbo \
        zlib1g \
        libfreetype6 \
        libffi8 \
        libssl3 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app && useradd --system --gid app --home /app app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app . /app

# Make sure the dirs the app expects exist and are writable. `config/`
# holds server.json + db_config.json (the app rewrites these at runtime),
# and static/uploads is the user-content directory. Both are mounted as
# named volumes in docker-compose, but creating them here keeps the image
# self-sufficient if someone runs it without compose.
RUN mkdir -p /app/config /app/static/uploads /app/database \
    && chown -R app:app /app

USER app

EXPOSE 5772

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://localhost:5772/ > /dev/null || exit 1

# Run gunicorn with `main:app` (Flask app object lives at module level
# in main.py). Worker count and timeout overridable via env vars above.
CMD ["sh", "-c", "exec gunicorn main:app \
        --bind ${GUNICORN_BIND} \
        --workers ${GUNICORN_WORKERS} \
        --timeout ${GUNICORN_TIMEOUT} \
        --access-logfile - \
        --error-logfile -"]
