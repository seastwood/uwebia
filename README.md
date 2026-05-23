# Uwebia

A self-hosted, single-user CMS — Flask + PostgreSQL, with a drag-and-drop page editor, public navbar, posts, calendar, store, and forum.

You can run it three ways:

1. **Docker Compose with the prebuilt image** — fastest, no build step.
2. **Docker Compose, building from source** — if you want to modify the code.
3. **Directly on Linux** — Python virtualenv + system Postgres, no Docker.

---

## 1. Docker (prebuilt image — easiest)

Images are published to Docker Hub as [`setheastwood/uwebia`](https://hub.docker.com/r/setheastwood/uwebia) on every push to `main` and on every `vX.Y.Z` tag.

### Prerequisites

- Docker Engine 20.10+ and the Docker Compose plugin (`docker compose ...`).
- ~500 MB of disk space for the image and ~1 GB for the Postgres data volume.

### Setup

```bash
# 1. Grab the deploy files (the image bundles the app code; you only need
#    docker-compose.yml + .env.example + Caddyfile from the repo).
mkdir uwebia && cd uwebia
curl -fsSLO https://raw.githubusercontent.com/seastwood/uwebia/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/seastwood/uwebia/main/.env.example
curl -fsSLO https://raw.githubusercontent.com/seastwood/uwebia/main/Caddyfile
mv .env.example .env

# 2. Edit .env — at minimum set POSTGRES_PASSWORD and SECRET_KEY.
#    Generate a SECRET_KEY:
python3 -c 'import secrets; print(secrets.token_hex(32))'

# 3. Tell compose to use the published image instead of building locally.
#    Either edit docker-compose.yml to change `build: .` → `image: setheastwood/uwebia:latest`,
#    or drop in this one-line override:
cat > docker-compose.override.yml <<'EOF'
services:
  app:
    image: setheastwood/uwebia:latest
    build: !reset null
EOF

# 4. Start it.
docker compose pull
docker compose up -d
docker compose logs -f app    # ctrl-C when you see "Listening at: http://0.0.0.0:5772"
```

The app is now on **`http://<docker-host>:5772`**. The first admin account is created on first visit — register at `/register`.

### Behind a reverse proxy (pfSense HAProxy, Nginx, Cloudflare, etc.)

The default config exposes port `5772` to the host. Point your proxy at `<docker-host-ip>:5772`. Make sure it forwards the standard headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `Host`) so the app sees the real client IP and detects HTTPS.

For pfSense HAProxy: under the backend's *Advanced settings*, add `option forwardfor` and (for HTTPS frontends) `http-request set-header X-Forwarded-Proto https if { ssl_fc }`.

To bind the port to loopback only (proxy on the same host):
```env
# in .env
LISTEN_ADDR=127.0.0.1
APP_HOST_PORT=5772
```

### With Caddy (auto-HTTPS, opt-in)

Skip the proxy section above and use the bundled Caddy service:

```env
# in .env
SITE_ADDRESS=example.com
ACME_EMAIL=you@example.com
```
```bash
docker compose --profile caddy up -d
```

Caddy provisions a Let's Encrypt certificate automatically and proxies to the app. Don't publish port `5772` to the host if Caddy is the only thing reaching the app — comment out the `ports:` block under `app` in `docker-compose.yml`.

### Updating

```bash
docker compose pull
docker compose up -d
```

The auto-migrator runs `db.create_all()` and adds any new columns on startup; no manual migration commands needed.

### Data persistence

These named volumes survive `docker compose down`:

| Volume          | Mounted at              | Holds                                         |
|-----------------|-------------------------|-----------------------------------------------|
| `db_data`       | `/var/lib/postgresql/data` | Postgres data                              |
| `uploads_data`  | `/app/static/uploads`   | User-uploaded images / assets                 |
| `config_data`   | `/app/config`           | `server.json`, `db_config.json` (admin-tuned) |
| `caddy_data`    | `/data`                 | Caddy TLS certs (only if you use Caddy)       |
| `caddy_config`  | `/config`               | Caddy autosave config (Caddy only)            |

To **back up** uploads and the database:
```bash
docker run --rm -v uwebia_uploads_data:/data -v "$PWD":/backup alpine \
    tar czf /backup/uploads-$(date +%F).tgz -C /data .
docker compose exec db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > db-$(date +%F).sql
```

Run `docker compose down -v` to **destroy** the volumes too (factory reset).

---

## 2. Docker, building from source

Same as above but clone the repo and let compose build locally — useful when you're modifying the code.

```bash
git clone https://github.com/seastwood/uwebia.git
cd uwebia
cp .env.example .env
# edit .env: POSTGRES_PASSWORD, SECRET_KEY, etc.
docker compose up -d --build
docker compose logs -f app
```

Every code change requires a rebuild: `docker compose up -d --build`. For faster iteration during development, mount the source as a bind volume and run the Flask dev server — see *Development* below.

---

## 3. Directly on Linux

For users who don't want Docker. Tested on Debian/Ubuntu; equivalent steps work on RHEL/Arch.

### Prerequisites

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-pip \
    postgresql postgresql-contrib \
    libpq-dev libjpeg-dev zlib1g-dev libfreetype6-dev \
    libffi-dev libssl-dev \
    build-essential git
```

### Database

```bash
sudo -u postgres psql <<'SQL'
CREATE USER uwebia WITH PASSWORD 'change-me';
CREATE DATABASE uwebia OWNER uwebia;
GRANT ALL PRIVILEGES ON DATABASE uwebia TO uwebia;
SQL
```

### App

```bash
git clone https://github.com/seastwood/uwebia.git
cd uwebia

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Tell the app how to reach Postgres + give Flask a session key.
export DATABASE_URL='postgresql+psycopg2://uwebia:change-me@localhost:5432/uwebia'
export SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Dev server (port 5772 by default — change in config/server.json).
python3 main.py
```

The auto-migrator creates the schema and adds new columns on every boot, so the first run sets everything up.

### Running as a systemd service

`/etc/systemd/system/uwebia.service`:
```ini
[Unit]
Description=Uwebia CMS
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=uwebia
WorkingDirectory=/opt/uwebia
Environment="DATABASE_URL=postgresql+psycopg2://uwebia:change-me@localhost:5432/uwebia"
Environment="SECRET_KEY=replace-with-64-hex-chars"
ExecStart=/opt/uwebia/venv/bin/gunicorn main:app \
    --bind 0.0.0.0:5772 \
    --workers 3 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo useradd --system --home /opt/uwebia uwebia
sudo cp -r . /opt/uwebia && sudo chown -R uwebia:uwebia /opt/uwebia
sudo systemctl daemon-reload
sudo systemctl enable --now uwebia
sudo systemctl status uwebia
journalctl -u uwebia -f       # tail logs
```

Put Nginx / Caddy / Apache in front the same way as any other gunicorn-served WSGI app.

---

## Development

```bash
git clone https://github.com/seastwood/uwebia.git
cd uwebia
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL='sqlite:///database/uwebia.db'   # or your local Postgres URL
python3 main.py
```

The Flask dev server has auto-reload on. SQLite is fine for local hacking; switch to Postgres before deploying since some features rely on Postgres-specific behavior (`server_default=false()`, JSON columns, etc.).

### Building a Docker image locally

```bash
docker build -t uwebia:dev .
docker run --rm -p 5772:5772 \
    -e DATABASE_URL=postgresql+psycopg2://uwebia:change-me@host.docker.internal:5432/uwebia \
    -e SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))') \
    uwebia:dev
```

### Releasing a versioned image

GitHub Actions builds and pushes on every push to `main` and every `vX.Y.Z` tag. To cut a release:

```bash
git tag v1.2.3
git push origin v1.2.3
```

The workflow at `.github/workflows/docker-publish.yml` builds multi-arch (`linux/amd64` + `linux/arm64`) and pushes `setheastwood/uwebia:1.2.3`, `:1.2`, `:1`, and `:latest`.

---

## Configuration reference

All settings can come from environment variables (preferred for Docker) or `config/server.json` / `config/db_config.json` (which the admin UI rewrites).

| Variable             | Default                         | Description                                                       |
|----------------------|---------------------------------|-------------------------------------------------------------------|
| `DATABASE_URL`       | sqlite under `database/`        | SQLAlchemy connection string                                       |
| `SECRET_KEY`         | *(must be set)*                 | Flask session / CSRF secret                                        |
| `GUNICORN_WORKERS`   | `3`                             | Worker process count (Docker only)                                 |
| `GUNICORN_TIMEOUT`   | `120`                           | Request timeout in seconds (Docker only)                           |
| `APP_HOST_PORT`      | `5772`                          | Host-side port the app container listens on (compose only)         |
| `LISTEN_ADDR`        | `0.0.0.0`                       | Host bind address (use `127.0.0.1` to restrict to loopback)        |
| `SITE_ADDRESS`       | `:80`                           | Caddy site address (only with `--profile caddy`)                   |
| `ACME_EMAIL`         | *(empty)*                       | Let's Encrypt registration email (Caddy only)                      |
| `POSTGRES_USER`      | `uwebia`                        | Postgres role used by the `db` service                             |
| `POSTGRES_PASSWORD`  | *(must be set)*                 | Postgres password                                                  |
| `POSTGRES_DB`        | `uwebia`                        | Postgres database name                                             |

---

## Troubleshooting

**Can't connect to the database.**  Check `docker compose logs db` for the actual Postgres error. The most common cause is a `POSTGRES_PASSWORD` change after the volume was initialized — Postgres uses the password from the *first* boot and ignores later env changes. Wipe the volume to reset: `docker compose down && docker volume rm uwebia_db_data`.

**Uploads disappear after `docker compose up`.**  You're missing the `uploads_data` volume or have a bind-mount of the local `./static` directory shadowing it. Check the `volumes:` block under the `app` service.

**Admin UI changes (DB URL, server config) revert on rebuild.**  The `config_data` volume isn't mounted. The app writes `config/server.json` and `config/db_config.json` at runtime — they must persist.

**Mobile URL bar shows the wrong color.**  This is `theme-color` getting cached by iOS Safari's bfcache. Reload without cache (long-press the reload button → *Reload Without Content Blockers*), or force-quit and reopen Safari.

---

## License

Add a `LICENSE` file. (TBD.)
