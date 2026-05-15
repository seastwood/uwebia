#!/usr/bin/env bash
# setup_postgres.sh — provision PostgreSQL for Uwebia
# Run as root (or with sudo) on the server that will host the database.
#
# Usage:
#   sudo bash setup_postgres.sh [options]
#
# Options:
#   --db       Database name   (default: uwebia)
#   --user     DB username     (default: uwebia_user)
#   --pass     DB password     (prompt if omitted, or use - to auto-generate)
#   --network  CIDR allowed to connect remotely, e.g. 192.168.1.0/24
#              (omit or use 'localhost' for local-only access)
#   --port     PostgreSQL port (default: 5432)

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
DB_NAME="uwebia"
DB_USER="uwebia_user"
DB_PASS=""
NETWORK=""
PG_PORT="5432"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)      DB_NAME="$2";  shift 2 ;;
        --user)    DB_USER="$2";  shift 2 ;;
        --pass)    DB_PASS="$2";  shift 2 ;;
        --network) NETWORK="$2";  shift 2 ;;
        --port)    PG_PORT="$2";  shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[info]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ok]\033[0m    $*"; }
warn()  { echo -e "\033[1;33m[warn]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[error]\033[0m $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)."
}

generate_password() {
    python3 -c "import secrets, string; \
        chars=string.ascii_letters+string.digits; \
        print(''.join(secrets.choice(chars) for _ in range(24)))"
}

# ── Password ──────────────────────────────────────────────────────────────────
require_root

if [[ "$DB_PASS" == "-" ]]; then
    DB_PASS="$(generate_password)"
    warn "Auto-generated password — save this, it won't be shown again."
elif [[ -z "$DB_PASS" ]]; then
    read -r -s -p "Enter password for PostgreSQL user '$DB_USER': " DB_PASS
    echo
    read -r -s -p "Confirm password: " DB_PASS2
    echo
    [[ "$DB_PASS" == "$DB_PASS2" ]] || die "Passwords do not match."
    [[ -n "$DB_PASS" ]] || die "Password cannot be empty."
fi

# ── Install PostgreSQL ────────────────────────────────────────────────────────
info "Checking PostgreSQL installation…"
if command -v psql &>/dev/null; then
    ok "PostgreSQL already installed ($(psql --version | head -1))"
else
    info "Installing PostgreSQL…"
    apt-get update -qq
    apt-get install -y postgresql postgresql-contrib
    ok "PostgreSQL installed"
fi

systemctl enable postgresql --quiet
systemctl start postgresql
ok "PostgreSQL service running"

# ── Find config files ─────────────────────────────────────────────────────────
PG_CONF_DIR=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1 | xargs dirname)
[[ -n "$PG_CONF_DIR" ]] || die "Could not locate postgresql.conf"
PG_CONF="$PG_CONF_DIR/postgresql.conf"
PG_HBA="$PG_CONF_DIR/pg_hba.conf"
info "Config directory: $PG_CONF_DIR"

# ── Create database and user ──────────────────────────────────────────────────
info "Creating database '$DB_NAME' and user '$DB_USER'…"

sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER') THEN
        CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
        RAISE NOTICE 'User $DB_USER created.';
    ELSE
        ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';
        RAISE NOTICE 'User $DB_USER already exists — password updated.';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE' WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'
) \gexec

DO \$\$
BEGIN
    -- Postgres 15+ requires explicit schema grant
    EXECUTE format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', '$DB_NAME', '$DB_USER');
END
\$\$;
SQL

# Schema ownership must be done inside the target database
sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" <<SQL
ALTER DATABASE $DB_NAME OWNER TO $DB_USER;
ALTER SCHEMA public OWNER TO $DB_USER;
GRANT ALL ON SCHEMA public TO $DB_USER;
SQL

ok "Database and user ready"

# ── Configure listen address ──────────────────────────────────────────────────
NEED_RESTART=false

if [[ -n "$NETWORK" && "$NETWORK" != "localhost" ]]; then
    info "Configuring PostgreSQL for remote access from $NETWORK…"

    # postgresql.conf — set listen_addresses = '*'
    if grep -qE "^#?listen_addresses\s*=" "$PG_CONF"; then
        sed -i "s|^#\?listen_addresses\s*=.*|listen_addresses = '*'|" "$PG_CONF"
    else
        echo "listen_addresses = '*'" >> "$PG_CONF"
    fi

    # Also update port if non-default
    if [[ "$PG_PORT" != "5432" ]]; then
        if grep -qE "^#?port\s*=" "$PG_CONF"; then
            sed -i "s|^#\?port\s*=.*|port = $PG_PORT|" "$PG_CONF"
        else
            echo "port = $PG_PORT" >> "$PG_CONF"
        fi
    fi

    # pg_hba.conf — add rule if not already present
    HBA_RULE="host    $DB_NAME    $DB_USER    $NETWORK    scram-sha-256"
    if ! grep -qF "$HBA_RULE" "$PG_HBA"; then
        echo "$HBA_RULE" >> "$PG_HBA"
        ok "Added pg_hba.conf rule: $HBA_RULE"
    else
        ok "pg_hba.conf rule already present"
    fi

    NEED_RESTART=true
else
    info "No --network specified — PostgreSQL will only accept local connections."
fi

# ── Restart if config changed ─────────────────────────────────────────────────
if $NEED_RESTART; then
    info "Restarting PostgreSQL to apply config changes…"
    systemctl restart postgresql
    ok "PostgreSQL restarted"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
HOST="localhost"
[[ -n "$NETWORK" && "$NETWORK" != "localhost" ]] && HOST="<server-ip>"

CONNECTION_STRING="postgresql://${DB_USER}:${DB_PASS}@${HOST}:${PG_PORT}/${DB_NAME}"

echo
echo "============================================================"
echo "  PostgreSQL is ready."
echo ""
echo "  Connection string:"
echo "  $CONNECTION_STRING"
echo ""
if [[ -n "$NETWORK" && "$NETWORK" != "localhost" ]]; then
    echo "  Remote access allowed from: $NETWORK"
    echo "  Replace <server-ip> with the actual server IP address."
    echo ""
fi
echo "  Paste this into the Uwebia admin Settings → Database"
echo "  page, or set DATABASE_URL in your gunicorn service file."
echo "============================================================"
echo
