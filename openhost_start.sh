#!/bin/bash
set -e

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/app/data}"
PG_DATA="$DATA_DIR/postgres"
UPLOADS_DIR="$DATA_DIR/uploads"

mkdir -p "$DATA_DIR" "$UPLOADS_DIR"

# --- Persist secrets across restarts ---
SECRETS_FILE="$DATA_DIR/.secrets"
if [ -f "$SECRETS_FILE" ]; then
    source "$SECRETS_FILE"
fi
if [ -z "$NEXTAUTH_SECRET" ]; then
    NEXTAUTH_SECRET=$(head -c 32 /dev/urandom | base64)
fi
cat > "$SECRETS_FILE" << EOF
NEXTAUTH_SECRET=$NEXTAUTH_SECRET
EOF

# --- Derive URL from OpenHost environment ---
if [ -n "$OPENHOST_ZONE_DOMAIN" ]; then
    APP_SUBDOMAIN="${OPENHOST_APP_NAME:-split-pro}"
    DOMAIN_NAME="${APP_SUBDOMAIN}.${OPENHOST_ZONE_DOMAIN}"
    NEXTAUTH_URL="https://${DOMAIN_NAME}"
else
    DOMAIN_NAME="localhost"
    NEXTAUTH_URL="http://localhost:8080"
fi

# --- Initialize PostgreSQL if needed ---
mkdir -p "$PG_DATA"
chown -R postgres:postgres "$PG_DATA"

export PATH="/usr/lib/postgresql/16/bin:$PATH"

if [ ! -f "$PG_DATA/PG_VERSION" ]; then
    echo "Initializing PostgreSQL..."
    su postgres -c "/usr/lib/postgresql/16/bin/initdb -D $PG_DATA --encoding=UTF8 --locale=C"
    echo "host all all 127.0.0.1/32 trust" >> "$PG_DATA/pg_hba.conf"
    echo "local all all trust" >> "$PG_DATA/pg_hba.conf"
    # Enable pg_cron for recurring expenses
    echo "shared_preload_libraries = 'pg_cron'" >> "$PG_DATA/postgresql.conf"
    echo "cron.database_name = 'splitpro'" >> "$PG_DATA/postgresql.conf"

    su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PG_DATA -l /tmp/pg_init.log start -w"
    su postgres -c "createdb splitpro"
    su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PG_DATA stop -w"
    echo "PostgreSQL initialized."
fi

# --- Export environment for supervisor child processes ---
export DATABASE_URL="postgresql://postgres@127.0.0.1:5432/splitpro"
export NEXTAUTH_SECRET
export NEXTAUTH_URL
export NEXTAUTH_URL_INTERNAL="http://127.0.0.1:3000"
export ENABLE_SENDING_INVITES="false"
export DISABLE_EMAIL_SIGNUP="false"
export INVITE_ONLY="false"
export DATA_DIR
export PORT=3000

echo "=== Split-Pro OpenHost ==="
echo "Domain:       $DOMAIN_NAME"
echo "NEXTAUTH_URL: $NEXTAUTH_URL"
echo "DATABASE_URL: $DATABASE_URL"
echo "Data dir:     $DATA_DIR"
echo "=========================="

# --- Start postgres, run migrations, then start the app via supervisor ---
su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PG_DATA -l /tmp/pg_start.log start -w"

echo "Running Prisma migrations..."
cd /app
prisma migrate deploy --schema=./prisma/schema.prisma
echo "Migrations complete."

# Stop postgres (supervisor will manage it from here)
su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PG_DATA stop -w"

exec supervisord -c /app/openhost_supervisor.conf
