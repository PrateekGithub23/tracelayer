#!/bin/sh
# Creates the least-privilege runtime role on first database initialisation.
#   tracelayer      (POSTGRES_USER)  owns the schema and runs migrations only
#   tracelayer_app  (runtime)        SELECT/INSERT/UPDATE/DELETE on tables it is granted, nothing else;
#                                    migration 0005 then removes UPDATE/DELETE on evidence tables.
# For an existing database volume run:  make db-roles   (this script is idempotent).
set -eu
: "${TL_APP_PASSWORD:?TL_APP_PASSWORD must be set}"
psql -v ON_ERROR_STOP=1 -v app_pw="$TL_APP_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
SELECT 'CREATE ROLE tracelayer_app LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tracelayer_app')\gexec
ALTER ROLE tracelayer_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_pw';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO tracelayer_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tracelayer_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tracelayer_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tracelayer_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO tracelayer_app;
SQL
echo "tracelayer_app role ready"
