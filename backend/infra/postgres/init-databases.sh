#!/usr/bin/env bash
# Postgres init script — runs once at container first-boot.
#
# Creates the two satellite databases used by Network Scanner Pro and SIEM
# Léger, plus a dedicated user per app. CVE Tracker's database is already
# bootstrapped by the standard POSTGRES_DB env var.
#
# Convention: same default password as the main DB for dev. Override in
# production via secrets / env vars.
set -euo pipefail

POSTGRES_USER="${POSTGRES_USER:-cve_tracker}"
SCANNER_DB="${SCANNER_DB:-network_scanner}"
SCANNER_USER="${SCANNER_USER:-scanner}"
SCANNER_PASSWORD="${SCANNER_PASSWORD:-scanner}"
SIEM_DB="${SIEM_DB:-siem}"
SIEM_USER="${SIEM_USER:-siem}"
SIEM_PASSWORD="${SIEM_PASSWORD:-siem}"

echo "[init-databases] creating ${SCANNER_DB} and ${SIEM_DB}..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
  -- Scanner database
  CREATE USER ${SCANNER_USER} WITH PASSWORD '${SCANNER_PASSWORD}';
  CREATE DATABASE ${SCANNER_DB} OWNER ${SCANNER_USER};
  GRANT ALL PRIVILEGES ON DATABASE ${SCANNER_DB} TO ${SCANNER_USER};

  -- SIEM database
  CREATE USER ${SIEM_USER} WITH PASSWORD '${SIEM_PASSWORD}';
  CREATE DATABASE ${SIEM_DB} OWNER ${SIEM_USER};
  GRANT ALL PRIVILEGES ON DATABASE ${SIEM_DB} TO ${SIEM_USER};
EOSQL

echo "[init-databases] done."
