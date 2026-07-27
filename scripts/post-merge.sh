#!/bin/bash
set -e
pnpm install --frozen-lockfile

# Only push the database schema if DATABASE_URL is configured.
# Run: pnpm --filter @workspace/db run push   (after provisioning a database)
if [ -n "$DATABASE_URL" ]; then
  pnpm --filter @workspace/db run push
else
  echo "Skipping DB schema push — DATABASE_URL not set. Provision a database and re-run this script."
fi

pnpm --filter @workspace/csv-profiler run build
pnpm --filter @workspace/api-server run build
