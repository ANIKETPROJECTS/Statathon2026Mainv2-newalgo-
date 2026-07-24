# AIRAVATA DEA — CSV Data Profiler

## Project overview

A monorepo web application for converting, anonymizing, and risk-assessing fixed-width format (FWF) survey datasets (e.g. NSSO/HCES). The app converts FWF files to CSV, profiles the data, performs privacy risk assessment using the Prosecutor Attack model (k-anonymity, l-diversity, t-closeness), and generates Word/CSV risk reports.

## Stack

- **Frontend**: React 19, Vite 7, Tailwind CSS 4, Radix UI, TanStack Query/Table, Recharts, Wouter
- **Backend**: Express 5, Pino logging
- **Database**: Drizzle ORM + PostgreSQL
- **Package manager**: pnpm (workspaces monorepo)
- **Language**: TypeScript

## Monorepo layout

```
artifacts/
  csv-profiler/     # Main React frontend (port 5000 in dev)
  api-server/       # Express backend (port 3001 in dev)
  mockup-sandbox/   # UI component prototyping environment
lib/
  db/               # Drizzle ORM schema and PostgreSQL client
  api-spec/         # OpenAPI definition + Orval codegen config
  api-client-react/ # Generated TanStack Query hooks
  api-zod/          # Generated Zod schemas
```

## How to run

The configured workflow `artifacts/csv-profiler: web` starts both the frontend (Vite) and the API server together:

```
pnpm --filter @workspace/csv-profiler run dev
```

This runs:
- Vite dev server on a dynamic port (previewed by Replit)
- API server on port 3001

## Environment

- `DATABASE_URL` — auto-provisioned by Replit (PostgreSQL)
- `SESSION_SECRET` — stored as a Replit Secret

## User preferences

- Keep existing monorepo structure and stack — do not restructure or migrate.
