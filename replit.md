# AIRAVATA DEA

A CSV/fixed-width data profiler and privacy risk assessment tool — upload layout files and data files, profile columns, anonymize sensitive fields, and export reports.

## Run & Operate

- Main workflow: `artifacts/csv-profiler: web` — starts both Vite frontend and the Express API server (port 3001)
- `pnpm --filter @workspace/api-server run dev` — run the API server standalone
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

_Populate as you build — short repo map plus pointers to the source-of-truth file for DB schema, API contracts, theme files, etc._

## Architecture decisions

_Populate as you build — non-obvious choices a reader couldn't infer from the code (3-5 bullets)._

## Product

_Describe the high-level user-facing capabilities of this app once they exist._

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Replit's workflow runner injects a dynamic `PORT` env var. The frontend dev script must NOT override `PORT` for Vite (Vite should use the injected value), but the API server's dev script hardcodes `PORT=3001` so both services don't race for the same port. The Vite proxy config forwards `/api` → `localhost:3001`.
- After `pnpm install`, always run `pnpm --filter @workspace/db run push` before starting the app if the schema may have changed.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
