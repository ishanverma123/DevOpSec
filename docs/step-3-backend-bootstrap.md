# Step 3: Backend Bootstrap and API Wiring

This step provides a production-ready backend baseline with security middleware, module routes, and a role-permission seed script.

## Implemented

- Backend dependencies and TypeScript tooling in [backend/package.json](../backend/package.json)
- Environment validation in [backend/src/config/env.ts](../backend/src/config/env.ts)
- PostgreSQL pool bootstrap in [backend/src/config/db.ts](../backend/src/config/db.ts)
- Global middleware and API mounting in [backend/src/app.ts](../backend/src/app.ts)
- Graceful server startup and shutdown in [backend/src/server.ts](../backend/src/server.ts)
- Route modules wired for auth, users, roles, secrets, and audit
- Seed SQL for default roles and permissions in [backend/prisma-or-sql/002_seed_roles_permissions.sql](../backend/prisma-or-sql/002_seed_roles_permissions.sql)

## API Base

- Health: GET /health
- API root: /api/v1

## Run locally

1. Copy backend/.env.example to backend/.env and fill values.
2. Install dependencies: npm install (inside backend).
3. Start development server: npm run dev.
4. Build production output: npm run build.

## Seed command

- npm run db:seed

The seed command requires psql in your shell environment.
