# Secure DevOps Secrets and Access Governance Platform

Scaffold initialized with backend, frontend, infrastructure, workflows, and docs.

## Generated Steps

- Step 1 (Project Structure): `docs/step-1-project-structure.md`
- Step 2 (Database Schema): `docs/step-2-database-schema.md`
- SQL Init Migration: `backend/prisma-or-sql/001_init_schema.sql`
- Step 3 (Backend Bootstrap): `docs/step-3-backend-bootstrap.md`
- SQL Seed Script: `backend/prisma-or-sql/002_seed_roles_permissions.sql`
- Step 4 (RBAC + Tests): `docs/step-4-rbac-and-tests.md`
- Step 5 (Next Steps Roadmap): `docs/step-5-next-steps-roadmap.md`

## Run Locally

1. Backend
	- Copy `backend/.env.example` to `backend/.env`
	- `cd backend && npm install && npm run build && npm run dev`

2. Frontend
	- Copy `frontend/.env.example` to `frontend/.env`
	- `cd frontend && npm install && npm run dev`

3. Frontend API base URL
	- `VITE_API_BASE_URL=http://localhost:4000/api/v1`
