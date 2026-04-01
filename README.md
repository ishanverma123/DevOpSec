# SentriVault

Cloud-native secrets management and access governance platform built with React, Node.js/Express, PostgreSQL, and AWS-focused CI/CD.

SentriVault helps teams store and manage sensitive values securely with encryption, runtime RBAC enforcement, and immutable audit trails.

## Core Capabilities

- Secrets are encrypted when they are not in use, and backend crypto utilities support authenticated encryption.
- Role-based access control on API routes with checks for permissions at runtime.
- Unchangeable audit logs for authentication, secret access, updates, and governance actions.
- Secret lifecycle controls, such as access, assignment, rotation workflow, and revoke flow.
- Risk insights endpoint to see how secure your system is.
- CI/CD with GitHub Actions to deploy the backend to Elastic Beanstalk and the frontend to S3.

## Tech Stack

### Frontend
- React 18
- TypeScript
- Vite
- React Router

### Backend
- Node.js 20
- Express
- TypeScript
- PostgreSQL (pg)
- Zod validation
- JWT authentication
- bcrypt password hashing
- Helmet, CORS, Morgan, rate limiting

### DevOps
- GitHub Actions CI/CD
- AWS Elastic Beanstalk (backend)
- Amazon S3 static hosting (frontend)
- Docker Compose (local PostgreSQL)

## Repository Structure

```
DevOpSec/
├─ backend/
│  ├─ src/
│  │  ├─ modules/         # auth, users, roles, secrets, audit, crypto
│  │  ├─ middleware/      # auth, rbac, error handling
│  │  ├─ config/          # env + db
│  │  └─ routes/
│  ├─ prisma-or-sql/      # SQL schema + seed scripts
│  └─ tests/
├─ frontend/
│  ├─ src/
│  │  ├─ pages/
│  │  ├─ components/
│  │  ├─ context/
│  │  ├─ api/
│  │  └─ layouts/
├─ .github/workflows/     # CI/CD pipeline
├─ docs/
├─ infra/
└─ report/
```

## Local Setup

### 1. Start PostgreSQL

```bash
docker-compose up -d
```

### 2. Backend Setup

```bash
cd backend
cp .env.example .env
npm install
npm run build
```

Run backend in dev mode:

```bash
npm run dev
```

Backend default URL:

- http://localhost:4000
- Health check: http://localhost:4000/health
- API base: http://localhost:4000/api/v1

### 3. Initialize Database

Apply SQL files in order against your PostgreSQL database:

- backend/prisma-or-sql/001_init_schema.sql
- backend/prisma-or-sql/002_seed_roles_permissions.sql
- backend/prisma-or-sql/003_org_assignment_rotation.sql

You can also run role/permission seeding with:

```bash
cd backend
npm run db:seed
```

### 4. Frontend Setup

```bash
cd frontend
npm install
```

Create frontend env and set API base URL:

```bash
echo "VITE_API_BASE_URL=http://localhost:4000/api/v1" > .env
```

Run frontend:

```bash
npm run dev
```

Frontend default URL:

- http://localhost:5173

## Environment Variables

### Backend (.env)

Required:

- PORT
- DATABASE_URL
- JWT_SECRET
- ENCRYPTION_KEY
- CORS_ORIGIN

Supported in code:

- TRIPLE_DES_KEY
- SUBSTITUTION_KEY

Example values are provided in backend/.env.example.

### Frontend (.env)

- VITE_API_BASE_URL

## Scripts

### Backend Scripts

```bash
npm run dev          # run with ts-node-dev
npm run build        # compile TypeScript
npm run start        # start compiled server
npm run typecheck    # tsc --noEmit
npm run test         # run vitest
npm run test:watch   # watch tests
npm run db:seed      # seed role/permission data
```

### Frontend Scripts

```bash
npm run dev
npm run build
npm run preview
```

## API Surface (High-Level)

Base path: /api/v1

- /auth
- /users
- /roles
- /secrets
- /audit
- /crypto

## Security Controls

- Route-level auth and RBAC middleware.
- CORS allowlist via CORS_ORIGIN.
- Request validation using Zod.
- API hardening with Helmet and rate limiting.
- Secret encryption/decryption utilities with audit-aware workflows.

## CI/CD

Workflow file:

- .github/workflows/ci-cd.yml

Pipeline Overview:

1. CI builds the front and back end of the application as code gets pushed or PRs created.
2. Continuous Deployment - Backend: Backend is packaged and deployed to AWS Elastic Beanstalk through S3 artifact.
3. Continuous Deployment - Frontend: Vite assets are built and the assets are synced to S3 from frontend/dist.

Assumed GitHub secrets: AWS access credentials, AWS region, AWS Elastic Beanstalk configuration, S3 bucket for front-end, and base URL for API.

## Deployment Guidelines

- Backend - AWS Elastic Beanstalk.
- Frontend - S3 static website hosting.
- The CORS_ORIGIN for the backend must include the origin of the S3 website.

## Documentation Files

- docs/step-1-project-structure.md
- docs/step-2-database-schema.md
- docs/step-3-backend-bootstrap.md
- docs/step-4-rbac-and-tests.md
- docs/step-5-next-steps-roadmap.md
- report/report_ieee_rearranged.tex


