# SentriVault

Cloud-native secrets management and access governance platform built with React, Node.js/Express, PostgreSQL, and AWS-focused CI/CD.

SentriVault helps teams store and manage sensitive values securely with encryption, runtime RBAC enforcement, and immutable audit trails.

## Core Capabilities

- When secrets aren't being used, they are encrypted, and backend crypto tools support authenticated encryption.
- Checks for permissions at runtime on API routes based on roles.
- Audit logs that can't be changed for authentication, secret access, updates, and governance actions.
- Secret lifecycle controls include access, assignment, rotation workflow, and revoke flow.
- Risk insights endpoint to check the safety of your system.
- Use GitHub Actions to do CI/CD to put the backend on Elastic Beanstalk and the frontend on S3.

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

NOTE - All the below configuration are for local setup. For AWS - refer docs/architecture.md

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
```

## Local Setup

### 1. Start PostgreSQL

```bash
postgres -U localhost -| user@password ${dbname}
```

### 2. Backend Setup

```bash
cd backend
cp .env
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

- Middleware for route-level authentication and role-based access control.
- CORS_ORIGIN lets you set up a CORS allowlist.
- Use Zod to check requests.
- Helmet and rate limiting to make the API more secure.
- Tools for secret encryption and decryption that work with audit-aware workflows.

## CI/CD

File for the workflow:
- .github/workflows/ci-cd.yml

An Overview of the Pipeline:

1. CI builds the front and back ends of the app when code is pushed or PRs are made.
2. Continuous Deployment—Backend: The backend is put together and sent to AWS Elastic Beanstalk using S3 artifacts.
3. Continuous Deployment - Frontend: The assets for Vite are built, and then the assets are synced to S3 from frontend/dist.

We thought that GitHub secrets included AWS access credentials, the AWS region, the AWS Elastic Beanstalk configuration, the S3 bucket for the front end, and the base URL for the API.

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


