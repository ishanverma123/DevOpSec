# Step 1: Project Structure

This structure is optimized for a security-focused full-stack app deployed on EC2.

## Repository Layout

```text
DevOpSec/
  backend/
    src/
      config/
      controllers/
      middleware/
      modules/
        auth/
        users/
        roles/
        secrets/
        audit/
      routes/
      services/
      utils/
      app.ts
      server.ts
    tests/
    prisma-or-sql/
    package.json
    tsconfig.json
    .env.example

  frontend/
    src/
      api/
      components/
      pages/
      hooks/
      context/
      utils/
      App.tsx
      main.tsx
    public/
    package.json
    vite.config.ts
    .env.example

  infra/
    nginx/
      devopsec.conf
    pm2/
      ecosystem.config.js
    scripts/
      deploy.sh

  .github/
    workflows/
      ci.yml
      cd-ec2.yml

  docs/
    architecture.md
    api-spec.md
    threat-model.md

  docker-compose.yml
  README.md
```

## Why this structure

- Clear separation of backend, frontend, and deployment concerns.
- Enables independent CI build steps for backend and frontend.
- Keeps EC2 deployment scripts and Nginx/PM2 config version-controlled.
- Supports incremental module development for RBAC, secrets, and auditing.
