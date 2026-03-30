# Step 5: Next Steps Roadmap

This roadmap is the recommended sequence to move the platform from feature-complete prototype to production-ready project.

## Phase 1: Frontend Productization

1. Split dashboard into page modules:
   - Auth page
   - Secrets page
   - Users page
   - Roles page
   - Audit page
2. Add route guards by authentication state.
3. Add role-aware UI controls (hide disabled actions).
4. Add loading skeletons and empty states for all data grids.

## Phase 2: Backend Hardening

1. Move route logic into controllers and services.
2. Add centralized request validation middleware for all endpoints.
3. Enforce permission checks at service layer as defense-in-depth.
4. Add pagination and filter validation on list endpoints.
5. Add structured error codes for frontend handling.

## Phase 3: Test Coverage

1. Add isolated test database setup for integration tests.
2. Cover full workflows:
   - register -> login -> create secret -> rotate -> access -> revoke
   - role creation and permission assignment
   - user lifecycle CRUD
   - audit retrieval and retention cleanup
3. Add coverage reporting and minimum thresholds.

## Phase 4: CI/CD Enhancements

1. Update CI workflow to run:
   - backend build
   - frontend build
   - backend tests
   - lint checks
2. Add dependency vulnerability scan gates.
3. Add deployment environment protection (manual approval for production).
4. Add versioned release tags and changelog generation.

## Phase 5: EC2 Production Readiness

1. Enable HTTPS with Nginx and certificates.
2. Store production secrets in AWS Parameter Store or Secrets Manager.
3. Add centralized logs and alarms.
4. Configure backups for PostgreSQL and restore drill.
5. Add rate-limiting policy and incident response runbook.

## Recommended immediate actions (this week)

1. Complete controller/service refactor.
2. Add test DB integration suite.
3. Gate deployment on tests in CI.
4. Add HTTPS and secret manager integration for EC2.
