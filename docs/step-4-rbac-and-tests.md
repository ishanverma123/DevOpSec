# Step 4: RBAC Enforcement and Integration Tests

This step adds explicit permission checks and a basic integration test harness.

## RBAC middleware

- Added [backend/src/middleware/rbac.ts](../backend/src/middleware/rbac.ts)
- Middleware checks user role-permission mapping in PostgreSQL for a permission key.

## Route permission wiring

- Users routes now enforce: users.read, users.create, users.update, users.delete
- Roles routes now enforce: roles.read, roles.create, roles.update, roles.delete, roles.assign
- Secrets routes now enforce: secrets.read, secrets.create, secrets.update, secrets.rotate, secrets.revoke
- Audit routes now enforce: audit.read, audit.delete

## Tests

- Added integration tests in [backend/tests/app.test.ts](../backend/tests/app.test.ts)
- Added scripts in backend/package.json:
  - npm run test
  - npm run test:watch

## Notes

- Current tests avoid live DB dependencies for fast CI checks.
- Add module-level tests with seeded test DB for full CRUD coverage next.
