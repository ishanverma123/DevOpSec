# Step 2: Database Schema (PostgreSQL)

The initial schema covers users, roles/permissions (RBAC), secrets, secret versioning, access policy, and audit logs.

## Entities

- `users`
- `roles`
- `permissions`
- `user_roles`
- `role_permissions`
- `secrets`
- `secret_versions`
- `secret_access_policies`
- `access_logs`
- `refresh_tokens`

## Migration file

Use [backend/prisma-or-sql/001_init_schema.sql](../backend/prisma-or-sql/001_init_schema.sql) to initialize the database.

## Security notes

- Store only encrypted secret values in `secret_versions.encrypted_value`.
- Keep `access_logs` append-only for audit integrity.
- Do not return encrypted values in list endpoints.
- Use `secret.current_version` and `secret_versions.version` for rotation history.
