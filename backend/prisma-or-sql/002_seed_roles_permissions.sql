INSERT INTO roles (name, description)
VALUES
  ('Admin', 'Full platform access'),
  ('Developer', 'Can manage and access project secrets'),
  ('Viewer', 'Read-only access to metadata and approved views')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (key, description)
VALUES
  ('users.create', 'Create users'),
  ('users.read', 'Read users'),
  ('users.update', 'Update users'),
  ('users.delete', 'Delete users'),
  ('roles.create', 'Create roles'),
  ('roles.read', 'Read roles'),
  ('roles.update', 'Update roles'),
  ('roles.delete', 'Delete roles'),
  ('roles.assign', 'Assign roles and permissions'),
  ('secrets.create', 'Create secrets'),
  ('secrets.read', 'Read secret metadata and value with access'),
  ('secrets.update', 'Update secret metadata'),
  ('secrets.assign', 'Assign secrets to users in same organization'),
  ('secrets.rotate', 'Rotate secret values'),
  ('secrets.revoke', 'Revoke secrets'),
  ('audit.read', 'Read audit logs'),
  ('audit.delete', 'Delete audit logs by retention policy')
ON CONFLICT (key) DO NOTHING;

WITH role_map AS (
  SELECT id, name FROM roles WHERE name IN ('Admin', 'Developer', 'Viewer')
),
permission_map AS (
  SELECT id, key FROM permissions
)
INSERT INTO role_permissions (role_id, permission_id)
SELECT rm.id, pm.id
FROM role_map rm
JOIN permission_map pm ON (
  rm.name = 'Admin'
  OR (rm.name = 'Developer' AND pm.key IN (
    'roles.read',
    'secrets.create',
    'secrets.read',
    'secrets.update',
    'secrets.assign',
    'secrets.rotate',
    'audit.read'
  ))
  OR (rm.name = 'Viewer' AND pm.key IN (
    'roles.read',
    'secrets.read',
    'audit.read'
  ))
)
ON CONFLICT (role_id, permission_id) DO NOTHING;
