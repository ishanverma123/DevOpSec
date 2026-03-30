import { Router } from "express";
import { z } from "zod";

import { type AuthenticatedRequest, requireAuth } from "../../middleware/auth";
import { requirePermission } from "../../middleware/rbac";
import { pool } from "../../config/db";
import { asyncHandler } from "../../utils/async-handler";
import { insertAuditLog } from "../../utils/audit";

const router = Router();

router.use(requireAuth);

const createRoleSchema = z.object({
  name: z.string().min(2).max(50),
  description: z.string().optional()
});

const updateRoleSchema = z
  .object({
    name: z.string().min(2).max(50).optional(),
    description: z.string().optional()
  })
  .refine((data) => Object.keys(data).length > 0, {
    message: "At least one field must be provided"
  });

const assignPermissionsSchema = z.object({
  permissionKeys: z.array(z.string().min(3)).min(1)
});

router.get(
  "/",
  requirePermission("roles.read"),
  asyncHandler(async (_req, res) => {
    const result = await pool.query(
      `
        SELECT
          r.id,
          r.name,
          r.description,
          r.created_at,
          r.updated_at,
          COALESCE(array_agg(p.key) FILTER (WHERE p.key IS NOT NULL), '{}') AS permissions
        FROM roles r
        LEFT JOIN role_permissions rp ON rp.role_id = r.id
        LEFT JOIN permissions p ON p.id = rp.permission_id
        GROUP BY r.id
        ORDER BY r.name ASC
      `
    );

    res.status(200).json({ roles: result.rows });
  })
);

router.post(
  "/",
  requirePermission("roles.create"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const parsed = createRoleSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const result = await pool.query(
      `
        INSERT INTO roles (name, description)
        VALUES ($1, $2)
        RETURNING id, name, description, created_at, updated_at
      `,
      [parsed.data.name, parsed.data.description ?? null]
    );

    await insertAuditLog({
      userId: requesterId,
      action: "manage_role",
      success: true,
      req,
      reason: `Created role ${parsed.data.name}`
    });

    res.status(201).json({ role: result.rows[0] });
  })
);

router.patch(
  "/:id",
  requirePermission("roles.update"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const parsed = updateRoleSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const updates: string[] = [];
    const values: unknown[] = [];

    if (parsed.data.name !== undefined) {
      values.push(parsed.data.name);
      updates.push(`name = $${values.length}`);
    }

    if (parsed.data.description !== undefined) {
      values.push(parsed.data.description);
      updates.push(`description = $${values.length}`);
    }

    values.push(req.params.id);

    const result = await pool.query(
      `
        UPDATE roles
        SET ${updates.join(", ")}, updated_at = NOW()
        WHERE id = $${values.length}
        RETURNING id, name, description, created_at, updated_at
      `,
      values
    );

    if (!result.rowCount) {
      res.status(404).json({ message: "Role not found" });
      return;
    }

    await insertAuditLog({
      userId: requesterId,
      action: "manage_role",
      success: true,
      req,
      reason: `Updated role ${req.params.id}`
    });

    res.status(200).json({ role: result.rows[0] });
  })
);

router.delete(
  "/:id",
  requirePermission("roles.delete"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const result = await pool.query("DELETE FROM roles WHERE id = $1 RETURNING id", [req.params.id]);
    if (!result.rowCount) {
      res.status(404).json({ message: "Role not found" });
      return;
    }

    await insertAuditLog({
      userId: requesterId,
      action: "manage_role",
      success: true,
      req,
      reason: `Deleted role ${req.params.id}`
    });

    res.status(204).send();
  })
);

router.post(
  "/:id/permissions",
  requirePermission("roles.assign"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const parsed = assignPermissionsSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const roleId = req.params.id;

    const role = await pool.query("SELECT id FROM roles WHERE id = $1", [roleId]);
    if (!role.rowCount) {
      res.status(404).json({ message: "Role not found" });
      return;
    }

    const permissions = await pool.query(
      "SELECT id, key FROM permissions WHERE key = ANY($1::text[])",
      [parsed.data.permissionKeys]
    );

    if (permissions.rowCount !== parsed.data.permissionKeys.length) {
      res.status(400).json({ message: "One or more permissions are invalid" });
      return;
    }

    await pool.query("DELETE FROM role_permissions WHERE role_id = $1", [roleId]);

    for (const permission of permissions.rows as Array<{ id: string }>) {
      await pool.query(
        `
          INSERT INTO role_permissions (role_id, permission_id)
          VALUES ($1, $2)
          ON CONFLICT (role_id, permission_id) DO NOTHING
        `,
        [roleId, permission.id]
      );
    }

    await insertAuditLog({
      userId: requesterId,
      action: "manage_role",
      success: true,
      req,
      reason: `Assigned permissions to role ${roleId}`
    });

    res.status(200).json({
      message: "Permissions updated",
      permissionKeys: parsed.data.permissionKeys
    });
  })
);

export default router;
