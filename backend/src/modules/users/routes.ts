import { Router } from "express";
import bcrypt from "bcrypt";
import { z } from "zod";

import { type AuthenticatedRequest, requireAuth } from "../../middleware/auth";
import { requirePermission } from "../../middleware/rbac";
import { asyncHandler } from "../../utils/async-handler";
import { insertAuditLog } from "../../utils/audit";
import { pool } from "../../config/db";

const router = Router();

router.use(requireAuth);

const createUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  roleIds: z.array(z.string().uuid()).optional()
});

const updateUserSchema = z
  .object({
    email: z.string().email().optional(),
    password: z.string().min(8).optional(),
    isActive: z.boolean().optional()
  })
  .refine((data) => Object.keys(data).length > 0, {
    message: "At least one field must be provided"
  });

router.get(
  "/",
  requirePermission("users.read"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const requesterOrgResult = await pool.query(
      "SELECT organization_id FROM users WHERE id = $1",
      [requesterId]
    );

    if ((requesterOrgResult.rowCount ?? 0) === 0) {
      res.status(400).json({ message: "Requester not found" });
      return;
    }

    const requesterOrgId = requesterOrgResult.rows[0].organization_id as string | null;
    if (!requesterOrgId) {
      res.status(400).json({ message: "Requester has no organization assigned" });
      return;
    }

    const result = await pool.query(
      `
        SELECT u.id, u.email, u.is_active, u.last_login_at, u.created_at, u.updated_at, u.organization_id, o.name as organization_name
        FROM users u
        LEFT JOIN organizations o ON u.organization_id = o.id
        WHERE u.organization_id = $1
        ORDER BY u.created_at DESC
      `,
      [requesterOrgId]
    );

    res.status(200).json({ users: result.rows });
  })
);

router.post(
  "/",
  requirePermission("users.create"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const { email, password, roleIds } = parsed.data;

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rowCount) {
      res.status(409).json({ message: "Email already exists" });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const userResult = await pool.query(
      `
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email, is_active, created_at, updated_at
      `,
      [email, passwordHash]
    );

    const user = userResult.rows[0] as { id: string };

    if (roleIds?.length) {
      for (const roleId of roleIds) {
        await pool.query(
          `
            INSERT INTO user_roles (user_id, role_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, role_id) DO NOTHING
          `,
          [user.id, roleId]
        );
      }
    }

    await insertAuditLog({
      userId: requesterId,
      action: "create_user",
      success: true,
      req,
      reason: `Created user ${email}`
    });

    res.status(201).json({ user: userResult.rows[0] });
  })
);

router.get(
  "/me",
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const result = await pool.query(
      `
        SELECT u.id, u.email, u.is_active, u.last_login_at, u.created_at, u.updated_at, u.organization_id, o.name as organization_name
        FROM users u
        LEFT JOIN organizations o ON u.organization_id = o.id
        WHERE u.id = $1
      `,
      [requesterId]
    );

    if (!result.rowCount) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.status(200).json({ user: result.rows[0] });
  })
);

router.get(
  "/:id",
  requirePermission("users.read"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const requesterOrgResult = await pool.query(
      "SELECT organization_id FROM users WHERE id = $1",
      [requesterId]
    );

    if ((requesterOrgResult.rowCount ?? 0) === 0) {
      res.status(400).json({ message: "Requester not found" });
      return;
    }

    const requesterOrgId = requesterOrgResult.rows[0].organization_id as string | null;
    if (!requesterOrgId) {
      res.status(400).json({ message: "Requester has no organization assigned" });
      return;
    }

    const result = await pool.query(
      `
        SELECT u.id, u.email, u.is_active, u.last_login_at, u.created_at, u.updated_at, u.organization_id, o.name as organization_name
        FROM users u
        LEFT JOIN organizations o ON u.organization_id = o.id
        WHERE u.id = $1 AND u.organization_id = $2
      `,
      [req.params.id, requesterOrgId]
    );

    if (!result.rowCount) {
      res.status(404).json({ message: "User not found or belongs to a different organization" });
      return;
    }

    res.status(200).json({ user: result.rows[0] });
  })
);

router.patch(
  "/:id",
  requirePermission("users.update"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const parsed = updateUserSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const updates: string[] = [];
    const values: unknown[] = [];

    if (parsed.data.email !== undefined) {
      values.push(parsed.data.email);
      updates.push(`email = $${values.length}`);
    }

    if (parsed.data.password !== undefined) {
      const hash = await bcrypt.hash(parsed.data.password, 12);
      values.push(hash);
      updates.push(`password_hash = $${values.length}`);
    }

    if (parsed.data.isActive !== undefined) {
      values.push(parsed.data.isActive);
      updates.push(`is_active = $${values.length}`);
    }

    values.push(req.params.id);

    const result = await pool.query(
      `
        UPDATE users
        SET ${updates.join(", ")}, updated_at = NOW()
        WHERE id = $${values.length}
        RETURNING id, email, is_active, last_login_at, created_at, updated_at
      `,
      values
    );

    if (!result.rowCount) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    await insertAuditLog({
      userId: requesterId,
      action: "update_user",
      success: true,
      req,
      reason: `Updated user ${req.params.id}`
    });

    res.status(200).json({ user: result.rows[0] });
  })
);

router.delete(
  "/:id",
  requirePermission("users.delete"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [req.params.id]);
    if (!result.rowCount) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    await insertAuditLog({
      userId: requesterId,
      action: "delete_user",
      success: true,
      req,
      reason: `Deleted user ${req.params.id}`
    });

    res.status(204).send();
  })
);

export default router;
