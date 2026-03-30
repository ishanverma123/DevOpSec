import { Router } from "express";
import { z } from "zod";

import { pool } from "../../config/db";
import { type AuthenticatedRequest, requireAuth } from "../../middleware/auth";
import { requirePermission } from "../../middleware/rbac";
import { asyncHandler } from "../../utils/async-handler";
import { isAdmin } from "../../utils/audit";

const router = Router();

router.use(requireAuth);

const retentionSchema = z.object({
  days: z.number().int().positive().max(3650).default(90)
});

router.get(
  "/",
  requirePermission("audit.read"),
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
      res.status(401).json({ message: "Requester not found" });
      return;
    }

    const requesterOrgId = requesterOrgResult.rows[0].organization_id as string | null;
    if (!requesterOrgId) {
      res.status(400).json({ message: "Requester has no organization assigned" });
      return;
    }

    const limit = Math.min(Number(req.query.limit ?? 100), 500);
    const action = req.query.action as string | undefined;
    const success = req.query.success as string | undefined;
    const secretId = req.query.secretId as string | undefined;
    const userId = req.query.userId as string | undefined;

    const where: string[] = [];
    const values: unknown[] = [requesterOrgId];

    // Filter by organization: logs must be either for secrets in the user's org, or actions by users in the org
    where.push(`(
      (al.secret_id IS NOT NULL AND s.organization_id = $1)
      OR (al.secret_id IS NULL AND u.organization_id = $1)
    )`);

    const isAdminResult = await isAdmin(requesterId);
    if (!isAdminResult) {
      values.push(requesterId);
      where.push(`(al.user_id = $${values.length})`);
    }

    if (action) {
      values.push(action);
      where.push(`al.action = $${values.length}`);
    }

    if (success === "true" || success === "false") {
      values.push(success === "true");
      where.push(`al.success = $${values.length}`);
    }

    if (secretId) {
      values.push(secretId);
      where.push(`al.secret_id = $${values.length}`);
    }

    if (userId) {
      values.push(userId);
      where.push(`al.user_id = $${values.length}`);
    }

    values.push(limit);

    const result = await pool.query(
      `
        SELECT al.id, al.user_id, al.secret_id, al.action, al.success, al.source_ip, al.user_agent, al.reason, al.created_at
        FROM access_logs al
        LEFT JOIN secrets s ON al.secret_id = s.id
        LEFT JOIN users u ON al.user_id = u.id
        ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
        ORDER BY al.created_at DESC
        LIMIT $${values.length}
      `,
      values
    );

    res.status(200).json({ logs: result.rows });
  })
);

router.delete(
  "/retention",
  requirePermission("audit.delete"),
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId || !(await isAdmin(requesterId))) {
      res.status(403).json({ message: "Admin role required" });
      return;
    }

    const parsed = retentionSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const { days } = parsed.data;

    const result = await pool.query(
      `
        DELETE FROM access_logs
        WHERE created_at < NOW() - ($1::text || ' days')::interval
      `,
      [days]
    );

    res.status(200).json({ message: "Retention cleanup complete", deleted: result.rowCount });
  })
);

export default router;
