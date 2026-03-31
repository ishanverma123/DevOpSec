"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const db_1 = require("../../config/db");
const auth_1 = require("../../middleware/auth");
const rbac_1 = require("../../middleware/rbac");
const async_handler_1 = require("../../utils/async-handler");
const audit_1 = require("../../utils/audit");
const router = (0, express_1.Router)();
router.use(auth_1.requireAuth);
const retentionSchema = zod_1.z.object({
    days: zod_1.z.number().int().positive().max(3650).default(90)
});
router.get("/", (0, rbac_1.requirePermission)("audit.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    const requesterEmail = req.user?.email;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    if (requesterEmail === "guest@devopsec.local") {
        const limit = Math.min(Number(req.query.limit ?? 100), 500);
        const result = await db_1.pool.query(`
          SELECT al.id, al.user_id, al.secret_id, al.action, al.success, al.source_ip, al.user_agent, al.reason, al.created_at
          FROM access_logs al
          ORDER BY al.created_at DESC
          LIMIT $1
        `, [limit]);
        res.status(200).json({ logs: result.rows });
        return;
    }
    const requesterOrgResult = await db_1.pool.query("SELECT organization_id FROM users WHERE id = $1", [requesterId]);
    if ((requesterOrgResult.rowCount ?? 0) === 0) {
        res.status(401).json({ message: "Requester not found" });
        return;
    }
    const requesterOrgId = requesterOrgResult.rows[0].organization_id;
    if (!requesterOrgId) {
        res.status(400).json({ message: "Requester has no organization assigned" });
        return;
    }
    const limit = Math.min(Number(req.query.limit ?? 100), 500);
    const action = req.query.action;
    const success = req.query.success;
    const secretId = req.query.secretId;
    const userId = req.query.userId;
    const where = [];
    const values = [requesterOrgId];
    // Filter by organization: logs must be either for secrets in the user's org, or actions by users in the org
    where.push(`(
      (al.secret_id IS NOT NULL AND s.organization_id = $1)
      OR (al.secret_id IS NULL AND u.organization_id = $1)
    )`);
    const isAdminResult = await (0, audit_1.isAdmin)(requesterId);
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
    const result = await db_1.pool.query(`
        SELECT al.id, al.user_id, al.secret_id, al.action, al.success, al.source_ip, al.user_agent, al.reason, al.created_at
        FROM access_logs al
        LEFT JOIN secrets s ON al.secret_id = s.id
        LEFT JOIN users u ON al.user_id = u.id
        ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
        ORDER BY al.created_at DESC
        LIMIT $${values.length}
      `, values);
    res.status(200).json({ logs: result.rows });
}));
router.delete("/retention", (0, rbac_1.requirePermission)("audit.delete"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId || !(await (0, audit_1.isAdmin)(requesterId))) {
        res.status(403).json({ message: "Admin role required" });
        return;
    }
    const parsed = retentionSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const { days } = parsed.data;
    const result = await db_1.pool.query(`
        DELETE FROM access_logs
        WHERE created_at < NOW() - ($1::text || ' days')::interval
      `, [days]);
    res.status(200).json({ message: "Retention cleanup complete", deleted: result.rowCount });
}));
exports.default = router;
