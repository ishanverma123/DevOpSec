"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcrypt_1 = __importDefault(require("bcrypt"));
const zod_1 = require("zod");
const auth_1 = require("../../middleware/auth");
const rbac_1 = require("../../middleware/rbac");
const async_handler_1 = require("../../utils/async-handler");
const audit_1 = require("../../utils/audit");
const db_1 = require("../../config/db");
const router = (0, express_1.Router)();
router.use(auth_1.requireAuth);
const createUserSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(8),
    roleIds: zod_1.z.array(zod_1.z.string().uuid()).optional()
});
const updateUserSchema = zod_1.z
    .object({
    email: zod_1.z.string().email().optional(),
    password: zod_1.z.string().min(8).optional(),
    isActive: zod_1.z.boolean().optional()
})
    .refine((data) => Object.keys(data).length > 0, {
    message: "At least one field must be provided"
});
router.get("/", (0, rbac_1.requirePermission)("users.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const requesterOrgResult = await db_1.pool.query("SELECT organization_id FROM users WHERE id = $1", [requesterId]);
    if ((requesterOrgResult.rowCount ?? 0) === 0) {
        res.status(400).json({ message: "Requester not found" });
        return;
    }
    const requesterOrgId = requesterOrgResult.rows[0].organization_id;
    if (!requesterOrgId) {
        res.status(400).json({ message: "Requester has no organization assigned" });
        return;
    }
    const result = await db_1.pool.query(`
        SELECT u.id, u.email, u.is_active, u.last_login_at, u.created_at, u.updated_at, u.organization_id, o.name as organization_name
        FROM users u
        LEFT JOIN organizations o ON u.organization_id = o.id
        WHERE u.organization_id = $1
        ORDER BY u.created_at DESC
      `, [requesterOrgId]);
    res.status(200).json({ users: result.rows });
}));
router.post("/", (0, rbac_1.requirePermission)("users.create"), (0, async_handler_1.asyncHandler)(async (req, res) => {
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
    const existing = await db_1.pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rowCount) {
        res.status(409).json({ message: "Email already exists" });
        return;
    }
    const passwordHash = await bcrypt_1.default.hash(password, 12);
    const userResult = await db_1.pool.query(`
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email, is_active, created_at, updated_at
      `, [email, passwordHash]);
    const user = userResult.rows[0];
    if (roleIds?.length) {
        for (const roleId of roleIds) {
            await db_1.pool.query(`
            INSERT INTO user_roles (user_id, role_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, role_id) DO NOTHING
          `, [user.id, roleId]);
        }
    }
    await (0, audit_1.insertAuditLog)({
        userId: requesterId,
        action: "create_user",
        success: true,
        req,
        reason: `Created user ${email}`
    });
    res.status(201).json({ user: userResult.rows[0] });
}));
router.get("/me", (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const result = await db_1.pool.query(`
        SELECT u.id, u.email, u.is_active, u.last_login_at, u.created_at, u.updated_at, u.organization_id, o.name as organization_name
        FROM users u
        LEFT JOIN organizations o ON u.organization_id = o.id
        WHERE u.id = $1
      `, [requesterId]);
    if (!result.rowCount) {
        res.status(404).json({ message: "User not found" });
        return;
    }
    res.status(200).json({ user: result.rows[0] });
}));
router.get("/:id", (0, rbac_1.requirePermission)("users.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const requesterOrgResult = await db_1.pool.query("SELECT organization_id FROM users WHERE id = $1", [requesterId]);
    if ((requesterOrgResult.rowCount ?? 0) === 0) {
        res.status(400).json({ message: "Requester not found" });
        return;
    }
    const requesterOrgId = requesterOrgResult.rows[0].organization_id;
    if (!requesterOrgId) {
        res.status(400).json({ message: "Requester has no organization assigned" });
        return;
    }
    const result = await db_1.pool.query(`
        SELECT u.id, u.email, u.is_active, u.last_login_at, u.created_at, u.updated_at, u.organization_id, o.name as organization_name
        FROM users u
        LEFT JOIN organizations o ON u.organization_id = o.id
        WHERE u.id = $1 AND u.organization_id = $2
      `, [req.params.id, requesterOrgId]);
    if (!result.rowCount) {
        res.status(404).json({ message: "User not found or belongs to a different organization" });
        return;
    }
    res.status(200).json({ user: result.rows[0] });
}));
router.patch("/:id", (0, rbac_1.requirePermission)("users.update"), (0, async_handler_1.asyncHandler)(async (req, res) => {
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
    const updates = [];
    const values = [];
    if (parsed.data.email !== undefined) {
        values.push(parsed.data.email);
        updates.push(`email = $${values.length}`);
    }
    if (parsed.data.password !== undefined) {
        const hash = await bcrypt_1.default.hash(parsed.data.password, 12);
        values.push(hash);
        updates.push(`password_hash = $${values.length}`);
    }
    if (parsed.data.isActive !== undefined) {
        values.push(parsed.data.isActive);
        updates.push(`is_active = $${values.length}`);
    }
    values.push(req.params.id);
    const result = await db_1.pool.query(`
        UPDATE users
        SET ${updates.join(", ")}, updated_at = NOW()
        WHERE id = $${values.length}
        RETURNING id, email, is_active, last_login_at, created_at, updated_at
      `, values);
    if (!result.rowCount) {
        res.status(404).json({ message: "User not found" });
        return;
    }
    await (0, audit_1.insertAuditLog)({
        userId: requesterId,
        action: "update_user",
        success: true,
        req,
        reason: `Updated user ${req.params.id}`
    });
    res.status(200).json({ user: result.rows[0] });
}));
router.delete("/:id", (0, rbac_1.requirePermission)("users.delete"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const result = await db_1.pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [req.params.id]);
    if (!result.rowCount) {
        res.status(404).json({ message: "User not found" });
        return;
    }
    await (0, audit_1.insertAuditLog)({
        userId: requesterId,
        action: "delete_user",
        success: true,
        req,
        reason: `Deleted user ${req.params.id}`
    });
    res.status(204).send();
}));
exports.default = router;
