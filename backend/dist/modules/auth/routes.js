"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const db_1 = require("../../config/db");
const env_1 = require("../../config/env");
const async_handler_1 = require("../../utils/async-handler");
const audit_1 = require("../../utils/audit");
const router = (0, express_1.Router)();
const registerSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(8),
    organizationName: zod_1.z.string().min(2).max(120),
    roleName: zod_1.z.string().optional()
});
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(8)
});
const GUEST_EMAIL = "guest@devopsec.local";
router.post("/register", (0, async_handler_1.asyncHandler)(async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const { email, password, roleName, organizationName } = parsed.data;
    const existing = await db_1.pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rowCount) {
        res.status(409).json({ message: "Email already registered" });
        return;
    }
    const existingOrg = await db_1.pool.query("SELECT id FROM organizations WHERE lower(name) = lower($1) LIMIT 1", [organizationName]);
    let organizationId;
    if ((existingOrg.rowCount ?? 0) > 0) {
        organizationId = existingOrg.rows[0].id;
    }
    else {
        const createdOrg = await db_1.pool.query("INSERT INTO organizations (name) VALUES ($1) RETURNING id", [organizationName]);
        organizationId = createdOrg.rows[0].id;
    }
    const passwordHash = await bcrypt_1.default.hash(password, 12);
    const userResult = await db_1.pool.query(`
        INSERT INTO users (email, password_hash, organization_id)
        VALUES ($1, $2, $3)
        RETURNING id, email, is_active, organization_id, created_at
      `, [email, passwordHash, organizationId]);
    const user = userResult.rows[0];
    const roleResult = await db_1.pool.query("SELECT id FROM roles WHERE name = $1 LIMIT 1", [roleName ?? "Viewer"]);
    if (roleResult.rowCount) {
        await db_1.pool.query(`
          INSERT INTO user_roles (user_id, role_id)
          VALUES ($1, $2)
          ON CONFLICT (user_id, role_id) DO NOTHING
        `, [user.id, roleResult.rows[0].id]);
    }
    const token = jsonwebtoken_1.default.sign({ sub: user.id, email: user.email }, env_1.env.JWT_SECRET, { expiresIn: "1h" });
    await (0, audit_1.insertAuditLog)({
        userId: user.id,
        action: "register",
        success: true,
        req
    });
    res.status(201).json({ token, user });
}));
router.post("/guest", (0, async_handler_1.asyncHandler)(async (req, res) => {
    const client = await db_1.pool.connect();
    try {
        await client.query("BEGIN");
        let orgId;
        const orgResult = await client.query(`
          SELECT o.id
          FROM organizations o
          LEFT JOIN users u ON u.organization_id = o.id
          LEFT JOIN secrets s ON s.organization_id = o.id
          GROUP BY o.id
          ORDER BY (COUNT(DISTINCT u.id) + COUNT(DISTINCT s.id)) DESC, o.id ASC
          LIMIT 1
        `);
        if ((orgResult.rowCount ?? 0) > 0) {
            orgId = orgResult.rows[0].id;
        }
        else {
            const createdOrg = await client.query("INSERT INTO organizations (name) VALUES ($1) RETURNING id", [
                "Default Organization"
            ]);
            orgId = createdOrg.rows[0].id;
        }
        let userId;
        const existingUser = await client.query("SELECT id, email FROM users WHERE lower(email) = lower($1) LIMIT 1", [GUEST_EMAIL]);
        if ((existingUser.rowCount ?? 0) > 0) {
            userId = existingUser.rows[0].id;
            await client.query("UPDATE users SET organization_id = $2, is_active = TRUE, updated_at = NOW() WHERE id = $1", [userId, orgId]);
        }
        else {
            const randomPasswordHash = await bcrypt_1.default.hash(`guest-${Date.now()}-${Math.random()}`, 10);
            const createdUser = await client.query(`
            INSERT INTO users (email, password_hash, organization_id, is_active)
            VALUES ($1, $2, $3, TRUE)
            RETURNING id
          `, [GUEST_EMAIL, randomPasswordHash, orgId]);
            userId = createdUser.rows[0].id;
        }
        const adminRole = await client.query("SELECT id FROM roles WHERE name = 'Admin' LIMIT 1");
        if ((adminRole.rowCount ?? 0) === 0) {
            await client.query("ROLLBACK");
            res.status(500).json({ message: "Admin role not found. Seed roles before using guest access." });
            return;
        }
        await client.query(`
          INSERT INTO user_roles (user_id, role_id)
          VALUES ($1, $2)
          ON CONFLICT (user_id, role_id) DO NOTHING
        `, [userId, adminRole.rows[0].id]);
        await client.query("UPDATE users SET last_login_at = NOW(), updated_at = NOW(), is_active = TRUE WHERE id = $1", [
            userId
        ]);
        await client.query("COMMIT");
        const token = jsonwebtoken_1.default.sign({ sub: userId, email: GUEST_EMAIL }, env_1.env.JWT_SECRET, { expiresIn: "1h" });
        await (0, audit_1.insertAuditLog)({
            userId,
            action: "login",
            success: true,
            req
        });
        res.status(200).json({
            token,
            user: {
                id: userId,
                email: GUEST_EMAIL
            }
        });
    }
    catch (error) {
        await client.query("ROLLBACK");
        throw error;
    }
    finally {
        client.release();
    }
}));
router.post("/login", (0, async_handler_1.asyncHandler)(async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const { email, password } = parsed.data;
    const result = await db_1.pool.query("SELECT id, email, password_hash, is_active FROM users WHERE email = $1 LIMIT 1", [email]);
    if (!result.rowCount) {
        res.status(401).json({ message: "Invalid credentials" });
        return;
    }
    const user = result.rows[0];
    if (!user.is_active) {
        res.status(403).json({ message: "User is inactive" });
        return;
    }
    const isValid = await bcrypt_1.default.compare(password, user.password_hash);
    if (!isValid) {
        res.status(401).json({ message: "Invalid credentials" });
        return;
    }
    await db_1.pool.query("UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1", [user.id]);
    const token = jsonwebtoken_1.default.sign({ sub: user.id, email: user.email }, env_1.env.JWT_SECRET, { expiresIn: "1h" });
    await (0, audit_1.insertAuditLog)({
        userId: user.id,
        action: "login",
        success: true,
        req
    });
    res.status(200).json({
        token,
        user: {
            id: user.id,
            email: user.email
        }
    });
}));
router.post("/refresh", (0, async_handler_1.asyncHandler)(async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({ message: "Missing or invalid authorization header" });
        return;
    }
    const token = authHeader.slice("Bearer ".length);
    try {
        const payload = jsonwebtoken_1.default.verify(token, env_1.env.JWT_SECRET);
        const newToken = jsonwebtoken_1.default.sign({ sub: payload.sub, email: payload.email }, env_1.env.JWT_SECRET, {
            expiresIn: "1h"
        });
        res.status(200).json({ token: newToken });
    }
    catch {
        res.status(401).json({ message: "Invalid or expired token" });
    }
}));
exports.default = router;
