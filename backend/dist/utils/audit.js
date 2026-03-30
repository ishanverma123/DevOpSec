"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isAdmin = exports.insertAuditLog = void 0;
const db_1 = require("../config/db");
const insertAuditLog = async (input) => {
    const sourceIp = input.req?.ip ?? null;
    const userAgent = input.req?.get("user-agent") ?? null;
    await db_1.pool.query(`
      INSERT INTO access_logs (user_id, secret_id, action, success, source_ip, user_agent, reason)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
        input.userId ?? null,
        input.secretId ?? null,
        input.action,
        input.success,
        sourceIp,
        userAgent,
        input.reason ?? null
    ]);
};
exports.insertAuditLog = insertAuditLog;
const isAdmin = async (userId) => {
    const result = await db_1.pool.query(`
      SELECT 1
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = $1 AND r.name = 'Admin'
      LIMIT 1
    `, [userId]);
    return (result.rowCount ?? 0) > 0;
};
exports.isAdmin = isAdmin;
