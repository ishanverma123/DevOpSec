import type { Request } from "express";

import { pool } from "../config/db";

type AuditAction =
  | "read_metadata"
  | "read_secret"
  | "create_secret"
  | "rotate_secret"
  | "revoke_secret"
  | "create_user"
  | "update_user"
  | "delete_user"
  | "login"
  | "register"
  | "manage_role";

export const insertAuditLog = async (input: {
  userId?: string;
  secretId?: string;
  action: AuditAction;
  success: boolean;
  req?: Request;
  reason?: string;
}) => {
  const sourceIp = input.req?.ip ?? null;
  const userAgent = input.req?.get("user-agent") ?? null;

  await pool.query(
    `
      INSERT INTO access_logs (user_id, secret_id, action, success, source_ip, user_agent, reason)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `,
    [
      input.userId ?? null,
      input.secretId ?? null,
      input.action,
      input.success,
      sourceIp,
      userAgent,
      input.reason ?? null
    ]
  );
};

export const isAdmin = async (userId: string) => {
  const result = await pool.query(
    `
      SELECT 1
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = $1 AND r.name = 'Admin'
      LIMIT 1
    `,
    [userId]
  );

  return (result.rowCount ?? 0) > 0;
};
