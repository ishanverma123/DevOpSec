import type { NextFunction, Response } from "express";

import { pool } from "../config/db";
import type { AuthenticatedRequest } from "./auth";

export const requirePermission = (permissionKey: string) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const userId = req.user?.sub;

    if (!userId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    // Keep permission checks in DB so role updates take effect immediately.
    const result = await pool.query(
      `
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        JOIN permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = $1 AND p.key = $2
        LIMIT 1
      `,
      [userId, permissionKey]
    );

    if ((result.rowCount ?? 0) === 0) {
      res.status(403).json({ message: `Missing permission: ${permissionKey}` });
      return;
    }

    next();
  };
};
