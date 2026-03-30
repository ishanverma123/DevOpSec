"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requirePermission = void 0;
const db_1 = require("../config/db");
const requirePermission = (permissionKey) => {
    return async (req, res, next) => {
        const userId = req.user?.sub;
        if (!userId) {
            res.status(401).json({ message: "Unauthorized" });
            return;
        }
        const result = await db_1.pool.query(`
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        JOIN permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = $1 AND p.key = $2
        LIMIT 1
      `, [userId, permissionKey]);
        if ((result.rowCount ?? 0) === 0) {
            res.status(403).json({ message: `Missing permission: ${permissionKey}` });
            return;
        }
        next();
    };
};
exports.requirePermission = requirePermission;
