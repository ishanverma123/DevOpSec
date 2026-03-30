import { Router } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { z } from "zod";

import { pool } from "../../config/db";
import { env } from "../../config/env";
import { asyncHandler } from "../../utils/async-handler";
import { insertAuditLog } from "../../utils/audit";

const router = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  organizationName: z.string().min(2).max(120),
  roleName: z.string().optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
});

router.post(
  "/register",
  asyncHandler(async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const { email, password, roleName, organizationName } = parsed.data;

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rowCount) {
      res.status(409).json({ message: "Email already registered" });
      return;
    }

    const existingOrg = await pool.query(
      "SELECT id FROM organizations WHERE lower(name) = lower($1) LIMIT 1",
      [organizationName]
    );

    let organizationId: string;
    if ((existingOrg.rowCount ?? 0) > 0) {
      organizationId = existingOrg.rows[0].id as string;
    } else {
      const createdOrg = await pool.query(
        "INSERT INTO organizations (name) VALUES ($1) RETURNING id",
        [organizationName]
      );
      organizationId = createdOrg.rows[0].id as string;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userResult = await pool.query(
      `
        INSERT INTO users (email, password_hash, organization_id)
        VALUES ($1, $2, $3)
        RETURNING id, email, is_active, organization_id, created_at
      `,
      [email, passwordHash, organizationId]
    );

    const user = userResult.rows[0] as {
      id: string;
      email: string;
      is_active: boolean;
      organization_id: string;
      created_at: string;
    };

    const roleResult = await pool.query(
      "SELECT id FROM roles WHERE name = $1 LIMIT 1",
      [roleName ?? "Viewer"]
    );

    if (roleResult.rowCount) {
      await pool.query(
        `
          INSERT INTO user_roles (user_id, role_id)
          VALUES ($1, $2)
          ON CONFLICT (user_id, role_id) DO NOTHING
        `,
        [user.id, roleResult.rows[0].id]
      );
    }

    const token = jwt.sign({ sub: user.id, email: user.email }, env.JWT_SECRET, { expiresIn: "1h" });

    await insertAuditLog({
      userId: user.id,
      action: "register",
      success: true,
      req
    });

    res.status(201).json({ token, user });
  })
);

router.post(
  "/login",
  asyncHandler(async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const { email, password } = parsed.data;

    const result = await pool.query(
      "SELECT id, email, password_hash, is_active FROM users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (!result.rowCount) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    const user = result.rows[0] as {
      id: string;
      email: string;
      password_hash: string;
      is_active: boolean;
    };

    if (!user.is_active) {
      res.status(403).json({ message: "User is inactive" });
      return;
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    await pool.query("UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1", [user.id]);

    const token = jwt.sign({ sub: user.id, email: user.email }, env.JWT_SECRET, { expiresIn: "1h" });

    await insertAuditLog({
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
  })
);

router.post(
  "/refresh",
  asyncHandler(async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ message: "Missing or invalid authorization header" });
      return;
    }

    const token = authHeader.slice("Bearer ".length);

    try {
      const payload = jwt.verify(token, env.JWT_SECRET) as { sub: string; email: string };
      const newToken = jwt.sign({ sub: payload.sub, email: payload.email }, env.JWT_SECRET, {
        expiresIn: "1h"
      });

      res.status(200).json({ token: newToken });
    } catch {
      res.status(401).json({ message: "Invalid or expired token" });
    }
  })
);

export default router;
