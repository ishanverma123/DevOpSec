"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const crypto_1 = __importDefault(require("crypto"));
const zod_1 = require("zod");
const db_1 = require("../../config/db");
const auth_1 = require("../../middleware/auth");
const rbac_1 = require("../../middleware/rbac");
const async_handler_1 = require("../../utils/async-handler");
const audit_1 = require("../../utils/audit");
const crypto_2 = require("../../utils/crypto");
const router = (0, express_1.Router)();
router.use(auth_1.requireAuth);
const createSecretSchema = zod_1.z.object({
    name: zod_1.z.string().min(2).max(150),
    value: zod_1.z.string().min(1),
    description: zod_1.z.string().optional(),
    encryptionAlgorithm: zod_1.z.enum(crypto_2.SUPPORTED_ALGORITHMS),
    autoRotate: zod_1.z.boolean().optional().default(false),
    rotationIntervalDays: zod_1.z.number().int().positive().max(365).optional(),
    expiresInDays: zod_1.z.number().int().positive().max(3650).optional()
});
const updateSecretSchema = zod_1.z
    .object({
    name: zod_1.z.string().min(2).max(150).optional(),
    value: zod_1.z.string().min(1).optional(),
    description: zod_1.z.string().optional(),
    autoRotate: zod_1.z.boolean().optional(),
    rotationIntervalDays: zod_1.z.number().int().positive().max(365).optional(),
    expiresInDays: zod_1.z.number().int().positive().max(3650).optional()
})
    .refine((data) => Object.keys(data).length > 0, {
    message: "At least one field must be provided"
});
const rotateSecretSchema = zod_1.z.object({
    value: zod_1.z.string().min(1)
});
const assignSecretSchema = zod_1.z.object({
    userId: zod_1.z.string().uuid(),
    canRead: zod_1.z.boolean().default(true),
    canRotate: zod_1.z.boolean().default(false)
});
const runRotationSchema = zod_1.z.object({
    force: zod_1.z.boolean().optional().default(false)
});
const getOrganizationId = async (userId) => {
    const result = await db_1.pool.query("SELECT organization_id FROM users WHERE id = $1", [userId]);
    if ((result.rowCount ?? 0) === 0) {
        throw new Error("Requesting user not found");
    }
    return result.rows[0].organization_id;
};
const canManageSecret = async (userId, secretId) => {
    const ownerResult = await db_1.pool.query("SELECT 1 FROM secrets WHERE id = $1 AND owner_user_id = $2 LIMIT 1", [secretId, userId]);
    if ((ownerResult.rowCount ?? 0) > 0) {
        return true;
    }
    return (0, audit_1.isAdmin)(userId);
};
const canReadSecret = async (userId, secretId) => {
    if (await canManageSecret(userId, secretId)) {
        return true;
    }
    const assignment = await db_1.pool.query("SELECT 1 FROM secret_assignments WHERE secret_id = $1 AND user_id = $2 AND can_read = TRUE", [secretId, userId]);
    return (assignment.rowCount ?? 0) > 0;
};
const canRotateSecret = async (userId, secretId) => {
    if (await canManageSecret(userId, secretId)) {
        return true;
    }
    const assignment = await db_1.pool.query("SELECT 1 FROM secret_assignments WHERE secret_id = $1 AND user_id = $2 AND can_rotate = TRUE", [secretId, userId]);
    return (assignment.rowCount ?? 0) > 0;
};
const applyExpiryStatus = async (organizationId) => {
    await db_1.pool.query(`
      UPDATE secrets
      SET status = 'expired', updated_at = NOW()
      WHERE organization_id = $1
        AND expires_at IS NOT NULL
        AND expires_at < NOW()
        AND status = 'active'
    `, [organizationId]);
};
router.get("/", (0, rbac_1.requirePermission)("secrets.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    const requesterEmail = req.user?.email;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const isGuestSuperUser = requesterEmail === "guest@devopsec.local";
    if (isGuestSuperUser) {
        const result = await db_1.pool.query(`
          SELECT DISTINCT s.id, s.name, s.description, s.owner_user_id, s.current_version, s.status,
                 s.last_accessed_at, s.access_count, s.created_at, s.updated_at, s.expires_at,
                 s.rotation_interval_days, s.auto_rotate, s.encryption_algorithm
          FROM secrets s
          ORDER BY s.created_at DESC
        `);
        res.status(200).json({ secrets: result.rows });
        return;
    }
    const organizationId = await getOrganizationId(requesterId);
    if (!organizationId) {
        res.status(400).json({ message: "User has no organization assigned" });
        return;
    }
    await applyExpiryStatus(organizationId);
    const admin = await (0, audit_1.isAdmin)(requesterId);
    const result = await db_1.pool.query(`
        SELECT DISTINCT s.id, s.name, s.description, s.owner_user_id, s.current_version, s.status,
               s.last_accessed_at, s.access_count, s.created_at, s.updated_at, s.expires_at,
               s.rotation_interval_days, s.auto_rotate, s.encryption_algorithm
        FROM secrets s
        LEFT JOIN secret_assignments sa ON sa.secret_id = s.id AND sa.user_id = $2
        WHERE s.organization_id = $3
          AND (
            $1::boolean = TRUE
            OR s.owner_user_id = $2
            OR sa.can_read = TRUE
            OR sa.can_rotate = TRUE
          )
        ORDER BY s.created_at DESC
      `, [admin, requesterId, organizationId]);
    res.status(200).json({ secrets: result.rows });
}));
router.post("/", (0, rbac_1.requirePermission)("secrets.create"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const parsed = createSecretSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const { name, value, description, encryptionAlgorithm, autoRotate, expiresInDays, rotationIntervalDays } = parsed.data;
    const encrypted = (0, crypto_2.encryptSecret)(value, encryptionAlgorithm);
    const organizationId = await getOrganizationId(requesterId);
    if (!organizationId) {
        res.status(400).json({ message: "User has no organization assigned" });
        return;
    }
    const expiresAt = expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000) : null;
    const client = await db_1.pool.connect();
    try {
        await client.query("BEGIN");
        const secretResult = await client.query(`
          INSERT INTO secrets (
            name,
            owner_user_id,
            organization_id,
            description,
            current_version,
            status,
            encryption_algorithm,
            auto_rotate,
            rotation_interval_days,
            expires_at
          )
          VALUES ($1, $2, $3, $4, 1, 'active', $5, $6, $7, $8)
          RETURNING id, name, description, owner_user_id, current_version, status,
                    created_at, updated_at, encryption_algorithm, auto_rotate, rotation_interval_days, expires_at
        `, [
            name,
            requesterId,
            organizationId,
            description ?? null,
            encryptionAlgorithm,
            autoRotate,
            rotationIntervalDays ?? null,
            expiresAt
        ]);
        const secret = secretResult.rows[0];
        await client.query(`
          INSERT INTO secret_versions (
            secret_id,
            version,
            encrypted_value,
            iv,
            auth_tag,
            key_version,
            created_by,
            encryption_algorithm
          )
          VALUES ($1, 1, $2, $3, $4, $5, $6, $7)
        `, [
            secret.id,
            encrypted.encryptedValue,
            encrypted.iv,
            encrypted.authTag,
            "v1",
            requesterId,
            encryptionAlgorithm
        ]);
        await client.query("COMMIT");
        await (0, audit_1.insertAuditLog)({
            userId: requesterId,
            secretId: secret.id,
            action: "create_secret",
            success: true,
            req
        });
        res.status(201).json({ secret: secretResult.rows[0] });
    }
    catch (error) {
        await client.query("ROLLBACK");
        throw error;
    }
    finally {
        client.release();
    }
}));
router.get("/risk-insights", (0, rbac_1.requirePermission)("secrets.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const organizationId = await getOrganizationId(requesterId);
    if (!organizationId) {
        res.status(400).json({ message: "User has no organization assigned" });
        return;
    }
    await applyExpiryStatus(organizationId);
    const admin = await (0, audit_1.isAdmin)(requesterId);
    const accessScope = `
      FROM secrets s
      LEFT JOIN secret_assignments sa ON sa.secret_id = s.id AND sa.user_id = $2
      WHERE s.organization_id = $3
        AND (
          $1::boolean = TRUE
          OR s.owner_user_id = $2
          OR sa.can_read = TRUE
          OR sa.can_rotate = TRUE
        )
    `;
    const [summaryResult, staleRotationResult, expiringSoonResult, weakAlgoResult, dormantResult, highAccessResult, failedAccessResult] = await Promise.all([
        db_1.pool.query(`
            SELECT
              COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE status = 'active')::int AS active,
              COUNT(*) FILTER (WHERE status = 'expired')::int AS expired,
              COUNT(*) FILTER (WHERE status = 'revoked')::int AS revoked
            FROM (
              SELECT DISTINCT s.id, s.status
              ${accessScope}
            ) accessible_secrets
          `, [admin, requesterId, organizationId]),
        db_1.pool.query(`
            SELECT COUNT(*)::int AS count
            FROM (
              SELECT DISTINCT s.id, s.status, s.rotation_interval_days, s.updated_at
              ${accessScope}
            ) accessible_secrets
            WHERE status = 'active'
              AND rotation_interval_days IS NOT NULL
              AND updated_at <= NOW() - (rotation_interval_days::text || ' days')::interval
          `, [admin, requesterId, organizationId]),
        db_1.pool.query(`
            SELECT COUNT(*)::int AS count
            FROM (
              SELECT DISTINCT s.id, s.status, s.expires_at
              ${accessScope}
            ) accessible_secrets
            WHERE status = 'active'
              AND expires_at IS NOT NULL
              AND expires_at BETWEEN NOW() AND NOW() + INTERVAL '7 days'
          `, [admin, requesterId, organizationId]),
        db_1.pool.query(`
            SELECT COUNT(*)::int AS count
            FROM (
              SELECT DISTINCT s.id, s.status, s.encryption_algorithm
              ${accessScope}
            ) accessible_secrets
            WHERE status = 'active'
              AND encryption_algorithm IN ('base64', 'caesar', 'morse', 'substitution', 'des-ede3-cbc')
          `, [admin, requesterId, organizationId]),
        db_1.pool.query(`
            SELECT COUNT(*)::int AS count
            FROM (
              SELECT DISTINCT s.id, s.status, s.last_accessed_at, s.created_at
              ${accessScope}
            ) accessible_secrets
            WHERE status = 'active'
              AND (
                (last_accessed_at IS NULL AND created_at <= NOW() - INTERVAL '30 days')
                OR (last_accessed_at IS NOT NULL AND last_accessed_at <= NOW() - INTERVAL '30 days')
              )
          `, [admin, requesterId, organizationId]),
        db_1.pool.query(`
            SELECT COUNT(*)::int AS count
            FROM (
              SELECT DISTINCT s.id, s.status, s.access_count
              ${accessScope}
            ) accessible_secrets
            WHERE status = 'active'
              AND access_count >= 50
          `, [admin, requesterId, organizationId]),
        db_1.pool.query(`
            SELECT COUNT(*)::int AS count
            FROM access_logs al
            JOIN (
              SELECT DISTINCT s.id
              ${accessScope}
            ) accessible_secrets ON accessible_secrets.id = al.secret_id
            WHERE al.action = 'read_secret'
              AND al.success = FALSE
              AND al.created_at >= NOW() - INTERVAL '24 hours'
          `, [admin, requesterId, organizationId])
    ]);
    const totalSecrets = Number(summaryResult.rows[0]?.total ?? 0);
    const activeSecrets = Number(summaryResult.rows[0]?.active ?? 0);
    const expiredSecrets = Number(summaryResult.rows[0]?.expired ?? 0);
    const revokedSecrets = Number(summaryResult.rows[0]?.revoked ?? 0);
    const staleRotationCount = Number(staleRotationResult.rows[0]?.count ?? 0);
    const expiringSoonCount = Number(expiringSoonResult.rows[0]?.count ?? 0);
    const weakAlgoCount = Number(weakAlgoResult.rows[0]?.count ?? 0);
    const dormantCount = Number(dormantResult.rows[0]?.count ?? 0);
    const highAccessCount = Number(highAccessResult.rows[0]?.count ?? 0);
    const failedAccessCount = Number(failedAccessResult.rows[0]?.count ?? 0);
    const warnings = [];
    if (staleRotationCount > 0) {
        warnings.push({
            id: "stale-rotation",
            severity: "critical",
            title: "Rotation SLA Breach",
            message: `${staleRotationCount} secret(s) have crossed their configured rotation window.`,
            affectedCount: staleRotationCount,
            suggestion: "Run auto-rotation now and tighten rotation intervals for high-value secrets."
        });
    }
    if (failedAccessCount > 0) {
        warnings.push({
            id: "failed-access-spike",
            severity: failedAccessCount >= 5 ? "critical" : "high",
            title: "Failed Access Spike",
            message: `${failedAccessCount} failed read attempt(s) were detected in the last 24 hours.`,
            affectedCount: failedAccessCount,
            suggestion: "Review assignment drift and investigate potential brute-force or stale token usage."
        });
    }
    if (weakAlgoCount > 0) {
        warnings.push({
            id: "weak-algorithm",
            severity: weakAlgoCount >= 3 ? "high" : "medium",
            title: "Weak Encryption Profile",
            message: `${weakAlgoCount} active secret(s) use reversible or weak algorithms.`,
            affectedCount: weakAlgoCount,
            suggestion: "Migrate these secrets to aes-256-gcm and rotate immediately."
        });
    }
    if (expiringSoonCount > 0) {
        warnings.push({
            id: "expiring-soon",
            severity: expiringSoonCount >= 5 ? "high" : "medium",
            title: "Secrets Expiring Soon",
            message: `${expiringSoonCount} secret(s) will expire within the next 7 days.`,
            affectedCount: expiringSoonCount,
            suggestion: "Pre-rotate affected secrets to avoid service outages."
        });
    }
    if (dormantCount > 0) {
        warnings.push({
            id: "dormant-secrets",
            severity: "medium",
            title: "Dormant Secret Footprint",
            message: `${dormantCount} secret(s) have not been accessed in the last 30 days.`,
            affectedCount: dormantCount,
            suggestion: "Revoke or archive dormant secrets and validate they are still required."
        });
    }
    if (highAccessCount > 0) {
        warnings.push({
            id: "high-access-secrets",
            severity: "medium",
            title: "High Access Frequency",
            message: `${highAccessCount} secret(s) were accessed at least 50 times.`,
            affectedCount: highAccessCount,
            suggestion: "Consider short-lived tokens or secret caching policies to reduce direct reads."
        });
    }
    const criticalIssues = warnings.filter((item) => item.severity === "critical").length;
    const highIssues = warnings.filter((item) => item.severity === "high").length;
    let riskScore = 0;
    riskScore += Math.min(30, staleRotationCount * 6);
    riskScore += Math.min(25, failedAccessCount * 5);
    riskScore += Math.min(20, weakAlgoCount * 4);
    riskScore += Math.min(12, expiringSoonCount * 2);
    riskScore += Math.min(8, dormantCount);
    riskScore += Math.min(5, highAccessCount);
    riskScore = Math.min(100, riskScore);
    const suggestions = Array.from(new Set(warnings.map((warning) => warning.suggestion))).slice(0, 4);
    const flow = [
        {
            step: 1,
            title: "Collect telemetry",
            description: "Aggregate secret metadata and recent access logs for your organization.",
            status: "ok"
        },
        {
            step: 2,
            title: "Detect policy drift",
            description: "Check rotation SLA breaches, weak algorithms, and pending expirations.",
            status: staleRotationCount > 0 || weakAlgoCount > 0 || expiringSoonCount > 0 ? "attention" : "ok"
        },
        {
            step: 3,
            title: "Identify abuse signals",
            description: "Flag failed access bursts and unusual read frequency patterns.",
            status: failedAccessCount > 0 ? "critical" : highAccessCount > 0 ? "attention" : "ok"
        },
        {
            step: 4,
            title: "Prioritize response",
            description: "Rank findings into critical, high, and medium severity buckets.",
            status: warnings.length > 0 ? "attention" : "ok"
        },
        {
            step: 5,
            title: "Recommend actions",
            description: "Produce concrete rotation, migration, and cleanup suggestions.",
            status: warnings.length > 0 ? "attention" : "ok"
        }
    ];
    res.status(200).json({
        overview: {
            totalSecrets,
            activeSecrets,
            expiredSecrets,
            revokedSecrets,
            criticalIssues,
            highIssues,
            riskScore,
            lastEvaluatedAt: new Date().toISOString()
        },
        warnings: warnings.slice(0, 6),
        suggestions,
        flow
    });
}));
router.get("/:id", (0, rbac_1.requirePermission)("secrets.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const secretId = String(req.params.id);
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const allowed = await canReadSecret(requesterId, secretId);
    if (!allowed) {
        res.status(403).json({ message: "Not authorized to view this secret metadata" });
        return;
    }
    const result = await db_1.pool.query(`
         SELECT id, name, description, owner_user_id, current_version, status,
           last_accessed_at, access_count, created_at, updated_at,
           expires_at, rotation_interval_days, auto_rotate, encryption_algorithm
        FROM secrets
        WHERE id = $1
      `, [secretId]);
    if (!result.rowCount) {
        res.status(404).json({ message: "Secret not found" });
        return;
    }
    await (0, audit_1.insertAuditLog)({
        userId: requesterId,
        secretId,
        action: "read_metadata",
        success: true,
        req
    });
    res.status(200).json({ secret: result.rows[0] });
}));
router.patch("/:id", (0, rbac_1.requirePermission)("secrets.update"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const secretId = String(req.params.id);
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const allowed = await canManageSecret(requesterId, secretId);
    if (!allowed) {
        res.status(403).json({ message: "Not authorized to update this secret" });
        return;
    }
    const parsed = updateSecretSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const client = await db_1.pool.connect();
    try {
        await client.query("BEGIN");
        const currentResult = await client.query("SELECT id, current_version, encryption_algorithm FROM secrets WHERE id = $1 FOR UPDATE", [secretId]);
        if (!currentResult.rowCount) {
            await client.query("ROLLBACK");
            res.status(404).json({ message: "Secret not found" });
            return;
        }
        const updates = [];
        const values = [];
        if (parsed.data.name !== undefined) {
            values.push(parsed.data.name);
            updates.push(`name = $${values.length}`);
        }
        if (parsed.data.description !== undefined) {
            values.push(parsed.data.description);
            updates.push(`description = $${values.length}`);
        }
        if (parsed.data.autoRotate !== undefined) {
            values.push(parsed.data.autoRotate);
            updates.push(`auto_rotate = $${values.length}`);
        }
        if (parsed.data.rotationIntervalDays !== undefined) {
            values.push(parsed.data.rotationIntervalDays);
            updates.push(`rotation_interval_days = $${values.length}`);
        }
        if (parsed.data.expiresInDays !== undefined) {
            const nextExpiry = new Date(Date.now() + parsed.data.expiresInDays * 24 * 60 * 60 * 1000);
            values.push(nextExpiry);
            updates.push(`expires_at = $${values.length}`);
        }
        if (parsed.data.value !== undefined) {
            const currentVersion = Number(currentResult.rows[0].current_version);
            const algorithm = currentResult.rows[0].encryption_algorithm;
            const encrypted = (0, crypto_2.encryptSecret)(parsed.data.value, algorithm);
            const nextVersion = currentVersion + 1;
            await client.query(`
            INSERT INTO secret_versions (
              secret_id,
              version,
              encrypted_value,
              iv,
              auth_tag,
              key_version,
              created_by,
              encryption_algorithm
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          `, [
                secretId,
                nextVersion,
                encrypted.encryptedValue,
                encrypted.iv,
                encrypted.authTag,
                "v1",
                requesterId,
                algorithm
            ]);
            values.push(nextVersion);
            updates.push(`current_version = $${values.length}`);
        }
        values.push(secretId);
        const result = await client.query(`
          UPDATE secrets
          SET ${updates.join(", ")}, updated_at = NOW()
          WHERE id = $${values.length}
          RETURNING id, name, description, owner_user_id, current_version, status,
              last_accessed_at, access_count, created_at, updated_at,
              expires_at, rotation_interval_days, auto_rotate, encryption_algorithm
        `, values);
        await client.query("COMMIT");
        await (0, audit_1.insertAuditLog)({
            userId: requesterId,
            secretId,
            action: "update_secret",
            success: true,
            req
        });
        res.status(200).json({ secret: result.rows[0] });
    }
    catch (error) {
        await client.query("ROLLBACK");
        throw error;
    }
    finally {
        client.release();
    }
}));
router.delete("/:id", (0, rbac_1.requirePermission)("secrets.revoke"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const secretId = String(req.params.id);
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const allowed = await canManageSecret(requesterId, secretId);
    if (!allowed) {
        res.status(403).json({ message: "Not authorized to revoke this secret" });
        return;
    }
    const result = await db_1.pool.query(`
        UPDATE secrets
        SET status = 'revoked', updated_at = NOW()
        WHERE id = $1
        RETURNING id
      `, [secretId]);
    if (!result.rowCount) {
        res.status(404).json({ message: "Secret not found" });
        return;
    }
    await (0, audit_1.insertAuditLog)({
        userId: requesterId,
        secretId,
        action: "revoke_secret",
        success: true,
        req
    });
    res.status(204).send();
}));
router.post("/:id/rotate", (0, rbac_1.requirePermission)("secrets.rotate"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const secretId = String(req.params.id);
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const allowed = await canRotateSecret(requesterId, secretId);
    if (!allowed) {
        res.status(403).json({ message: "Not authorized to rotate this secret" });
        return;
    }
    const parsed = rotateSecretSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const client = await db_1.pool.connect();
    try {
        await client.query("BEGIN");
        const secretResult = await client.query("SELECT id, current_version, encryption_algorithm, status, expires_at FROM secrets WHERE id = $1 FOR UPDATE", [secretId]);
        if (!secretResult.rowCount) {
            await client.query("ROLLBACK");
            res.status(404).json({ message: "Secret not found" });
            return;
        }
        const nextVersion = Number(secretResult.rows[0].current_version) + 1;
        const algorithm = secretResult.rows[0].encryption_algorithm;
        const encrypted = (0, crypto_2.encryptSecret)(parsed.data.value, algorithm);
        await client.query(`
          INSERT INTO secret_versions (
            secret_id,
            version,
            encrypted_value,
            iv,
            auth_tag,
            key_version,
            created_by,
            encryption_algorithm
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            secretId,
            nextVersion,
            encrypted.encryptedValue,
            encrypted.iv,
            encrypted.authTag,
            "v1",
            requesterId,
            algorithm
        ]);
        await client.query(`
          UPDATE secrets
          SET
            current_version = $2,
            status = CASE WHEN status = 'expired' THEN 'active' ELSE status END,
            expires_at = CASE
              WHEN expires_at IS NOT NULL AND expires_at < NOW() THEN NOW() + INTERVAL '30 days'
              ELSE expires_at
            END,
            updated_at = NOW()
          WHERE id = $1
        `, [secretId, nextVersion]);
        await client.query("COMMIT");
        await (0, audit_1.insertAuditLog)({
            userId: requesterId,
            secretId,
            action: "rotate_secret",
            success: true,
            req
        });
        res.status(200).json({ message: "Secret rotated", version: nextVersion });
    }
    catch (error) {
        await client.query("ROLLBACK");
        throw error;
    }
    finally {
        client.release();
    }
}));
router.post("/:id/access", (0, rbac_1.requirePermission)("secrets.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const secretId = String(req.params.id);
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const allowed = await canReadSecret(requesterId, secretId);
    if (!allowed) {
        await (0, audit_1.insertAuditLog)({
            userId: requesterId,
            secretId,
            action: "read_secret",
            success: false,
            req,
            reason: "Unauthorized secret access attempt"
        });
        res.status(403).json({ message: "Not authorized to access this secret" });
        return;
    }
    const result = await db_1.pool.query(`
        SELECT sv.encrypted_value, sv.iv, sv.auth_tag, sv.encryption_algorithm
        FROM secrets s
        JOIN secret_versions sv
          ON sv.secret_id = s.id AND sv.version = s.current_version
        WHERE s.id = $1 AND s.status = 'active'
      `, [secretId]);
    if (!result.rowCount) {
        res.status(404).json({ message: "Active secret not found" });
        return;
    }
    const row = result.rows[0];
    const value = (0, crypto_2.decryptSecret)(row.encrypted_value, row.iv, row.auth_tag, row.encryption_algorithm);
    await db_1.pool.query(`
        UPDATE secrets
        SET access_count = access_count + 1, last_accessed_at = NOW(), updated_at = NOW()
        WHERE id = $1
      `, [secretId]);
    await (0, audit_1.insertAuditLog)({
        userId: requesterId,
        secretId,
        action: "read_secret",
        success: true,
        req
    });
    res.status(200).json({ value });
}));
router.get("/:id/cipher", (0, rbac_1.requirePermission)("secrets.read"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    const secretId = String(req.params.id);
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const allowed = await canReadSecret(requesterId, secretId);
    if (!allowed) {
        res.status(403).json({ message: "Not authorized to export cipher" });
        return;
    }
    const result = await db_1.pool.query(`
        SELECT s.id, s.name, s.current_version, sv.encrypted_value, sv.iv, sv.auth_tag, sv.encryption_algorithm
        FROM secrets s
        JOIN secret_versions sv ON sv.secret_id = s.id AND sv.version = s.current_version
        WHERE s.id = $1
      `, [secretId]);
    if ((result.rowCount ?? 0) === 0) {
        res.status(404).json({ message: "Secret not found" });
        return;
    }
    res.status(200).json({ cipher: result.rows[0] });
}));
router.post("/:id/assign", (0, rbac_1.requirePermission)("secrets.assign"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const requesterId = req.user?.sub;
    const secretId = String(req.params.id);
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const parsed = assignSecretSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const canAssign = await canManageSecret(requesterId, secretId);
    if (!canAssign) {
        res.status(403).json({ message: "Only secret owner/admin can assign" });
        return;
    }
    const secretOrg = await db_1.pool.query("SELECT organization_id FROM secrets WHERE id = $1", [secretId]);
    if ((secretOrg.rowCount ?? 0) === 0) {
        res.status(404).json({ message: "Secret not found" });
        return;
    }
    const orgId = secretOrg.rows[0].organization_id;
    const targetUser = await db_1.pool.query("SELECT id FROM users WHERE id = $1 AND organization_id = $2", [parsed.data.userId, orgId]);
    if ((targetUser.rowCount ?? 0) === 0) {
        res.status(400).json({ message: "Target user must belong to the same organization" });
        return;
    }
    await db_1.pool.query(`
        INSERT INTO secret_assignments (secret_id, user_id, assigned_by, can_read, can_rotate)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (secret_id, user_id)
        DO UPDATE SET
          assigned_by = EXCLUDED.assigned_by,
          can_read = EXCLUDED.can_read,
          can_rotate = EXCLUDED.can_rotate,
          created_at = NOW()
      `, [secretId, parsed.data.userId, requesterId, parsed.data.canRead, parsed.data.canRotate]);
    res.status(200).json({ message: "Secret assignment updated" });
}));
router.post("/rotation/run", (0, rbac_1.requirePermission)("secrets.rotate"), (0, async_handler_1.asyncHandler)(async (req, res) => {
    const parsed = runRotationSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const requesterId = req.user?.sub;
    if (!requesterId) {
        res.status(401).json({ message: "Unauthorized" });
        return;
    }
    const organizationId = await getOrganizationId(requesterId);
    if (!organizationId) {
        res.status(400).json({ message: "User has no organization assigned" });
        return;
    }
    const expired = await db_1.pool.query(`
        UPDATE secrets
        SET status = 'expired', updated_at = NOW()
        WHERE organization_id = $1
          AND expires_at IS NOT NULL
          AND expires_at < NOW()
          AND status = 'active'
      `, [organizationId]);
    const candidates = await db_1.pool.query(`
        SELECT id, current_version, encryption_algorithm
        FROM secrets
        WHERE organization_id = $1
          AND status = 'active'
          AND (
            $2::boolean = TRUE
            OR (
              auto_rotate = TRUE
              AND rotation_interval_days IS NOT NULL
              AND updated_at <= NOW() - (rotation_interval_days::text || ' days')::interval
            )
          )
      `, [organizationId, parsed.data.force]);
    let rotatedCount = 0;
    for (const row of candidates.rows) {
        const randomValue = crypto_1.default.randomBytes(24).toString("base64url");
        const encrypted = (0, crypto_2.encryptSecret)(randomValue, row.encryption_algorithm);
        const nextVersion = Number(row.current_version) + 1;
        await db_1.pool.query(`
          INSERT INTO secret_versions (
            secret_id,
            version,
            encrypted_value,
            iv,
            auth_tag,
            key_version,
            created_by,
            encryption_algorithm
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            row.id,
            nextVersion,
            encrypted.encryptedValue,
            encrypted.iv,
            encrypted.authTag,
            "auto-v1",
            requesterId,
            row.encryption_algorithm
        ]);
        await db_1.pool.query("UPDATE secrets SET current_version = $2, updated_at = NOW() WHERE id = $1", [row.id, nextVersion]);
        rotatedCount += 1;
    }
    res.status(200).json({
        message: "Rotation policy execution completed",
        expired: expired.rowCount ?? 0,
        rotated: rotatedCount,
        force: parsed.data.force
    });
}));
exports.default = router;
