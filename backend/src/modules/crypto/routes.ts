import { Router } from "express";
import { z } from "zod";

import { type AuthenticatedRequest, requireAuth } from "../../middleware/auth";
import { requirePermission } from "../../middleware/rbac";
import { asyncHandler } from "../../utils/async-handler";
import { decryptSecret, SUPPORTED_ALGORITHMS } from "../../utils/crypto";

const router = Router();

router.use(requireAuth);
router.use(requirePermission("secrets.read"));

const decryptSchema = z.object({
  encryptedValue: z.string().min(1),
  iv: z.string().default("-"),
  authTag: z.string().default("-"),
  algorithm: z.enum(SUPPORTED_ALGORITHMS)
});

router.post(
  "/decrypt",
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const parsed = decryptSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
      return;
    }

    const plainText = decryptSecret(
      parsed.data.encryptedValue,
      parsed.data.iv,
      parsed.data.authTag,
      parsed.data.algorithm
    );

    res.status(200).json({ plainText });
  })
);

export default router;
