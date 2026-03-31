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

    if (parsed.data.algorithm === "aes-256-gcm") {
      const ivBytes = Buffer.from(parsed.data.iv, "base64");
      const tagBytes = Buffer.from(parsed.data.authTag, "base64");

      if (ivBytes.length !== 12) {
        res.status(400).json({ message: "AES decrypt requires a valid base64 IV (12 bytes)." });
        return;
      }

      if (tagBytes.length !== 16) {
        res.status(400).json({ message: "AES decrypt requires a valid base64 auth tag (16 bytes)." });
        return;
      }
    }

    if (parsed.data.algorithm === "des-ede3-cbc") {
      const ivBytes = Buffer.from(parsed.data.iv, "base64");
      if (ivBytes.length !== 8) {
        res.status(400).json({ message: "3DES decrypt requires a valid base64 IV (8 bytes)." });
        return;
      }
    }

    let plainText = "";
    try {
      plainText = decryptSecret(
        parsed.data.encryptedValue,
        parsed.data.iv,
        parsed.data.authTag,
        parsed.data.algorithm
      );
    } catch {
      res.status(400).json({ message: "Invalid cipher payload for selected algorithm." });
      return;
    }

    res.status(200).json({ plainText });
  })
);

export default router;
