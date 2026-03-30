"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const auth_1 = require("../../middleware/auth");
const rbac_1 = require("../../middleware/rbac");
const async_handler_1 = require("../../utils/async-handler");
const crypto_1 = require("../../utils/crypto");
const router = (0, express_1.Router)();
router.use(auth_1.requireAuth);
router.use((0, rbac_1.requirePermission)("secrets.read"));
const decryptSchema = zod_1.z.object({
    encryptedValue: zod_1.z.string().min(1),
    iv: zod_1.z.string().default("-"),
    authTag: zod_1.z.string().default("-"),
    algorithm: zod_1.z.enum(crypto_1.SUPPORTED_ALGORITHMS)
});
router.post("/decrypt", (0, async_handler_1.asyncHandler)(async (req, res) => {
    const parsed = decryptSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ message: parsed.error.issues[0]?.message ?? "Invalid request body" });
        return;
    }
    const plainText = (0, crypto_1.decryptSecret)(parsed.data.encryptedValue, parsed.data.iv, parsed.data.authTag, parsed.data.algorithm);
    res.status(200).json({ plainText });
}));
exports.default = router;
