import { Router } from "express";

import auditRoutes from "../modules/audit/routes";
import authRoutes from "../modules/auth/routes";
import cryptoRoutes from "../modules/crypto/routes";
import rolesRoutes from "../modules/roles/routes";
import secretsRoutes from "../modules/secrets/routes";
import usersRoutes from "../modules/users/routes";

const router = Router();

router.use("/auth", authRoutes);
router.use("/users", usersRoutes);
router.use("/roles", rolesRoutes);
router.use("/secrets", secretsRoutes);
router.use("/audit", auditRoutes);
router.use("/crypto", cryptoRoutes);

export default router;
