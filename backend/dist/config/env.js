"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.env = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
const zod_1 = require("zod");
dotenv_1.default.config();
const envSchema = zod_1.z.object({
    NODE_ENV: zod_1.z.enum(["development", "test", "production"]).default("development"),
    PORT: zod_1.z.coerce.number().int().positive().default(4000),
    DATABASE_URL: zod_1.z.string().min(1),
    JWT_SECRET: zod_1.z.string().min(16),
    ENCRYPTION_KEY: zod_1.z.string().min(16),
    TRIPLE_DES_KEY: zod_1.z.string().min(16).default("devopsec-3des-key-2026"),
    SUBSTITUTION_KEY: zod_1.z
        .string()
        .regex(/^[A-Za-z]{26}$/)
        .default("QWERTYUIOPASDFGHJKLZXCVBNM"),
    CORS_ORIGIN: zod_1.z.string().default("*")
});
const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
    console.error("Invalid environment configuration", parsed.error.flatten().fieldErrors);
    throw new Error("Invalid environment configuration");
}
exports.env = parsed.data;
