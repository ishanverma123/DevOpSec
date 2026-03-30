import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(16),
  ENCRYPTION_KEY: z.string().min(16),
  TRIPLE_DES_KEY: z.string().min(16).default("devopsec-3des-key-2026"),
  SUBSTITUTION_KEY: z
    .string()
    .regex(/^[A-Za-z]{26}$/)
    .default("QWERTYUIOPASDFGHJKLZXCVBNM"),
  CORS_ORIGIN: z.string().default("*")
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error("Invalid environment configuration", parsed.error.flatten().fieldErrors);
  throw new Error("Invalid environment configuration");
}

export const env = parsed.data;
