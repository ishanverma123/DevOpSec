import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";

let app: (typeof import("../src/app"))["default"];

beforeAll(async () => {
  process.env.NODE_ENV = "test";
  process.env.PORT = "4000";
  process.env.DATABASE_URL = "postgres://postgres:postgres@localhost:5432/devopsec";
  process.env.JWT_SECRET = "test-jwt-secret-which-is-long";
  process.env.ENCRYPTION_KEY = "test-encryption-key-long-enough";
  process.env.CORS_ORIGIN = "*";

  const module = await import("../src/app");
  app = module.default;
});

describe("app", () => {
  it("returns health status", async () => {
    const response = await request(app).get("/health");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("blocks secrets list without token", async () => {
    const response = await request(app).get("/api/v1/secrets");

    expect(response.status).toBe(401);
    expect(response.body.message).toContain("authorization");
  });
});
