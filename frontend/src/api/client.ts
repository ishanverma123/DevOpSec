import type { AuditLog, CipherPayload, EncryptionAlgorithm, RiskInsightsResponse, Role, SecretMeta, User } from "../types";

// One base URL keeps local and deployed builds switching via env only.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

type ApiOptions = {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  token?: string;
  body?: unknown;
};

const apiRequest = async <T>(path: string, options: ApiOptions = {}): Promise<T> => {
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method ?? "GET",
    headers: {
      "Content-Type": "application/json",
      ...(options.token ? { Authorization: `Bearer ${options.token}` } : {})
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined
  });

  const data = await response.json().catch(() => ({}));

  // Backend usually sends { message }, fallback keeps errors readable.
  if (!response.ok) {
    throw new Error(data.message ?? `Request failed (${response.status})`);
  }

  return data as T;
};

export const api = {
  register: (input: { email: string; password: string; roleName?: string; organizationName: string }) =>
    apiRequest<{ token: string; user: User }>("/auth/register", {
      method: "POST",
      body: input
    }),

  login: (input: { email: string; password: string }) =>
    apiRequest<{ token: string; user: { id: string; email: string } }>("/auth/login", {
      method: "POST",
      body: input
    }),

  guestLogin: () =>
    apiRequest<{ token: string; user: { id: string; email: string } }>("/auth/guest", {
      method: "POST"
    }),

  getSecrets: (token: string) =>
    apiRequest<{ secrets: SecretMeta[] }>("/secrets", {
      token
    }),

  getRiskInsights: (token: string) =>
    apiRequest<RiskInsightsResponse>("/secrets/risk-insights", {
      token
    }),

  createSecret: (
    token: string,
    input: {
      name: string;
      value: string;
      description?: string;
      encryptionAlgorithm: EncryptionAlgorithm;
      rotationIntervalDays?: number;
      expiresInDays?: number;
      autoRotate?: boolean;
    }
  ) =>
    apiRequest<{ secret: SecretMeta }>("/secrets", {
      method: "POST",
      token,
      body: input
    }),

  updateSecret: (
    token: string,
    secretId: string,
    input: {
      name?: string;
      value?: string;
      description?: string;
      autoRotate?: boolean;
      rotationIntervalDays?: number;
      expiresInDays?: number;
    }
  ) =>
    apiRequest<{ secret: SecretMeta }>(`/secrets/${secretId}`, {
      method: "PATCH",
      token,
      body: input
    }),

  assignSecret: (
    token: string,
    secretId: string,
    input: { userId: string; canRead: boolean; canRotate: boolean }
  ) =>
    apiRequest<{ message: string }>(`/secrets/${secretId}/assign`, {
      method: "POST",
      token,
      body: input
    }),

  getCipherPayload: (token: string, secretId: string) =>
    apiRequest<{ cipher: CipherPayload }>(`/secrets/${secretId}/cipher`, {
      token
    }),

  decryptCipher: (
    token: string,
    input: {
      encryptedValue: string;
      iv: string;
      authTag: string;
      algorithm: EncryptionAlgorithm;
    }
  ) =>
    apiRequest<{ plainText: string }>("/crypto/decrypt", {
      method: "POST",
      token,
      body: input
    }),

  runRotationPolicy: (token: string, force = false) =>
    apiRequest<{ message: string; expired: number; rotated: number; force?: boolean }>("/secrets/rotation/run", {
      method: "POST",
      token,
      body: { force }
    }),

  rotateSecret: (token: string, secretId: string, value: string) =>
    apiRequest<{ message: string; version: number }>(`/secrets/${secretId}/rotate`, {
      method: "POST",
      token,
      body: { value }
    }),

  accessSecret: (token: string, secretId: string) =>
    apiRequest<{ value: string }>(`/secrets/${secretId}/access`, {
      method: "POST",
      token
    }),

  revokeSecret: (token: string, secretId: string) =>
    apiRequest<void>(`/secrets/${secretId}`, {
      method: "DELETE",
      token
    }),

  getUsers: (token: string) =>
    apiRequest<{ users: User[] }>("/users", {
      token
    }),

  getRoles: (token: string) =>
    apiRequest<{ roles: Role[] }>("/roles", {
      token
    }),

  getAuditLogs: (token: string) =>
    apiRequest<{ logs: AuditLog[] }>("/audit?limit=50", {
      token
    }),

  getMe: (token: string) =>
    apiRequest<{ user: User }>("/users/me", {
      token
    })
};
