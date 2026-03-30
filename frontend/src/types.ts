export type User = {
  id: string;
  email: string;
  is_active: boolean;
  organization_id?: string | null;
  organization_name?: string | null;
  last_login_at?: string | null;
  created_at: string;
  updated_at: string;
};

export type EncryptionAlgorithm =
  | "aes-256-gcm"
  | "des-ede3-cbc"
  | "caesar"
  | "substitution"
  | "morse"
  | "base64";

export type Role = {
  id: string;
  name: string;
  description?: string | null;
  permissions: string[];
};

export type SecretMeta = {
  id: string;
  name: string;
  description?: string | null;
  owner_user_id: string;
  current_version: number;
  status: string;
  encryption_algorithm?: EncryptionAlgorithm;
  expires_at?: string | null;
  rotation_interval_days?: number | null;
  auto_rotate?: boolean;
  last_accessed_at?: string | null;
  access_count: number;
  created_at: string;
  updated_at: string;
};

export type CipherPayload = {
  id: string;
  name: string;
  current_version: number;
  encrypted_value: string;
  iv: string;
  auth_tag: string;
  encryption_algorithm: EncryptionAlgorithm;
};

export type AuditLog = {
  id: string;
  user_id?: string | null;
  secret_id?: string | null;
  action: string;
  success: boolean;
  source_ip?: string | null;
  user_agent?: string | null;
  reason?: string | null;
  created_at: string;
};

export type RiskSeverity = "critical" | "high" | "medium";

export type RiskInsight = {
  id: string;
  severity: RiskSeverity;
  title: string;
  message: string;
  affectedCount: number;
  suggestion: string;
};

export type RiskFlowStep = {
  step: number;
  title: string;
  description: string;
  status: "ok" | "attention" | "critical";
};

export type RiskInsightsResponse = {
  overview: {
    totalSecrets: number;
    activeSecrets: number;
    expiredSecrets: number;
    revokedSecrets: number;
    criticalIssues: number;
    highIssues: number;
    riskScore: number;
    lastEvaluatedAt: string;
  };
  warnings: RiskInsight[];
  suggestions: string[];
  flow: RiskFlowStep[];
};
