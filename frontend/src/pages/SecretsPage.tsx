import { useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import RiskInsightsPanel from "../components/RiskInsightsPanel";
import { useAuth } from "../context/AuthContext";
import type { EncryptionAlgorithm, SecretMeta, User } from "../types";

const algorithms: EncryptionAlgorithm[] = [
  "aes-256-gcm",
  "des-ede3-cbc",
  "caesar",
  "substitution",
  "morse",
  "base64"
];

export default function SecretsPage() {
  const { token } = useAuth();
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [nowMs, setNowMs] = useState(Date.now());
  const [dismissedAlerts, setDismissedAlerts] = useState<Record<string, boolean>>({});

  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [algorithm, setAlgorithm] = useState<EncryptionAlgorithm>("aes-256-gcm");
  const [expiresInDays, setExpiresInDays] = useState("30");

  const [assignUser, setAssignUser] = useState<Record<string, string>>({});

  const load = async () => {
    setError("");
    const [secretsRes, usersRes] = await Promise.allSettled([api.getSecrets(token), api.getUsers(token)]);

    if (secretsRes.status === "fulfilled") {
      setSecrets(secretsRes.value.secrets);
    } else {
      setError(secretsRes.reason?.message ?? "Failed loading secrets");
    }

    if (usersRes.status === "fulfilled") {
      setUsers(usersRes.value.users);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  const getExpiryDelta = (secret: SecretMeta) => {
    if (!secret.expires_at) {
      return null;
    }

    return new Date(secret.expires_at).getTime() - nowMs;
  };

  const formatExpiryTimer = (deltaMs: number | null) => {
    if (deltaMs === null) {
      return "No expiry";
    }

    if (deltaMs <= 0) {
      return "Expired";
    }

    const totalSeconds = Math.floor(deltaMs / 1000);
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m ${seconds}s`;
    }

    return `${hours}h ${minutes}m ${seconds}s`;
  };

  const alerts = useMemo(() => {
    const entries = secrets
      .map((secret) => {
        const deltaMs = getExpiryDelta(secret);
        if (deltaMs === null) {
          return null;
        }

        if (deltaMs <= 0) {
          return {
            id: `expired-${secret.id}`,
            level: "critical" as const,
            secretName: secret.name,
            message: "Secret has expired and should be rotated immediately.",
            timerText: "Expired"
          };
        }

        if (deltaMs <= 24 * 60 * 60 * 1000) {
          return {
            id: `expiring-${secret.id}`,
            level: "warning" as const,
            secretName: secret.name,
            message: "Secret is close to expiry. Rotate before downtime risk increases.",
            timerText: formatExpiryTimer(deltaMs)
          };
        }

        return null;
      })
      .filter((item): item is NonNullable<typeof item> => Boolean(item))
      .filter((item) => !dismissedAlerts[item.id]);

    return entries;
  }, [secrets, nowMs, dismissedAlerts]);

  const createSecret = async () => {
    setError("");
    setSuccess("");

    try {
      await api.createSecret(token, {
        name: name.trim(),
        value,
        description: description.trim() || undefined,
        encryptionAlgorithm: algorithm,
        expiresInDays:
          expiresInDays.trim().length > 0 && Number(expiresInDays) > 0
            ? Number(expiresInDays)
            : undefined
      });
      setName("");
      setValue("");
      setDescription("");
      setExpiresInDays("30");
      setSuccess("Secret created.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed");
    }
  };

  const accessSecret = async (secretId: string) => {
    setError("");
    setSuccess("");
    try {
      const response = await api.accessSecret(token, secretId);
      setSuccess(`Plain text: ${response.value}`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Access failed");
    }
  };

  const copyCipher = async (secretId: string) => {
    setError("");
    setSuccess("");
    try {
      const response = await api.getCipherPayload(token, secretId);
      await navigator.clipboard.writeText(response.cipher.encrypted_value);
      setSuccess("Cipher copied to clipboard.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Copy failed");
    }
  };

  const assign = async (secretId: string) => {
    const userId = assignUser[secretId]?.trim();
    if (!userId) {
      setError("Enter target user id");
      return;
    }

    setError("");
    setSuccess("");

    try {
      await api.assignSecret(token, secretId, { userId, canRead: true, canRotate: false });
      setSuccess("Secret assigned.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Assign failed");
    }
  };

  return (
    <>
      {secrets.length > 0 ? (
        <RiskInsightsPanel />
      ) : (
        <section className="notice-hub">
          <p className="side-note">Threat and suggestion insights appear when you have at least one assigned or owned secret.</p>
        </section>
      )}

      {alerts.length > 0 ? (
        <section className="notice-hub">
          <div className="module-top">
            <h3>Expiry Notifications</h3>
          </div>

          <div className="notice-feed">
            {alerts.map((alert) => (
              <article
                key={alert.id}
                className={`notice-card ${alert.level === "critical" ? "notice-critical" : "notice-warning"}`}
              >
                <div>
                  <p className="notice-title">{alert.secretName}</p>
                  <p>{alert.message}</p>
                  <p className="fixed-face">Timer: {alert.timerText}</p>
                </div>
                <button
                  className="notice-dismiss"
                  onClick={() =>
                    setDismissedAlerts((prev) => ({
                      ...prev,
                      [alert.id]: true
                    }))
                  }
                >
                  Dismiss
                </button>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="module">
        <div className="module-top">
          <h3>Secrets</h3>
          <button className="btn-compact btn-automation" onClick={() => void api.runRotationPolicy(token)}>
            Run Auto Rotation
          </button>
        </div>

        <div className="input-row input-row-secrets">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Secret name" />
          <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="Secret value" />
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description" />
          <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as EncryptionAlgorithm)}>
            {algorithms.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
            <input
              type="number"
              min={1}
              max={3650}
              value={expiresInDays}
              onChange={(e) => setExpiresInDays(e.target.value)}
              placeholder="Expiry (days)"
            />
          <button onClick={createSecret}>Create</button>
        </div>

        {error ? <p className="fail-text">{error}</p> : null}
        {success ? <p className="pass-text">{success}</p> : null}

        <div className="data-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Algorithm</th>
                <th>Status</th>
                <th>Version</th>
                <th>Expiry Timer</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {secrets.map((secret) => (
                <tr key={secret.id}>
                  <td>{secret.name}</td>
                  <td className="fixed-face">{secret.encryption_algorithm}</td>
                  <td>{secret.status}</td>
                  <td>v{secret.current_version}</td>
                  <td
                    className={`fixed-face ${
                      getExpiryDelta(secret) !== null && (getExpiryDelta(secret) ?? 0) <= 0
                        ? "fail-text"
                        : getExpiryDelta(secret) !== null && (getExpiryDelta(secret) ?? 0) <= 24 * 60 * 60 * 1000
                          ? "warn-text"
                          : ""
                    }`}
                  >
                    {formatExpiryTimer(getExpiryDelta(secret))}
                  </td>
                  <td>
                    <div className="action-col">
                      <button className="btn-compact btn-subtle" onClick={() => void accessSecret(secret.id)}>
                        Access
                      </button>
                      <button className="btn-compact btn-subtle" onClick={() => void copyCipher(secret.id)}>
                        Copy Cipher
                      </button>
                      <select
                        value={assignUser[secret.id] ?? ""}
                        onChange={(e) =>
                          setAssignUser((prev) => ({
                            ...prev,
                            [secret.id]: e.target.value
                          }))
                        }
                      >
                        <option value="">Assign to user...</option>
                        {users.map((user) => (
                          <option key={user.id} value={user.id}>
                            {user.email}
                          </option>
                        ))}
                      </select>
                      <button className="btn-compact btn-assign" onClick={() => void assign(secret.id)}>
                        Assign
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
