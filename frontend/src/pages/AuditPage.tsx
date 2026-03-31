import { useEffect, useState } from "react";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { AuditLog } from "../types";

export default function AuditPage() {
  const { token } = useAuth();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const run = async () => {
      try {
        const result = await api.getAuditLogs(token);
        setLogs(result.logs);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to load audit logs");
      } finally {
        setIsLoading(false);
      }
    };

    void run();
  }, []);

  return (
    <section className="module">
      <div className="module-top">
        <h3>Audit Timeline</h3>
      </div>
      {isLoading ? (
        <div className="loader-inline" role="status" aria-live="polite">
          <span className="loader-dot" />
          <p>Loading audit timeline...</p>
        </div>
      ) : null}
      {error ? <p className="fail-text">{error}</p> : null}
      <div className="event-feed">
        {logs.map((log) => (
          <article key={log.id} className="event-entry">
            <strong>{log.action}</strong>
            <span className={log.success ? "pass-text" : "fail-text"}>{log.success ? "success" : "failed"}</span>
            <p className="fixed-face">user: {log.user_id ?? "-"}</p>
            <p className="fixed-face">secret: {log.secret_id ?? "-"}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
