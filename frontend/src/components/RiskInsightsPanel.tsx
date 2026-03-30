import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { RiskInsightsResponse, RiskSeverity } from "../types";

const severityLabel: Record<RiskSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium"
};

const toneBySeverity: Record<RiskSeverity, "red" | "orange" | "green"> = {
  critical: "red",
  high: "orange",
  medium: "green"
};

const toneByFlowStatus: Record<"ok" | "attention" | "critical", "green" | "orange" | "red"> = {
  ok: "green",
  attention: "orange",
  critical: "red"
};

const emptyInsights: RiskInsightsResponse = {
  overview: {
    totalSecrets: 0,
    activeSecrets: 0,
    expiredSecrets: 0,
    revokedSecrets: 0,
    criticalIssues: 0,
    highIssues: 0,
    riskScore: 0,
    lastEvaluatedAt: new Date().toISOString()
  },
  warnings: [],
  suggestions: [],
  flow: []
};

export default function RiskInsightsPanel() {
  const { token, user } = useAuth();
  const [insights, setInsights] = useState<RiskInsightsResponse>(emptyInsights);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadInsights = useCallback(async () => {
    setError("");
    try {
      const response = await api.getRiskInsights(token);
      setInsights(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load risk insights");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void loadInsights();
    const timer = window.setInterval(() => {
      void loadInsights();
    }, 45000);

    return () => window.clearInterval(timer);
  }, [loadInsights]);

  const riskBand = useMemo<"red" | "orange" | "green">(() => {
    if (insights.overview.riskScore >= 70) {
      return "red";
    }
    if (insights.overview.riskScore >= 40) {
      return "orange";
    }
    return "green";
  }, [insights.overview.riskScore]);

  if (loading) {
    return <p className="side-note">Calculating current secret risk posture...</p>;
  }

  if (error) {
    return <p className="fail-text">{error}</p>;
  }

  return (
    <section className="health-board" aria-label="Ongoing secret risks and recommendations">
      {user?.organization_name && (
        <p style={{ fontSize: "0.875rem", color: "#888", marginBottom: "1rem", textAlign: "center" }}>
          Risk insights for <strong>{user.organization_name}</strong>
        </p>
      )}
      <div className="health-numbers">
        <article className="number-cell">
          <p>Risk Score</p>
          <h3 className={`score-value tone-${riskBand}`}>{insights.overview.riskScore}/100</h3>
        </article>
        <article className="number-cell">
          <p>Critical Issues</p>
          <h3>{insights.overview.criticalIssues}</h3>
        </article>
        <article className="number-cell">
          <p>High Issues</p>
          <h3>{insights.overview.highIssues}</h3>
        </article>
        <article className="number-cell">
          <p>Active Secrets</p>
          <h3>{insights.overview.activeSecrets}</h3>
        </article>
      </div>

      <div className="health-split">
        <div>
          <h4>Ongoing Warnings</h4>
          {insights.warnings.length === 0 ? (
            <p className="pass-text">No high-risk signals detected right now.</p>
          ) : (
            <div className="warning-feed">
              {insights.warnings.slice(0, 3).map((warning) => (
                <article key={warning.id} className={`warning-card level-${toneBySeverity[warning.severity]}`}>
                  <span className={`severity-dot level-${toneBySeverity[warning.severity]}`}>
                    {severityLabel[warning.severity]}
                  </span>
                  <p className="warning-name">{warning.title}</p>
                  <p>{warning.message}</p>
                </article>
              ))}
            </div>
          )}
        </div>

        <div>
          <h4>Suggested Actions</h4>
          {insights.suggestions.length === 0 ? (
            <p className="side-note">No action needed at this moment.</p>
          ) : (
            <ul className="advice-feed">
              {insights.suggestions.slice(0, 3).map((suggestion, index) => (
                <li
                  key={suggestion}
                  className={`advice-item level-${index === 0 ? "red" : index === 1 ? "orange" : "green"}`}
                >
                  {suggestion}
                </li>
              ))}
            </ul>
          )}

          <h4>Logic Flow</h4>
          <div className="steps-feed">
            {insights.flow.slice(0, 3).map((step) => (
              <div key={step.step} className="step-row">
                <span className={`step-marker level-${toneByFlowStatus[step.status]}`}>Step {step.step}</span>
                <div>
                  <p className="step-name">{step.title}</p>
                  <p className="side-note">{step.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
