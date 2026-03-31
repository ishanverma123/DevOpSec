import { Link, Navigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

export default function LandingPage() {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated) {
    return <Navigate to="/dashboard/secrets" replace />;
  }

  return (
    <main className="landing-shell">
      <section className="landing-hero">
        <p className="landing-kicker">DevOpSec Platform</p>
        <h1>Secure Secrets. Reduce Drift. Ship with Confidence.</h1>
        <p className="landing-copy">
          A focused workspace for managing secret lifecycle, access assignment, audit history, and policy-driven
          rotation across your organization.
        </p>
        <div className="landing-cta-row">
          <Link className="landing-cta-primary" to="/signup">
            Start Free Workspace
          </Link>
          <Link className="landing-cta-ghost" to="/signin">
            Sign In
          </Link>
        </div>
      </section>

      <section className="landing-metrics">
        <article>
          <h3>Centralized Vault</h3>
          <p>Manage encrypted secrets with lifecycle status, version history, and ownership controls.</p>
        </article>
        <article>
          <h3>Automated Rotation</h3>
          <p>Run policy-based and manual rotation workflows to limit credential exposure windows.</p>
        </article>
        <article>
          <h3>Audit Visibility</h3>
          <p>Track every sensitive action with timestamped access logs and role-based accountability.</p>
        </article>
      </section>
    </main>
  );
}
