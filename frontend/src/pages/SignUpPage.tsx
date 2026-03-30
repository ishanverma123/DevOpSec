import { useState } from "react";
import { Link, Navigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

export default function SignUpPage() {
  const { register, isAuthenticated } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [roleName, setRoleName] = useState("Viewer");
  const [error, setError] = useState("");

  if (isAuthenticated) {
    return <Navigate to="/dashboard/secrets" replace />;
  }

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");

    try {
      await register({ email: email.trim(), password, organizationName: organizationName.trim(), roleName });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign up failed");
    }
  };

  return (
    <section className="gate-wrap">
      <article className="entry-card">
        <h1>Create Workspace Account</h1>
        <p>Join or bootstrap your organization.</p>
        <form onSubmit={onSubmit}>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
          />
          <input
            value={organizationName}
            onChange={(e) => setOrganizationName(e.target.value)}
            placeholder="Organization"
          />
          <select value={roleName} onChange={(e) => setRoleName(e.target.value)}>
            <option>Admin</option>
            <option>Developer</option>
            <option>Viewer</option>
          </select>
          <button type="submit">Create Account</button>
        </form>
        {error ? <p className="fail-text">{error}</p> : null}
        <p className="toggle-hint">
          Already have an account? <Link to="/signin">Sign in</Link>
        </p>
      </article>
    </section>
  );
}
