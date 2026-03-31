import { useState } from "react";
import { Link, Navigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const passwordRules = {
  minLength: (value: string) => value.length >= 10,
  upper: (value: string) => /[A-Z]/.test(value),
  lower: (value: string) => /[a-z]/.test(value),
  number: (value: string) => /\d/.test(value),
  symbol: (value: string) => /[^A-Za-z0-9]/.test(value)
};

export default function SignUpPage() {
  const { register, isAuthenticated } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [roleName, setRoleName] = useState("Viewer");
  const [error, setError] = useState("");
  const [emailError, setEmailError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [organizationError, setOrganizationError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/dashboard/secrets" replace />;
  }

  const validateEmail = (value: string) => {
    if (!value.trim()) {
      return "Email is required.";
    }

    if (!emailRegex.test(value.trim())) {
      return "Enter a valid email address.";
    }

    return "";
  };

  const validateOrganization = (value: string) => {
    if (!value.trim()) {
      return "Organization is required.";
    }

    if (value.trim().length < 2) {
      return "Organization must be at least 2 characters.";
    }

    return "";
  };

  const validatePassword = (value: string) => {
    if (!value) {
      return "Password is required.";
    }

    const checks = Object.values(passwordRules).every((rule) => rule(value));
    if (!checks) {
      return "Password does not meet strength requirements.";
    }

    return "";
  };

  const passedRules = Object.values(passwordRules).filter((rule) => rule(password)).length;
  const passwordStrength = Math.round((passedRules / 5) * 100);

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");

    const nextEmailError = validateEmail(email);
    const nextPasswordError = validatePassword(password);
    const nextOrganizationError = validateOrganization(organizationName);

    setEmailError(nextEmailError);
    setPasswordError(nextPasswordError);
    setOrganizationError(nextOrganizationError);

    if (nextEmailError || nextPasswordError || nextOrganizationError) {
      return;
    }

    setIsSubmitting(true);

    try {
      await register({ email: email.trim(), password, organizationName: organizationName.trim(), roleName });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign up failed");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="gate-wrap">
      <article className="entry-card">
        <h1>Create Workspace Account</h1>
        <p>Join or bootstrap your organization.</p>
        <form onSubmit={onSubmit}>
          <input
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              if (emailError) {
                setEmailError(validateEmail(e.target.value));
              }
            }}
            onBlur={() => setEmailError(validateEmail(email))}
            placeholder="Email"
          />
          {emailError ? <p className="field-error">{emailError}</p> : null}
          <input
            type="password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              if (passwordError) {
                setPasswordError(validatePassword(e.target.value));
              }
            }}
            onBlur={() => setPasswordError(validatePassword(password))}
            placeholder="Password"
          />
          <div className="password-meter">
            <div className="password-meter-track">
              <span className="password-meter-bar" style={{ width: `${passwordStrength}%` }} />
            </div>
            <p className="field-note">Strength: {passwordStrength}%</p>
          </div>
          <ul className="password-rules">
            <li className={passwordRules.minLength(password) ? "rule-ok" : "rule-pending"}>At least 10 characters</li>
            <li className={passwordRules.upper(password) ? "rule-ok" : "rule-pending"}>One uppercase letter</li>
            <li className={passwordRules.lower(password) ? "rule-ok" : "rule-pending"}>One lowercase letter</li>
            <li className={passwordRules.number(password) ? "rule-ok" : "rule-pending"}>One number</li>
            <li className={passwordRules.symbol(password) ? "rule-ok" : "rule-pending"}>One special character</li>
          </ul>
          {passwordError ? <p className="field-error">{passwordError}</p> : null}
          <input
            value={organizationName}
            onChange={(e) => {
              setOrganizationName(e.target.value);
              if (organizationError) {
                setOrganizationError(validateOrganization(e.target.value));
              }
            }}
            onBlur={() => setOrganizationError(validateOrganization(organizationName))}
            placeholder="Organization"
          />
          {organizationError ? <p className="field-error">{organizationError}</p> : null}
          <select value={roleName} onChange={(e) => setRoleName(e.target.value)}>
            <option>Admin</option>
            <option>Developer</option>
            <option>Viewer</option>
          </select>
          <button
            type="submit"
            disabled={isSubmitting || Boolean(emailError) || Boolean(passwordError) || Boolean(organizationError)}
          >
            {isSubmitting ? "Creating account..." : "Create Account"}
          </button>
        </form>
        {error ? <p className="fail-text">{error}</p> : null}
        <p className="toggle-hint">
          <Link to="/">Back to home</Link>
          <span> · </span>
          Already have an account? <Link to="/signin">Sign in</Link>
        </p>
      </article>
    </section>
  );
}
