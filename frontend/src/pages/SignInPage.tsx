import { useState } from "react";
import { Link, Navigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function SignInPage() {
  const { login, isAuthenticated } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [emailError, setEmailError] = useState("");
  const [passwordError, setPasswordError] = useState("");
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

  const validatePassword = (value: string) => {
    if (!value) {
      return "Password is required.";
    }

    if (value.length < 8) {
      return "Password must be at least 8 characters.";
    }

    return "";
  };

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");

    const nextEmailError = validateEmail(email);
    const nextPasswordError = validatePassword(password);
    setEmailError(nextEmailError);
    setPasswordError(nextPasswordError);

    if (nextEmailError || nextPasswordError) {
      return;
    }

    setIsSubmitting(true);

    try {
      await login(email.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="gate-wrap">
      <article className="entry-card">
        <h1>Sign In</h1>
        <p>Access your organization secret workspace.</p>
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
          {passwordError ? <p className="field-error">{passwordError}</p> : null}
          <button type="submit" disabled={isSubmitting || Boolean(emailError) || Boolean(passwordError)}>
            {isSubmitting ? "Signing in..." : "Sign In"}
          </button>
        </form>
        {error ? <p className="fail-text">{error}</p> : null}
        <p className="toggle-hint">
          <Link to="/">Back to home</Link>
          <span> · </span>
          New here? <Link to="/signup">Create account</Link>
        </p>
      </article>
    </section>
  );
}
