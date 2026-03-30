import { useEffect, useState } from "react";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { Role } from "../types";

export default function RolesPage() {
  const { token } = useAuth();
  const [roles, setRoles] = useState<Role[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const run = async () => {
      try {
        const result = await api.getRoles(token);
        setRoles(result.roles);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to load roles");
      }
    };

    void run();
  }, []);

  return (
    <section className="module">
      <div className="module-top">
        <h3>Roles</h3>
      </div>
      {error ? <p className="fail-text">{error}</p> : null}
      <div className="tile-grid">
        {roles.map((role) => (
          <article key={role.id} className="info-tile">
            <h4>{role.name}</h4>
            <p>{role.description}</p>
            <div className="tag-row">
              {role.permissions.map((permission) => (
                <span key={permission} className="label-tag fixed-face">
                  {permission}
                </span>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
