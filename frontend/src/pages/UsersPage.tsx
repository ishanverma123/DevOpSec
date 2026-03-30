import { useEffect, useState } from "react";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { User } from "../types";

export default function UsersPage() {
  const { token } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const run = async () => {
      try {
        const result = await api.getUsers(token);
        setUsers(result.users);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to load users");
      }
    };

    void run();
  }, []);

  return (
    <section className="module">
      <div className="module-top">
        <h3>Users</h3>
      </div>
      {error ? <p className="fail-text">{error}</p> : null}
      <div className="tile-grid">
        {users.map((user) => (
          <article key={user.id} className="info-tile">
            <h4>{user.email}</h4>
            <p className="fixed-face">{user.id}</p>
            <p>{user.is_active ? "Active" : "Inactive"}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
