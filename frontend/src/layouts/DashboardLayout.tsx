import { NavLink, Outlet } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

const links = [
  { to: "/dashboard/secrets", label: "Secrets" },
  { to: "/dashboard/users", label: "Users" },
  { to: "/dashboard/roles", label: "Roles" },
  { to: "/dashboard/audit", label: "Audit" },
  { to: "/dashboard/decrypt", label: "Decrypt" }
];

export default function DashboardLayout() {
  const { logout, user } = useAuth();

  return (
    <div className="workspace">
      <aside className="rail">
        <div className="identity">
          <p className="product-label">SentriVault</p>
          <h1>Secrets Governance</h1>
          {user?.organization_name && (
            <p style={{ fontSize: "0.875rem", color: "var(--faded)", marginTop: "0.5rem" }}>
              Organization: {user.organization_name}
            </p>
          )}
        </div>

        <nav className="nav-links">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) => `nav-entry ${isActive ? "active" : ""}`}
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        <button className="exit-btn" onClick={logout}>
          Logout
        </button>
      </aside>

      <main className="stage">
        <header className="banner">
          <div>
            <h2>Enterprise Secret Management Console</h2>
            <p>Control access, policies, and secure distribution from one dashboard.</p>
          </div>
          {user?.organization_name && (
            <div style={{ textAlign: "right" }}>
              <p style={{ fontSize: "0.875rem", color: "var(--faded)", marginBottom: "0.25rem" }}>Current Organization</p>
              <p style={{ fontWeight: "700", color: "var(--ink)" }}>{user.organization_name}</p>
            </div>
          )}
        </header>
        <Outlet />
      </main>
    </div>
  );
}
