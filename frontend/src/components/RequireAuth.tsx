import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

export default function RequireAuth() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    // Keep the last route so sign-in flow can return user to intended page.
    return <Navigate to="/signin" state={{ from: location.pathname }} replace />;
  }

  return <Outlet />;
}
