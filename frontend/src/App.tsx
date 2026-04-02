import { Navigate, Route, BrowserRouter as Router, Routes } from "react-router-dom";

import RequireAuth from "./components/RequireAuth";
import { AuthProvider } from "./context/AuthContext";
import DashboardLayout from "./layouts/DashboardLayout";
import AuditPage from "./pages/AuditPage";
import DecryptPage from "./pages/DecryptPage";
import LandingPage from "./pages/LandingPage";
import RolesPage from "./pages/RolesPage";
import SecretsPage from "./pages/SecretsPage";
import SignInPage from "./pages/SignInPage";
import SignUpPage from "./pages/SignUpPage";
import UsersPage from "./pages/UsersPage";

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/signin" element={<SignInPage />} />
          <Route path="/signup" element={<SignUpPage />} />

          {/* Everything under /dashboard must be authenticated. */}
          <Route element={<RequireAuth />}>
            <Route path="/dashboard" element={<DashboardLayout />}>
              <Route path="secrets" element={<SecretsPage />} />
              <Route path="users" element={<UsersPage />} />
              <Route path="roles" element={<RolesPage />} />
              <Route path="audit" element={<AuditPage />} />
              <Route path="decrypt" element={<DecryptPage />} />
              <Route index element={<Navigate to="secrets" replace />} />
            </Route>
          </Route>

          {/* Unknown routes fall back to landing instead of blank state. */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}
