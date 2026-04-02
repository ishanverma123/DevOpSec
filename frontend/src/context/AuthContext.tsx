import { createContext, useContext, useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import type { User } from "../types";

const TOKEN_KEY = "devopsec.token";

type RegisterInput = {
  email: string;
  password: string;
  organizationName: string;
  roleName?: string;
};

type AuthContextValue = {
  token: string;
  isAuthenticated: boolean;
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  loginAsGuest: () => Promise<void>;
  register: (input: RegisterInput) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Restore session token after page refresh.
  const [token, setToken] = useState<string>(() => localStorage.getItem(TOKEN_KEY) ?? "");
  const [user, setUser] = useState<User | null>(null);

  const persistToken = (nextToken: string) => {
    setToken(nextToken);
    if (nextToken) {
      localStorage.setItem(TOKEN_KEY, nextToken);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  };

  const loadUserProfile = async (token: string) => {
    try {
      const response = await api.getMe(token);
      setUser(response.user);
    } catch (error) {
      console.error("Failed to load user profile:", error);
      setUser(null);
    }
  };

  // Load user profile on mount if token exists
  useEffect(() => {
    if (token && !user) {
      void loadUserProfile(token);
    }
  }, [token]);

  // Memo keeps consumers from re-rendering unless auth state actually changes.
  const value = useMemo<AuthContextValue>(
    () => ({
      token,
      isAuthenticated: Boolean(token),
      user,
      login: async (email, password) => {
        const response = await api.login({ email, password });
        persistToken(response.token);
        await loadUserProfile(response.token);
      },
      loginAsGuest: async () => {
        const response = await api.guestLogin();
        persistToken(response.token);
        await loadUserProfile(response.token);
      },
      register: async (input) => {
        const response = await api.register(input);
        persistToken(response.token);
        await loadUserProfile(response.token);
      },
      logout: () => {
        persistToken("");
        setUser(null);
      }
    }),
    [token, user]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }

  return context;
}
