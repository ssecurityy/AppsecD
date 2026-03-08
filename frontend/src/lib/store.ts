"use client";
import { create } from "zustand";

interface User {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: string;
  organization_id?: string;
  organization_name?: string;
  xp_points: number;
  level: number;
  badges: string[];
  streak_days?: number;
}

interface OrgSettings {
  sast_enabled: boolean;
}

interface AuthStore {
  user: User | null;
  token: string | null;
  orgSettings: OrgSettings;
  setAuth: (user: User, token: string) => void;
  setUser: (user: User) => void;
  setOrgSettings: (settings: Partial<OrgSettings>) => void;
  clearAuth: () => void;
  hydrate: () => void;
}

export const useAuthStore = create<AuthStore>((set) => ({
  user: null,
  token: null,
  orgSettings: { sast_enabled: false },
  setAuth: (user, token) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("appsecdtoken", token);
      localStorage.setItem("appsecduser", JSON.stringify(user));
    }
    set({ user, token });
  },
  setUser: (user) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("appsecduser", JSON.stringify(user));
    }
    set({ user });
  },
  setOrgSettings: (settings) => {
    set((state) => {
      const merged = { ...state.orgSettings, ...settings };
      if (typeof window !== "undefined") {
        localStorage.setItem("appsecdorgsettings", JSON.stringify(merged));
      }
      return { orgSettings: merged };
    });
  },
  clearAuth: () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("appsecdtoken");
      localStorage.removeItem("appsecduser");
      localStorage.removeItem("appsecdorgsettings");
    }
    set({ user: null, token: null, orgSettings: { sast_enabled: false } });
  },
  hydrate: () => {
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("appsecdtoken");
      const userStr = localStorage.getItem("appsecduser");
      if (token && userStr) {
        try {
          set({ token, user: JSON.parse(userStr) });
        } catch {
          localStorage.removeItem("appsecdtoken");
          localStorage.removeItem("appsecduser");
        }
      }
      const orgStr = localStorage.getItem("appsecdorgsettings");
      if (orgStr) {
        try {
          set({ orgSettings: JSON.parse(orgStr) });
        } catch {
          localStorage.removeItem("appsecdorgsettings");
        }
      }
    }
  },
}));

// Helper to check admin roles
export function isAdmin(role?: string): boolean {
  return role === "admin" || role === "super_admin";
}

export function isSuperAdmin(role?: string): boolean {
  return role === "super_admin";
}
