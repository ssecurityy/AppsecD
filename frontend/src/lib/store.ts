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

interface AuthStore {
  user: User | null;
  token: string | null;
  setAuth: (user: User, token: string) => void;
  setUser: (user: User) => void;
  clearAuth: () => void;
  hydrate: () => void;
}

export const useAuthStore = create<AuthStore>((set) => ({
  user: null,
  token: null,
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
  clearAuth: () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("appsecdtoken");
      localStorage.removeItem("appsecduser");
    }
    set({ user: null, token: null });
  },
  hydrate: () => {
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("appsecdtoken");
      const userStr = localStorage.getItem("appsecduser");
      if (token && userStr) {
        set({ token, user: JSON.parse(userStr) });
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
