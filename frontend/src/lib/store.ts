"use client";
import { create } from "zustand";

interface User {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: string;
  xp_points: number;
  level: number;
  badges: string[];
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
      localStorage.setItem("vapt_token", token);
      localStorage.setItem("vapt_user", JSON.stringify(user));
    }
    set({ user, token });
  },
  setUser: (user) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("vapt_user", JSON.stringify(user));
    }
    set({ user });
  },
  clearAuth: () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("vapt_token");
      localStorage.removeItem("vapt_user");
    }
    set({ user: null, token: null });
  },
  hydrate: () => {
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("vapt_token");
      const userStr = localStorage.getItem("vapt_user");
      if (token && userStr) {
        set({ token, user: JSON.parse(userStr) });
      }
    }
  },
}));
