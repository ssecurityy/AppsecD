"use client";
import { useEffect, useState } from "react";
import { LogOut, Zap, Home, FolderOpen, BookOpen, FileText, Settings, ShieldCheck, Users, Crown, Building2, Sun, Moon, Shield } from "lucide-react";
import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
import { useTheme } from "@/components/ThemeProvider";
import { api, getApiBase } from "@/lib/api";
import toast from "react-hot-toast";
import { motion } from "framer-motion";

const BADGE_MAP: Record<string, { label: string; color: string }> = {
  first_blood: { label: "FB", color: "text-red-400 bg-red-500/10 border-red-500/20" },
  recon_master: { label: "RM", color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
  sql_slayer: { label: "SQ", color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
  xss_hunter: { label: "XS", color: "text-purple-400 bg-purple-500/10 border-purple-500/20" },
  lock_picker: { label: "LP", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
  mission_complete: { label: "MC", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
  on_fire: { label: "OF", color: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
  vapt_veteran: { label: "VT", color: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20" },
};

export default function Navbar() {
  const { user, clearAuth } = useAuthStore();
  const { theme, toggleTheme } = useTheme();
  const router = useRouter();
  const pathname = usePathname();
  const [branding, setBranding] = useState<any>(null);

  useEffect(() => {
    if (user) {
      api.getMyBranding().then(setBranding).catch(() => {});
    }
  }, [user]);

  const logout = () => {
    clearAuth();
    toast.success("Signed out successfully");
    router.push("/login");
  };

  const nav = [
    { href: "/dashboard", icon: Home, label: "Dashboard" },
    { href: "/projects", icon: FolderOpen, label: "Projects" },
    { href: "/payloads", icon: BookOpen, label: "Wordlists" },
    ...(isAdmin(user?.role) ? [
      { href: "/dashboard/security-intel", icon: Shield, label: "Intel" },
      { href: "/admin/users", icon: Users, label: "Users" },
      { href: "/admin/organizations", icon: Building2, label: "Orgs" },
      { href: "/admin/audit", icon: FileText, label: "Audit" },
      { href: "/admin/settings", icon: Settings, label: "Settings" },
    ] : []),
  ];

  return (
    <nav className="h-14 border-b flex items-center px-5 gap-1 sticky top-0 z-50 backdrop-blur-xl"
      style={{ background: theme === "dark" ? "rgba(9,9,11,0.95)" : "rgba(255,255,255,0.95)", borderColor: "var(--border-subtle)" }}>
      {/* Brand */}
      <Link href="/dashboard" className="flex items-center gap-2.5 mr-6 group">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center shadow-lg transition-shadow"
          style={{
            background: branding?.brand_color
              ? `linear-gradient(135deg, ${branding.brand_color}, ${branding.brand_color}dd)`
              : "linear-gradient(135deg, #6366f1, #9333ea)",
            boxShadow: branding?.brand_color
              ? `0 4px 14px ${branding.brand_color}33`
              : "0 4px 14px rgba(99,102,241,0.2)",
          }}
        >
          <ShieldCheck className="w-4.5 h-4.5 text-white" />
        </div>
        {branding?.logo_url && (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={branding.logo_url.startsWith("http") ? branding.logo_url : `${getApiBase()}${branding.logo_url}`}
            alt="Org logo"
            className="w-8 h-8 rounded-lg object-cover border"
            style={{ borderColor: "var(--border-subtle)" }}
          />
        )}
        <div className="hidden sm:block">
          <span className="font-bold text-sm tracking-tight block" style={{ color: "var(--text-primary)" }}>
            AppSec<span className="text-indigo-500">D</span>
          </span>
          {branding?.name && (
            <span className="text-[10px] block leading-none" style={{ color: "var(--text-muted)" }}>
              {branding.name}
            </span>
          )}
        </div>
      </Link>

      {/* Nav links */}
      <div className="flex items-center gap-0.5 overflow-x-auto min-w-0 flex-1 scrollbar-none" style={{ scrollbarWidth: 'none' }}>
        {nav.map(({ href, icon: Icon, label }) => {
          const active = pathname.startsWith(href);
          return (
            <Link key={href} href={href}
              className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                active
                  ? "bg-[var(--bg-hover)]"
                  : "hover:bg-[var(--bg-hover)]"
              }`}
              style={{ color: active ? "var(--text-primary)" : "var(--text-muted)" }}>
              <Icon className="w-3.5 h-3.5" />
              <span className="hidden md:inline">{label}</span>
              {active && (
                <motion.div
                  layoutId="nav-indicator"
                  className="absolute bottom-0 left-3 right-3 h-[2px] bg-indigo-500 rounded-full"
                  transition={{ type: "spring", bounce: 0.15, duration: 0.4 }}
                />
              )}
            </Link>
          );
        })}
      </div>

      {/* Right side */}
      <div className="ml-auto flex items-center gap-2">
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="relative w-14 h-7 rounded-full transition-all duration-300 flex items-center"
          style={{
            background: theme === "dark"
              ? "linear-gradient(135deg, #1e293b 0%, #0f172a 100%)"
              : "linear-gradient(135deg, #bfdbfe 0%, #93c5fd 100%)",
            border: `1px solid ${theme === "dark" ? "#334155" : "#60a5fa"}`,
          }}
          title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        >
          <motion.div
            className="absolute w-5 h-5 rounded-full flex items-center justify-center shadow-sm"
            style={{
              background: theme === "dark" ? "#1e293b" : "#ffffff",
              border: `1px solid ${theme === "dark" ? "#475569" : "#93c5fd"}`,
            }}
            animate={{ x: theme === "dark" ? 3 : 29 }}
            transition={{ type: "spring", stiffness: 500, damping: 30 }}
          >
            {theme === "dark" ? (
              <Moon className="w-3 h-3 text-indigo-400" />
            ) : (
              <Sun className="w-3 h-3 text-amber-500" />
            )}
          </motion.div>
          <span className="absolute left-1.5 top-1/2 -translate-y-1/2">
            {theme === "light" && <Moon className="w-3 h-3 text-blue-700 opacity-40" />}
          </span>
          <span className="absolute right-1.5 top-1/2 -translate-y-1/2">
            {theme === "dark" && <Sun className="w-3 h-3 text-amber-400 opacity-40" />}
          </span>
        </button>

        {user && (
          <>
            {/* Badges */}
            {user.badges?.length > 0 && (
              <div className="hidden lg:flex items-center gap-1">
                {user.badges.slice(0, 4).map((b: string) => {
                  const badge = BADGE_MAP[b];
                  return badge ? (
                    <span key={b}
                      className={`w-6 h-6 rounded-md border flex items-center justify-center text-[9px] font-bold ${badge.color}`}
                      title={b.replace(/_/g, " ")}>
                      {badge.label}
                    </span>
                  ) : null;
                })}
              </div>
            )}

            {/* XP */}
            <div className="flex items-center gap-1.5 rounded-lg px-2.5 py-1"
              style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
              <Zap className="w-3 h-3 text-indigo-400" />
              <span className="text-indigo-400 text-xs font-semibold tabular-nums">{user.xp_points}</span>
            </div>

            {/* User */}
            <div className="flex items-center gap-2">
              <div className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold ${
                isSuperAdmin(user.role)
                  ? "bg-gradient-to-br from-amber-500/20 to-orange-500/20 border border-amber-500/30 text-amber-400"
                  : user.role === "admin"
                    ? "bg-gradient-to-br from-emerald-500/20 to-teal-500/20 border border-emerald-500/20 text-emerald-400"
                    : "bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/20 text-indigo-400"
              }`}>
                {isSuperAdmin(user.role) ? <Crown className="w-3.5 h-3.5" /> : (user.full_name || "U")[0].toUpperCase()}
              </div>
              <div className="hidden md:block">
                <div className="text-xs font-medium leading-none flex items-center gap-1 max-w-[120px]" style={{ color: "var(--text-primary)" }}>
                  <span className="truncate">{user.full_name}</span>
                  {isSuperAdmin(user.role) && <span className="text-[9px] text-amber-400 bg-amber-500/10 px-1 rounded">SA</span>}
                </div>
                <div className="text-[10px] leading-none mt-0.5" style={{ color: "var(--text-muted)" }}>
                  Lv.{user.level} · {user.role === "super_admin" ? "Super Admin" : user.role}
                </div>
              </div>
            </div>

            {/* Logout */}
            <button onClick={logout}
              className="p-1.5 rounded-lg text-[#64748b] hover:text-red-400 hover:bg-red-500/5 transition-all">
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </>
        )}
      </div>
    </nav>
  );
}
