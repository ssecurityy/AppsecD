"use client";
import { useEffect, useState, useRef } from "react";
import { LogOut, Zap, Home, FolderOpen, BookOpen, FileText, Settings, ShieldCheck, Users, Crown, Building2, Sun, Moon, Shield, Cpu, ChevronDown, Bell } from "lucide-react";
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
  const { user, clearAuth, setOrgSettings } = useAuthStore();
  const { theme, toggleTheme } = useTheme();
  const router = useRouter();
  const pathname = usePathname();
  const [branding, setBranding] = useState<any>(null);

  useEffect(() => {
    if (user) {
      api.getMyBranding().then((data: any) => {
        setBranding(data);
        if (data?.sast_enabled !== undefined) {
          setOrgSettings({ sast_enabled: !!data.sast_enabled });
        }
      }).catch(() => {});
    }
  }, [user, setOrgSettings]);

  const logout = () => {
    clearAuth();
    toast.success("Signed out successfully");
    router.push("/login");
  };

  const nav = [
    { href: "/dashboard", icon: Home, label: "Dashboard" },
    { href: "/projects", icon: FolderOpen, label: "Projects" },
    ...(isAdmin(user?.role) ? [{ href: "/dashboard/security-intel", icon: Cpu, label: "Intel" }] : []),
    { href: "/payloads", icon: BookOpen, label: "Wordlists" },
  ];

  const [profileOpen, setProfileOpen] = useState(false);
  const profileRef = useRef<HTMLDivElement>(null);
  const [notifOpen, setNotifOpen] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifItems, setNotifItems] = useState<any[]>([]);
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) setProfileOpen(false);
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotifOpen(false);
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);
  useEffect(() => {
    if (!user) return;
    const load = () => {
      api.getUnreadNotificationCount().then((r: any) => setUnreadCount(r?.count ?? 0)).catch(() => {});
    };
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [user]);
  const openNotifPanel = () => {
    if (!notifOpen) api.getNotifications(1).then((r: any) => setNotifItems(r?.items ?? [])).catch(() => {});
    setNotifOpen((o) => !o);
  };

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
          <picture>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={branding.logo_url.startsWith("http") ? branding.logo_url : `${getApiBase()}${branding.logo_url}`}
              alt={branding?.name || "Organization logo"}
              className="w-8 h-8 rounded-lg object-contain border shadow-sm"
              style={{
                borderColor: branding?.brand_color ? `${branding.brand_color}40` : "var(--border-subtle)",
                background: "var(--bg-elevated)",
              }}
              onError={(e) => {
                const img = e.target as HTMLImageElement;
                img.style.display = "none";
              }}
            />
          </picture>
        )}
        <div className="hidden sm:block">
          <span className="font-bold text-sm tracking-tight block" style={{ color: "var(--text-primary)" }}>
            {branding?.name ? (
              <span style={{ color: branding?.brand_color || "var(--text-primary)" }}>
                {branding.name}
              </span>
            ) : (
              <>AppSec<span className="text-indigo-500">D</span></>
            )}
          </span>
          {branding?.description && (
            <span className="text-[10px] block leading-none truncate max-w-[140px]" style={{ color: "var(--text-muted)" }}>
              {branding.description}
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
            {/* Notifications bell (5E) */}
            <div className="relative" ref={notifRef}>
              <button onClick={openNotifPanel} className="relative p-1.5 rounded-lg hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }} title="Notifications">
                <Bell className="w-4 h-4" />
                {unreadCount > 0 && (
                  <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-3.5 px-1 rounded-full text-[10px] font-bold flex items-center justify-center bg-red-500 text-white">
                    {unreadCount > 99 ? "99+" : unreadCount}
                  </span>
                )}
              </button>
              {notifOpen && (
                <div className="absolute right-0 top-full mt-1 w-72 max-h-80 overflow-y-auto rounded-xl border shadow-xl py-1 z-[100]" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                  <div className="px-3 py-2 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                    <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Notifications</span>
                    {unreadCount > 0 && (
                      <button onClick={() => api.markAllNotificationsRead().then(() => setUnreadCount(0))} className="ml-2 text-[10px]" style={{ color: "var(--text-muted)" }}>Mark all read</button>
                    )}
                  </div>
                  {notifItems.length === 0 ? (
                    <p className="px-3 py-4 text-xs" style={{ color: "var(--text-muted)" }}>No notifications</p>
                  ) : (
                    notifItems.slice(0, 10).map((n: any) => (
                      <div key={n.id} className="px-3 py-2 border-b last:border-0" style={{ borderColor: "var(--border-subtle)" }}>
                        <p className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{n.title}</p>
                        <p className="text-[10px] truncate mt-0.5" style={{ color: "var(--text-muted)" }}>{n.message}</p>
                        {!n.is_read && <button onClick={() => api.markNotificationRead(n.id).then(() => setUnreadCount((c) => Math.max(0, c - 1))) } className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>Mark read</button>}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
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

            {/* Profile dropdown */}
            <div className="relative" ref={profileRef}>
              <button
                onClick={() => setProfileOpen((o) => !o)}
                className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-[var(--bg-hover)] transition-colors"
                style={{ color: "var(--text-primary)" }}
              >
                <div className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold ${
                  isSuperAdmin(user.role)
                    ? "bg-gradient-to-br from-amber-500/20 to-orange-500/20 border border-amber-500/30 text-amber-400"
                    : user.role === "admin"
                      ? "bg-gradient-to-br from-emerald-500/20 to-teal-500/20 border border-emerald-500/20 text-emerald-400"
                      : "bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/20 text-indigo-400"
                }`}>
                  {isSuperAdmin(user.role) ? <Crown className="w-3.5 h-3.5" /> : (user.full_name || "U")[0].toUpperCase()}
                </div>
                <div className="hidden md:block text-left">
                  <div className="text-xs font-medium leading-none flex items-center gap-1 max-w-[120px]" style={{ color: "var(--text-primary)" }}>
                    <span className="truncate">{user.full_name}</span>
                    {isSuperAdmin(user.role) && <span className="text-[9px] text-amber-400 bg-amber-500/10 px-1 rounded">SA</span>}
                  </div>
                  <div className="text-[10px] leading-none mt-0.5" style={{ color: "var(--text-muted)" }}>
                    Lv.{user.level} · {user.role === "super_admin" ? "Super Admin" : user.role}
                  </div>
                </div>
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${profileOpen ? "rotate-180" : ""}`} style={{ color: "var(--text-muted)" }} />
              </button>
              {profileOpen && (
                <div
                  className="absolute right-0 top-full mt-1 w-64 rounded-xl border shadow-xl py-1 z-[100]"
                  style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                >
                  <div className="px-4 py-3 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                    <p className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>{user.full_name}</p>
                    <p className="text-xs truncate mt-0.5" style={{ color: "var(--text-muted)" }}>{(user as any).email || "—"}</p>
                    <p className="text-[10px] truncate mt-0.5" style={{ color: "var(--text-muted)" }}>{(user as any).organization_name || "—"}</p>
                    <div className="flex items-center gap-2 mt-2">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium" style={{
                        backgroundColor: isSuperAdmin(user.role) ? "#f59e0b22" : user.role === "admin" ? "#10b98122" : "#6366f122",
                        color: isSuperAdmin(user.role) ? "#f59e0b" : user.role === "admin" ? "#10b981" : "#6366f1",
                      }}>
                        {user.role === "super_admin" ? "Super Admin" : user.role}
                      </span>
                      <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>Lv.{user.level} · {user.xp_points} XP</span>
                    </div>
                  </div>
                  <div className="py-1">
                    <Link href="/dashboard/executive" onClick={() => setProfileOpen(false)} className="flex items-center gap-2 px-4 py-2 text-xs hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }}>
                      <Shield className="w-3.5 h-3.5" /> Executive Dashboard
                    </Link>
                    <Link href="/settings/security" onClick={() => setProfileOpen(false)} className="flex items-center gap-2 px-4 py-2 text-xs hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }}>
                      <Shield className="w-3.5 h-3.5" /> Security Settings
                    </Link>
                    {isAdmin(user.role) && (
                      <>
                        <Link href="/admin/organizations" onClick={() => setProfileOpen(false)} className="flex items-center gap-2 px-4 py-2 text-xs hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }}>
                          <Building2 className="w-3.5 h-3.5" /> Organization
                        </Link>
                        <Link href="/admin/users" onClick={() => setProfileOpen(false)} className="flex items-center gap-2 px-4 py-2 text-xs hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }}>
                          <Users className="w-3.5 h-3.5" /> Users
                        </Link>
                        <Link href="/admin/settings" onClick={() => setProfileOpen(false)} className="flex items-center gap-2 px-4 py-2 text-xs hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }}>
                          <Settings className="w-3.5 h-3.5" /> Platform Settings
                        </Link>
                        <Link href="/admin/ai-usage" onClick={() => setProfileOpen(false)} className="flex items-center gap-2 px-4 py-2 text-xs hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }}>
                          <Cpu className="w-3.5 h-3.5" /> AI Usage
                        </Link>
                        <Link href="/admin/audit" onClick={() => setProfileOpen(false)} className="flex items-center gap-2 px-4 py-2 text-xs hover:bg-[var(--bg-hover)]" style={{ color: "var(--text-primary)" }}>
                          <FileText className="w-3.5 h-3.5" /> Audit Logs
                        </Link>
                      </>
                    )}
                  </div>
                  <div className="border-t py-1" style={{ borderColor: "var(--border-subtle)" }}>
                    <button onClick={() => { setProfileOpen(false); logout(); }} className="flex items-center gap-2 px-4 py-2 text-xs w-full hover:bg-red-500/10 text-red-400">
                      <LogOut className="w-3.5 h-3.5" /> Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </nav>
  );
}
