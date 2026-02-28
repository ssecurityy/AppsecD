"use client";
import { LogOut, Zap, Home, FolderOpen, BookOpen, FileText, Settings, ShieldCheck, Users, Crown, Building2 } from "lucide-react";
import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
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
  const router = useRouter();
  const pathname = usePathname();

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
      { href: "/admin/users", icon: Users, label: "Users" },
      { href: "/admin/audit", icon: FileText, label: "Audit" },
      { href: "/admin/settings", icon: Settings, label: "Settings" },
    ] : []),
  ];

  return (
    <nav className="h-14 bg-[#09090b]/95 border-b border-[#1e2330] flex items-center px-5 gap-1 sticky top-0 z-50 backdrop-blur-xl">
      {/* Brand */}
      <Link href="/dashboard" className="flex items-center gap-2.5 mr-6 group">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20 group-hover:shadow-indigo-500/40 transition-shadow">
          <ShieldCheck className="w-4.5 h-4.5 text-white" />
        </div>
        <span className="font-bold text-white text-sm tracking-tight hidden sm:block">
          AppSec<span className="text-indigo-400">D</span>
        </span>
      </Link>

      {/* Nav links */}
      <div className="flex items-center gap-0.5">
        {nav.map(({ href, icon: Icon, label }) => {
          const active = pathname.startsWith(href);
          return (
            <Link key={href} href={href}
              className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                active
                  ? "text-white bg-white/[0.06]"
                  : "text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.03]"
              }`}>
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
      <div className="ml-auto flex items-center gap-3">
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
            <div className="flex items-center gap-1.5 bg-[#161922] border border-[#1e2330] rounded-lg px-2.5 py-1">
              <Zap className="w-3 h-3 text-indigo-400" />
              <span className="text-indigo-300 text-xs font-semibold tabular-nums">{user.xp_points}</span>
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
                <div className="text-xs font-medium text-white leading-none flex items-center gap-1">
                  {user.full_name}
                  {isSuperAdmin(user.role) && <span className="text-[9px] text-amber-400 bg-amber-500/10 px-1 rounded">SA</span>}
                </div>
                <div className="text-[10px] text-[#64748b] leading-none mt-0.5">
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
