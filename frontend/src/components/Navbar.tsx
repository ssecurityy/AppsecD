"use client";
import { Shield, LogOut, Zap, Home, FolderOpen, BookOpen, FileText, Settings, Target, Search, Bug, Key, Award } from "lucide-react";
import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { motion } from "framer-motion";

export default function Navbar() {
  const { user, clearAuth } = useAuthStore();
  const router = useRouter();
  const pathname = usePathname();

  const logout = () => {
    clearAuth();
    toast.success("Logged out");
    router.push("/login");
  };

  const nav = [
    { href: "/dashboard", icon: Home, label: "Dashboard" },
    { href: "/projects", icon: FolderOpen, label: "Projects" },
    { href: "/payloads", icon: BookOpen, label: "Payloads" },
    ...(user?.role === "admin" ? [{ href: "/admin/users", icon: Shield, label: "Users" }, { href: "/admin/audit", icon: FileText, label: "Audit" }, { href: "/admin/settings", icon: Settings, label: "Settings" }] : []),
  ];

  const BADGE_ICONS: Record<string, React.ReactNode> = {
    first_blood: <Target className="w-3.5 h-3.5" />,
    recon_master: <Search className="w-3.5 h-3.5" />,
    sql_slayer: <Bug className="w-3.5 h-3.5" />,
    xss_hunter: <Bug className="w-3.5 h-3.5" />,
    lock_picker: <Key className="w-3.5 h-3.5" />,
    mission_complete: <Award className="w-3.5 h-3.5" />,
    on_fire: <Zap className="w-3.5 h-3.5" />,
    vapt_veteran: <Shield className="w-3.5 h-3.5" />,
  };

  return (
    <nav className="h-14 bg-[#0A0F1A] border-b border-[#1E293B] flex items-center px-4 gap-4 sticky top-0 z-50 backdrop-blur-sm">
      <Link href="/dashboard" className="flex items-center gap-2 mr-4">
        <Shield className="w-5 h-5 text-blue-400" />
        <span className="font-bold text-white text-sm hidden sm:block">VAPT Navigator</span>
      </Link>

      {nav.map(({ href, icon: Icon, label }) => (
        <Link key={href} href={href}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-sm transition-colors ${
            pathname.startsWith(href)
              ? "bg-blue-600/20 text-blue-400"
              : "text-[#9CA3AF] hover:text-white"
          }`}>
          <Icon className="w-4 h-4" />
          <span className="hidden sm:inline">{label}</span>
        </Link>
      ))}

      <div className="ml-auto flex items-center gap-3">
        {user && (
          <div className="flex items-center gap-2">
            {user.badges?.length > 0 && (
              <div className="flex items-center gap-1.5" title={user.badges.join(", ")}>
                {user.badges.slice(0, 5).map((b: string) => (
                  <span key={b} className="w-7 h-7 rounded-lg bg-[#1E293B] border border-[#334155] flex items-center justify-center text-amber-400" title={b.replace(/_/g, " ")}>
                    {BADGE_ICONS[b] || <Award className="w-3.5 h-3.5" />}
                  </span>
                ))}
              </div>
            )}
            <motion.div
              initial={{ opacity: 0.8 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.5 }}
              className="flex items-center gap-1.5 bg-[#1E293B] border border-[#334155] rounded-lg px-2.5 py-1"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span className="text-amber-300 text-xs font-semibold">{user.xp_points} XP</span>
            </motion.div>
            <span className="text-[#9CA3AF] text-sm hidden md:block">
              Lv.{user.level} {user.full_name}
            </span>
          </div>
        )}
        <button onClick={logout}
          className="flex items-center gap-1.5 text-[#9CA3AF] hover:text-red-400 transition-colors text-sm">
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </nav>
  );
}
