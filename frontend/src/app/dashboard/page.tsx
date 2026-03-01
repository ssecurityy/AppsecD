"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import {
  Plus, FolderOpen, ShieldCheck, Target, AlertTriangle, TrendingUp,
  ChevronRight, Building2, Users, Crown, Zap, BookOpen, BarChart3,
  Activity, Clock, Flame, Award, Shield
} from "lucide-react";
import Link from "next/link";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500",
  medium: "bg-yellow-500", low: "bg-emerald-500", info: "bg-sky-500",
};

export default function Dashboard() {
  const { user, hydrate } = useAuthStore();
  const router = useRouter();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [trendData, setTrendData] = useState<{ by_date: { date: string; total: number; dast: number; manual: number }[]; by_severity: Record<string, number> } | null>(null);
  const [trendLoading, setTrendLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user === null && !loading) router.replace("/login");
  }, [user, router, loading]);

  useEffect(() => {
    api.listProjects()
      .then((r: any) => setProjects(r?.items ?? (Array.isArray(r) ? r : [])))
      .catch(() => {})
      .finally(() => setLoading(false));
    setTrendLoading(true);
    api.getDashboardFindingsTrend()
      .then((r: any) => setTrendData(r || { by_date: [], by_severity: {} }))
      .catch(() => setTrendData({ by_date: [], by_severity: {} }))
      .finally(() => setTrendLoading(false));

    if (isAdmin(user?.role)) {
      api.listOrganizations().then(setOrgs).catch(() => {});
      api.users().then(setUsers).catch(() => {});
    }
  }, [user]);

  const stats = {
    total: projects.length,
    active: projects.filter(p => p.status === "in_progress").length,
    completed: projects.filter(p => p.status === "completed").length,
    findings: projects.reduce((s, p) => s + (p.finding_count ?? p.failed_count ?? 0), 0),
    review: projects.filter(p => p.status === "review").length,
    draft: projects.filter(p => p.status === "draft").length,
  };

  const recentProjects = projects.slice(0, 8);

  const quickLinks = [
    { href: "/projects/new", label: "New Project", icon: Plus, color: "text-indigo-400 bg-indigo-500/10" },
    { href: "/payloads", label: "Wordlists", icon: BookOpen, color: "text-blue-400 bg-blue-500/10" },
    ...(isAdmin(user?.role) ? [
      { href: "/dashboard/security-intel", label: "Security Intel", icon: Shield, color: "text-purple-400 bg-purple-500/10" },
      { href: "/admin/users", label: "Users", icon: Users, color: "text-emerald-400 bg-emerald-500/10" },
      { href: "/admin/audit", label: "Audit", icon: Activity, color: "text-amber-400 bg-amber-500/10" },
    ] : []),
  ];

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-7xl mx-auto p-6 space-y-6">
        {/* Welcome banner */}
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
          className="relative overflow-hidden rounded-2xl border p-6"
          style={{ borderColor: "var(--border-subtle)", background: "var(--gradient-brand-subtle)" }}
        >
          <div className="absolute top-0 right-0 w-[400px] h-[200px] bg-indigo-500/5 rounded-full blur-[80px]" />
          <div className="relative flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold tracking-tight flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                Welcome back, {user?.full_name || "Tester"}
                {isSuperAdmin(user?.role) && (
                  <span className="text-xs text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full flex items-center gap-1">
                    <Crown className="w-3 h-3" /> Super Admin
                  </span>
                )}
                {user?.role === "admin" && (
                  <span className="text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full flex items-center gap-1">
                    <Building2 className="w-3 h-3" /> Org Admin
                  </span>
                )}
              </h1>
              <p className="mt-1 text-sm" style={{ color: "var(--text-muted)" }}>
                {new Date().toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric", year: "numeric" })}
              </p>
              {user?.streak_days && user.streak_days > 0 ? (
                <div className="flex items-center gap-1 mt-2 text-xs text-amber-400">
                  <Flame className="w-3 h-3" /> {user.streak_days} day streak
                </div>
              ) : null}
            </div>
            <div className="text-right hidden sm:block">
              <div className="text-3xl font-bold gradient-text tabular-nums">{user?.xp_points || 0}</div>
              <div className="text-xs font-medium mt-0.5 flex items-center gap-1 justify-end" style={{ color: "var(--text-muted)" }}>
                <Zap className="w-3 h-3 text-indigo-400" /> XP &middot; Level {user?.level || 1}
              </div>
              {user?.badges && user.badges.length > 0 && (
                <div className="flex items-center gap-1 mt-1 justify-end">
                  <Award className="w-3 h-3 text-amber-400" />
                  <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{user.badges.length} badge{user.badges.length !== 1 ? "s" : ""}</span>
                </div>
              )}
            </div>
          </div>

          {/* Quick links */}
          <div className="relative flex items-center gap-2 mt-4 flex-wrap">
            {quickLinks.map(({ href, label, icon: Icon, color }) => (
              <Link key={href} href={href}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium ${color} hover:opacity-80 transition-all`}>
                <Icon className="w-3 h-3" /> {label}
              </Link>
            ))}
          </div>
        </motion.div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "Total Projects", value: stats.total, icon: FolderOpen, gradient: "from-blue-500/10 to-cyan-500/5", iconColor: "text-blue-400", borderColor: "border-blue-500/10" },
            { label: "Active Testing", value: stats.active, icon: ShieldCheck, gradient: "from-indigo-500/10 to-purple-500/5", iconColor: "text-indigo-400", borderColor: "border-indigo-500/10" },
            { label: "Completed", value: stats.completed, icon: Target, gradient: "from-emerald-500/10 to-green-500/5", iconColor: "text-emerald-400", borderColor: "border-emerald-500/10" },
            { label: "Findings", value: stats.findings, icon: AlertTriangle, gradient: "from-red-500/10 to-orange-500/5", iconColor: "text-red-400", borderColor: "border-red-500/10" },
          ].map(({ label, value, icon: Icon, gradient, iconColor, borderColor }, i) => (
            <motion.div key={label} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
              className={`card p-5 ${borderColor} bg-gradient-to-br ${gradient}`}>
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs font-medium tracking-wide uppercase" style={{ color: "var(--text-muted)" }}>{label}</p>
                  <p className="text-2xl font-bold mt-2 tabular-nums" style={{ color: "var(--text-primary)" }}>{value}</p>
                </div>
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${iconColor}`} style={{ background: "var(--bg-card)" }}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Admin overview - Orgs & Users */}
        {isSuperAdmin(user?.role) && orgs.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
            className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Organizations */}
            <div className="card p-5 border-emerald-500/10">
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-3" style={{ color: "var(--text-primary)" }}>
                <Building2 className="w-4 h-4 text-emerald-400" /> Organizations ({orgs.length})
              </h3>
              <div className="space-y-2">
                {orgs.slice(0, 5).map((o: any) => {
                  const orgProjects = projects.filter(p => p.organization_id === o.id);
                  const orgUsers_ = users.filter((u: any) => u.organization_id === o.id);
                  return (
                    <div key={o.id} className="flex items-center justify-between py-1.5">
                      <div className="flex items-center gap-2 min-w-0">
                        <div className="w-6 h-6 rounded bg-emerald-500/10 flex items-center justify-center text-emerald-400 text-[10px] font-bold">
                          {o.name[0].toUpperCase()}
                        </div>
                        <span className="text-sm truncate" style={{ color: "var(--text-primary)" }}>{o.name}</span>
                      </div>
                      <div className="flex items-center gap-3 text-xs" style={{ color: "var(--text-muted)" }}>
                        <span>{orgProjects.length} projects</span>
                        <span>{orgUsers_.length} users</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Platform Stats */}
            <div className="card p-5 border-indigo-500/10">
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-3" style={{ color: "var(--text-primary)" }}>
                <BarChart3 className="w-4 h-4 text-indigo-400" /> Platform Overview
              </h3>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg p-3 text-center" style={{ background: "var(--bg-card)" }}>
                  <p className="text-xl font-bold tabular-nums" style={{ color: "var(--text-primary)" }}>{users.length}</p>
                  <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>Total Users</p>
                </div>
                <div className="rounded-lg p-3 text-center" style={{ background: "var(--bg-card)" }}>
                  <p className="text-xl font-bold tabular-nums" style={{ color: "var(--text-primary)" }}>{orgs.length}</p>
                  <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>Organizations</p>
                </div>
                <div className="rounded-lg p-3 text-center" style={{ background: "var(--bg-card)" }}>
                  <p className="text-xl font-bold tabular-nums" style={{ color: "var(--text-primary)" }}>{stats.review}</p>
                  <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>In Review</p>
                </div>
                <div className="rounded-lg p-3 text-center" style={{ background: "var(--bg-card)" }}>
                  <p className="text-xl font-bold tabular-nums" style={{ color: "var(--text-primary)" }}>{stats.draft}</p>
                  <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>Draft</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Vulnerability & Findings Trend Charts — always visible for trend awareness */}
        {user && (
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
            className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Issues Trend — GET /projects/trend/findings */}
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}
              className="card p-5 overflow-hidden" style={{ borderColor: "var(--border-subtle)" }}>
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
                <TrendingUp className="w-4 h-4 text-indigo-400" /> Issues Trend
              </h3>
              {trendLoading ? (
                <div className="h-48 flex items-center justify-center" style={{ background: "var(--bg-elevated)", borderRadius: 8 }}>
                  <motion.div animate={{ opacity: [0.4, 0.8, 0.4] }} transition={{ duration: 1.5, repeat: Infinity }}
                    className="text-xs" style={{ color: "var(--text-muted)" }}>Loading trend...</motion.div>
                </div>
              ) : trendData?.by_date && trendData.by_date.length > 0 ? (
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={[...(trendData.by_date)].sort((a, b) => (a.date || "").localeCompare(b.date || ""))} margin={{ top: 5, right: 5, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="dastGradDash" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#10b981" stopOpacity={0.5} />
                          <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="manualGradDash" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#6366f1" stopOpacity={0.5} />
                          <stop offset="100%" stopColor="#6366f1" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                      <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="var(--text-muted)" />
                      <YAxis tick={{ fontSize: 10 }} stroke="var(--text-muted)" />
                      <Tooltip contentStyle={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)", borderRadius: 8 }} labelStyle={{ color: "var(--text-primary)" }} labelFormatter={(l) => `Date: ${l}`} formatter={(value: number | undefined) => [value ?? 0, ""]} />
                      <Legend />
                      <Area type="monotone" dataKey="dast" name="DAST" stackId="1" stroke="#10b981" fill="url(#dastGradDash)" strokeWidth={2} isAnimationActive />
                      <Area type="monotone" dataKey="manual" name="Manual" stackId="1" stroke="#6366f1" fill="url(#manualGradDash)" strokeWidth={2} isAnimationActive />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-48 flex flex-col items-center justify-center rounded-lg" style={{ background: "var(--bg-elevated)", border: "1px dashed var(--border-subtle)" }}>
                  <TrendingUp className="w-10 h-10 mb-2" style={{ color: "var(--text-muted)", opacity: 0.5 }} />
                  <p className="text-xs text-center px-4" style={{ color: "var(--text-muted)" }}>No findings yet. Run DAST scans or add manual findings to see date-wise trends.</p>
                </div>
              )}
            </motion.div>
            {/* Vulnerability Distribution by severity */}
            <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}
              className="card p-5" style={{ borderColor: "var(--border-subtle)" }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                  <BarChart3 className="w-4 h-4 text-indigo-400" /> Vulnerability Distribution
                </h3>
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>{stats.findings} total findings</span>
              </div>
              <div className="flex gap-1 h-2.5 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                {(() => {
                  const sevCounts: Record<string, number> = trendData?.by_severity && Object.keys(trendData.by_severity).length > 0
                    ? { critical: 0, high: 0, medium: 0, low: 0, info: 0, ...trendData.by_severity }
                    : {};
                  const total = Object.values(sevCounts).reduce((a, b) => a + b, 0) || 1;
                  const order = ["critical", "high", "medium", "low", "info"];
                  const segments = order.filter(s => (sevCounts[s] || 0) > 0);
                  if (segments.length === 0) {
                    return <div className="w-full h-full flex items-center justify-center" style={{ background: "var(--bg-elevated)", borderRadius: 4 }} />;
                  }
                  return segments.map((sev, i) => (
                    <motion.div key={sev} initial={{ width: 0 }} animate={{ width: `${((sevCounts[sev] || 0) / total) * 100}%` }}
                      transition={{ delay: 0.5 + i * 0.05, duration: 0.6 }}
                      className={`${SEVERITY_COLORS[sev] || "bg-gray-500"}`} title={`${sev}: ${sevCounts[sev]}`} />
                  ));
                })()}
              </div>
              <div className="flex gap-4 mt-3 flex-wrap">
                {["critical", "high", "medium", "low", "info"].map(sev => (
                  <div key={sev} className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--text-muted)" }}>
                    <div className={`w-2 h-2 rounded-full ${SEVERITY_COLORS[sev]}`} />
                    <span className="capitalize">{sev}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          </motion.div>
        )}

        {/* Projects */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
              <FolderOpen className="w-4 h-4" style={{ color: "var(--text-muted)" }} /> Projects
            </h2>
            <Link href="/projects/new" className="btn-primary flex items-center gap-2 text-xs py-2 px-4">
              <Plus className="w-3.5 h-3.5" /> New Project
            </Link>
          </div>

          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3].map(i => (
                <div key={i} className="card p-5 animate-shimmer h-20" />
              ))}
            </div>
          ) : projects.length === 0 ? (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="card p-16 text-center border-dashed" style={{ borderColor: "var(--border-subtle)" }}>
              <div className="w-14 h-14 rounded-2xl bg-indigo-500/10 flex items-center justify-center mx-auto mb-4">
                <ShieldCheck className="w-7 h-7 text-indigo-400" />
              </div>
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>No projects yet. Start your first security assessment.</p>
              <Link href="/projects/new" className="btn-primary inline-flex items-center gap-2 mt-5 text-xs">
                <Plus className="w-3.5 h-3.5" /> Create Project
              </Link>
            </motion.div>
          ) : (
            <div className="space-y-2">
              {recentProjects.map((p, i) => {
                const pct = p.total_test_cases > 0
                  ? Math.round(((p.tested_count || 0) / p.total_test_cases) * 100)
                  : 0;
                return (
                  <motion.div key={p.id} initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04, duration: 0.3 }}>
                    <Link href={`/projects/${p.id}`}
                      className="card p-4 flex items-center gap-4 hover:border-indigo-500/20 transition-all block group">
                      <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border border-indigo-500/10 flex items-center justify-center shrink-0">
                        <span className="text-sm font-bold text-indigo-400">{(p.application_name || "P")[0].toUpperCase()}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm group-hover:text-indigo-300 transition-colors truncate max-w-[200px]" style={{ color: "var(--text-primary)" }} title={p.application_name}>
                            {p.application_name}
                          </span>
                          <span className={`status-pill ${
                            p.status === "completed" ? "text-emerald-400 bg-emerald-500/10 border border-emerald-500/20" :
                            p.status === "in_progress" ? "text-indigo-400 bg-indigo-500/10 border border-indigo-500/20" :
                            p.status === "review" ? "text-yellow-400 bg-yellow-500/10 border border-yellow-500/20" :
                            "bg-[var(--bg-elevated)] border border-[var(--border-subtle)]" + " " + "text-[var(--text-muted)]"
                          }`}>
                            {(p.status || "draft").replace("_", " ")}
                          </span>
                          {p.organization_name && (
                            <span className="text-[10px] text-emerald-500 flex items-center gap-0.5">
                              <Building2 className="w-3 h-3" /> {p.organization_name}
                            </span>
                          )}
                        </div>
                        <div className="mt-2 flex items-center gap-3">
                          <div className="flex-1">
                            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${pct}%` }}
                                transition={{ duration: 0.8, delay: i * 0.04 }}
                                className={`h-full rounded-full ${
                                  pct === 100 ? "bg-emerald-500" : "bg-indigo-500"
                                }`}
                              />
                            </div>
                          </div>
                          <span className="text-[11px] tabular-nums shrink-0" style={{ color: "var(--text-muted)" }}>{pct}%</span>
                        </div>
                      </div>
                      <div className="text-right shrink-0 hidden sm:block">
                        <div className="text-xs font-semibold text-red-400 tabular-nums">{p.finding_count ?? p.failed_count ?? 0} findings</div>
                        <div className="text-[11px] text-emerald-500 mt-0.5 tabular-nums">{p.passed_count || 0} passed</div>
                      </div>
                      <ChevronRight className="w-4 h-4 group-hover:text-indigo-400 transition-colors shrink-0" style={{ color: "var(--text-muted)" }} />
                    </Link>
                  </motion.div>
                );
              })}
              {projects.length > 8 && (
                <Link href="/projects" className="block text-center py-3 text-xs text-indigo-400 hover:text-indigo-300 transition-colors">
                  View all {projects.length} projects
                </Link>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
