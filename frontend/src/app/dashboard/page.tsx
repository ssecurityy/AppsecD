"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { Plus, FolderOpen, Shield, Zap, Target, AlertTriangle } from "lucide-react";
import Link from "next/link";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400",
  medium: "text-yellow-400", low: "text-green-400", info: "text-blue-400",
};

export default function Dashboard() {
  const { user, hydrate } = useAuthStore();
  const router = useRouter();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user === null && !loading) router.replace("/login");
  }, [user, router, loading]);

  useEffect(() => {
    api.listProjects()
      .then(setProjects)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const stats = {
    total: projects.length,
    active: projects.filter(p => p.status === "in_progress").length,
    completed: projects.filter(p => p.status === "completed").length,
    findings: projects.reduce((s, p) => s + (p.failed_count || 0), 0),
  };

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Welcome banner */}
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: "easeOut" }}
          className="card p-6 border-[#1E293B]"
          style={{ background: "linear-gradient(135deg, #0D1321 0%, #0F1624 100%)" }}
        >
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Welcome back, {user?.full_name || "Tester"}
              </h1>
              <p className="text-[#94A3B8] mt-1 text-sm">
                Security testing command center · {new Date().toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" })}
              </p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-purple-400">{user?.xp_points || 0} XP</div>
              <div className="text-[#9CA3AF] text-sm">Level {user?.level || 1}</div>
            </div>
          </div>
        </motion.div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Total Projects", value: stats.total, icon: FolderOpen, cardCls: "border-blue-900/30", valCls: "text-blue-400", iconCls: "text-blue-600" },
            { label: "Active Testing", value: stats.active, icon: Shield, cardCls: "border-cyan-900/30", valCls: "text-cyan-400", iconCls: "text-cyan-600" },
            { label: "Completed", value: stats.completed, icon: Target, cardCls: "border-green-900/30", valCls: "text-green-400", iconCls: "text-green-600" },
            { label: "Total Findings", value: stats.findings, icon: AlertTriangle, cardCls: "border-red-900/30", valCls: "text-red-400", iconCls: "text-red-600" },
          ].map(({ label, value, icon: Icon, cardCls, valCls, iconCls }, i) => (
            <motion.div key={label} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08, duration: 0.35 }}
              className={`card p-4 ${cardCls}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[#94A3B8] text-xs font-medium">{label}</p>
                  <p className={`text-2xl font-bold mt-1 ${valCls}`}>{value}</p>
                </div>
                <Icon className={`w-8 h-8 ${iconCls} opacity-60`} />
              </div>
            </motion.div>
          ))}
        </div>

        {/* Projects list */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold text-white">Active Projects</h2>
            <Link href="/projects/new" className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> New Project
            </Link>
          </div>

          {loading ? (
            <div className="card p-8 text-center text-[#9CA3AF]">Loading projects...</div>
          ) : projects.length === 0 ? (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="card p-12 text-center border-dashed">
              <Shield className="w-12 h-12 text-[#374151] mx-auto mb-3" />
              <p className="text-[#9CA3AF]">No projects yet. Start your first security assessment!</p>
              <Link href="/projects/new" className="btn-primary inline-flex items-center gap-2 mt-4 text-sm">
                <Plus className="w-4 h-4" /> Create First Project
              </Link>
            </motion.div>
          ) : (
            <div className="space-y-3">
              {projects.map((p, i) => {
                const pct = p.total_test_cases > 0
                  ? Math.round(((p.tested_count || 0) / p.total_test_cases) * 100)
                  : 0;
                return (
                  <motion.div key={p.id} initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}>
                    <Link href={`/projects/${p.id}`}
                      className="card p-4 flex items-center gap-4 hover:border-blue-700/50 transition-all block group">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-white group-hover:text-blue-400 transition-colors">
                            {p.application_name}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full border ${
                            p.status === "completed" ? "text-green-400 bg-green-900/20 border-green-800" :
                            p.status === "in_progress" ? "text-blue-400 bg-blue-900/20 border-blue-800" :
                            "text-[#9CA3AF] bg-[#1F2937] border-[#374151]"
                          }`}>
                            {p.status.replace("_", " ")}
                          </span>
                        </div>
                        <p className="text-[#9CA3AF] text-sm mt-0.5">{p.application_url}</p>
                        <div className="mt-2">
                          <div className="flex items-center justify-between text-xs text-[#9CA3AF] mb-1">
                            <span>{p.tested_count || 0}/{p.total_test_cases || 0} test cases</span>
                            <span>{pct}%</span>
                          </div>
                          <div className="h-1.5 bg-[#374151] rounded-full overflow-hidden">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${pct}%` }}
                              transition={{ duration: 0.8, delay: i * 0.05 }}
                              className={`h-full rounded-full ${
                                pct === 100 ? "bg-green-500" : pct > 50 ? "bg-blue-500" : "bg-blue-700"
                              }`}
                            />
                          </div>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="text-red-400 text-sm font-bold">{p.failed_count || 0} Findings</div>
                        <div className="text-green-400 text-xs mt-0.5">{p.passed_count || 0} Passed</div>
                      </div>
                    </Link>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
