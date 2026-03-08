"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { Plus, ArrowRight, ShieldCheck, Search, Filter, Calendar, Users, AlertTriangle } from "lucide-react";

export default function ProjectsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (!user && !loading) router.replace("/login"); }, [user, router, loading]);

  useEffect(() => {
    api.listProjects()
      .then((r: any) => setProjects(r?.items ?? (Array.isArray(r) ? r : [])))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const filtered = projects.filter((p) => {
    if (statusFilter !== "all" && p.status !== statusFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        (p.application_name || "").toLowerCase().includes(q) ||
        (p.application_url || "").toLowerCase().includes(q) ||
        (p.app_owner_name || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  const stats = {
    total: projects.length,
    inProgress: projects.filter((p) => p.status === "in_progress").length,
    completed: projects.filter((p) => p.status === "completed").length,
    totalFindings: projects.reduce((sum, p) => sum + (p.finding_count ?? p.failed_count ?? 0), 0),
  };

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-6xl mx-auto p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <ShieldCheck className="w-6 h-6 text-indigo-400" />Security Projects
          </h1>
          <Link href="/projects/new" className="btn-primary flex items-center gap-2 text-sm">
            <Plus className="w-4 h-4" /> New Project
          </Link>
        </div>

        {/* Stats Row */}
        {!loading && projects.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            {[
              { label: "Total Projects", value: stats.total, color: "text-indigo-400", icon: ShieldCheck },
              { label: "In Progress", value: stats.inProgress, color: "text-blue-400", icon: Users },
              { label: "Completed", value: stats.completed, color: "text-emerald-400", icon: Calendar },
              { label: "Total Findings", value: stats.totalFindings, color: "text-red-400", icon: AlertTriangle },
            ].map(({ label, value, color, icon: Icon }) => (
              <div key={label} className="card p-4 text-center">
                <Icon className={`w-4 h-4 mx-auto mb-1 ${color}`} />
                <div className={`text-xl font-bold ${color}`}>{value}</div>
                <div className="text-xs" style={{ color: "var(--text-muted)" }}>{label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Search & Filter */}
        {!loading && projects.length > 0 && (
          <div className="flex items-center gap-3 mb-4 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--text-muted)" }} />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search projects by name, URL, or owner..."
                className="input-field w-full pl-9 pr-3 py-2 text-sm"
              />
            </div>
            <div className="flex items-center gap-1">
              <Filter className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
              {["all", "in_progress", "completed", "draft"].map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    statusFilter === s ? "bg-indigo-500/20 text-indigo-400 border border-indigo-500/30" : "hover:bg-[var(--bg-hover)]"
                  }`}
                  style={statusFilter !== s ? { color: "var(--text-muted)" } : undefined}
                >
                  {s === "all" ? "All" : s.replace("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                </button>
              ))}
            </div>
          </div>
        )}

        {loading ? (
          <div className="grid gap-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="card p-5 animate-pulse">
                <div className="h-5 rounded w-1/3 mb-2" style={{ background: "var(--bg-elevated)" }} />
                <div className="h-3 rounded w-1/2 mb-3" style={{ background: "var(--bg-elevated)" }} />
                <div className="h-2 rounded-full w-full" style={{ background: "var(--bg-elevated)" }} />
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="card p-12 text-center">
            <ShieldCheck className="w-12 h-12 mx-auto mb-4" style={{ color: "var(--text-muted)" }} />
            <h3 className="text-lg font-semibold mb-2" style={{ color: "var(--text-primary)" }}>
              {projects.length === 0 ? "No projects yet" : "No projects match your filters"}
            </h3>
            <p className="text-sm mb-4" style={{ color: "var(--text-muted)" }}>
              {projects.length === 0
                ? "Create your first security testing project to get started."
                : "Try adjusting your search or filter criteria."}
            </p>
            {projects.length === 0 && (
              <Link href="/projects/new" className="btn-primary inline-flex items-center gap-2 text-sm">
                <Plus className="w-4 h-4" /> Create First Project
              </Link>
            )}
          </div>
        ) : (
          <div className="grid gap-3">
            {filtered.map((p, i) => {
              const pct = p.total_test_cases > 0 ? Math.round(((p.tested_count || 0) / p.total_test_cases) * 100) : 0;
              const findings = p.finding_count ?? p.failed_count ?? 0;
              return (
                <motion.div key={p.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.03 }}>
                  <Link href={`/projects/${p.id}`}
                    className="card p-5 flex items-center gap-4 hover:border-indigo-500/50 transition-all block group">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <h3 className="font-semibold group-hover:text-indigo-400 transition-colors truncate" style={{ color: "var(--text-primary)" }}>
                          {p.application_name}
                        </h3>
                        <span className={`text-xs px-2 py-0.5 rounded border ${
                          p.status === "completed" ? "text-green-400 bg-green-900/20 border-green-800" :
                          p.status === "in_progress" ? "text-indigo-400 bg-indigo-500/10 border-indigo-500/30" :
                          "text-[var(--text-muted)] bg-[var(--bg-elevated)] border-[var(--border-subtle)]"
                        }`}>{(p.status || "draft").replace("_", " ")}</span>
                        {findings > 0 && (
                          <span className="text-xs px-2 py-0.5 rounded border text-red-400 bg-red-500/10 border-red-500/30">
                            {findings} finding{findings !== 1 ? "s" : ""}
                          </span>
                        )}
                      </div>
                      <p className="text-xs truncate mb-1" style={{ color: "var(--text-muted)" }} title={p.application_url}>{p.application_url}</p>
                      {/* Extra detail row */}
                      <div className="flex items-center gap-3 text-xs flex-wrap" style={{ color: "var(--text-muted)" }}>
                        {p.app_owner_name && <span>Owner: {p.app_owner_name}</span>}
                        {p.testing_type && <><span style={{ color: "#374151" }}>|</span><span>{p.testing_type.replace("_", " ")}</span></>}
                        {p.environment && <><span style={{ color: "#374151" }}>|</span><span>{p.environment}</span></>}
                        {p.created_at && <><span style={{ color: "#374151" }}>|</span><span>{new Date(p.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}</span></>}
                      </div>
                      <div className="flex items-center gap-3 mt-2">
                        <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                          <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                            className={`h-full rounded-full ${pct === 100 ? "bg-green-500" : "bg-indigo-500"}`} />
                        </div>
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>{pct}%</span>
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-sm font-medium" style={{ color: "var(--text-secondary)" }}>{p.total_test_cases} cases</div>
                      <div className="text-xs" style={{ color: "var(--text-muted)" }}>{p.tested_count || 0} tested</div>
                    </div>
                    <ArrowRight className="w-5 h-5 text-[#374151] group-hover:text-indigo-400 transition-colors shrink-0" />
                  </Link>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
