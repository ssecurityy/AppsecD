"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { Plus, ArrowRight, ShieldCheck } from "lucide-react";

export default function ProjectsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (!user && !loading) router.replace("/login"); }, [user, router, loading]);

  useEffect(() => {
    api.listProjects()
      .then((r: any) => setProjects(r?.items ?? (Array.isArray(r) ? r : [])))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}><ShieldCheck className="w-6 h-6 text-indigo-400" />Security Projects</h1>
          <Link href="/projects/new" className="btn-primary flex items-center gap-2 text-sm">
            <Plus className="w-4 h-4" /> New Project
          </Link>
        </div>

        {loading ? (
          <div className="text-center py-16" style={{ color: "var(--text-muted)" }}>Loading...</div>
        ) : (
          <div className="grid gap-4">
            {projects.map((p, i) => {
              const pct = p.total_test_cases > 0 ? Math.round(((p.tested_count || 0) / p.total_test_cases) * 100) : 0;
              return (
                <motion.div key={p.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}>
                  <Link href={`/projects/${p.id}`}
                    className="card p-5 flex items-center gap-4 hover:border-indigo-500/50 transition-all block group overflow-visible">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-semibold group-hover:text-indigo-400 transition-colors" style={{ color: "var(--text-primary)" }}>
                          {p.application_name}
                        </h3>
                        <span className={`text-xs px-2 py-0.5 rounded border ${
                          p.status === "completed" ? "text-green-400 bg-green-900/20 border-green-800" :
                          p.status === "in_progress" ? "text-indigo-400 bg-indigo-500/10 border-indigo-500/30" :
                          "text-[#64748b] bg-[#1F2937] border-[#374151]"
                        }`}>{p.status.replace("_", " ")}</span>
                      </div>
                      <p className="text-xs" style={{ color: "var(--text-muted)" }}>{p.application_url}</p>
                      <div className="flex items-center gap-3 mt-2">
                        <div className="flex-1 h-1.5 bg-[#374151] rounded-full overflow-hidden">
                          <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                            className={`h-full rounded-full ${pct === 100 ? "bg-green-500" : "bg-indigo-500"}`} />
                        </div>
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>{pct}%</span>
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-sm" style={{ color: "var(--text-muted)" }}>{p.total_test_cases} cases</div>
                      <div className="text-red-400 text-sm">{p.failed_count || 0} findings</div>
                    </div>
                    <ArrowRight className="w-5 h-5 text-[#374151] group-hover:text-indigo-400 transition-colors" />
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
