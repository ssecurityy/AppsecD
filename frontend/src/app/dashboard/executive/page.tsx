"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { Shield, TrendingUp, AlertTriangle, Activity, DollarSign, BarChart3 } from "lucide-react";
import Link from "next/link";

export default function ExecutiveDashboardPage() {
  const { user, hydrate } = useAuthStore();
  const router = useRouter();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user === null && !loading) router.replace("/login");
  }, [user, router, loading]);

  useEffect(() => {
    api.getExecutiveDashboard()
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [user]);

  if (loading || !data) {
    return (
      <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
        <Navbar />
        <main className="max-w-6xl mx-auto p-6">
          <div className="animate-pulse rounded-xl h-64" style={{ background: "var(--bg-card)" }} />
        </main>
      </div>
    );
  }

  const score = data.security_posture_score ?? 0;
  const scoreColor = score >= 80 ? "#16a34a" : score >= 50 ? "#ca8a04" : "#dc2626";

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <main className="max-w-6xl mx-auto p-6">
        <div className="flex items-center gap-2 mb-6">
          <Link href="/dashboard" className="text-sm" style={{ color: "var(--text-muted)" }}>Dashboard</Link>
          <span style={{ color: "var(--text-muted)" }}>/</span>
          <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Executive</span>
        </div>
        <h1 className="text-2xl font-bold mb-6" style={{ color: "var(--text-primary)" }}>Executive Security Dashboard</h1>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="rounded-xl border p-6 flex flex-col items-center" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <Shield size={32} style={{ color: scoreColor }} />
            <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>Security Posture Score</p>
            <p className="text-4xl font-bold mt-1" style={{ color: scoreColor }}>{score}</p>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>0–100</p>
          </div>
          <div className="rounded-xl border p-6" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <Activity size={24} className="mb-2" style={{ color: "#3b82f6" }} />
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>Scanner Coverage</p>
            <p className="text-2xl font-bold mt-1" style={{ color: "var(--text-primary)" }}>{data.scanner_coverage ?? 0}%</p>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>Projects scanned (30d)</p>
          </div>
          <div className="rounded-xl border p-6" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <DollarSign size={24} className="mb-2" style={{ color: "#8b5cf6" }} />
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>AI Cost (month)</p>
            <p className="text-2xl font-bold mt-1" style={{ color: "var(--text-primary)" }}>${(data.cost_summary?.total_usd ?? 0).toFixed(2)}</p>
          </div>
          <div className="rounded-xl border p-6" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <BarChart3 size={24} className="mb-2" style={{ color: "#ea580c" }} />
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>SLA Compliance</p>
            <p className="text-2xl font-bold mt-1" style={{ color: "var(--text-primary)" }}>{data.sla_compliance?.on_track ?? 100}%</p>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>On track</p>
          </div>
        </div>

        {Array.isArray(data.top_vulnerable_projects) && data.top_vulnerable_projects.length > 0 && (
          <div className="rounded-xl border p-6 mb-8" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
              <AlertTriangle size={20} style={{ color: "#dc2626" }} /> Top Vulnerable Projects
            </h2>
            <ul className="space-y-2">
              {data.top_vulnerable_projects.map((p: any) => (
                <li key={p.project_id} className="flex items-center justify-between py-2 border-b last:border-0" style={{ borderColor: "var(--border-subtle)" }}>
                  <Link href={`/projects/${p.project_id}`} className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{p.name || p.project_id}</Link>
                  <span className="text-sm font-bold" style={{ color: "#dc2626" }}>{p.count} critical/high</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {Array.isArray(data.findings_trend) && data.findings_trend.length > 0 && (
          <div className="rounded-xl border p-6" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
              <TrendingUp size={20} style={{ color: "#3b82f6" }} /> Findings Trend (90 days)
            </h2>
            <div className="flex flex-wrap gap-4">
              {data.findings_trend.slice(-8).map((t: any, i: number) => (
                <div key={i} className="px-3 py-2 rounded-lg" style={{ backgroundColor: "var(--bg-primary)" }}>
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>{t.week?.slice(0, 10)}</span>
                  <span className="ml-2 text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{t.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
