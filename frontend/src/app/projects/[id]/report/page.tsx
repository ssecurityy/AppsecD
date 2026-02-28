"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api, getApiBase } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { motion, AnimatePresence } from "framer-motion";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { ArrowLeft, FileText, RefreshCw, Download, ExternalLink, FileCode, FileSpreadsheet, FileJson, File } from "lucide-react";
import toast from "react-hot-toast";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  info: "#2563eb",
};

const FORMATS = [
  { key: "html", label: "HTML", icon: FileCode, color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
  { key: "pdf", label: "PDF", icon: File, color: "text-red-400 bg-red-500/10 border-red-500/20" },
  { key: "docx", label: "DOCX", icon: FileText, color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
  { key: "json", label: "JSON", icon: FileJson, color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
  { key: "csv", label: "CSV", icon: FileSpreadsheet, color: "text-purple-400 bg-purple-500/10 border-purple-500/20" },
] as const;

export default function LiveReportPage() {
  const params = useParams();
  const id = params?.id as string;
  const router = useRouter();
  const { user, hydrate } = useAuthStore();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (!id) return;
    api.getReportData(id)
      .then(setData)
      .catch((e: Error) => { setError(e.message); toast.error(e.message); })
      .finally(() => setLoading(false));
  }, [id]);

  const refresh = () => {
    setLoading(true);
    api.getReportData(id).then(setData).catch(() => {}).finally(() => setLoading(false));
  };

  const handleDownload = async (format: string) => {
    setDownloading(format);
    try {
      const name = data?.project?.application_name?.replace(/\s/g, "_") || "Report";
      await api.downloadReport(id, format as any, `AppSecD_${name}.${format}`);
      toast.success(`${format.toUpperCase()} downloaded`);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setDownloading(null);
    }
  };

  if (!user) return null;

  if (loading && !data) {
    return (
      <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
        <Navbar />
        <div className="max-w-6xl mx-auto p-6 flex items-center justify-center min-h-[60vh]">
          <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            className="w-12 h-12 border-2 border-indigo-500 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
        <Navbar />
        <div className="max-w-6xl mx-auto p-6">
          <div className="card p-8 text-center text-red-400">{error}</div>
          <Link href={`/projects/${id}`} className="btn-primary mt-4 inline-flex gap-2">
            <ArrowLeft className="w-4 h-4" /> Back to Project
          </Link>
        </div>
      </div>
    );
  }

  const p = data?.project || {};
  const findings = data?.findings || [];
  const risk = data?.risk_score ?? 0;
  const riskLevel = data?.risk_level || "Medium";
  const cov = data?.coverage_pct ?? 0;
  const sev = data?.severity_distribution || {};
  const owasp = data?.owasp_mapping || {};

  const severityChartData = Object.entries(sev).map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v, color: SEVERITY_COLORS[k] || "#6b7280" }));
  const owaspChartData = Object.entries(owasp).slice(0, 10).map(([k, v]) => ({ name: k.length > 20 ? k.slice(0, 18) + "..." : k, count: v }));

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <Link href={`/projects/${id}`}
              className="p-2 rounded-lg transition-all"
              style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>
              <ArrowLeft className="w-4 h-4" />
            </Link>
            <div>
              <h1 className="text-xl font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <FileText className="w-5 h-5 text-indigo-400" /> Live Report Preview
              </h1>
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>{p.application_name}</p>
            </div>
          </div>
          <button onClick={refresh}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all"
            style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
        </motion.div>

        {/* Download Formats */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.05 }}
          className="card p-4">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <Download className="w-4 h-4 text-indigo-400" /> Download Report
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {FORMATS.map(f => (
              <button key={f.key} onClick={() => handleDownload(f.key)}
                disabled={downloading === f.key}
                className={`flex items-center justify-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 ${f.color}`}>
                <f.icon className="w-4 h-4" />
                {downloading === f.key ? "..." : f.label}
              </button>
            ))}
          </div>
        </motion.div>

        {/* Table of Contents */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}
          className="card p-4">
          <h2 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider mb-3">Table of Contents</h2>
          <div className="flex flex-wrap gap-2">
            {["Executive Summary", "Charts & Analytics", "Findings", "Details"].map(s => (
              <a key={s} href={`#${s.toLowerCase().replace(/\s/g, "-").replace(/&/g, "")}`}
                className="text-xs px-3 py-1.5 rounded transition-all"
                style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>
                {s}
              </a>
            ))}
          </div>
        </motion.div>

        {/* Executive Summary */}
        <motion.section id="executive-summary" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}
          className="card p-6">
          <h2 className="text-lg font-bold mb-4 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">1</span>
            Executive Summary
          </h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                This report presents the findings of a security assessment conducted on <strong style={{ color: "var(--text-primary)" }}>{p.application_name}</strong>.
                The assessment evaluated the application against industry-standard security controls including OWASP Top 10, CWE Top 25, and related frameworks.
              </p>
              <div className="mt-4 grid grid-cols-3 gap-4">
                <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                  <div className="text-xs" style={{ color: "var(--text-muted)" }}>Risk Rating</div>
                  <div className={`text-xl font-bold mt-1 ${
                    riskLevel === "Critical" ? "text-red-500" :
                    riskLevel === "High" ? "text-orange-500" :
                    riskLevel === "Medium" ? "text-yellow-500" : "text-green-500"
                  }`}>
                    {riskLevel}
                  </div>
                  <div className="text-xs" style={{ color: "var(--text-muted)" }}>{risk}/100</div>
                </div>
                <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                  <div className="text-xs" style={{ color: "var(--text-muted)" }}>Coverage</div>
                  <div className="text-xl font-bold text-indigo-400 mt-1">{cov}%</div>
                  <div className="h-1.5 rounded-full mt-2 overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                    <div className="h-full bg-indigo-500 rounded-full" style={{ width: `${cov}%` }} />
                  </div>
                </div>
                <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                  <div className="text-xs" style={{ color: "var(--text-muted)" }}>Findings</div>
                  <div className="text-xl font-bold mt-1" style={{ color: "var(--text-primary)" }}>{findings.length}</div>
                  <div className="text-xs" style={{ color: "var(--text-muted)" }}>total issues</div>
                </div>
              </div>
            </div>
            <div className="space-y-2">
              {[
                { label: "Passed", value: p.passed_count || 0, color: "text-emerald-500" },
                { label: "Failed", value: p.failed_count || 0, color: "text-red-500" },
                { label: "N/A", value: p.na_count || 0, color: "var(--text-muted)" },
              ].map(item => (
                <div key={item.label} className="flex items-center justify-between p-2.5 rounded-lg" style={{ background: "var(--bg-tertiary)" }}>
                  <span className="text-sm" style={{ color: "var(--text-secondary)" }}>{item.label}</span>
                  <span className={`text-sm font-semibold ${item.color.startsWith("text-") ? item.color : ""}`}
                    style={!item.color.startsWith("text-") ? { color: item.color } : {}}>
                    {item.value}
                  </span>
                </div>
              ))}
              <div className="pt-2">
                <div className="flex justify-between text-xs mb-1">
                  <span style={{ color: "var(--text-muted)" }}>Progress</span>
                  <span className="font-medium" style={{ color: "var(--text-secondary)" }}>{cov}%</span>
                </div>
                <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                  <div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full transition-all" style={{ width: `${cov}%` }} />
                </div>
              </div>
            </div>
          </div>
        </motion.section>

        {/* Charts */}
        <motion.section id="charts-analytics" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="card p-6">
          <h2 className="text-lg font-bold mb-4 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">2</span>
            Charts & Analytics
          </h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="rounded-xl p-4" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
              <h3 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>Severity Distribution</h3>
              {severityChartData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={severityChartData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={2} dataKey="value">
                        {severityChartData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", borderRadius: "8px", color: "var(--text-primary)" }}
                        formatter={(v: any) => [v ?? 0, "Count"]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="flex flex-wrap gap-2 mt-2 justify-center">
                    {severityChartData.map(d => (
                      <div key={d.name} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                        <div className="w-2.5 h-2.5 rounded-sm" style={{ background: d.color }} />
                        {d.name}: {d.value as any}
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="h-[200px] flex items-center justify-center text-sm" style={{ color: "var(--text-muted)" }}>No data</div>
              )}
            </div>
            <div className="rounded-xl p-4" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
              <h3 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>OWASP Top 10 Mapping</h3>
              {owaspChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={owaspChartData} layout="vertical" margin={{ top: 0, right: 20, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                    <XAxis type="number" stroke="var(--text-muted)" fontSize={11} />
                    <YAxis type="category" dataKey="name" width={100} stroke="var(--text-muted)" fontSize={10} />
                    <Tooltip contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", borderRadius: "8px", color: "var(--text-primary)" }} />
                    <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[220px] flex items-center justify-center text-sm" style={{ color: "var(--text-muted)" }}>No data</div>
              )}
            </div>
          </div>
        </motion.section>

        {/* Findings Table */}
        <motion.section id="findings" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}
          className="card p-6">
          <h2 className="text-lg font-bold mb-4 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">3</span>
            Detailed Findings
          </h2>
          <div className="overflow-x-auto rounded-lg" style={{ border: "1px solid var(--border-subtle)" }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  {["#", "Title", "Severity", "OWASP", "CWE", "URL"].map(h => (
                    <th key={h} className="p-3 text-left text-xs font-medium uppercase tracking-wider" style={{ color: "var(--text-muted)", background: "var(--bg-tertiary)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any, i: number) => (
                  <tr key={i} className="transition-colors hover:bg-[var(--bg-hover)]" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td className="p-3" style={{ color: "var(--text-muted)" }}>{i + 1}</td>
                    <td className="p-3 font-medium" style={{ color: "var(--text-primary)" }}>{f.title}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        f.severity === "critical" ? "bg-red-500/10 text-red-500" :
                        f.severity === "high" ? "bg-orange-500/10 text-orange-500" :
                        f.severity === "medium" ? "bg-yellow-500/10 text-yellow-500" :
                        f.severity === "low" ? "bg-emerald-500/10 text-emerald-500" : "bg-blue-500/10 text-blue-500"
                      }`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="p-3" style={{ color: "var(--text-secondary)" }}>{f.owasp_category || "-"}</td>
                    <td className="p-3" style={{ color: "var(--text-secondary)" }}>{f.cwe_id || "-"}</td>
                    <td className="p-3 truncate max-w-[200px]" style={{ color: "var(--text-muted)" }}>{f.affected_url || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {findings.length === 0 && (
            <div className="py-12 text-center" style={{ color: "var(--text-muted)" }}>No findings yet</div>
          )}
        </motion.section>

        {/* Finding Details */}
        <motion.section id="details" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="space-y-4">
          <h2 className="text-lg font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">4</span>
            Finding Details with Evidence
          </h2>
          <AnimatePresence>
            {findings.map((f: any, i: number) => (
              <motion.div key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.05 * i }} className="card p-5">
                <div className="flex items-start justify-between gap-3 mb-3">
                  <h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>
                    #{i + 1} {f.title}
                  </h3>
                  <span className={`shrink-0 px-2.5 py-0.5 rounded text-xs font-medium ${
                    f.severity === "critical" ? "bg-red-500/10 text-red-500 border border-red-500/20" :
                    f.severity === "high" ? "bg-orange-500/10 text-orange-500 border border-orange-500/20" :
                    f.severity === "medium" ? "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20" :
                    f.severity === "low" ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20" :
                    "bg-blue-500/10 text-blue-500 border border-blue-500/20"
                  }`}>{f.severity}</span>
                </div>
                <div className="space-y-2">
                  <div className="rounded-lg p-3" style={{ background: "var(--bg-tertiary)" }}>
                    <div className="text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Description</div>
                    <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>{f.description || "No description provided"}</p>
                  </div>
                  <div className="grid md:grid-cols-2 gap-2">
                    <div className="rounded-lg p-3" style={{ background: "var(--bg-tertiary)" }}>
                      <div className="text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Affected URL</div>
                      <p className="text-sm break-all" style={{ color: "var(--text-code)" }}>{f.affected_url || "-"}</p>
                    </div>
                    <div className="rounded-lg p-3" style={{ background: "var(--bg-tertiary)" }}>
                      <div className="text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Recommendation</div>
                      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>{f.recommendation || "-"}</p>
                    </div>
                  </div>
                  {f.evidence?.length > 0 && (
                    <div className="flex gap-2 flex-wrap pt-1">
                      {f.evidence.map((e: any, j: number) => (
                        <a key={j} href={`${getApiBase()}${e.url}`} target="_blank" rel="noopener noreferrer"
                          className="text-xs px-2.5 py-1.5 rounded-lg text-indigo-400 hover:text-indigo-300 transition-all"
                          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                          {e.filename || "Evidence"}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </motion.section>

        <p className="text-xs text-center py-8" style={{ color: "var(--text-muted)" }}>
          Report generated at {data?.generated_at ? new Date(data.generated_at).toLocaleString() : "--"} · Live preview updates on refresh
        </p>
      </div>
    </div>
  );
}
