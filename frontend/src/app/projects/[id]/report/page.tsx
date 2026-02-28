"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api, getApiBase } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { motion, AnimatePresence } from "framer-motion";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  LineChart, Line,
} from "recharts";
import { ArrowLeft, FileText, RefreshCw, Download, ExternalLink } from "lucide-react";
import toast from "react-hot-toast";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  info: "#2563eb",
};

export default function LiveReportPage() {
  const params = useParams();
  const id = params?.id as string;
  const router = useRouter();
  const { user, hydrate } = useAuthStore();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  if (!user) return null;

  if (loading && !data) {
    return (
      <div className="min-h-screen bg-[#09090b]">
        <Navbar />
        <div className="max-w-6xl mx-auto p-6 flex items-center justify-center min-h-[60vh]">
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            className="w-12 h-12 border-2 border-blue-500 border-t-transparent rounded-full"
          />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="min-h-screen bg-[#09090b]">
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
  const cwe = data?.cwe_mapping || {};

  const severityChartData = Object.entries(sev).map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v, color: SEVERITY_COLORS[k] || "#6b7280" }));
  const owaspChartData = Object.entries(owasp).slice(0, 10).map(([k, v]) => ({ name: k.length > 20 ? k.slice(0, 18) + "…" : k, count: v }));

  return (
    <div className="min-h-screen bg-[#09090b]">
      <Navbar />
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between flex-wrap gap-4"
        >
          <div className="flex items-center gap-4">
            <Link
              href={`/projects/${id}`}
              className="p-2 rounded-lg bg-[#161922] border border-[#1e2330] hover:border-indigo-500/50 text-[#94a3b8] hover:text-white transition-all"
            >
              <ArrowLeft className="w-4 h-4" />
            </Link>
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-indigo-400" /> Live Report Preview
              </h1>
              <p className="text-[#94a3b8] text-sm">{p.application_name}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={refresh}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#161922] border border-[#1e2330] text-[#94a3b8] hover:text-white hover:border-indigo-500/50 transition-all text-sm"
            >
              <RefreshCw className="w-4 h-4" /> Refresh
            </button>
            <a
              href={`${getApiBase()}/projects/${id}/report?format=html`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 text-white text-sm"
            >
              <ExternalLink className="w-4 h-4" /> Open Full HTML
            </a>
            <button
              onClick={async () => {
                try {
                  await api.downloadReport(id, "pdf", `AppSecD_Report_${p.application_name?.replace(/\s/g, "_")}.pdf`);
                  toast.success("Downloading PDF...");
                } catch (e: any) {
                  toast.error(e.message);
                }
              }}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#161922] border border-[#1e2330] text-[#94a3b8] hover:text-white hover:border-indigo-500/50 transition-all text-sm"
            >
              <Download className="w-4 h-4" /> Download PDF
            </button>
          </div>
        </motion.div>

        {/* Table of Contents */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="card p-4 border-blue-900/30"
        >
          <h2 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider mb-3">Table of Contents</h2>
          <div className="flex flex-wrap gap-2">
            {["Executive Summary", "Charts & Analytics", "Severity Distribution", "OWASP Mapping", "Findings", "Details"].map((s, i) => (
              <a key={s} href={`#${s.toLowerCase().replace(/\s/g, "-")}`} className="text-xs px-3 py-1.5 rounded bg-[#161922] border border-[#1e2330] text-[#94a3b8] hover:text-indigo-400 hover:border-indigo-500/50 transition-all">
                {s}
              </a>
            ))}
          </div>
        </motion.div>

        {/* Executive Summary */}
        <motion.section
          id="executive-summary"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="card p-6 border-blue-900/30"
        >
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">1</span>
            Executive Summary
          </h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <p className="text-[#D1D5DB] text-sm leading-relaxed">
                This report presents the findings of a security assessment conducted on <strong className="text-white">{p.application_name}</strong>.
                The assessment evaluated the application against industry-standard security controls including OWASP Top 10, CWE Top 25, and related frameworks.
              </p>
              <div className="mt-4 flex items-center gap-4">
                <div>
                  <div className="text-xs text-[#94a3b8]">Risk Rating</div>
                  <div className={`text-2xl font-bold ${
                    riskLevel === "Critical" ? "text-red-400" :
                    riskLevel === "High" ? "text-orange-400" :
                    riskLevel === "Medium" ? "text-yellow-400" : "text-green-400"
                  }`}>
                    {riskLevel} ({risk}/100)
                  </div>
                </div>
                <div>
                  <div className="text-xs text-[#94a3b8]">Coverage</div>
                  <div className="text-2xl font-bold text-indigo-400">{cov}%</div>
                </div>
                <div>
                  <div className="text-xs text-[#94a3b8]">Findings</div>
                  <div className="text-2xl font-bold text-white">{findings.length}</div>
                </div>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-[#94a3b8]">Passed</span>
                <span className="text-green-400 font-medium">{p.passed_count || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-[#94a3b8]">Failed</span>
                <span className="text-red-400 font-medium">{p.failed_count || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-[#94a3b8]">N/A</span>
                <span className="text-[#94a3b8] font-medium">{p.na_count || 0}</span>
              </div>
              <div className="h-2 bg-[#161922] rounded-full overflow-hidden mt-2">
                <div className="h-full bg-indigo-500 rounded-full" style={{ width: `${cov}%` }} />
              </div>
            </div>
          </div>
        </motion.section>

        {/* Charts */}
        <motion.section
          id="charts-analytics"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card p-6 border-blue-900/30"
        >
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">2</span>
            Charts & Analytics
          </h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-[#0e1018] rounded-xl p-4 border border-[#1e2330]">
              <h3 className="text-sm font-semibold text-[#94a3b8] mb-4">Severity Distribution</h3>
              {severityChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={severityChartData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2} dataKey="value">
                      {severityChartData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(v) => [v ?? 0, "Count"]} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[220px] flex items-center justify-center text-[#64748b] text-sm">No data</div>
              )}
            </div>
            <div className="bg-[#0e1018] rounded-xl p-4 border border-[#1e2330]">
              <h3 className="text-sm font-semibold text-[#94a3b8] mb-4">OWASP Top 10 Mapping</h3>
              {owaspChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={owaspChartData} layout="vertical" margin={{ top: 0, right: 20, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis type="number" stroke="#9CA3AF" fontSize={11} />
                    <YAxis type="category" dataKey="name" width={100} stroke="#9CA3AF" fontSize={10} />
                    <Tooltip contentStyle={{ backgroundColor: "#1a2332", border: "1px solid #374151" }} />
                    <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[220px] flex items-center justify-center text-[#64748b] text-sm">No data</div>
              )}
            </div>
          </div>
        </motion.section>

        {/* Findings Table */}
        <motion.section
          id="findings"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="card p-6 border-blue-900/30 overflow-hidden"
        >
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">3</span>
            Detailed Findings
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2330] text-left text-[#94a3b8]">
                  <th className="p-3">#</th>
                  <th className="p-3">Title</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">OWASP</th>
                  <th className="p-3">CWE</th>
                  <th className="p-3">URL</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any, i: number) => (
                  <tr key={i} className="border-b border-[#1e2330]/50 hover:bg-[#161922]/30 transition-colors">
                    <td className="p-3 text-[#94a3b8]">{i + 1}</td>
                    <td className="p-3 font-medium text-white">{f.title}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        f.severity === "critical" ? "bg-red-900/40 text-red-300" :
                        f.severity === "high" ? "bg-orange-900/40 text-orange-300" :
                        f.severity === "medium" ? "bg-yellow-900/40 text-yellow-300" :
                        f.severity === "low" ? "bg-green-900/40 text-green-300" : "bg-blue-900/40 text-blue-300"
                      }`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="p-3 text-[#94a3b8]">{f.owasp_category || "-"}</td>
                    <td className="p-3 text-[#94a3b8]">{f.cwe_id || "-"}</td>
                    <td className="p-3 text-[#94a3b8] truncate max-w-[200px]">{f.affected_url || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {findings.length === 0 && (
            <div className="py-12 text-center text-[#64748b]">No findings yet</div>
          )}
        </motion.section>

        {/* Finding Details */}
        <motion.section
          id="details"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-4"
        >
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <span className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm">4</span>
            Finding Details with Evidence
          </h2>
          <AnimatePresence>
            {findings.map((f: any, i: number) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.05 * i }}
                className="card p-5 border-[#1e2330] hover:border-blue-900/50 transition-colors"
              >
                <h3 className="font-semibold text-white mb-2">
                  #{i + 1} {f.title} <span className={`text-xs px-2 py-0.5 rounded ml-2 ${
                    f.severity === "critical" ? "bg-red-900/40 text-red-300" :
                    f.severity === "high" ? "bg-orange-900/40 text-orange-300" :
                    f.severity === "medium" ? "bg-yellow-900/40 text-yellow-300" :
                    f.severity === "low" ? "bg-green-900/40 text-green-300" : "bg-blue-900/40 text-blue-300"
                  }`}>{f.severity}</span>
                </h3>
                <p className="text-sm text-[#94a3b8] mb-2">{f.description || "-"}</p>
                <p className="text-xs text-[#64748b]">URL: {f.affected_url || "-"}</p>
                <p className="text-xs text-[#64748b] mt-1">Recommendation: {f.recommendation || "-"}</p>
                {f.evidence?.length > 0 && (
                  <div className="mt-3 flex gap-2 flex-wrap">
                    {f.evidence.map((e: any, j: number) => (
                      <a
                        key={j}
                        href={`${getApiBase()}${e.url}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs px-2 py-1 rounded bg-[#161922] border border-[#1e2330] text-indigo-400 hover:border-indigo-500/50"
                      >
                        {e.filename || "Evidence"}
                      </a>
                    ))}
                  </div>
                )}
              </motion.div>
            ))}
          </AnimatePresence>
        </motion.section>

        <p className="text-[#64748b] text-xs text-center py-8">
          Report generated at {data?.generated_at ? new Date(data.generated_at).toLocaleString() : "—"} · Live preview updates on refresh
        </p>
      </div>
    </div>
  );
}
