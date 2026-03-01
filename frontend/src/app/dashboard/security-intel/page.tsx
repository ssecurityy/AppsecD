"use client";
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useRouter } from "next/navigation";
import { useAuthStore, isAdmin } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import toast from "react-hot-toast";
import {
  Shield, AlertTriangle, Activity, Cpu, ChevronDown, ChevronUp,
  ExternalLink, Search, Loader2, Zap, Target, BarChart3, RefreshCw,
} from "lucide-react";
import Link from "next/link";

const SEVERITY_COLORS: Record<string, { text: string; bg: string; border: string }> = {
  CRITICAL: { text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
  HIGH: { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  MEDIUM: { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
  LOW: { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
  critical: { text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
  high: { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  medium: { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
  low: { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
  info: { text: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/20" },
};

function getSeverityStyle(severity: string) {
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS["MEDIUM"];
}

export default function SecurityIntelPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();

  // CVE Feed state
  const [cves, setCves] = useState<any[]>([]);
  const [cvesLoading, setCvesLoading] = useState(true);
  const [expandedCve, setExpandedCve] = useState<string | null>(null);

  // Dashboard stats
  const [dashStats, setDashStats] = useState<any>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  // AI Test Case Generator
  const [genForm, setGenForm] = useState({ context: "", tech_stack: "", app_type: "" });
  const [generating, setGenerating] = useState(false);
  const [generatedTests, setGeneratedTests] = useState<any[]>([]);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user === null && !cvesLoading) router.replace("/login");
  }, [user, router, cvesLoading]);

  useEffect(() => {
    // Load CVE feed
    api.cveFeed()
      .then((res) => setCves(res.cves || res.items || res || []))
      .catch(() => setCves([]))
      .finally(() => setCvesLoading(false));

    // Load dashboard stats
    api.securityDashboard()
      .then(setDashStats)
      .catch(() => setDashStats(null))
      .finally(() => setStatsLoading(false));
  }, []);

  const handleGenerate = async () => {
    if (!genForm.context.trim()) {
      toast.error("Please provide context for test case generation");
      return;
    }
    setGenerating(true);
    try {
      const res = await api.generateTestCases({
        context: genForm.context,
        tech_stack: genForm.tech_stack || undefined,
        app_type: genForm.app_type || undefined,
      });
      const tests = res.test_cases || res.tests || res.items || [];
      setGeneratedTests(tests);
      toast.success(`Generated ${tests.length} test cases`);
    } catch (err: any) {
      toast.error(err.message || "Test case generation failed");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-7xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between"
        >
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2.5" style={{ color: "var(--text-primary)" }}>
              <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/20">
                <Shield className="w-5 h-5 text-indigo-400" />
              </div>
              Security Intelligence
            </h1>
            <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
              CVE monitoring, AI-powered test generation, and aggregate security insights
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard" className="btn-secondary text-xs flex items-center gap-1.5">
              <BarChart3 className="w-3 h-3" /> Main Dashboard
            </Link>
          </div>
        </motion.div>

        {/* Aggregate Stats */}
        {dashStats && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3"
          >
            {[
              { label: "Total Findings", value: dashStats.total_findings ?? "N/A", color: "text-red-400", bg: "from-red-500/10 to-red-500/5" },
              { label: "Critical", value: dashStats.by_severity?.critical ?? dashStats.critical ?? 0, color: "text-red-500", bg: "from-red-600/10 to-red-600/5" },
              { label: "High", value: dashStats.by_severity?.high ?? dashStats.high ?? 0, color: "text-orange-400", bg: "from-orange-500/10 to-orange-500/5" },
              { label: "Medium", value: dashStats.by_severity?.medium ?? dashStats.medium ?? 0, color: "text-yellow-400", bg: "from-yellow-500/10 to-yellow-500/5" },
              { label: "Low", value: dashStats.by_severity?.low ?? dashStats.low ?? 0, color: "text-emerald-400", bg: "from-emerald-500/10 to-emerald-500/5" },
              { label: "Projects", value: dashStats.total_projects ?? dashStats.projects ?? "N/A", color: "text-indigo-400", bg: "from-indigo-500/10 to-indigo-500/5" },
            ].map((s, i) => (
              <motion.div
                key={s.label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className={`bg-gradient-to-br ${s.bg} rounded-xl p-4 border text-center`}
                style={{ borderColor: "var(--border-subtle)" }}
              >
                <div className={`text-2xl font-bold tabular-nums ${s.color}`}>{s.value}</div>
                <div className="text-[10px] uppercase tracking-wider mt-0.5" style={{ color: "var(--text-muted)" }}>{s.label}</div>
              </motion.div>
            ))}
          </motion.div>
        )}

        {statsLoading && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {[1, 2, 3, 4, 5, 6].map(i => (
              <div key={i} className="h-20 rounded-xl animate-shimmer" style={{ background: "var(--bg-elevated)" }} />
            ))}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* CVE Feed */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
            className="card p-5"
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                Latest CVE Feed
              </h2>
              <button
                onClick={() => {
                  setCvesLoading(true);
                  api.cveFeed()
                    .then((res) => setCves(res.cves || res.items || res || []))
                    .catch(() => {})
                    .finally(() => setCvesLoading(false));
                }}
                className="text-xs flex items-center gap-1 text-indigo-400 hover:text-indigo-300"
              >
                <RefreshCw className={`w-3 h-3 ${cvesLoading ? "animate-spin" : ""}`} /> Refresh
              </button>
            </div>

            {cvesLoading ? (
              <div className="space-y-3">
                {[1, 2, 3, 4].map(i => (
                  <div key={i} className="h-16 rounded-lg animate-shimmer" style={{ background: "var(--bg-elevated)" }} />
                ))}
              </div>
            ) : cves.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="w-8 h-8 mx-auto mb-2" style={{ color: "var(--text-muted)" }} />
                <p className="text-sm" style={{ color: "var(--text-muted)" }}>No CVE data available. Backend endpoint may need configuration.</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {cves.slice(0, 20).map((cve: any, i: number) => {
                  const cveId = cve.cve_id || cve.id || `CVE-${i}`;
                  const severity = cve.severity || cve.baseSeverity || "MEDIUM";
                  const sc = getSeverityStyle(severity);
                  const isExpanded = expandedCve === cveId;
                  return (
                    <motion.div
                      key={cveId}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.03 }}
                      className="rounded-lg border overflow-hidden"
                      style={{ background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)" }}
                    >
                      <div
                        className="p-3 cursor-pointer flex items-start gap-3"
                        onClick={() => setExpandedCve(isExpanded ? null : cveId)}
                      >
                        <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase shrink-0 mt-0.5 ${sc.text} ${sc.bg} ${sc.border}`}>
                          {severity}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>{cveId}</div>
                          <p className="text-xs mt-0.5 line-clamp-2" style={{ color: "var(--text-secondary)" }}>
                            {cve.description || cve.summary || "No description available"}
                          </p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {cve.published_date || cve.published ? (
                            <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                              {new Date(cve.published_date || cve.published).toLocaleDateString()}
                            </span>
                          ) : null}
                          {isExpanded ? <ChevronUp className="w-3 h-3" style={{ color: "var(--text-muted)" }} /> : <ChevronDown className="w-3 h-3" style={{ color: "var(--text-muted)" }} />}
                        </div>
                      </div>
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="px-3 pb-3 space-y-2" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                              <p className="text-xs pt-2" style={{ color: "var(--text-secondary)" }}>
                                {cve.description || cve.summary || "No detailed description available."}
                              </p>
                              <div className="flex items-center gap-3 text-xs" style={{ color: "var(--text-muted)" }}>
                                {cve.cvss_score && <span>CVSS: <span className="font-bold" style={{ color: "var(--text-primary)" }}>{cve.cvss_score}</span></span>}
                                {cve.attack_vector && <span>Vector: {cve.attack_vector}</span>}
                                {(cve.references?.length > 0 || cve.url || cve.link) && (
                                  <a
                                    href={cve.url || cve.link || cve.references?.[0]}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                                  >
                                    <ExternalLink className="w-3 h-3" /> Details
                                  </a>
                                )}
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </motion.div>

          {/* AI Test Case Generator */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="card p-5"
          >
            <h2 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
              <Cpu className="w-4 h-4 text-purple-400" />
              AI Test Case Generator
            </h2>

            <div className="space-y-3 mb-4">
              <div>
                <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Context / Description</label>
                <textarea
                  className="input-field text-sm h-20 resize-none w-full"
                  placeholder="Describe the application, feature, or vulnerability category to generate test cases for..."
                  value={genForm.context}
                  onChange={(e) => setGenForm({ ...genForm, context: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Tech Stack</label>
                  <input
                    className="input-field text-sm py-2 w-full"
                    placeholder="e.g., React, Node.js, PostgreSQL"
                    value={genForm.tech_stack}
                    onChange={(e) => setGenForm({ ...genForm, tech_stack: e.target.value })}
                  />
                </div>
                <div>
                  <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>App Type</label>
                  <input
                    className="input-field text-sm py-2 w-full"
                    placeholder="e.g., Web App, API, Mobile"
                    value={genForm.app_type}
                    onChange={(e) => setGenForm({ ...genForm, app_type: e.target.value })}
                  />
                </div>
              </div>
              <button
                onClick={handleGenerate}
                disabled={generating || !genForm.context.trim()}
                className="btn-primary text-sm flex items-center gap-2 w-full justify-center disabled:opacity-50"
              >
                {generating ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Zap className="w-4 h-4" />
                )}
                {generating ? "Generating test cases..." : "Generate Test Cases"}
              </button>
            </div>

            {/* Generated Results */}
            {generatedTests.length > 0 && (
              <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                    Generated {generatedTests.length} test cases
                  </span>
                  <button
                    onClick={() => setGeneratedTests([])}
                    className="text-xs text-red-400 hover:text-red-300"
                  >
                    Clear
                  </button>
                </div>
                {generatedTests.map((tc: any, i: number) => {
                  const title = typeof tc === "string" ? tc : tc.title || tc.name || `Test Case ${i + 1}`;
                  const description = typeof tc === "string" ? "" : tc.description || tc.how_to_test || "";
                  const severity = typeof tc === "string" ? "" : tc.severity || "";
                  const category = typeof tc === "string" ? "" : tc.category || tc.phase || "";
                  return (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.04 }}
                      className="rounded-lg p-3 border"
                      style={{ background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)" }}
                    >
                      <div className="flex items-start gap-2">
                        <Target className="w-3.5 h-3.5 text-purple-400 mt-0.5 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>{title}</span>
                            {severity && (
                              <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-medium ${getSeverityStyle(severity).text} ${getSeverityStyle(severity).bg} ${getSeverityStyle(severity).border}`}>
                                {severity}
                              </span>
                            )}
                            {category && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                {category}
                              </span>
                            )}
                          </div>
                          {description && (
                            <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>{description}</p>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            )}

            {generatedTests.length === 0 && !generating && (
              <div className="text-center py-6 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                <Cpu className="w-8 h-8 mx-auto mb-2" style={{ color: "var(--border-subtle)" }} />
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Describe your application context above and let AI generate relevant security test cases.
                </p>
              </div>
            )}
          </motion.div>
        </div>
      </div>
    </div>
  );
}
