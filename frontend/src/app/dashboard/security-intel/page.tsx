"use client";
import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useRouter } from "next/navigation";
import { useAuthStore, isAdmin } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import toast from "react-hot-toast";
import {
  Shield, AlertTriangle, Activity, Cpu, ChevronDown, ChevronUp,
  ExternalLink, Search, Loader2, Zap, Target, BarChart3, RefreshCw,
  MessageSquare, Send, Save, ChevronLeft, ChevronRight, Database,
  Lock, X, Plus, FolderPlus,
} from "lucide-react";
import Link from "next/link";

const SEVERITY_COLORS: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
  high: { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  medium: { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
  low: { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
  info: { text: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/20" },
};

function getSeverityStyle(severity: string) {
  return SEVERITY_COLORS[severity?.toLowerCase()] || SEVERITY_COLORS["medium"];
}

export default function SecurityIntelPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();

  // Tab state
  const [activeTab, setActiveTab] = useState<"cves" | "generator" | "assistant">("cves");

  // CVE Feed state
  const [cves, setCves] = useState<any[]>([]);
  const [cvesLoading, setCvesLoading] = useState(true);
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [cvePage, setCvePage] = useState(1);
  const [cveTotal, setCveTotal] = useState(0);
  const [cvePageSize] = useState(20);
  const [cveKeyword, setCveKeyword] = useState("");
  const [cveSeverityFilter, setCveSeverityFilter] = useState("");
  const [cveSource, setCveSource] = useState("");
  const [needsSync, setNeedsSync] = useState(false);
  const [syncing, setSyncing] = useState(false);

  // Dashboard stats
  const [dashStats, setDashStats] = useState<any>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  // AI Test Case Generator
  const [genForm, setGenForm] = useState({ context: "", tech_stack: "", app_type: "", focus_areas: "" });
  const [generating, setGenerating] = useState(false);
  const [generatedTests, setGeneratedTests] = useState<any[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProject, setSelectedProject] = useState("");
  const [saving, setSaving] = useState(false);
  const [selectedTests, setSelectedTests] = useState<Set<number>>(new Set());

  // Security Assistant
  const [assistantQuestion, setAssistantQuestion] = useState("");
  const [assistantHistory, setAssistantHistory] = useState<{ role: string; content: string }[]>([]);
  const [assistantLoading, setAssistantLoading] = useState(false);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user === null && !cvesLoading) router.replace("/login");
  }, [user, router, cvesLoading]);

  const loadCves = useCallback(async (page = 1, keyword = "", severity = "") => {
    setCvesLoading(true);
    try {
      const res = await api.cveFeed({ page, page_size: cvePageSize, keyword, severity });
      setCves(res.cves || []);
      setCveTotal(res.total || 0);
      setCveSource(res.source || "");
      setNeedsSync(res.needs_sync || false);
    } catch {
      setCves([]);
    } finally {
      setCvesLoading(false);
    }
  }, [cvePageSize]);

  useEffect(() => {
    loadCves(1, "", "");
    api.securityDashboard()
      .then(setDashStats)
      .catch(() => setDashStats(null))
      .finally(() => setStatsLoading(false));
    api.listProjects().then((res: any) => {
      const items = res.items || res.projects || res || [];
      setProjects(Array.isArray(items) ? items : []);
    }).catch(() => {});
  }, [loadCves]);

  const handleCveSearch = () => {
    setCvePage(1);
    loadCves(1, cveKeyword, cveSeverityFilter);
  };

  const handleCvePageChange = (newPage: number) => {
    setCvePage(newPage);
    loadCves(newPage, cveKeyword, cveSeverityFilter);
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const res = await api.cveSync({ days: 120 });
      toast.success(res.message || `Synced ${res.synced} CVEs`);
      loadCves(1, cveKeyword, cveSeverityFilter);
    } catch (err: any) {
      toast.error(err.message || "CVE sync failed");
    } finally {
      setSyncing(false);
    }
  };

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
        focus_areas: genForm.focus_areas ? genForm.focus_areas.split(",").map(s => s.trim()).filter(Boolean) : undefined,
        project_id: selectedProject || undefined,
      });
      const tests = res.test_cases || [];
      setGeneratedTests(tests);
      setSelectedTests(new Set(tests.map((_: any, i: number) => i)));
      toast.success(`Generated ${tests.length} test cases`);
    } catch (err: any) {
      toast.error(err.message || "Test case generation failed");
    } finally {
      setGenerating(false);
    }
  };

  const handleSaveToProject = async () => {
    if (!selectedProject) {
      toast.error("Please select a project");
      return;
    }
    const selected = generatedTests.filter((_, i) => selectedTests.has(i));
    if (selected.length === 0) {
      toast.error("Please select at least one test case");
      return;
    }
    setSaving(true);
    try {
      const res = await api.saveTestCases({ project_id: selectedProject, test_cases: selected });
      toast.success(res.message || `Saved ${res.saved} test cases`);
      if (res.skipped > 0) {
        toast(`${res.skipped} duplicates were skipped`, { icon: "ℹ️" });
      }
    } catch (err: any) {
      toast.error(err.message || "Failed to save test cases");
    } finally {
      setSaving(false);
    }
  };

  const handleAssistantAsk = async () => {
    if (!assistantQuestion.trim()) return;
    const q = assistantQuestion.trim();
    setAssistantQuestion("");
    setAssistantHistory(prev => [...prev, { role: "user", content: q }]);
    setAssistantLoading(true);
    try {
      const res = await api.securityAssistant({
        question: q,
        project_id: selectedProject || undefined,
      });
      setAssistantHistory(prev => [...prev, { role: "assistant", content: res.answer }]);
    } catch (err: any) {
      setAssistantHistory(prev => [...prev, { role: "assistant", content: `Error: ${err.message}` }]);
    } finally {
      setAssistantLoading(false);
    }
  };

  const toggleTest = (i: number) => {
    setSelectedTests(prev => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      return next;
    });
  };

  const totalCvePages = Math.ceil(cveTotal / cvePageSize);

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-7xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2.5" style={{ color: "var(--text-primary)" }}>
              <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/20">
                <Shield className="w-5 h-5 text-indigo-400" />
              </div>
              Security Intelligence
            </h1>
            <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
              CVE monitoring, AI-powered test generation, and security assistant
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard" className="btn-secondary text-xs flex items-center gap-1.5">
              <BarChart3 className="w-3 h-3" /> Dashboard
            </Link>
          </div>
        </motion.div>

        {/* Stats */}
        {dashStats && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
            className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { label: "Total Findings", value: dashStats.total_findings ?? 0, color: "text-red-400", bg: "from-red-500/10 to-red-500/5" },
              { label: "Critical", value: dashStats.findings_by_severity?.critical ?? 0, color: "text-red-500", bg: "from-red-600/10 to-red-600/5" },
              { label: "High", value: dashStats.findings_by_severity?.high ?? 0, color: "text-orange-400", bg: "from-orange-500/10 to-orange-500/5" },
              { label: "Medium", value: dashStats.findings_by_severity?.medium ?? 0, color: "text-yellow-400", bg: "from-yellow-500/10 to-yellow-500/5" },
              { label: "Low", value: dashStats.findings_by_severity?.low ?? 0, color: "text-emerald-400", bg: "from-emerald-500/10 to-emerald-500/5" },
              { label: "Projects", value: dashStats.total_projects ?? 0, color: "text-indigo-400", bg: "from-indigo-500/10 to-indigo-500/5" },
              { label: "CVEs in DB", value: dashStats.cve_count ?? 0, color: "text-purple-400", bg: "from-purple-500/10 to-purple-500/5" },
            ].map((s, i) => (
              <motion.div key={s.label} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                className={`bg-gradient-to-br ${s.bg} rounded-xl p-3 border text-center`}
                style={{ borderColor: "var(--border-subtle)" }}>
                <div className={`text-xl font-bold tabular-nums ${s.color}`}>{s.value}</div>
                <div className="text-[10px] uppercase tracking-wider mt-0.5 truncate" style={{ color: "var(--text-muted)" }}>{s.label}</div>
              </motion.div>
            ))}
          </motion.div>
        )}

        {statsLoading && (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {[1, 2, 3, 4, 5, 6, 7].map(i => (
              <div key={i} className="h-16 rounded-xl animate-shimmer" style={{ background: "var(--bg-elevated)" }} />
            ))}
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 p-1 rounded-xl" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
          {[
            { key: "cves", label: "CVE Feed", icon: AlertTriangle },
            { key: "generator", label: "AI Test Generator", icon: Cpu },
            { key: "assistant", label: "Security Assistant", icon: MessageSquare },
          ].map(tab => (
            <button key={tab.key}
              onClick={() => setActiveTab(tab.key as any)}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === tab.key ? "text-white shadow-sm" : ""
              }`}
              style={activeTab === tab.key
                ? { background: "var(--accent-indigo)", color: "white" }
                : { color: "var(--text-secondary)" }
              }>
              <tab.icon className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          ))}
        </div>

        {/* CVE Feed Tab */}
        {activeTab === "cves" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
            {/* Search & Controls */}
            <div className="card p-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex-1 min-w-[200px] flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                    <input className="input-field text-sm py-2 pl-9 w-full"
                      placeholder="Search CVE ID or description..."
                      value={cveKeyword}
                      onChange={e => setCveKeyword(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && handleCveSearch()} />
                  </div>
                  <select className="input-field text-sm py-2 w-32"
                    value={cveSeverityFilter}
                    onChange={e => { setCveSeverityFilter(e.target.value); setCvePage(1); loadCves(1, cveKeyword, e.target.value); }}>
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <button onClick={handleCveSearch} className="btn-primary text-xs px-3">
                    <Search className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  {cveSource === "database" && (
                    <span className="text-[10px] px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                      <Database className="w-3 h-3" /> DB: {cveTotal.toLocaleString()} CVEs
                    </span>
                  )}
                  {(needsSync || (user && isAdmin(user.role))) && (
                    <button onClick={handleSync} disabled={syncing}
                      className="btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50">
                      <RefreshCw className={`w-3 h-3 ${syncing ? "animate-spin" : ""}`} />
                      {syncing ? "Syncing..." : "Sync CVEs"}
                    </button>
                  )}
                </div>
              </div>
              {needsSync && (
                <div className="mt-3 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-xs text-yellow-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>No CVEs in database yet. Click &quot;Sync CVEs&quot; to fetch and store the latest CVEs from NVD.</span>
                </div>
              )}
            </div>

            {/* CVE List */}
            <div className="card p-4">
              {cvesLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3, 4, 5].map(i => (
                    <div key={i} className="h-16 rounded-lg animate-shimmer" style={{ background: "var(--bg-elevated)" }} />
                  ))}
                </div>
              ) : cves.length === 0 ? (
                <div className="text-center py-12">
                  <Shield className="w-10 h-10 mx-auto mb-3" style={{ color: "var(--text-muted)" }} />
                  <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                    {cveKeyword ? "No CVEs match your search" : "No CVEs available. Sync from NVD to populate."}
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {cves.map((cve: any, i: number) => {
                    const cveId = cve.cve_id || cve.id || `CVE-${i}`;
                    const severity = cve.severity || "medium";
                    const sc = getSeverityStyle(severity);
                    const isExpanded = expandedCve === cveId;
                    return (
                      <motion.div key={cveId}
                        initial={{ opacity: 0, x: -6 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.02 }}
                        className="rounded-lg border overflow-hidden"
                        style={{ background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)" }}>
                        <div className="p-3 cursor-pointer flex items-start gap-3"
                          onClick={() => setExpandedCve(isExpanded ? null : cveId)}>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase shrink-0 mt-0.5 ${sc.text} ${sc.bg} ${sc.border}`}>
                            {severity}
                          </span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>{cveId}</span>
                              {cve.cvss_score && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-medium">
                                  CVSS {cve.cvss_score}
                                </span>
                              )}
                            </div>
                            <p className="text-xs mt-0.5 line-clamp-2" style={{ color: "var(--text-secondary)" }}>
                              {cve.description || "No description available"}
                            </p>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            {cve.published && (
                              <span className="text-[10px] whitespace-nowrap" style={{ color: "var(--text-muted)" }}>
                                {new Date(cve.published).toLocaleDateString()}
                              </span>
                            )}
                            {isExpanded ? <ChevronUp className="w-3 h-3" style={{ color: "var(--text-muted)" }} /> : <ChevronDown className="w-3 h-3" style={{ color: "var(--text-muted)" }} />}
                          </div>
                        </div>
                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                              <div className="px-3 pb-3 space-y-2" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                                <p className="text-xs pt-2 whitespace-pre-wrap break-words" style={{ color: "var(--text-secondary)" }}>
                                  {cve.description || "No detailed description."}
                                </p>
                                <div className="flex flex-wrap items-center gap-3 text-xs" style={{ color: "var(--text-muted)" }}>
                                  {cve.cwes?.length > 0 && (
                                    <span>CWE: <span style={{ color: "var(--text-primary)" }}>{cve.cwes.join(", ")}</span></span>
                                  )}
                                  {cve.references?.length > 0 && (
                                    <a href={cve.references[0]?.url} target="_blank" rel="noopener noreferrer"
                                      className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1">
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

              {/* Pagination */}
              {totalCvePages > 1 && (
                <div className="flex items-center justify-between mt-4 pt-4" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                    Page {cvePage} of {totalCvePages} ({cveTotal.toLocaleString()} CVEs)
                  </span>
                  <div className="flex items-center gap-1">
                    <button onClick={() => handleCvePageChange(cvePage - 1)} disabled={cvePage <= 1}
                      className="btn-ghost text-xs p-1.5 disabled:opacity-30">
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    {[...Array(Math.min(5, totalCvePages))].map((_, i) => {
                      let pageNum: number;
                      if (totalCvePages <= 5) {
                        pageNum = i + 1;
                      } else if (cvePage <= 3) {
                        pageNum = i + 1;
                      } else if (cvePage >= totalCvePages - 2) {
                        pageNum = totalCvePages - 4 + i;
                      } else {
                        pageNum = cvePage - 2 + i;
                      }
                      return (
                        <button key={pageNum} onClick={() => handleCvePageChange(pageNum)}
                          className={`text-xs px-2.5 py-1 rounded-lg transition-all ${
                            pageNum === cvePage ? "font-bold" : ""
                          }`}
                          style={pageNum === cvePage
                            ? { background: "var(--accent-indigo)", color: "white" }
                            : { color: "var(--text-secondary)" }
                          }>
                          {pageNum}
                        </button>
                      );
                    })}
                    <button onClick={() => handleCvePageChange(cvePage + 1)} disabled={cvePage >= totalCvePages}
                      className="btn-ghost text-xs p-1.5 disabled:opacity-30">
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* AI Test Case Generator Tab */}
        {activeTab === "generator" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
            <div className="card p-5">
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
                <Cpu className="w-4 h-4 text-purple-400" />
                AI Test Case Generator
              </h2>

              <div className="space-y-3 mb-4">
                <div>
                  <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Context / Description *</label>
                  <textarea className="input-field text-sm h-24 resize-none w-full"
                    placeholder="Describe the application, feature, or vulnerability category to generate test cases for..."
                    value={genForm.context}
                    onChange={e => setGenForm({ ...genForm, context: e.target.value })} />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Tech Stack</label>
                    <input className="input-field text-sm py-2 w-full"
                      placeholder="e.g., React, Node.js, PostgreSQL"
                      value={genForm.tech_stack}
                      onChange={e => setGenForm({ ...genForm, tech_stack: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>App Type</label>
                    <input className="input-field text-sm py-2 w-full"
                      placeholder="e.g., Web App, API, Mobile"
                      value={genForm.app_type}
                      onChange={e => setGenForm({ ...genForm, app_type: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Focus Areas</label>
                    <input className="input-field text-sm py-2 w-full"
                      placeholder="e.g., auth, file upload, IDOR"
                      value={genForm.focus_areas}
                      onChange={e => setGenForm({ ...genForm, focus_areas: e.target.value })} />
                  </div>
                </div>
                <div className="flex flex-wrap items-end gap-3">
                  <div className="flex-1 min-w-[200px]">
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Target Project (for saving)</label>
                    <select className="input-field text-sm py-2 w-full" value={selectedProject}
                      onChange={e => setSelectedProject(e.target.value)}>
                      <option value="">Select a project...</option>
                      {projects.map((p: any) => (
                        <option key={p.id} value={p.id}>{p.application_name || p.name}</option>
                      ))}
                    </select>
                  </div>
                  <button onClick={handleGenerate} disabled={generating || !genForm.context.trim()}
                    className="btn-primary text-sm flex items-center gap-2 px-6 disabled:opacity-50 whitespace-nowrap">
                    {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                    {generating ? "Generating..." : "Generate"}
                  </button>
                </div>
              </div>
            </div>

            {/* Generated Results */}
            {generatedTests.length > 0 && (
              <div className="card p-5 space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                    Generated {generatedTests.length} test cases ({selectedTests.size} selected)
                  </span>
                  <div className="flex items-center gap-2">
                    <button onClick={() => {
                      if (selectedTests.size === generatedTests.length) setSelectedTests(new Set());
                      else setSelectedTests(new Set(generatedTests.map((_, i) => i)));
                    }} className="text-xs text-indigo-400 hover:text-indigo-300">
                      {selectedTests.size === generatedTests.length ? "Deselect All" : "Select All"}
                    </button>
                    <button onClick={handleSaveToProject} disabled={saving || !selectedProject || selectedTests.size === 0}
                      className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50">
                      {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <FolderPlus className="w-3 h-3" />}
                      {saving ? "Saving..." : "Save to Project"}
                    </button>
                    <button onClick={() => setGeneratedTests([])} className="text-xs text-red-400 hover:text-red-300">
                      Clear
                    </button>
                  </div>
                </div>
                <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                  {generatedTests.map((tc: any, i: number) => {
                    const title = tc.title || `Test Case ${i + 1}`;
                    const severity = tc.severity || "";
                    const isSelected = selectedTests.has(i);
                    return (
                      <motion.div key={i} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: i * 0.03 }}
                        className={`rounded-lg p-3 border cursor-pointer transition-all ${isSelected ? "ring-1 ring-indigo-500/50" : ""}`}
                        style={{ background: "var(--bg-tertiary)", borderColor: isSelected ? "var(--accent-indigo)" : "var(--border-subtle)" }}
                        onClick={() => toggleTest(i)}>
                        <div className="flex items-start gap-2">
                          <input type="checkbox" checked={isSelected} onChange={() => toggleTest(i)}
                            className="mt-1 shrink-0 accent-indigo-500" onClick={e => e.stopPropagation()} />
                          <Target className="w-3.5 h-3.5 text-purple-400 mt-0.5 shrink-0" />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>{title}</span>
                              {severity && (
                                <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-medium ${getSeverityStyle(severity).text} ${getSeverityStyle(severity).bg} ${getSeverityStyle(severity).border}`}>
                                  {severity}
                                </span>
                              )}
                              {tc.owasp_category && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                  {tc.owasp_category}
                                </span>
                              )}
                              {tc.cwe_id && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>
                                  {tc.cwe_id}
                                </span>
                              )}
                            </div>
                            {tc.description && (
                              <p className="text-xs mt-1 line-clamp-2" style={{ color: "var(--text-secondary)" }}>{tc.description}</p>
                            )}
                            {tc.how_to_test && (
                              <p className="text-xs mt-1 line-clamp-2" style={{ color: "var(--text-muted)" }}>{tc.how_to_test}</p>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            )}

            {generatedTests.length === 0 && !generating && (
              <div className="card p-8 text-center">
                <Cpu className="w-10 h-10 mx-auto mb-3" style={{ color: "var(--border-subtle)" }} />
                <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                  Describe your application context above and let AI generate relevant security test cases.
                </p>
                <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
                  Generated tests can be saved directly to a project for execution.
                </p>
              </div>
            )}
          </motion.div>
        )}

        {/* Security Assistant Tab */}
        {activeTab === "assistant" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
            <div className="card p-5 flex flex-col" style={{ minHeight: "500px" }}>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                  <MessageSquare className="w-4 h-4 text-indigo-400" />
                  AI Security Assistant
                </h2>
                {assistantHistory.length > 0 && (
                  <button onClick={() => setAssistantHistory([])} className="text-xs text-red-400 hover:text-red-300">
                    Clear Chat
                  </button>
                )}
              </div>

              {/* Project context selector */}
              <div className="mb-4">
                <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-muted)" }}>Project Context (optional)</label>
                <select className="input-field text-sm py-2 w-full max-w-xs" value={selectedProject}
                  onChange={e => setSelectedProject(e.target.value)}>
                  <option value="">No project context</option>
                  {projects.map((p: any) => (
                    <option key={p.id} value={p.id}>{p.application_name || p.name}</option>
                  ))}
                </select>
              </div>

              {/* Chat history */}
              <div className="flex-1 space-y-3 overflow-y-auto mb-4 max-h-[400px]">
                {assistantHistory.length === 0 && (
                  <div className="text-center py-12">
                    <MessageSquare className="w-10 h-10 mx-auto mb-3" style={{ color: "var(--border-subtle)" }} />
                    <p className="text-sm font-medium" style={{ color: "var(--text-secondary)" }}>Ask me anything about security testing</p>
                    <div className="mt-4 flex flex-wrap justify-center gap-2">
                      {["How do I test for IDOR?", "Latest Spring Boot CVEs?", "SQLi testing checklist", "XSS bypass techniques"].map(q => (
                        <button key={q} onClick={() => { setAssistantQuestion(q); }}
                          className="text-xs px-3 py-1.5 rounded-lg transition-all hover:scale-[1.02]"
                          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>
                          {q}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                {assistantHistory.map((msg, i) => (
                  <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                    <div className={`max-w-[85%] rounded-xl px-4 py-3 text-sm ${
                      msg.role === "user" ? "" : ""
                    }`}
                      style={msg.role === "user"
                        ? { background: "var(--accent-indigo)", color: "white" }
                        : { background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }
                      }>
                      <div className="whitespace-pre-wrap break-words">{msg.content}</div>
                    </div>
                  </div>
                ))}
                {assistantLoading && (
                  <div className="flex justify-start">
                    <div className="rounded-xl px-4 py-3 flex items-center gap-2"
                      style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                      <Loader2 className="w-4 h-4 animate-spin text-indigo-400" />
                      <span className="text-xs" style={{ color: "var(--text-muted)" }}>Thinking...</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Input */}
              <div className="flex items-center gap-2">
                <input className="input-field text-sm py-2.5 flex-1"
                  placeholder="Ask a security question... (e.g., 'How to test for IDOR?')"
                  value={assistantQuestion}
                  onChange={e => setAssistantQuestion(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !e.shiftKey && handleAssistantAsk()} />
                <button onClick={handleAssistantAsk} disabled={assistantLoading || !assistantQuestion.trim()}
                  className="btn-primary px-4 py-2.5 disabled:opacity-50">
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
