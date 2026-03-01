"use client";
import { useEffect, useState, useCallback, useRef, useMemo } from "react";
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
  Lock, X, Plus, FolderPlus, Calendar, Filter, Globe, Clock,
  Trash2, PlusCircle, Hash, Info, CheckCircle, Copy, Tag,
} from "lucide-react";
import Link from "next/link";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, { text: string; bg: string; border: string; left: string }> = {
  critical: { text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20", left: "border-l-red-500" },
  high: { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20", left: "border-l-orange-500" },
  medium: { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20", left: "border-l-yellow-500" },
  low: { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20", left: "border-l-emerald-500" },
  info: { text: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/20", left: "border-l-sky-500" },
};

function getSeverityStyle(severity: string) {
  return SEVERITY_COLORS[severity?.toLowerCase()] || SEVERITY_COLORS["medium"];
}

const CVE_SOURCES = [
  { key: "nvd", label: "NVD", color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/20" },
  { key: "github", label: "GitHub", color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  { key: "circl", label: "CIRCL", color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
];

// ---------------------------------------------------------------------------
// Chat Session Types & localStorage helpers
// ---------------------------------------------------------------------------

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: number;
  suggestedTests?: any[];
  projectContext?: string;
}

interface ChatSession {
  id: string;
  title: string;
  messages: ChatMessage[];
  createdAt: number;
  updatedAt: number;
  projectId?: string;
}

const CHAT_STORAGE_KEY = "appsec_assistant_chats";

function loadChatSessions(): ChatSession[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(CHAT_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveChatSessions(sessions: ChatSession[]) {
  if (typeof window === "undefined") return;
  localStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(sessions));
}

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function createNewSession(): ChatSession {
  return {
    id: generateId(),
    title: "New Chat",
    messages: [],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// CVE Detail Modal
// ---------------------------------------------------------------------------

function CveDetailModal({
  cve,
  onClose,
  loading,
}: {
  cve: any;
  onClose: () => void;
  loading: boolean;
}) {
  if (!cve && !loading) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="relative w-full max-w-3xl max-h-[85vh] overflow-y-auto rounded-2xl border shadow-2xl"
        style={{ background: "var(--bg-secondary)", borderColor: "var(--border-subtle)" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 z-10 flex items-center justify-between p-5 border-b" style={{ background: "var(--bg-secondary)", borderColor: "var(--border-subtle)" }}>
          {loading ? (
            <div className="flex items-center gap-2">
              <Loader2 className="w-5 h-5 animate-spin text-indigo-400" />
              <span className="text-sm" style={{ color: "var(--text-muted)" }}>Loading CVE details...</span>
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <span className="text-base font-bold" style={{ color: "var(--text-primary)" }}>
                {cve?.cve_id || cve?.id}
              </span>
              {cve?.severity && (
                <span className={`text-xs px-2.5 py-1 rounded-full border font-bold uppercase ${getSeverityStyle(cve.severity).text} ${getSeverityStyle(cve.severity).bg} ${getSeverityStyle(cve.severity).border}`}>
                  {cve.severity}
                </span>
              )}
            </div>
          )}
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 transition-colors">
            <X className="w-5 h-5" style={{ color: "var(--text-muted)" }} />
          </button>
        </div>

        {loading ? (
          <div className="p-8 flex items-center justify-center">
            <Loader2 className="w-8 h-8 animate-spin text-indigo-400" />
          </div>
        ) : cve ? (
          <div className="p-5 space-y-5">
            {/* Description */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>Description</h3>
              <p className="text-sm leading-relaxed whitespace-pre-wrap" style={{ color: "var(--text-secondary)" }}>
                {cve.description || "No description available."}
              </p>
            </div>

            {/* CVSS Breakdown */}
            {(cve.cvss_score || cve.cvss_vector) && (
              <div className="rounded-xl p-4 border" style={{ background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)" }}>
                <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: "var(--text-muted)" }}>CVSS Breakdown</h3>
                <div className="flex flex-wrap items-center gap-4">
                  {cve.cvss_score != null && (
                    <div className="flex items-center gap-2">
                      <div className={`text-2xl font-bold tabular-nums ${
                        cve.cvss_score >= 9 ? "text-red-400" :
                        cve.cvss_score >= 7 ? "text-orange-400" :
                        cve.cvss_score >= 4 ? "text-yellow-400" : "text-emerald-400"
                      }`}>
                        {cve.cvss_score}
                      </div>
                      <span className="text-xs" style={{ color: "var(--text-muted)" }}>/ 10.0</span>
                    </div>
                  )}
                  {cve.cvss_vector && (
                    <code className="text-[11px] px-3 py-1.5 rounded-lg font-mono break-all" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>
                      {cve.cvss_vector}
                    </code>
                  )}
                </div>
                {/* Parse CVSS v3 vector for visual breakdown */}
                {cve.cvss_vector && cve.cvss_vector.includes("CVSS:3") && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3">
                    {(() => {
                      const parts = cve.cvss_vector.split("/").slice(1);
                      const labels: Record<string, string> = {
                        AV: "Attack Vector", AC: "Attack Complexity", PR: "Privileges Required",
                        UI: "User Interaction", S: "Scope", C: "Confidentiality", I: "Integrity", A: "Availability",
                      };
                      const valueLabels: Record<string, Record<string, string>> = {
                        AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
                        AC: { L: "Low", H: "High" },
                        PR: { N: "None", L: "Low", H: "High" },
                        UI: { N: "None", R: "Required" },
                        S: { U: "Unchanged", C: "Changed" },
                        C: { N: "None", L: "Low", H: "High" },
                        I: { N: "None", L: "Low", H: "High" },
                        A: { N: "None", L: "Low", H: "High" },
                      };
                      return parts.map((p: string) => {
                        const [k, v] = p.split(":");
                        return (
                          <div key={k} className="rounded-lg p-2 text-center" style={{ background: "var(--bg-elevated)" }}>
                            <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{labels[k] || k}</div>
                            <div className="text-xs font-semibold mt-0.5" style={{ color: "var(--text-primary)" }}>{valueLabels[k]?.[v] || v}</div>
                          </div>
                        );
                      });
                    })()}
                  </div>
                )}
              </div>
            )}

            {/* Affected Products */}
            {cve.affected_products && cve.affected_products.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>Affected Products</h3>
                <div className="flex flex-wrap gap-2">
                  {cve.affected_products.map((product: string, i: number) => (
                    <span key={i} className="text-xs px-2.5 py-1 rounded-lg border" style={{ background: "var(--bg-elevated)", borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}>
                      {product}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* CWE List */}
            {cve.cwes && cve.cwes.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>CWE Classifications</h3>
                <div className="flex flex-wrap gap-2">
                  {cve.cwes.map((cwe: string, i: number) => (
                    <a
                      key={i}
                      href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/\D/g, "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs px-2.5 py-1 rounded-lg border flex items-center gap-1.5 hover:bg-white/5 transition-colors"
                      style={{ background: "var(--bg-elevated)", borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                    >
                      <Hash className="w-3 h-3 text-indigo-400" />
                      {cwe}
                      <ExternalLink className="w-2.5 h-2.5" style={{ color: "var(--text-muted)" }} />
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Dates */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {cve.published && (
                <div className="rounded-lg p-3" style={{ background: "var(--bg-tertiary)" }}>
                  <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Published</div>
                  <div className="text-xs font-medium mt-0.5" style={{ color: "var(--text-primary)" }}>
                    {new Date(cve.published).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}
                  </div>
                </div>
              )}
              {cve.modified && (
                <div className="rounded-lg p-3" style={{ background: "var(--bg-tertiary)" }}>
                  <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Modified</div>
                  <div className="text-xs font-medium mt-0.5" style={{ color: "var(--text-primary)" }}>
                    {new Date(cve.modified).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}
                  </div>
                </div>
              )}
              {cve.source && (
                <div className="rounded-lg p-3" style={{ background: "var(--bg-tertiary)" }}>
                  <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Source</div>
                  <div className="text-xs font-medium mt-0.5" style={{ color: "var(--text-primary)" }}>{cve.source}</div>
                </div>
              )}
            </div>

            {/* References */}
            {cve.references && cve.references.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
                  References ({cve.references.length})
                </h3>
                <div className="space-y-1.5 max-h-60 overflow-y-auto">
                  {cve.references.map((ref: any, i: number) => {
                    const url = typeof ref === "string" ? ref : ref?.url;
                    const tags = typeof ref === "object" ? ref?.tags : undefined;
                    if (!url) return null;
                    return (
                      <a
                        key={i}
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-start gap-2 rounded-lg p-2.5 border hover:bg-white/5 transition-colors group"
                        style={{ background: "var(--bg-elevated)", borderColor: "var(--border-subtle)" }}
                      >
                        <ExternalLink className="w-3.5 h-3.5 text-indigo-400 mt-0.5 shrink-0 group-hover:text-indigo-300" />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs break-all text-indigo-400 group-hover:text-indigo-300">{url}</div>
                          {tags && tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {tags.map((tag: string, j: number) => (
                                <span key={j} className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-tertiary)", color: "var(--text-muted)" }}>
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </a>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        ) : null}
      </motion.div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sync Source Picker (multi-source button)
// ---------------------------------------------------------------------------

function SyncSourcePicker({
  syncing,
  syncProgress,
  onSync,
}: {
  syncing: boolean;
  syncProgress: string;
  onSync: (source?: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <div className="flex items-center">
        <button
          onClick={() => onSync()}
          disabled={syncing}
          className="btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50 rounded-r-none border-r-0"
        >
          <RefreshCw className={`w-3 h-3 ${syncing ? "animate-spin" : ""}`} />
          {syncing ? syncProgress || "Syncing..." : "Sync CVEs"}
        </button>
        <button
          onClick={() => setOpen(!open)}
          disabled={syncing}
          className="btn-secondary text-xs px-1.5 disabled:opacity-50 rounded-l-none"
        >
          <ChevronDown className="w-3 h-3" />
        </button>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            className="absolute right-0 top-full mt-1 z-20 rounded-xl border shadow-xl p-2 min-w-[180px]"
            style={{ background: "var(--bg-elevated)", borderColor: "var(--border-subtle)" }}
          >
            <div className="text-[10px] uppercase tracking-wider px-2 py-1 mb-1" style={{ color: "var(--text-muted)" }}>
              Sync from source
            </div>
            <button
              onClick={() => { setOpen(false); onSync(); }}
              className="w-full text-left text-xs px-3 py-2 rounded-lg hover:bg-white/5 flex items-center gap-2 transition-colors"
              style={{ color: "var(--text-secondary)" }}
            >
              <Globe className="w-3.5 h-3.5 text-indigo-400" />
              All Sources
            </button>
            {CVE_SOURCES.map((src) => (
              <button
                key={src.key}
                onClick={() => { setOpen(false); onSync(src.key); }}
                className="w-full text-left text-xs px-3 py-2 rounded-lg hover:bg-white/5 flex items-center gap-2 transition-colors"
                style={{ color: "var(--text-secondary)" }}
              >
                <span className={`w-2 h-2 rounded-full ${src.bg} border ${src.border}`} />
                {src.label}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function SecurityIntelPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();

  // Tab state
  const [activeTab, setActiveTab] = useState<"cves" | "generator" | "assistant">("cves");

  // ----- CVE Feed state -----
  const [cves, setCves] = useState<any[]>([]);
  const [cvesLoading, setCvesLoading] = useState(true);
  const [cvePage, setCvePage] = useState(1);
  const [cveTotal, setCveTotal] = useState(0);
  const [cvePageSize] = useState(20);
  const [cveKeyword, setCveKeyword] = useState("");
  const [cveSeverityFilter, setCveSeverityFilter] = useState("");
  const [cveSource, setCveSource] = useState("");
  const [needsSync, setNeedsSync] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncProgress, setSyncProgress] = useState("");

  // Advanced CVE filters
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [cveCweFilter, setCveCweFilter] = useState("");
  const [cveDateFrom, setCveDateFrom] = useState("");
  const [cveDateTo, setCveDateTo] = useState("");

  // CVE real-time search
  const [cveIdSearch, setCveIdSearch] = useState("");
  const [cveIdResults, setCveIdResults] = useState<any[]>([]);
  const [cveIdSearching, setCveIdSearching] = useState(false);
  const cveIdDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // CVE Detail modal
  const [cveDetailModal, setCveDetailModal] = useState<any>(null);
  const [cveDetailLoading, setCveDetailLoading] = useState(false);

  // Dashboard stats
  const [dashStats, setDashStats] = useState<any>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  // ----- AI Test Case Generator -----
  const [genForm, setGenForm] = useState({ context: "", tech_stack: "", app_type: "", focus_areas: "" });
  const [generating, setGenerating] = useState(false);
  const [generatedTests, setGeneratedTests] = useState<any[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProject, setSelectedProject] = useState("");
  const [saving, setSaving] = useState(false);
  const [selectedTests, setSelectedTests] = useState<Set<number>>(new Set());

  // ----- Security Assistant -----
  const [chatSessions, setChatSessions] = useState<ChatSession[]>([]);
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [assistantQuestion, setAssistantQuestion] = useState("");
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [showChatSidebar, setShowChatSidebar] = useState(true);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const chatContainerRef = useRef<HTMLDivElement>(null);

  // Computed active session
  const activeSession = useMemo(() => {
    return chatSessions.find((s) => s.id === activeChatId) || null;
  }, [chatSessions, activeChatId]);

  // Initialize
  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user === null && !cvesLoading) router.replace("/login");
  }, [user, router, cvesLoading]);

  // Load chat sessions from localStorage
  useEffect(() => {
    const sessions = loadChatSessions();
    setChatSessions(sessions);
    if (sessions.length > 0) {
      setActiveChatId(sessions[0].id);
    }
  }, []);

  // Auto-scroll to latest message
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [activeSession?.messages?.length, assistantLoading]);

  // ---------------------------------------------------------------------------
  // CVE Feed Logic
  // ---------------------------------------------------------------------------

  const loadCves = useCallback(async (
    page = 1,
    keyword = "",
    severity = "",
    cwe = "",
    dateFrom = "",
    dateTo = "",
  ) => {
    setCvesLoading(true);
    try {
      const res = await api.cveFeed({
        page,
        page_size: cvePageSize,
        keyword,
        severity,
        cwe: cwe || undefined,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
      });
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
    loadCves(1, cveKeyword, cveSeverityFilter, cveCweFilter, cveDateFrom, cveDateTo);
  };

  const handleCvePageChange = (newPage: number) => {
    setCvePage(newPage);
    loadCves(newPage, cveKeyword, cveSeverityFilter, cveCweFilter, cveDateFrom, cveDateTo);
  };

  const handleSync = async (source?: string) => {
    setSyncing(true);
    setSyncProgress(source ? `Syncing from ${source.toUpperCase()}...` : "Syncing all sources...");
    try {
      const res = await api.cveSync({ days: 120, source });
      toast.success(res.message || `Synced ${res.synced} CVEs`);
      loadCves(1, cveKeyword, cveSeverityFilter, cveCweFilter, cveDateFrom, cveDateTo);
    } catch (err: any) {
      toast.error(err.message || "CVE sync failed");
    } finally {
      setSyncing(false);
      setSyncProgress("");
    }
  };

  // Real-time CVE ID search
  const handleCveIdSearch = useCallback((value: string) => {
    setCveIdSearch(value);
    if (cveIdDebounceRef.current) clearTimeout(cveIdDebounceRef.current);
    if (!value.trim() || value.trim().length < 4) {
      setCveIdResults([]);
      setCveIdSearching(false);
      return;
    }
    setCveIdSearching(true);
    cveIdDebounceRef.current = setTimeout(async () => {
      try {
        const res = await api.cveSearch(value.trim());
        setCveIdResults(res.results || res.cves || (Array.isArray(res) ? res : []));
      } catch {
        setCveIdResults([]);
      } finally {
        setCveIdSearching(false);
      }
    }, 300);
  }, []);

  // Open CVE detail
  const openCveDetail = async (cveId: string) => {
    setCveDetailLoading(true);
    setCveDetailModal({});
    try {
      const res = await api.cveDetail(cveId);
      setCveDetailModal(res.cve || res);
    } catch {
      toast.error("Failed to load CVE details");
      setCveDetailModal(null);
    } finally {
      setCveDetailLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // AI Test Generator Logic
  // ---------------------------------------------------------------------------

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
        focus_areas: genForm.focus_areas ? genForm.focus_areas.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
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
      toast.success(
        res.message || `Saved ${res.saved} test cases to project`,
        { duration: 4000, icon: "✅" }
      );
      if (res.skipped > 0) {
        toast(`${res.skipped} duplicates were skipped`, { icon: "ℹ️" });
      }
    } catch (err: any) {
      toast.error(err.message || "Failed to save test cases");
    } finally {
      setSaving(false);
    }
  };

  const toggleTest = (i: number) => {
    setSelectedTests((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  // ---------------------------------------------------------------------------
  // Security Assistant Logic
  // ---------------------------------------------------------------------------

  const persistSessions = useCallback((sessions: ChatSession[]) => {
    setChatSessions(sessions);
    saveChatSessions(sessions);
  }, []);

  const handleNewChat = useCallback(() => {
    const session = createNewSession();
    const updated = [session, ...chatSessions];
    persistSessions(updated);
    setActiveChatId(session.id);
  }, [chatSessions, persistSessions]);

  const handleDeleteChat = useCallback((id: string) => {
    const updated = chatSessions.filter((s) => s.id !== id);
    persistSessions(updated);
    if (activeChatId === id) {
      setActiveChatId(updated.length > 0 ? updated[0].id : null);
    }
  }, [chatSessions, activeChatId, persistSessions]);

  const handleAssistantAsk = async () => {
    if (!assistantQuestion.trim() || assistantLoading) return;
    const q = assistantQuestion.trim();
    setAssistantQuestion("");

    let currentSessionId = activeChatId;
    let sessions = [...chatSessions];

    // Create new session if none active
    if (!currentSessionId) {
      const session = createNewSession();
      sessions = [session, ...sessions];
      currentSessionId = session.id;
      setActiveChatId(session.id);
    }

    // Add user message
    const userMsg: ChatMessage = { role: "user", content: q, timestamp: Date.now() };
    sessions = sessions.map((s) =>
      s.id === currentSessionId
        ? {
            ...s,
            messages: [...s.messages, userMsg],
            title: s.messages.length === 0 ? q.slice(0, 50) + (q.length > 50 ? "..." : "") : s.title,
            updatedAt: Date.now(),
            projectId: selectedProject || s.projectId,
          }
        : s
    );
    persistSessions(sessions);
    setAssistantLoading(true);

    try {
      const currentSession = sessions.find((s) => s.id === currentSessionId);
      const history = (currentSession?.messages || []).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const selectedProjectObj = projects.find((p) => p.id === selectedProject);
      const contextStr = selectedProjectObj
        ? `Project: ${selectedProjectObj.application_name || selectedProjectObj.name}`
        : undefined;

      const res = await api.securityAssistant({
        question: q,
        project_id: selectedProject || undefined,
        context: contextStr,
        chat_history: history,
      });

      const assistantMsg: ChatMessage = {
        role: "assistant",
        content: res.answer,
        timestamp: Date.now(),
        suggestedTests: res.suggested_tests || res.test_cases || undefined,
        projectContext: selectedProjectObj?.application_name || selectedProjectObj?.name,
      };

      const finalSessions = sessions.map((s) =>
        s.id === currentSessionId
          ? { ...s, messages: [...s.messages, assistantMsg], updatedAt: Date.now() }
          : s
      );
      persistSessions(finalSessions);
    } catch (err: any) {
      const errMsg: ChatMessage = {
        role: "assistant",
        content: `Error: ${err.message || "Something went wrong"}`,
        timestamp: Date.now(),
      };
      const finalSessions = sessions.map((s) =>
        s.id === currentSessionId
          ? { ...s, messages: [...s.messages, errMsg], updatedAt: Date.now() }
          : s
      );
      persistSessions(finalSessions);
    } finally {
      setAssistantLoading(false);
    }
  };

  const handleAddTestsToProject = async (tests: any[]) => {
    if (!selectedProject) {
      toast.error("Please select a project first");
      return;
    }
    try {
      const res = await api.assistantAddTestCases({ project_id: selectedProject, test_cases: tests });
      toast.success(res.message || `Added ${tests.length} test cases to project`, { duration: 4000, icon: "✅" });
    } catch (err: any) {
      // Fall back to saveTestCases
      try {
        const res = await api.saveTestCases({ project_id: selectedProject, test_cases: tests });
        toast.success(res.message || `Saved ${res.saved} test cases`, { duration: 4000, icon: "✅" });
      } catch (e2: any) {
        toast.error(e2.message || "Failed to add test cases");
      }
    }
  };

  // ---------------------------------------------------------------------------
  // Computed values
  // ---------------------------------------------------------------------------

  const totalCvePages = Math.ceil(cveTotal / cvePageSize);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

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
            {[1, 2, 3, 4, 5, 6, 7].map((i) => (
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
          ].map((tab) => (
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

        {/* ================================================================= */}
        {/* CVE FEED TAB                                                      */}
        {/* ================================================================= */}
        {activeTab === "cves" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
            {/* Search & Controls */}
            <div className="card p-4 space-y-3">
              <div className="flex flex-wrap items-center gap-3">
                {/* Main keyword search */}
                <div className="flex-1 min-w-[200px] flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                    <input className="input-field text-sm py-2 pl-9 w-full"
                      placeholder="Search CVE ID or description..."
                      value={cveKeyword}
                      onChange={(e) => setCveKeyword(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleCveSearch()} />
                  </div>
                  <select className="input-field text-sm py-2 w-32"
                    value={cveSeverityFilter}
                    onChange={(e) => { setCveSeverityFilter(e.target.value); setCvePage(1); loadCves(1, cveKeyword, e.target.value, cveCweFilter, cveDateFrom, cveDateTo); }}>
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <button onClick={handleCveSearch} className="btn-primary text-xs px-3">
                    <Search className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
                    className={`btn-ghost text-xs px-3 flex items-center gap-1.5 ${showAdvancedFilters ? "text-indigo-400" : ""}`}
                  >
                    <Filter className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Filters</span>
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  {cveSource === "database" && (
                    <span className="text-[10px] px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                      <Database className="w-3 h-3" /> DB: {cveTotal.toLocaleString()} CVEs
                    </span>
                  )}
                  {(needsSync || (user && isAdmin(user.role))) && (
                    <SyncSourcePicker syncing={syncing} syncProgress={syncProgress} onSync={handleSync} />
                  )}
                </div>
              </div>

              {/* Advanced Filters */}
              <AnimatePresence>
                {showAdvancedFilters && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                      <div>
                        <label className="text-[10px] font-medium uppercase tracking-wider block mb-1" style={{ color: "var(--text-muted)" }}>
                          CWE Filter
                        </label>
                        <input
                          className="input-field text-sm py-2 w-full"
                          placeholder="e.g., CWE-79, CWE-89"
                          value={cveCweFilter}
                          onChange={(e) => setCveCweFilter(e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="text-[10px] font-medium uppercase tracking-wider block mb-1" style={{ color: "var(--text-muted)" }}>
                          Date From
                        </label>
                        <input
                          type="date"
                          className="input-field text-sm py-2 w-full"
                          value={cveDateFrom}
                          onChange={(e) => setCveDateFrom(e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="text-[10px] font-medium uppercase tracking-wider block mb-1" style={{ color: "var(--text-muted)" }}>
                          Date To
                        </label>
                        <input
                          type="date"
                          className="input-field text-sm py-2 w-full"
                          value={cveDateTo}
                          onChange={(e) => setCveDateTo(e.target.value)}
                        />
                      </div>
                    </div>
                    <div className="flex items-center gap-2 mt-3">
                      <button onClick={handleCveSearch} className="btn-primary text-xs px-4">
                        Apply Filters
                      </button>
                      <button
                        onClick={() => {
                          setCveCweFilter("");
                          setCveDateFrom("");
                          setCveDateTo("");
                          setCveSeverityFilter("");
                          setCveKeyword("");
                          setCvePage(1);
                          loadCves(1, "", "", "", "", "");
                        }}
                        className="btn-ghost text-xs px-4"
                      >
                        Reset All
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Real-time CVE ID search */}
              <div className="relative">
                <div className="relative">
                  <Hash className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-indigo-400" />
                  <input
                    className="input-field text-sm py-2 pl-9 w-full sm:w-80"
                    placeholder="Quick lookup: CVE-2024-xxxx..."
                    value={cveIdSearch}
                    onChange={(e) => handleCveIdSearch(e.target.value)}
                  />
                  {cveIdSearching && (
                    <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 animate-spin text-indigo-400" />
                  )}
                </div>
                {/* Quick lookup dropdown */}
                <AnimatePresence>
                  {cveIdResults.length > 0 && cveIdSearch.trim() && (
                    <motion.div
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -4 }}
                      className="absolute left-0 right-0 sm:right-auto sm:w-[500px] top-full mt-1 z-20 rounded-xl border shadow-xl max-h-64 overflow-y-auto"
                      style={{ background: "var(--bg-elevated)", borderColor: "var(--border-subtle)" }}
                    >
                      {cveIdResults.slice(0, 8).map((result: any, i: number) => {
                        const id = result.cve_id || result.id;
                        const sev = result.severity || "medium";
                        const sc = getSeverityStyle(sev);
                        return (
                          <button
                            key={id || i}
                            className="w-full text-left px-4 py-2.5 hover:bg-white/5 transition-colors flex items-start gap-3"
                            style={{ borderBottom: i < cveIdResults.length - 1 ? "1px solid var(--border-subtle)" : undefined }}
                            onClick={() => {
                              openCveDetail(id);
                              setCveIdSearch("");
                              setCveIdResults([]);
                            }}
                          >
                            <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-bold uppercase shrink-0 mt-0.5 ${sc.text} ${sc.bg} ${sc.border}`}>
                              {sev}
                            </span>
                            <div className="min-w-0 flex-1">
                              <div className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>{id}</div>
                              <p className="text-[11px] line-clamp-1 mt-0.5" style={{ color: "var(--text-muted)" }}>
                                {result.description || "No description"}
                              </p>
                            </div>
                            {result.cvss_score && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-medium shrink-0">
                                {result.cvss_score}
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {needsSync && (
                <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-xs text-yellow-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>No CVEs in database yet. Click &quot;Sync CVEs&quot; to fetch and store the latest CVEs from NVD.</span>
                </div>
              )}

              {/* Sync progress indicator */}
              {syncing && (
                <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-xs text-indigo-400 flex items-center gap-3">
                  <div className="relative">
                    <Loader2 className="w-5 h-5 animate-spin" />
                  </div>
                  <div className="flex-1">
                    <div className="font-medium">{syncProgress || "Syncing CVEs..."}</div>
                    <div className="mt-1.5 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--bg-tertiary)" }}>
                      <motion.div
                        className="h-full rounded-full bg-indigo-500"
                        initial={{ width: "0%" }}
                        animate={{ width: "100%" }}
                        transition={{ duration: 30, ease: "linear" }}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* CVE List */}
            <div className="card p-4">
              {cvesLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3, 4, 5].map((i) => (
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
                    return (
                      <motion.div key={cveId}
                        initial={{ opacity: 0, x: -6 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.02 }}
                        className={`rounded-lg border-l-4 border overflow-hidden cursor-pointer hover:bg-white/[0.02] transition-colors ${sc.left}`}
                        style={{ background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)", borderLeftColor: undefined }}
                        onClick={() => openCveDetail(cveId)}
                      >
                        <div className="p-3 flex items-start gap-3">
                          <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase shrink-0 mt-0.5 ${sc.text} ${sc.bg} ${sc.border}`}>
                            {severity}
                          </span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>{cveId}</span>
                              {cve.cvss_score && (
                                <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${
                                  cve.cvss_score >= 9 ? "bg-red-500/10 text-red-400 border-red-500/20" :
                                  cve.cvss_score >= 7 ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                                  cve.cvss_score >= 4 ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
                                  "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                                }`}>
                                  CVSS {cve.cvss_score}
                                </span>
                              )}
                              {cve.cwes?.slice(0, 2).map((cwe: string, j: number) => (
                                <span key={j} className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>
                                  {cwe}
                                </span>
                              ))}
                              {cve.cwes?.length > 2 && (
                                <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>+{cve.cwes.length - 2}</span>
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
                            <ExternalLink className="w-3 h-3 text-indigo-400" />
                          </div>
                        </div>
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

        {/* CVE Detail Modal */}
        <AnimatePresence>
          {(cveDetailModal || cveDetailLoading) && (
            <CveDetailModal
              cve={cveDetailModal}
              onClose={() => { setCveDetailModal(null); setCveDetailLoading(false); }}
              loading={cveDetailLoading}
            />
          )}
        </AnimatePresence>

        {/* ================================================================= */}
        {/* AI TEST GENERATOR TAB                                             */}
        {/* ================================================================= */}
        {activeTab === "generator" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
            <div className="card p-5">
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
                <div className="p-1.5 rounded-lg bg-purple-500/10 border border-purple-500/20">
                  <Cpu className="w-4 h-4 text-purple-400" />
                </div>
                AI Test Case Generator
              </h2>

              <div className="space-y-3 mb-4">
                <div>
                  <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Context / Description *</label>
                  <textarea className="input-field text-sm h-24 resize-none w-full"
                    placeholder="Describe the application, feature, or vulnerability category to generate test cases for..."
                    value={genForm.context}
                    onChange={(e) => setGenForm({ ...genForm, context: e.target.value })} />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Tech Stack</label>
                    <input className="input-field text-sm py-2 w-full"
                      placeholder="e.g., React, Node.js, PostgreSQL"
                      value={genForm.tech_stack}
                      onChange={(e) => setGenForm({ ...genForm, tech_stack: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>App Type</label>
                    <input className="input-field text-sm py-2 w-full"
                      placeholder="e.g., Web App, API, Mobile"
                      value={genForm.app_type}
                      onChange={(e) => setGenForm({ ...genForm, app_type: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Focus Areas</label>
                    <input className="input-field text-sm py-2 w-full"
                      placeholder="e.g., auth, file upload, IDOR"
                      value={genForm.focus_areas}
                      onChange={(e) => setGenForm({ ...genForm, focus_areas: e.target.value })} />
                  </div>
                </div>
                <div className="flex flex-wrap items-end gap-3">
                  <div className="flex-1 min-w-[200px]">
                    <label className="text-xs font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Target Project (for saving)</label>
                    <select className="input-field text-sm py-2 w-full" value={selectedProject}
                      onChange={(e) => setSelectedProject(e.target.value)}>
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
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                      Generated {generatedTests.length} test cases ({selectedTests.size} selected)
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20 flex items-center gap-1">
                      <Cpu className="w-3 h-3" /> AI Generated
                    </span>
                  </div>
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
                        className={`rounded-lg p-3.5 border cursor-pointer transition-all ${isSelected ? "ring-1 ring-indigo-500/50" : ""}`}
                        style={{ background: "var(--bg-tertiary)", borderColor: isSelected ? "var(--accent-indigo)" : "var(--border-subtle)" }}
                        onClick={() => toggleTest(i)}>
                        <div className="flex items-start gap-2.5">
                          <input type="checkbox" checked={isSelected} onChange={() => toggleTest(i)}
                            className="mt-1 shrink-0 accent-indigo-500" onClick={(e) => e.stopPropagation()} />
                          <div className="p-1 rounded-md bg-purple-500/10">
                            <Target className="w-3 h-3 text-purple-400" />
                          </div>
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
                              {tc.phase && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                  {tc.phase}
                                </span>
                              )}
                            </div>
                            {tc.description && (
                              <p className="text-xs mt-1.5 leading-relaxed" style={{ color: "var(--text-secondary)" }}>{tc.description}</p>
                            )}
                            {tc.how_to_test && (
                              <div className="mt-2 p-2.5 rounded-lg text-xs leading-relaxed" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>
                                <span className="font-medium" style={{ color: "var(--text-secondary)" }}>How to test: </span>
                                {tc.how_to_test}
                              </div>
                            )}
                            {tc.expected_result && (
                              <div className="mt-1.5 text-[11px]" style={{ color: "var(--text-muted)" }}>
                                <span className="font-medium">Expected: </span>{tc.expected_result}
                              </div>
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
                <div className="inline-flex p-3 rounded-2xl bg-purple-500/10 border border-purple-500/20 mb-4">
                  <Cpu className="w-8 h-8 text-purple-400" />
                </div>
                <p className="text-sm font-medium" style={{ color: "var(--text-secondary)" }}>
                  Describe your application context above and let AI generate relevant security test cases.
                </p>
                <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
                  Generated tests will be categorized as &quot;AI Generated&quot; and can be saved directly to a project for execution.
                </p>
              </div>
            )}
          </motion.div>
        )}

        {/* ================================================================= */}
        {/* SECURITY ASSISTANT TAB                                            */}
        {/* ================================================================= */}
        {activeTab === "assistant" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-0">
            <div className="flex rounded-2xl border overflow-hidden" style={{ background: "var(--bg-secondary)", borderColor: "var(--border-subtle)", minHeight: "600px" }}>

              {/* Chat Sidebar */}
              <AnimatePresence>
                {showChatSidebar && (
                  <motion.div
                    initial={{ width: 0, opacity: 0 }}
                    animate={{ width: 260, opacity: 1 }}
                    exit={{ width: 0, opacity: 0 }}
                    className="flex flex-col border-r shrink-0 overflow-hidden"
                    style={{ borderColor: "var(--border-subtle)" }}
                  >
                    {/* Sidebar header */}
                    <div className="p-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                      <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Chat History</span>
                      <button
                        onClick={handleNewChat}
                        className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
                        title="New Chat"
                      >
                        <PlusCircle className="w-4 h-4 text-indigo-400" />
                      </button>
                    </div>

                    {/* Session list */}
                    <div className="flex-1 overflow-y-auto p-2 space-y-1">
                      {chatSessions.length === 0 && (
                        <div className="text-center py-8">
                          <MessageSquare className="w-6 h-6 mx-auto mb-2" style={{ color: "var(--border-subtle)" }} />
                          <p className="text-[11px]" style={{ color: "var(--text-muted)" }}>No chats yet</p>
                        </div>
                      )}
                      {chatSessions.map((session) => (
                        <div
                          key={session.id}
                          className={`group flex items-center gap-2 px-3 py-2.5 rounded-lg cursor-pointer transition-all ${
                            activeChatId === session.id ? "ring-1 ring-indigo-500/30" : ""
                          }`}
                          style={{
                            background: activeChatId === session.id ? "var(--bg-elevated)" : "transparent",
                          }}
                          onClick={() => setActiveChatId(session.id)}
                        >
                          <MessageSquare className="w-3.5 h-3.5 shrink-0 text-indigo-400" />
                          <div className="flex-1 min-w-0">
                            <div className="text-xs font-medium truncate" style={{ color: "var(--text-primary)" }}>
                              {session.title}
                            </div>
                            <div className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                              {session.messages.length} messages
                              {session.projectId && " \u00b7 Project linked"}
                            </div>
                          </div>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteChat(session.id);
                            }}
                            className="p-1 rounded opacity-0 group-hover:opacity-100 hover:bg-red-500/10 transition-all"
                            title="Delete chat"
                          >
                            <Trash2 className="w-3 h-3 text-red-400" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Main chat area */}
              <div className="flex-1 flex flex-col min-w-0">
                {/* Chat header */}
                <div className="p-4 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setShowChatSidebar(!showChatSidebar)}
                      className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
                    >
                      {showChatSidebar ? <ChevronLeft className="w-4 h-4" style={{ color: "var(--text-muted)" }} /> : <ChevronRight className="w-4 h-4" style={{ color: "var(--text-muted)" }} />}
                    </button>
                    <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                      <MessageSquare className="w-4 h-4 text-indigo-400" />
                      {activeSession?.title || "AI Security Assistant"}
                    </h2>
                  </div>
                  <div className="flex items-center gap-2">
                    {/* Project context selector */}
                    <select
                      className="input-field text-xs py-1.5 w-40"
                      value={selectedProject}
                      onChange={(e) => setSelectedProject(e.target.value)}
                    >
                      <option value="">No project context</option>
                      {projects.map((p: any) => (
                        <option key={p.id} value={p.id}>{p.application_name || p.name}</option>
                      ))}
                    </select>
                    {activeSession && activeSession.messages.length > 0 && (
                      <button
                        onClick={() => {
                          if (activeChatId) handleDeleteChat(activeChatId);
                        }}
                        className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 px-2 py-1 rounded-lg hover:bg-red-500/10 transition-colors"
                      >
                        <Trash2 className="w-3 h-3" /> Clear
                      </button>
                    )}
                    <button
                      onClick={handleNewChat}
                      className="btn-secondary text-xs flex items-center gap-1.5"
                    >
                      <Plus className="w-3 h-3" /> New Chat
                    </button>
                  </div>
                </div>

                {/* Project context badge */}
                {selectedProject && (
                  <div className="px-4 pt-2">
                    <span className="inline-flex items-center gap-1.5 text-[10px] px-2.5 py-1 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                      <Database className="w-3 h-3" />
                      Context: {projects.find((p) => p.id === selectedProject)?.application_name || projects.find((p) => p.id === selectedProject)?.name || "Project"}
                    </span>
                  </div>
                )}

                {/* Messages */}
                <div ref={chatContainerRef} className="flex-1 overflow-y-auto p-4 space-y-4">
                  {(!activeSession || activeSession.messages.length === 0) && !assistantLoading && (
                    <div className="text-center py-16">
                      <div className="inline-flex p-4 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 mb-4">
                        <MessageSquare className="w-8 h-8 text-indigo-400" />
                      </div>
                      <p className="text-sm font-medium" style={{ color: "var(--text-secondary)" }}>
                        Ask me anything about security testing
                      </p>
                      <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                        I can help with vulnerability testing, CVE analysis, and security best practices.
                      </p>
                      <div className="mt-6 flex flex-wrap justify-center gap-2 max-w-md mx-auto">
                        {[
                          "How do I test for IDOR?",
                          "Latest Spring Boot CVEs?",
                          "SQLi testing checklist",
                          "XSS bypass techniques",
                          "OWASP Top 10 summary",
                          "API security best practices",
                        ].map((q) => (
                          <button key={q} onClick={() => setAssistantQuestion(q)}
                            className="text-xs px-3 py-1.5 rounded-lg transition-all hover:scale-[1.02] hover:bg-white/5"
                            style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>
                            {q}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {activeSession?.messages.map((msg, i) => (
                    <motion.div
                      key={`${activeSession.id}-${i}`}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.05 }}
                      className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                    >
                      <div className={`max-w-[85%] ${msg.role === "user" ? "" : "w-full max-w-[85%]"}`}>
                        {/* Project context badge on assistant messages */}
                        {msg.role === "assistant" && msg.projectContext && (
                          <div className="mb-1.5 flex items-center gap-1">
                            <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>
                              Context: {msg.projectContext}
                            </span>
                          </div>
                        )}

                        <div
                          className={`rounded-xl px-4 py-3 text-sm ${msg.role === "user" ? "" : ""}`}
                          style={msg.role === "user"
                            ? { background: "var(--accent-indigo)", color: "white" }
                            : { background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }
                          }
                        >
                          <div className="whitespace-pre-wrap break-words leading-relaxed">{msg.content}</div>
                        </div>

                        {/* Suggested test cases from assistant */}
                        {msg.role === "assistant" && msg.suggestedTests && msg.suggestedTests.length > 0 && (
                          <div className="mt-2 rounded-xl p-3 border space-y-2" style={{ background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)" }}>
                            <div className="flex items-center justify-between">
                              <span className="text-[11px] font-medium flex items-center gap-1.5" style={{ color: "var(--text-secondary)" }}>
                                <Target className="w-3 h-3 text-purple-400" />
                                Suggested Test Cases ({msg.suggestedTests.length})
                              </span>
                              {selectedProject && (
                                <button
                                  onClick={() => handleAddTestsToProject(msg.suggestedTests!)}
                                  className="text-[11px] px-2.5 py-1 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 hover:bg-indigo-500/20 transition-colors flex items-center gap-1"
                                >
                                  <FolderPlus className="w-3 h-3" /> Add to Project
                                </button>
                              )}
                            </div>
                            {msg.suggestedTests.map((tc: any, j: number) => (
                              <div key={j} className="rounded-lg p-2.5 text-xs" style={{ background: "var(--bg-elevated)" }}>
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="font-medium" style={{ color: "var(--text-primary)" }}>{tc.title || `Test ${j + 1}`}</span>
                                  {tc.severity && (
                                    <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-medium ${getSeverityStyle(tc.severity).text} ${getSeverityStyle(tc.severity).bg} ${getSeverityStyle(tc.severity).border}`}>
                                      {tc.severity}
                                    </span>
                                  )}
                                </div>
                                {tc.description && (
                                  <p className="mt-1" style={{ color: "var(--text-muted)" }}>{tc.description}</p>
                                )}
                              </div>
                            ))}
                            {!selectedProject && (
                              <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
                                Select a project context above to enable &quot;Add to Project&quot;
                              </p>
                            )}
                          </div>
                        )}

                        {/* Timestamp */}
                        <div className={`text-[10px] mt-1 ${msg.role === "user" ? "text-right" : "text-left"}`} style={{ color: "var(--text-muted)" }}>
                          {new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                        </div>
                      </div>
                    </motion.div>
                  ))}

                  {/* Thinking indicator */}
                  {assistantLoading && (
                    <motion.div
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="flex justify-start"
                    >
                      <div className="rounded-xl px-4 py-3 flex items-center gap-3"
                        style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                        <div className="flex gap-1">
                          <motion.div
                            className="w-2 h-2 rounded-full bg-indigo-400"
                            animate={{ scale: [1, 1.3, 1], opacity: [0.5, 1, 0.5] }}
                            transition={{ duration: 1.2, repeat: Infinity, delay: 0 }}
                          />
                          <motion.div
                            className="w-2 h-2 rounded-full bg-indigo-400"
                            animate={{ scale: [1, 1.3, 1], opacity: [0.5, 1, 0.5] }}
                            transition={{ duration: 1.2, repeat: Infinity, delay: 0.2 }}
                          />
                          <motion.div
                            className="w-2 h-2 rounded-full bg-indigo-400"
                            animate={{ scale: [1, 1.3, 1], opacity: [0.5, 1, 0.5] }}
                            transition={{ duration: 1.2, repeat: Infinity, delay: 0.4 }}
                          />
                        </div>
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>Thinking...</span>
                      </div>
                    </motion.div>
                  )}

                  <div ref={chatEndRef} />
                </div>

                {/* Input */}
                <div className="p-4" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                  <div className="flex items-center gap-2">
                    <input className="input-field text-sm py-2.5 flex-1"
                      placeholder="Ask a security question... (e.g., 'How to test for IDOR?')"
                      value={assistantQuestion}
                      onChange={(e) => setAssistantQuestion(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && !e.shiftKey) {
                          e.preventDefault();
                          handleAssistantAsk();
                        }
                      }}
                    />
                    <button onClick={handleAssistantAsk} disabled={assistantLoading || !assistantQuestion.trim()}
                      className="btn-primary px-4 py-2.5 disabled:opacity-50">
                      {assistantLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
