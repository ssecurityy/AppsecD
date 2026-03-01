"use client";
import { useEffect, useState, useRef } from "react";
import { useParams } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import toast from "react-hot-toast";
import { 
  Shield, Play, CheckCircle, XCircle, AlertTriangle, Loader2, 
  ArrowLeft, ChevronDown, Globe, Lock,
  Cookie, Server, FileText, Folder, ExternalLink, Zap, Clock,
  Code, Database, BookOpen, Layers, Wrench, HardDrive, FormInput,
  History, Calendar, Filter, ChevronRight, Search, LayoutGrid
} from "lucide-react";
import Link from "next/link";

const STUCK_THRESHOLD_SEC = 30;
const POLL_INTERVAL_MS = 1500;

const CHECK_ICONS: Record<string, any> = {
  security_headers: Shield, ssl_tls: Lock, cookie_security: Cookie,
  cors: Globe, info_disclosure: Server, http_methods: Zap,
  robots_txt: FileText, directory_listing: Folder, open_redirect: ExternalLink,
  rate_limiting: Clock, xss_basic: Code, sqli_error: Database,
  api_docs_exposure: BookOpen, host_header_injection: Layers, crlf_injection: Wrench,
  sensitive_data: HardDrive, sri: Shield, cache_control: Clock,
  form_autocomplete: FormInput, backup_files: FileText, directory_discovery: Folder, dir: Folder,
  security_txt: FileText, http_redirect_https: ExternalLink, hsts_preload: Lock,
  version_headers: Server, coop_coep: Shield, weak_referrer: Globe, debug_response: Wrench,
  dotenv_git: HardDrive, content_type_sniffing: Code, clickjacking: Shield,
  trace_xst: Zap, expect_ct: Lock, permissions_policy: Shield, xss_protection_header: Code,
  csp_reporting: Shield, server_timing: Server, via_header: Server, x_forwarded_disclosure: Server,
  allow_dangerous: Zap, corp: Shield, clear_site_data: Cookie, cache_age: Clock,
  upgrade_insecure: Lock, cookie_prefix: Cookie, redirect_chain: ExternalLink,
  timing_allow_origin: Clock, alt_svc: Lock, hsts_subdomains: Lock,
  content_disposition: FileText, pragma_no_cache: Clock,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#16a34a", info: "#3b82f6",
};

export default function DastScanPage() {
  const { id } = useParams();
  const { user, hydrate } = useAuthStore();
  const [project, setProject] = useState<any>(null);
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<any>(null);
  const [scanResult, setScanResult] = useState<any>(null);
  const [stuck, setStuck] = useState(false);
  const [availableChecks, setAvailableChecks] = useState<any[]>([]);
  const [selectedChecks, setSelectedChecks] = useState<string[]>([]);
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set());
  const [initialExpandDone, setInitialExpandDone] = useState(false);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [checksSectionExpanded, setChecksSectionExpanded] = useState(false);
  const [checksSearch, setChecksSearch] = useState("");
  const [resultFilter, setResultFilter] = useState<"failed" | "passed" | "all" | "error">("failed");
  const [resultSearch, setResultSearch] = useState("");
  const [historyExpanded, setHistoryExpanded] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { hydrate(); }, [hydrate]);

  // Default filter when new scan results load: failed if any, else passed
  const hasSetFilterForScan = useRef<string | null>(null);
  useEffect(() => {
    if (!scanResult?.results?.length || !scanResult?.scan_id) return;
    if (hasSetFilterForScan.current === scanResult.scan_id) return;
    hasSetFilterForScan.current = scanResult.scan_id;
    const fails = scanResult.results.filter((r: any) => r.status === "failed").length;
    setResultFilter(fails > 0 ? "failed" : "passed");
  }, [scanResult?.scan_id, scanResult?.results?.length]);

  useEffect(() => {
    if (id) {
      api.getProject(id as string).then(setProject).catch(() => toast.error("Failed to load project"));
      api.dastChecks().then((r: any) => {
        setAvailableChecks(r.checks || []);
        setSelectedChecks((r.checks || []).map((c: any) => c.id));
      }).catch(() => {});
      // Load latest from DB (scan ran in background, user returned). Fallback to localStorage.
      api.dastProjectLatest(id as string).then((r: any) => {
        setScanResult(r);
        try { localStorage.setItem(`dast_result_${id}`, JSON.stringify(r)); } catch {}
      }).catch(() => {
        try {
          const saved = localStorage.getItem(`dast_result_${id}`);
          if (saved) setScanResult(JSON.parse(saved));
        } catch {}
      });
      // Load scan history
      api.dastProjectHistory(id as string, 50).then((r: any) => {
        setScanHistory(r?.scans ?? []);
      }).catch(() => {});
      // If a scan is still running for this project, resume polling
      api.dastScans().then((r: any) => {
        const active = (r?.scans ?? []).find((s: any) => s.project_id === id && s.status === "running");
        if (active?.scan_id) {
          setScanning(true);
          setScanId(active.scan_id);
          setScanProgress(active);
          const res = { scan_id: active.scan_id };
          const poll = async () => {
            try {
              const prog = await api.dastScanProgress(res.scan_id) as any;
              setScanProgress(prog);
              if (prog?.status === "completed") {
                setScanning(false);
                if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
                const result = { target_url: prog.target_url || active.target_url, total_checks: prog.results?.length ?? 0, passed: prog.passed ?? 0, failed: prog.failed ?? 0, errors: prog.errors ?? 0, duration_seconds: prog.duration_seconds ?? 0, results: prog.results ?? [], findings_created: prog.findings_created ?? 0, finding_titles: prog.finding_titles ?? [] };
                setScanResult(result);
                setInitialExpandDone(false);
                try { localStorage.setItem(`dast_result_${id}`, JSON.stringify(result)); } catch {}
                toast.success(prog.failed === 0 ? "All checks passed!" : `Scan complete: ${prog.failed} issue(s) found`);
              }
            } catch (_) {}
          };
          poll();
          pollRef.current = setInterval(poll, 1500);
        }
      }).catch(() => {});
    }
  }, [id]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const handleScan = async () => {
    if (!project) return;
    setScanning(true);
    setScanResult(null);
    setScanProgress(null);
    setScanId(null);
    setStuck(false);
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    try {
      const res = await api.dastScan({
        project_id: id as string,
        checks: selectedChecks.length < availableChecks.length ? selectedChecks : undefined,
      }) as { scan_id: string; project_id: string; target_url: string };
      setScanId(res.scan_id);
      const poll = async () => {
        try {
          const prog = await api.dastScanProgress(res.scan_id) as {
            status: string;
            current_check?: string;
            completed_count: number;
            total: number;
            results: any[];
            last_updated: number;
            error?: string;
            target_url?: string;
            passed?: number;
            failed?: number;
            errors?: number;
            duration_seconds?: number;
            findings_created?: number;
            finding_titles?: string[];
          };
          setScanProgress(prog);
          if (prog.error) {
            setStuck(false);
            setScanning(false);
            if (pollRef.current) {
              clearInterval(pollRef.current);
              pollRef.current = null;
            }
            toast.error(prog.error);
            return;
          }
          const age = (Date.now() / 1000) - prog.last_updated;
          setStuck(prog.status === "running" && age > STUCK_THRESHOLD_SEC);
          if (prog.status === "completed") {
            setScanning(false);
            if (pollRef.current) {
              clearInterval(pollRef.current);
              pollRef.current = null;
            }
            const result = {
              target_url: prog.target_url || project.application_url,
              total_checks: prog.results?.length ?? prog.total ?? 0,
              passed: prog.passed ?? 0,
              failed: prog.failed ?? 0,
              errors: prog.errors ?? 0,
              duration_seconds: prog.duration_seconds ?? 0,
              results: prog.results ?? [],
              findings_created: prog.findings_created ?? 0,
              finding_titles: prog.finding_titles ?? [],
            };
            setScanResult(result);
            setInitialExpandDone(false);
            try { localStorage.setItem(`dast_result_${id}`, JSON.stringify(result)); } catch {}
            api.dastProjectHistory(id as string, 50).then((r: any) => setScanHistory(r?.scans ?? [])).catch(() => {});
            setTimeout(() => {
              api.dastProjectLatest(id as string).then((r: any) => {
                setScanResult(r);
                try { localStorage.setItem(`dast_result_${id}`, JSON.stringify(r)); } catch {}
              }).catch(() => {});
            }, 800);
            if (result.findings_created > 0) {
              toast.success(`Scan complete! ${result.findings_created} finding(s) auto-created.`);
            } else if (result.failed === 0) {
              toast.success("All checks passed!");
            } else {
              toast(`Scan complete: ${result.failed} issue(s) found`, { icon: "⚠️" });
            }
          }
        } catch (e) {
          setScanning(false);
          if (pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
          }
          toast.error("Failed to fetch scan progress");
        }
      };
      poll();
      pollRef.current = setInterval(poll, POLL_INTERVAL_MS);
    } catch (err: unknown) {
      setScanning(false);
      toast.error(err instanceof Error ? err.message : "Scan failed");
    }
  };

  const toggleCheck = (checkId: string) => {
    setSelectedChecks(prev => 
      prev.includes(checkId) ? prev.filter(c => c !== checkId) : [...prev, checkId]
    );
  };

  const toggleExpand = (checkId: string) => {
    setExpandedResults(prev => {
      const next = new Set(prev);
      if (next.has(checkId)) next.delete(checkId); else next.add(checkId);
      return next;
    });
  };

  // Auto-expand failed checks when results first load; default filter to failed
  useEffect(() => {
    if (scanResult?.results && !initialExpandDone) {
      const results = scanResult.results as any[];
      const failedIds = new Set(results.filter((r: any) => r.status === "failed").map((r: any) => r.check_id));
      setExpandedResults(prev => new Set([...Array.from(prev), ...Array.from(failedIds)]));
      setInitialExpandDone(true);
      if (results.some((r: any) => r.status === "failed")) setResultFilter("failed");
    }
  }, [scanResult, initialExpandDone]);

  const results = (scanResult?.results || []) as any[];
  const failedCount = results.filter((r: any) => r.status === "failed").length;
  const passedCount = results.filter((r: any) => r.status === "passed").length;
  const errorCount = results.filter((r: any) => r.status === "error").length;
  const statusFiltered = results.filter((r: any) => {
    if (resultFilter === "failed") return r.status === "failed";
    if (resultFilter === "passed") return r.status === "passed";
    if (resultFilter === "error") return r.status === "error";
    return true;
  });
  const q = resultSearch.trim().toLowerCase();
  const filteredResults = q
    ? statusFiltered.filter((r: any) =>
        (r.title || "").toLowerCase().includes(q) ||
        (r.description || "").toLowerCase().includes(q) ||
        (r.check_id || "").toLowerCase().includes(q)
      )
    : statusFiltered;


  if (!user) return null;

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-5xl mx-auto p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href={`/projects/${id}`} className="p-2 rounded-lg hover:bg-white/5">
              <ArrowLeft className="w-5 h-5" style={{ color: "var(--text-secondary)" }} />
            </Link>
            <div>
              <h1 className="text-xl font-bold" style={{ color: "var(--text-primary)" }}>
                DAST Automated Scan
              </h1>
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                {project?.application_name} — {project?.application_url}
              </p>
            </div>
          </div>
          <button
            onClick={handleScan}
            disabled={scanning || selectedChecks.length === 0}
            className="flex items-center gap-2 px-6 py-2.5 rounded-lg font-medium text-white disabled:opacity-50 transition-all"
            style={{ background: scanning ? "#4B5563" : "#2563eb" }}
          >
            {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {scanning ? "Scanning..." : "Run Scan"}
          </button>
        </div>

        {/* Last Scan Summary - Compact */}
        {scanResult && (
          <div className="rounded-xl p-3 flex items-center gap-4 flex-wrap" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
            <div className="flex items-center gap-2">
              <History className="w-4 h-4" style={{ color: "var(--accent-indigo)" }} />
              <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Last Scan</span>
            </div>
            <div className="flex flex-wrap gap-3 text-sm">
              {scanResult.created_at && (
                <span className="flex items-center gap-1" style={{ color: "var(--text-secondary)" }}>
                  <Calendar className="w-3.5 h-3.5" />
                  {new Date(scanResult.created_at).toLocaleString()}
                </span>
              )}
              <span style={{ color: "var(--text-muted)" }}>{scanResult.duration_seconds ?? 0}s</span>
              <span className="flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5 text-emerald-500" /><span style={{ color: "#16a34a" }}>{scanResult.passed ?? 0}</span></span>
              <span className="flex items-center gap-1"><XCircle className="w-3.5 h-3.5 text-red-500" /><span style={{ color: "#dc2626" }}>{scanResult.failed ?? 0}</span></span>
              {(scanResult.findings_created ?? 0) > 0 && <span style={{ color: "#ea580c" }}>{scanResult.findings_created} findings</span>}
            </div>
          </div>
        )}

        {/* Collapsible Scan History */}
        {scanHistory.length > 0 && (
          <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
            <button onClick={() => setHistoryExpanded(!historyExpanded)} className="w-full flex items-center justify-between p-3 text-left hover:bg-white/5">
              <div className="flex items-center gap-2">
                <ChevronRight className={`w-4 h-4 transition-transform ${historyExpanded ? "rotate-90" : ""}`} style={{ color: "var(--text-muted)" }} />
                <History className="w-4 h-4" style={{ color: "var(--accent-indigo)" }} />
                <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Scan History</span>
                <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>{scanHistory.length}</span>
              </div>
            </button>
            {historyExpanded && (
              <div className="px-3 pb-3 pt-0 overflow-y-auto" style={{ maxHeight: "240px" }}>
                <div className="flex gap-4 px-2 py-1.5 text-xs font-medium" style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border-subtle)" }}>
                  <span className="flex-1 min-w-[130px]">Date & Time</span>
                  <span className="w-10">Total</span>
                  <span className="w-8">P</span>
                  <span className="w-8">F</span>
                  <span className="w-10">Time</span>
                </div>
                {scanHistory.map((s: any) => (
                  <div key={s.id || s.scan_id} className="flex gap-4 py-1.5 px-2 text-xs rounded hover:bg-white/5" style={{ borderBottom: "1px solid var(--border-subtle)" }} title={s.target_url}>
                    <span className="flex-1 min-w-[130px]" style={{ color: "var(--text-secondary)" }}>{s.created_at ? new Date(s.created_at).toLocaleString() : "—"}</span>
                    <span className="w-10" style={{ color: "var(--text-primary)" }}>{s.total_checks ?? "-"}</span>
                    <span className="w-8" style={{ color: "#16a34a" }}>{s.passed ?? 0}</span>
                    <span className="w-8" style={{ color: "#dc2626" }}>{s.failed ?? 0}</span>
                    <span className="w-10" style={{ color: "var(--text-muted)" }}>{s.duration_seconds ?? 0}s</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Collapsible Security Checks - Compact, folded by default */}
        <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
          <button onClick={() => setChecksSectionExpanded(!checksSectionExpanded)} className="w-full flex items-center justify-between p-2.5 text-left hover:bg-white/5 transition-colors">
            <div className="flex items-center gap-2 min-w-0">
              <ChevronRight className={`w-4 h-4 flex-shrink-0 transition-transform ${checksSectionExpanded ? "rotate-90" : ""}`} style={{ color: "var(--text-muted)" }} />
              <LayoutGrid className="w-4 h-4 flex-shrink-0" style={{ color: "var(--accent-indigo)" }} />
              <span className="text-sm font-medium truncate" style={{ color: "var(--text-primary)" }}>Security Checks</span>
              <span className="text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0" style={{ background: "rgba(37, 99, 235, 0.15)", color: "var(--accent-indigo)" }}>
                {selectedChecks.length}/{availableChecks.length} selected
              </span>
            </div>
          </button>
          {checksSectionExpanded && (
            <div className="px-3 pb-3 pt-0" style={{ borderTop: "1px solid var(--border-subtle)" }}>
              <div className="flex flex-col sm:flex-row gap-2 mt-2 mb-2">
                <div className="relative flex-1 min-w-0">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                  <input
                    type="text"
                    placeholder="Search checks..."
                    value={checksSearch}
                    onChange={(e) => setChecksSearch(e.target.value)}
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg text-xs"
                    style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                  />
                </div>
                <button onClick={() => setSelectedChecks(selectedChecks.length === availableChecks.length ? [] : availableChecks.map((c: any) => c.id))} className="text-xs px-3 py-1.5 rounded-lg font-medium whitespace-nowrap" style={{ background: "var(--bg-elevated)", color: "var(--accent-indigo)", border: "1px solid var(--border-subtle)" }}>
                  {selectedChecks.length === availableChecks.length ? "Deselect All" : "Select All"}
                </button>
              </div>
              {(() => {
                const q = checksSearch.trim().toLowerCase();
                const filtered = q ? availableChecks.filter((c: any) => (c.title || "").toLowerCase().includes(q) || (c.description || "").toLowerCase().includes(q)) : availableChecks;
                return (
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-1.5 max-h-56 overflow-y-auto pr-1">
                    {filtered.map((check: any) => {
                      const Icon = CHECK_ICONS[check.id] || Shield;
                      const selected = selectedChecks.includes(check.id);
                      return (
                        <button key={check.id} onClick={() => toggleCheck(check.id)} className="flex items-center gap-2 p-1.5 rounded-lg text-xs transition-all text-left"
                          style={{ background: selected ? "rgba(37, 99, 235, 0.12)" : "var(--bg-elevated)", border: `1px solid ${selected ? "rgba(37, 99, 235, 0.35)" : "var(--border-subtle)"}`, color: selected ? "var(--accent-indigo)" : "var(--text-secondary)" }}>
                          <Icon className="w-3 h-3 flex-shrink-0 opacity-80" />
                          <span className="truncate flex-1 min-w-0">{check.title?.replace("Check for ", "").replace("Check ", "") || check.id}</span>
                        </button>
                      );
                    })}
                  </div>
                );
              })()}
              {checksSearch.trim() && availableChecks.filter((c: any) => (c.title || "").toLowerCase().includes(checksSearch.trim().toLowerCase()) || (c.description || "").toLowerCase().includes(checksSearch.trim().toLowerCase())).length === 0 && (
                <p className="text-xs py-4 text-center" style={{ color: "var(--text-muted)" }}>No checks match &quot;{checksSearch}&quot;</p>
              )}
            </div>
          )}
        </div>

        {/* Live Progress - Which scan is running */}
        {scanning && (
          <div className="rounded-xl p-4 space-y-4" style={{ background: "var(--bg-card)", border: stuck ? "1px solid #dc2626" : "1px solid var(--border-subtle)" }}>
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <h2 className="font-semibold" style={{ color: "var(--text-primary)" }}>Scan in Progress</h2>
                <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                  Target: {project?.application_url || scanProgress?.target_url} {scanId && `• ID: ${scanId.slice(0, 8)}…`}
                </p>
              </div>
              {stuck && (
                <span className="flex items-center gap-1.5 text-sm font-medium px-3 py-1 rounded" style={{ background: "rgba(220, 38, 38, 0.15)", color: "#dc2626" }}>
                  <AlertTriangle className="w-4 h-4" /> Stuck — no updates for &gt;{STUCK_THRESHOLD_SEC}s
                </span>
              )}
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span style={{ color: "var(--text-secondary)" }}>
                  {scanProgress?.current_check ? (
                    <span className="flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin flex-shrink-0" />
                      {scanProgress.current_check}
                    </span>
                  ) : (
                    "Starting..."
                  )}
                </span>
                <span style={{ color: "var(--text-secondary)" }}>
                  {scanProgress?.completed_count ?? 0} / {scanProgress?.total ?? 0} completed
                </span>
              </div>
              <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                <div
                  className="h-full rounded-full transition-all duration-300"
                  style={{
                    width: `${scanProgress?.total ? Math.min(100, (100 * (scanProgress?.completed_count ?? 0)) / scanProgress.total) : 0}%`,
                    background: stuck ? "#dc2626" : "#2563eb",
                  }}
                />
              </div>
            </div>
            {(scanProgress?.results?.length ?? 0) > 0 && (
              <div className="pt-2">
                <p className="text-xs font-medium mb-2" style={{ color: "var(--text-secondary)" }}>Completed checks</p>
                <div className="flex flex-wrap gap-1.5">
                  {(scanProgress?.results ?? []).map((r: any) => (
                    <span
                      key={r.check_id}
                      className="flex items-center gap-1 text-xs px-2 py-1 rounded"
                      style={{
                        background: r.status === "passed" ? "rgba(22, 163, 74, 0.15)" : r.status === "failed" ? "rgba(220, 38, 38, 0.15)" : "var(--bg-elevated)",
                        color: r.status === "passed" ? "#16a34a" : r.status === "failed" ? "#dc2626" : "var(--text-secondary)",
                      }}
                    >
                      {r.status === "passed" ? <CheckCircle className="w-3 h-3" /> : r.status === "failed" ? <XCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                      {r.title}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Results - Scan Complete */}
        {scanResult && (
          <div className="space-y-4">
            {/* Filter & Summary Bar */}
            <div className="rounded-xl p-3 space-y-2" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex items-center gap-1.5">
                  <Filter className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
                  <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>Show:</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {(["failed", "passed", "error", "all"] as const).map((f) => (
                    <button key={f} onClick={() => setResultFilter(f)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                        resultFilter === f ? "text-white" : ""
                      }`}
                      style={{
                        background: resultFilter === f ? (f === "failed" ? "#dc2626" : f === "passed" ? "#16a34a" : f === "error" ? "#ca8a04" : "#6366f1") : "var(--bg-elevated)",
                        color: resultFilter === f ? "white" : "var(--text-secondary)",
                        border: resultFilter === f ? "none" : "1px solid var(--border-subtle)",
                      }}>
                      {f === "failed" && <XCircle className="w-3 h-3 inline mr-1 align-middle" />}
                      {f === "passed" && <CheckCircle className="w-3 h-3 inline mr-1 align-middle" />}
                      {f === "error" && <AlertTriangle className="w-3 h-3 inline mr-1 align-middle" />}
                      {f.charAt(0).toUpperCase() + f.slice(1)} {f === "failed" ? `(${failedCount})` : f === "passed" ? `(${passedCount})` : f === "error" ? `(${errorCount})` : `(${results.length})`}
                    </button>
                  ))}
                </div>
                <span className="text-xs ml-auto" style={{ color: "var(--text-muted)" }}>
                  {filteredResults.length} of {results.length}
                </span>
              </div>
              {results.length > 8 && (
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                  <input
                    type="text"
                    placeholder="Search results by title or description..."
                    value={resultSearch}
                    onChange={(e) => setResultSearch(e.target.value)}
                    className="w-full sm:w-64 pl-8 pr-3 py-1.5 rounded-lg text-xs"
                    style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                  />
                </div>
              )}
            </div>

            {/* Individual Results - Compact & Segregated */}
            <div className="space-y-2">
              {filteredResults.length === 0 ? (
                <div className="rounded-xl p-8 text-center" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                  <p className="text-sm" style={{ color: "var(--text-muted)" }}>No {resultFilter} results</p>
                </div>
              ) : (
                filteredResults.map((check: any) => {
                  const expanded = expandedResults.has(check.check_id);
                  return (
                    <div key={check.check_id} className="rounded-lg overflow-hidden" style={{ background: "var(--bg-card)", border: `1px solid ${check.status === "failed" ? "rgba(220, 38, 38, 0.25)" : "var(--border-subtle)"}` }}>
                      <button onClick={() => toggleExpand(check.check_id)} className="w-full flex items-center justify-between p-3 text-left hover:bg-white/5 transition-colors">
                        <div className="flex items-center gap-3 min-w-0">
                          {check.status === "passed" ? <CheckCircle className="w-5 h-5 flex-shrink-0" style={{ color: "#16a34a" }} /> : check.status === "failed" ? <XCircle className="w-5 h-5 flex-shrink-0" style={{ color: "#dc2626" }} /> : <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: "#ca8a04" }} />}
                          <div className="min-w-0">
                            <p className="font-medium text-sm truncate" style={{ color: "var(--text-primary)" }}>{check.title}</p>
                            <p className="text-xs truncate" style={{ color: "var(--text-secondary)" }}>{check.description}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {check.status === "failed" && (
                            <span className="text-xs px-2 py-0.5 rounded font-medium" style={{ background: `${SEVERITY_COLORS[check.severity] || "#6b7280"}22`, color: SEVERITY_COLORS[check.severity] || "#6b7280" }}>{check.severity}</span>
                          )}
                          <ChevronDown className={`w-4 h-4 transition-transform ${expanded ? "rotate-180" : ""}`} style={{ color: "var(--text-muted)" }} />
                        </div>
                      </button>
                      {expanded && (
                        <div className="px-3 pb-3 pt-0 space-y-3 text-sm" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                          {/* Issue/Pass callout */}
                          {check.status === "failed" && (
                            <div className="p-2.5 rounded-lg" style={{ background: "rgba(220, 38, 38, 0.08)", borderLeft: "4px solid #dc2626" }}>
                              <p className="text-xs font-semibold mb-1" style={{ color: "#dc2626" }}>Issue</p>
                              <p className="text-xs" style={{ color: "var(--text-primary)" }}>{check.description}</p>
                              {check.evidence && <p className="text-xs mt-1.5 font-mono opacity-90" style={{ color: "var(--text-secondary)" }}>{check.evidence}</p>}
                            </div>
                          )}
                          {check.status === "passed" && (
                            <div className="p-2.5 rounded-lg" style={{ background: "rgba(22, 163, 74, 0.08)", borderLeft: "4px solid #16a34a" }}>
                              <p className="text-xs font-semibold mb-0.5" style={{ color: "#16a34a" }}>Passed</p>
                              <p className="text-xs" style={{ color: "var(--text-primary)" }}>{check.description}</p>
                            </div>
                          )}
                          {check.status === "error" && (
                            <div className="p-2.5 rounded-lg" style={{ background: "rgba(202, 138, 4, 0.08)", borderLeft: "4px solid #ca8a04" }}>
                              <p className="text-xs font-semibold mb-0.5" style={{ color: "#ca8a04" }}>Error</p>
                              <p className="text-xs" style={{ color: "var(--text-primary)" }}>{check.description}</p>
                            </div>
                          )}
                          {/* Request / Response - Collapsible */}
                          {(check.request_raw || check.response_raw) && (
                            <div className="space-y-2">
                              {check.request_raw && (
                                <details className="group">
                                  <summary className="cursor-pointer text-xs font-medium flex items-center gap-1" style={{ color: "var(--accent-indigo)" }}>
                                    <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform" /> Request
                                  </summary>
                                  <pre className="mt-1.5 p-2.5 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all font-mono max-h-40 overflow-y-auto" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", fontSize: "11px" }}>{check.request_raw}</pre>
                                </details>
                              )}
                              {check.response_raw && (
                                <details className="group">
                                  <summary className="cursor-pointer text-xs font-medium flex items-center gap-1" style={{ color: "var(--accent-indigo)" }}>
                                    <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform" /> Response {check.status === "failed" && <span className="text-red-500">(anomaly)</span>}
                                  </summary>
                                  <pre className="mt-1.5 p-2.5 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all font-mono max-h-48 overflow-y-auto" style={{ background: check.status === "failed" ? "rgba(220, 38, 38, 0.05)" : "var(--bg-elevated)", color: "var(--text-secondary)", fontSize: "11px" }}>{check.response_raw}</pre>
                                </details>
                              )}
                            </div>
                          )}
                          {/* Steps & Remediation - Compact */}
                          <div className="grid sm:grid-cols-2 gap-2">
                            {check.reproduction_steps && (
                              <div><p className="text-xs font-semibold mb-0.5" style={{ color: "var(--text-primary)" }}>Steps</p><pre className="text-xs whitespace-pre-wrap p-2 rounded" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>{check.reproduction_steps}</pre></div>
                            )}
                            {check.remediation && (
                              <div><p className="text-xs font-semibold mb-0.5" style={{ color: "var(--text-primary)" }}>Remediation</p><p className="text-xs p-2 rounded" style={{ background: "rgba(22, 163, 74, 0.08)", color: "var(--text-secondary)" }}>{check.remediation}</p></div>
                            )}
                          </div>
                          {check.cwe_id && <p className="text-xs" style={{ color: "var(--text-muted)" }}>CWE: {check.cwe_id} | OWASP: {check.owasp_ref}</p>}
                          {check.details && Object.keys(check.details).length > 0 && (
                            <details className="text-xs">
                              <summary className="cursor-pointer flex items-center gap-1" style={{ color: "var(--accent-indigo)" }}><ChevronRight className="w-3 h-3" /> Raw Details</summary>
                              <pre className="mt-1 p-2 rounded overflow-x-auto text-xs" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>{JSON.stringify(check.details, null, 2)}</pre>
                            </details>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}

        {!scanResult && !scanning && (
          <div className="text-center py-16 rounded-xl" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
            <Shield className="w-12 h-12 mx-auto mb-3" style={{ color: "var(--text-secondary)", opacity: 0.5 }} />
            <p className="font-medium" style={{ color: "var(--text-primary)" }}>Ready to Scan</p>
            <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
              Select checks and click &quot;Run Scan&quot; to start automated security testing
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
