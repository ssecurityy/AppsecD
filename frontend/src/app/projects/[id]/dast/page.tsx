"use client";
import { useEffect, useState, useRef } from "react";
import { useParams } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import toast from "react-hot-toast";
import { 
  Shield, Play, CheckCircle, XCircle, AlertTriangle, Loader2, 
  ArrowLeft, ChevronDown, ChevronUp, Globe, Lock,
  Cookie, Server, FileText, Folder, ExternalLink, Zap, Clock,
  Code, Database, BookOpen, Layers, Wrench, HardDrive, FormInput,
  History, Calendar
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
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { hydrate(); }, [hydrate]);

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

  // Auto-expand failed checks when results first load
  useEffect(() => {
    if (scanResult?.results && !initialExpandDone) {
      const failedIds = new Set((scanResult.results as any[]).filter((r: any) => r.status === "failed").map((r: any) => r.check_id));
      setExpandedResults(prev => new Set([...Array.from(prev), ...Array.from(failedIds)]));
      setInitialExpandDone(true);
    }
  }, [scanResult, initialExpandDone]);

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

        {/* Previous Scan Summary & Full History */}
        {(scanResult || scanHistory.length > 0) && (
          <div className="space-y-4">
            {scanResult && (
              <div className="rounded-xl p-4 flex items-center gap-4 flex-wrap" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <div className="flex items-center gap-2">
                  <History className="w-5 h-5" style={{ color: "var(--accent-indigo)" }} />
                  <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Last Scan</span>
                </div>
                <div className="flex flex-wrap gap-4 text-sm">
                  {scanResult.created_at && (
                    <span className="flex items-center gap-1" style={{ color: "var(--text-secondary)" }}>
                      <Calendar className="w-4 h-4" />
                      {new Date(scanResult.created_at).toLocaleString()}
                    </span>
                  )}
                  {scanResult.duration_seconds != null && (
                    <span style={{ color: "var(--text-secondary)" }}>{scanResult.duration_seconds}s</span>
                  )}
                  <span style={{ color: "var(--text-secondary)" }}>
                    {(scanResult.passed ?? 0) + (scanResult.failed ?? 0) + (scanResult.errors ?? 0)} total
                  </span>
                  <span className="flex items-center gap-1">
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                    <span style={{ color: "#16a34a" }}>{scanResult.passed ?? 0} Passed</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <XCircle className="w-4 h-4 text-red-500" />
                    <span style={{ color: "#dc2626" }}>{scanResult.failed ?? 0} Failed</span>
                  </span>
                  {(scanResult.findings_created ?? 0) > 0 && (
                    <span style={{ color: "#ea580c" }}>{scanResult.findings_created} findings</span>
                  )}
                </div>
              </div>
            )}
            {scanHistory.length > 0 && (
              <div className="rounded-xl p-4" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <div className="flex items-center gap-2 mb-3">
                  <History className="w-4 h-4" style={{ color: "var(--accent-indigo)" }} />
                  <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>All Scan History</span>
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>({scanHistory.length} scans)</span>
                </div>
                <div className="overflow-y-auto" style={{ maxHeight: "300px" }}>
                  <div className="min-w-[400px]">
                    <div className="flex gap-4 px-2 py-1.5 text-xs font-medium" style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border-subtle)" }}>
                      <span className="flex-1 min-w-[140px]">Date & Time</span>
                      <span className="w-12">Total</span>
                      <span className="w-10">Passed</span>
                      <span className="w-10">Failed</span>
                      <span className="w-12">Duration</span>
                      <span className="w-14">Findings</span>
                    </div>
                    {scanHistory.map((s: any) => (
                      <div key={s.id || s.scan_id} className="flex gap-4 py-2 px-2 rounded hover:bg-white/5 items-center text-xs" style={{ borderBottom: "1px solid var(--border-subtle)" }} title={s.target_url}>
                        <span className="flex-1 min-w-[140px]" style={{ color: "var(--text-secondary)" }}>
                          {s.created_at ? new Date(s.created_at).toLocaleString() : "—"}
                        </span>
                        <span className="w-12" style={{ color: "var(--text-primary)" }}>{s.total_checks ?? (s.passed ?? 0) + (s.failed ?? 0) + (s.errors_count ?? 0)}</span>
                        <span className="w-10" style={{ color: "#16a34a" }}>{s.passed ?? 0}</span>
                        <span className="w-10" style={{ color: "#dc2626" }}>{s.failed ?? 0}</span>
                        <span className="w-12" style={{ color: "var(--text-muted)" }}>{s.duration_seconds ?? 0}s</span>
                        <span className="w-14" style={{ color: (s.findings_created ?? 0) > 0 ? "#ea580c" : "var(--text-muted)" }}>{s.findings_created ?? 0}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Check Selection */}
        <div className="rounded-xl p-4" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
              Security Checks ({selectedChecks.length}/{availableChecks.length} selected)
            </h2>
            <button onClick={() => setSelectedChecks(
              selectedChecks.length === availableChecks.length ? [] : availableChecks.map(c => c.id)
            )} className="text-xs px-3 py-1 rounded" style={{ color: "var(--accent-indigo)" }}>
              {selectedChecks.length === availableChecks.length ? "Deselect All" : "Select All"}
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
            {availableChecks.map((check: any) => {
              const Icon = CHECK_ICONS[check.id] || Shield;
              const selected = selectedChecks.includes(check.id);
              return (
                <button
                  key={check.id}
                  onClick={() => toggleCheck(check.id)}
                  className="flex items-center gap-2 p-2 rounded-lg text-xs transition-all"
                  style={{
                    background: selected ? "rgba(37, 99, 235, 0.15)" : "var(--bg-elevated)",
                    border: `1px solid ${selected ? "rgba(37, 99, 235, 0.4)" : "var(--border-subtle)"}`,
                    color: selected ? "var(--accent-indigo)" : "var(--text-secondary)",
                  }}
                >
                  <Icon className="w-3.5 h-3.5 flex-shrink-0" />
                  <span className="truncate">{check.title.replace("Check for ", "").replace("Check ", "")}</span>
                </button>
              );
            })}
          </div>
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
            {/* Summary - Scan Complete */}
            <div className="rounded-xl p-4" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h2 className="font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                    <CheckCircle className="w-5 h-5 text-emerald-500" /> Scan Complete
                  </h2>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                    Target: {scanResult.target_url}
                  </p>
                </div>
                <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  {scanResult.duration_seconds}s | {scanResult.total_checks} checks
                </span>
              </div>
              <div className="flex gap-4 text-sm">
                <span className="flex items-center gap-1" style={{ color: "#16a34a" }}>
                  <CheckCircle className="w-4 h-4" /> {scanResult.passed} Passed
                </span>
                <span className="flex items-center gap-1" style={{ color: "#dc2626" }}>
                  <XCircle className="w-4 h-4" /> {scanResult.failed} Failed
                </span>
                {scanResult.errors > 0 && (
                  <span className="flex items-center gap-1" style={{ color: "#ca8a04" }}>
                    <AlertTriangle className="w-4 h-4" /> {scanResult.errors} Errors
                  </span>
                )}
                {scanResult.findings_created > 0 && (
                  <span className="flex items-center gap-1 font-medium" style={{ color: "#ea580c" }}>
                    {scanResult.findings_created} findings auto-created
                  </span>
                )}
              </div>
            </div>

            {/* Individual Results */}
            {(scanResult.results || []).map((check: any) => {
              const Icon = CHECK_ICONS[check.check_id?.split("-")[1]?.toLowerCase()] || Shield;
              const expanded = expandedResults.has(check.check_id);
              return (
                <div key={check.check_id} className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: `1px solid ${check.status === "failed" ? "rgba(220, 38, 38, 0.3)" : "var(--border-subtle)"}` }}>
                  <button onClick={() => toggleExpand(check.check_id)} className="w-full flex items-center justify-between p-4">
                    <div className="flex items-center gap-3">
                      {check.status === "passed" ? <CheckCircle className="w-5 h-5" style={{ color: "#16a34a" }} /> : check.status === "failed" ? <XCircle className="w-5 h-5" style={{ color: "#dc2626" }} /> : <AlertTriangle className="w-5 h-5" style={{ color: "#ca8a04" }} />}
                      <div className="text-left">
                        <p className="font-medium text-sm" style={{ color: "var(--text-primary)" }}>{check.title}</p>
                        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>{check.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {check.status === "failed" && (
                        <span className="text-xs px-2 py-0.5 rounded font-medium" style={{ background: `${SEVERITY_COLORS[check.severity]}20`, color: SEVERITY_COLORS[check.severity] }}>
                          {check.severity}
                        </span>
                      )}
                      {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </button>
                  {expanded && (
                    <div className="px-4 pb-4 space-y-4 text-sm" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                      {/* Status callout: failed = highlight issue, passed = everything correct */}
                      {check.status === "failed" && (
                        <div className="p-3 rounded-lg" style={{ background: "rgba(220, 38, 38, 0.12)", border: "1px solid rgba(220, 38, 38, 0.3)" }}>
                          <p className="text-sm font-semibold flex items-center gap-2" style={{ color: "#dc2626" }}>
                            <XCircle className="w-4 h-4" /> Issue
                          </p>
                          <p className="text-sm mt-1" style={{ color: "var(--text-primary)" }}>{check.description}</p>
                          {check.evidence && <p className="text-xs mt-2 font-mono" style={{ color: "var(--text-secondary)" }}>{check.evidence}</p>}
                        </div>
                      )}
                      {check.status === "passed" && (
                        <div className="p-3 rounded-lg" style={{ background: "rgba(22, 163, 74, 0.12)", border: "1px solid rgba(22, 163, 74, 0.3)" }}>
                          <p className="text-sm font-semibold flex items-center gap-2" style={{ color: "#16a34a" }}>
                            <CheckCircle className="w-4 h-4" /> All checks correct
                          </p>
                          <p className="text-sm mt-1" style={{ color: "var(--text-primary)" }}>{check.description}</p>
                        </div>
                      )}
                      {check.status === "error" && (
                        <div className="p-3 rounded-lg" style={{ background: "rgba(202, 138, 4, 0.12)", border: "1px solid rgba(202, 138, 4, 0.3)" }}>
                          <p className="text-sm font-semibold flex items-center gap-2" style={{ color: "#ca8a04" }}>
                            <AlertTriangle className="w-4 h-4" /> Error
                          </p>
                          <p className="text-sm mt-1" style={{ color: "var(--text-primary)" }}>{check.description}</p>
                        </div>
                      )}
                      {/* Request — always show when available */}
                      {check.request_raw && (
                        <div>
                          <p className="text-xs font-semibold mb-1" style={{ color: "var(--text-primary)" }}>Request</p>
                          <pre className="p-3 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all font-mono" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", borderLeft: check.status === "failed" ? "4px solid #dc2626" : "4px solid var(--border-subtle)" }}>{check.request_raw}</pre>
                        </div>
                      )}
                      {/* Response — always show when available */}
                      {check.response_raw && (
                        <div>
                          <p className="text-xs font-semibold mb-1" style={{ color: "var(--text-primary)" }}>Response</p>
                          <pre className="p-3 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all font-mono max-h-64 overflow-y-auto" style={{ background: check.status === "failed" ? "rgba(220, 38, 38, 0.06)" : "var(--bg-elevated)", color: "var(--text-secondary)", borderLeft: check.status === "failed" ? "4px solid #dc2626" : "4px solid var(--border-subtle)" }}>{check.response_raw}</pre>
                          {check.status === "failed" && <p className="text-xs font-medium mt-1" style={{ color: "#dc2626" }}>Anomaly detected — review response above</p>}
                        </div>
                      )}
                      {check.reproduction_steps && (
                        <div><strong style={{ color: "var(--text-primary)" }}>Steps to Reproduce:</strong><pre className="mt-1 p-2 rounded text-xs whitespace-pre-wrap" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>{check.reproduction_steps}</pre></div>
                      )}
                      {check.remediation && (
                        <div><strong style={{ color: "var(--text-primary)" }}>Remediation:</strong><p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>{check.remediation}</p></div>
                      )}
                      {check.cwe_id && <p className="text-xs" style={{ color: "var(--text-secondary)" }}>CWE: {check.cwe_id} | OWASP: {check.owasp_ref}</p>}
                      {check.details && Object.keys(check.details).length > 0 && (
                        <details className="text-xs"><summary className="cursor-pointer" style={{ color: "var(--accent-indigo)" }}>Raw Details</summary><pre className="mt-1 p-2 rounded overflow-x-auto" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>{JSON.stringify(check.details, null, 2)}</pre></details>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
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
