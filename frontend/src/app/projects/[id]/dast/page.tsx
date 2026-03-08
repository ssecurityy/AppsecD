"use client";
import { useEffect, useState, useRef, useCallback } from "react";
import { useParams } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import toast from "react-hot-toast";
import {
  Shield, Play, CheckCircle, XCircle, AlertTriangle, Loader2,
  ArrowLeft, ChevronDown, ChevronRight, Globe, Lock,
  Cookie, Server, FileText, Folder, File, ExternalLink, Zap, Clock,
  Code, Database, BookOpen, Layers, Wrench, HardDrive, FormInput,
  History, Calendar, Filter, Search, LayoutGrid,
  Bug, Key, Link2, Eye, EyeOff, Settings2, Activity, Radio, Hash, Braces,
  Sparkles, Square, DollarSign, RotateCcw, Brain, FileDown
} from "lucide-react";
import Link from "next/link";
import ProjectSubNav from "@/components/ProjectSubNav";

const STUCK_THRESHOLD_SEC = 30;
const POLL_INTERVAL_MS = 1500;

const CHECK_ICONS: Record<string, any> = {
  security_headers: Shield, ssl_tls: Lock, cookie_security: Cookie,
  cors: Globe, info_disclosure: Server, http_methods: Zap,
  robots_txt: FileText, directory_listing: Folder, open_redirect: ExternalLink,
  tech_fingerprint: Layers, sitemap_xml: FileText,
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
  const { user, hydrate, orgSettings } = useAuthStore();
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
  const [dirsSectionExpanded, setDirsSectionExpanded] = useState(false);
  const [dastActiveTab, setDastActiveTab] = useState<"results" | "directories" | "crawl" | "claude">("results");
  const [ffufScanning, setFfufScanning] = useState<string | null>(null);
  const [ffufResults, setFfufResults] = useState<Record<string, { discovered: { path: string; status: number }[]; wordlist_used: string }>>({});
  const [ffufExhaustiveJobId, setFfufExhaustiveJobId] = useState<string | null>(null);
  const [ffufExhaustiveScanning, setFfufExhaustiveScanning] = useState(false);
  const exhaustivePollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [dirTreeExpanded, setDirTreeExpanded] = useState<Set<string>>(new Set(["/"]));
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Crawler state
  const [crawling, setCrawling] = useState(false);
  const [crawlId, setCrawlId] = useState<string | null>(null);
  const [crawlProgress, setCrawlProgress] = useState<any>(null);
  const [crawlResult, setCrawlResult] = useState<any>(null);
  const [crawlHistory, setCrawlHistory] = useState<any[]>([]);
  const crawlPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Auth config for crawler
  const [authType, setAuthType] = useState<string>("none");
  const [authHeaderName, setAuthHeaderName] = useState("Authorization");
  const [authHeaderValue, setAuthHeaderValue] = useState("");
  const [authCookieValue, setAuthCookieValue] = useState("");
  const [authCustomHeaders, setAuthCustomHeaders] = useState("");
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [crawlScope, setCrawlScope] = useState("host");
  const [runParamDiscovery, setRunParamDiscovery] = useState(true);
  const [usePlaywright, setUsePlaywright] = useState(false);
  const [crawlUrlFilter, setCrawlUrlFilter] = useState("");
  const [crawlActiveSubTab, setCrawlActiveSubTab] = useState<"urls" | "api" | "params" | "forms" | "js" | "deeplinks" | "sca" | "ai">("urls");
  // Recursive directory scan state
  const [recursiveDirScanning, setRecursiveDirScanning] = useState(false);
  const [recursiveDirJobId, setRecursiveDirJobId] = useState<string | null>(null);
  const [recursiveDirResult, setRecursiveDirResult] = useState<any>(null);
  const [recursiveDirDepth, setRecursiveDirDepth] = useState(3);
  const recursiveDirPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // URL content viewer
  const [fetchingUrl, setFetchingUrl] = useState<string | null>(null);
  const [urlContent, setUrlContent] = useState<Record<string, any>>({});
  // AI Analysis state
  const [aiScanSummary, setAiScanSummary] = useState<any>(null);
  const [aiScanSummaryLoading, setAiScanSummaryLoading] = useState(false);
  const [aiCrawlAnalysis, setAiCrawlAnalysis] = useState<any>(null);
  const [aiCrawlAnalysisLoading, setAiCrawlAnalysisLoading] = useState(false);
  const [aiSuggestedChecks, setAiSuggestedChecks] = useState<any>(null);
  const [aiSuggestLoading, setAiSuggestLoading] = useState(false);

  // Claude AI DAST state
  const [claudeScanning, setClaudeScanning] = useState(false);
  const [claudeScanId, setClaudeScanId] = useState<string | null>(null);
  const [claudeProgress, setClaudeProgress] = useState<any>(null);
  const [claudeScanMode, setClaudeScanMode] = useState<"quick" | "standard" | "deep">("standard");
  const [claudeIncludeSubdomains, setClaudeIncludeSubdomains] = useState(false);
  const [claudeSession, setClaudeSession] = useState<any>(null);
  const [claudeHistory, setClaudeHistory] = useState<any[]>([]);
  const [claudeCostEstimate, setClaudeCostEstimate] = useState<any>(null);
  const [claudeCrawlResults, setClaudeCrawlResults] = useState<any[]>([]);
  const [claudeActiveSubTab, setClaudeActiveSubTab] = useState<"dashboard" | "crawled" | "history" | "session">("dashboard");
  const [claudeCrawlSubTab, setClaudeCrawlSubTab] = useState<"pages" | "apis" | "hidden_paths" | "hidden_params" | "forms" | "subdomains" | "js_analysis" | "sca" | "technology" | "attack_surface">("pages");
  const claudePollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Export dropdown state
  const [showExportMenu, setShowExportMenu] = useState(false);

  // Claude DAST auth config state
  const [claudeAuthType, setClaudeAuthType] = useState("none");
  const [claudeAuthToken, setClaudeAuthToken] = useState("");
  const [claudeAuthUsername, setClaudeAuthUsername] = useState("");
  const [claudeAuthPassword, setClaudeAuthPassword] = useState("");
  const [claudeAuthHeaderName, setClaudeAuthHeaderName] = useState("");
  const [claudeAuthHeaderValue, setClaudeAuthHeaderValue] = useState("");
  const [claudeProxyUrl, setClaudeProxyUrl] = useState("");

  // Scheduling & Baselines state
  const [showSchedule, setShowSchedule] = useState(false);
  const [schedule, setSchedule] = useState<any>(null);
  const [scheduleLoading, setScheduleLoading] = useState(false);
  const [cronExpression, setCronExpression] = useState("0 2 * * 1");
  const [baselines, setBaselines] = useState<any[]>([]);
  const [showBaselines, setShowBaselines] = useState(false);
  const [baselinesLoading, setBaselinesLoading] = useState(false);

  type PathItem = { path: string; status: number };
  const buildPathTree = (items: PathItem[]): { name: string; fullPath: string; status?: number; children: any[]; isFile: boolean } => {
    const root: any = { name: "/", fullPath: "/", children: [], isFile: false };
    const addPath = (parts: string[], status: number, node: any, fullSoFar: string) => {
      if (parts.length === 0) return;
      const [first, ...rest] = parts;
      const seg = first || "";
      if (!seg) return;
      const childPath = fullSoFar === "/" ? `/${seg}` : `${fullSoFar}/${seg}`;
      let child = node.children.find((c: any) => c.name === seg);
      if (!child) {
        child = { name: seg, fullPath: childPath, status: rest.length === 0 ? status : undefined, children: [], isFile: rest.length === 0 && !seg.match(/\/$/) };
        node.children.push(child);
      } else if (rest.length === 0 && child.status == null) {
        child.status = status;
      }
      addPath(rest, status, child, childPath);
    };
    for (const it of items) {
      const p = (it.path || "/").replace(/\/+/g, "/").replace(/^\//, "").replace(/\/$/, "") || "";
      const parts = p ? p.split("/") : [];
      addPath(parts, it.status, root, "/");
    }
    const sortChildren = (n: any) => {
      n.children.sort((a: any, b: any) => {
        if (a.children?.length && !b.children?.length) return -1;
        if (!a.children?.length && b.children?.length) return 1;
        return (a.name || "").localeCompare(b.name || "");
      });
      n.children.forEach(sortChildren);
    };
    sortChildren(root);
    return root;
  };

  const allDiscoveredPaths = (() => {
    const dirCheck = (scanResult?.results || []).find((r: any) => r.check_id === "DAST-DIR-02");
    const base = (dirCheck?.details?.discovered || []) as PathItem[];
    const fromFfuf = Object.values(ffufResults).flatMap((r) => r.discovered);
    const fromRecursive = [
      ...(recursiveDirResult?.directories || []).map((d: any) => ({ path: d.path || d, status: d.status ?? 200 })),
      ...(recursiveDirResult?.files || []).map((f: any) => ({ path: f.path || f, status: f.status ?? 200 })),
      ...(recursiveDirResult?.flat || []).map((x: any) => ({ path: x.path || x, status: x.status ?? 200 })),
    ];
    const byPath = new Map<string, number>();
    for (const x of [...base, ...fromFfuf, ...fromRecursive]) {
      const p = (x.path || "").replace(/\/+$/, "") || "/";
      const norm = p === "" || p === "/" ? "/" : p.startsWith("/") ? p : `/${p}`;
      if (!byPath.has(norm)) byPath.set(norm, x.status);
    }
    return Array.from(byPath.entries()).map(([path, status]) => ({ path, status }));
  })();

  const pathTreeRoot = allDiscoveredPaths.length > 0 ? buildPathTree(allDiscoveredPaths) : null;

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
      // Load last discovered paths (exhaustive scan persisted to ProjectTestResult) so Directory tree shows after reload
      api.dastLastDiscoveredPaths(id as string).then((r: any) => {
        const discovered = r?.discovered || [];
        if (discovered.length > 0) {
          setFfufResults((prev) => ({
            ...prev,
            _persisted: { discovered, wordlist_used: "exhaustive (persisted)" },
          }));
        }
      }).catch(() => {});
      // Load last recursive dir scan (persisted to CrawlSession) so Directory tree shows after reload
      api.dastLastDirScan(id as string).then((r: any) => {
        const flat = r?.flat || [];
        if (flat.length > 0) {
          setRecursiveDirResult({ directories: flat, files: [], flat, total_found: flat.length });
        }
      }).catch(() => {});
      // Resume polling for in-progress scans (job IDs in sessionStorage)
      try {
        const storedExhaustive = sessionStorage.getItem(`dast_exhaustive_job_${id}`);
        const storedRecursive = sessionStorage.getItem(`dast_recursive_job_${id}`);
        if (storedExhaustive) {
          setFfufExhaustiveJobId(storedExhaustive);
          setFfufExhaustiveScanning(true);
          const poll = async () => {
            try {
              const prog = await api.dastFfufExhaustiveProgress(storedExhaustive) as any;
              if (prog.status === "completed") {
                sessionStorage.removeItem(`dast_exhaustive_job_${id}`);
                setFfufExhaustiveScanning(false);
                setFfufExhaustiveJobId(null);
                if (exhaustivePollRef.current) { clearInterval(exhaustivePollRef.current); exhaustivePollRef.current = null; }
                const disc = prog.discovered || [];
                setFfufResults(prev => ({ ...prev, "/": { discovered: disc, wordlist_used: (prog.wordlists_used || []).join(", ") } }));
                toast.success(`Exhaustive scan complete: ${disc.length} path(s) found`);
              } else if (prog.status === "error") {
                sessionStorage.removeItem(`dast_exhaustive_job_${id}`);
                setFfufExhaustiveScanning(false);
                setFfufExhaustiveJobId(null);
                if (exhaustivePollRef.current) { clearInterval(exhaustivePollRef.current); exhaustivePollRef.current = null; }
              }
            } catch { sessionStorage.removeItem(`dast_exhaustive_job_${id}`); setFfufExhaustiveScanning(false); }
          };
          poll();
          exhaustivePollRef.current = setInterval(poll, 2000);
        }
        if (storedRecursive) {
          setRecursiveDirJobId(storedRecursive);
          setRecursiveDirScanning(true);
          const poll = async () => {
            try {
              const prog = await api.dastDirScanProgress(storedRecursive) as any;
              if (prog.status === "completed") {
                sessionStorage.removeItem(`dast_recursive_job_${id}`);
                setRecursiveDirScanning(false);
                setRecursiveDirJobId(null);
                if (recursiveDirPollRef.current) { clearInterval(recursiveDirPollRef.current); recursiveDirPollRef.current = null; }
                const flat = prog.flat || [];
                const dirs = flat.filter((x: any) => x.type === "dir" || (x.path || "").endsWith("/"));
                const files = flat.filter((x: any) => x.type !== "dir" && !(x.path || "").endsWith("/"));
                setRecursiveDirResult({ directories: dirs.length ? dirs : flat, files: files.length ? files : [], ...prog });
                toast.success(`Recursive scan complete: ${prog.total_found || flat.length} path(s) found`);
              } else if (prog.status === "error") {
                sessionStorage.removeItem(`dast_recursive_job_${id}`);
                setRecursiveDirScanning(false);
                setRecursiveDirJobId(null);
                if (recursiveDirPollRef.current) { clearInterval(recursiveDirPollRef.current); recursiveDirPollRef.current = null; }
              }
            } catch { sessionStorage.removeItem(`dast_recursive_job_${id}`); setRecursiveDirScanning(false); }
          };
          poll();
          recursiveDirPollRef.current = setInterval(poll, 2000);
        }
        // Resume Claude AI scan from sessionStorage
        const storedClaude = sessionStorage.getItem(`dast_claude_job_${id}`);
        if (storedClaude) {
          setClaudeScanId(storedClaude);
          setClaudeScanning(true);
          setDastActiveTab("claude");
          // Restore last progress snapshot immediately
          try {
            const savedProg = sessionStorage.getItem(`dast_claude_progress_${id}`);
            if (savedProg) setClaudeProgress(JSON.parse(savedProg));
          } catch {}
          const claudeResumePoll = async () => {
            try {
              const prog = await api.claudeDastScanProgress(storedClaude);
              setClaudeProgress(prog);
              try {
                sessionStorage.setItem(`dast_claude_progress_${id}`, JSON.stringify({
                  current_phase: prog.current_phase, current_activity: prog.current_activity,
                  findings_so_far: prog.findings_so_far, pages_crawled: prog.pages_crawled,
                  cost: prog.cost, activity_log: prog.activity_log, findings_by_severity: prog.findings_by_severity,
                  checks_completed: prog.checks_completed, tool_calls_used: prog.tool_calls_used,
                  progress_pct: prog.progress_pct, eta_seconds: prog.eta_seconds,
                  live_crawl_results: prog.live_crawl_results,
                }));
              } catch {}
              if (prog.live_crawl_results?.length > 0) {
                setClaudeCrawlResults((prev: any[]) => {
                  const urls = new Set((prev || []).map((p: any) => p.url));
                  const newItems = prog.live_crawl_results.filter((r: any) => !urls.has(r.url));
                  return newItems.length > 0 ? [...(prev || []), ...newItems] : prev;
                });
              }
              if (prog.status === "completed" || prog.status === "error" || prog.status === "stopped") {
                sessionStorage.removeItem(`dast_claude_job_${id}`);
                sessionStorage.removeItem(`dast_claude_progress_${id}`);
                setClaudeScanning(false);
                if (claudePollRef.current) { clearInterval(claudePollRef.current); claudePollRef.current = null; }
                if (prog.status === "completed") {
                  toast.success(`Scan complete: ${prog.total_findings || 0} findings`);
                  api.claudeDastHistory(id as string).then(setClaudeHistory).catch(() => {});
                  api.claudeDastCrawlResults(id as string).then(setClaudeCrawlResults).catch(() => {});
                  api.claudeDastSession(id as string).then(setClaudeSession).catch(() => {});
                }
              }
            } catch { sessionStorage.removeItem(`dast_claude_job_${id}`); setClaudeScanning(false); }
          };
          claudeResumePoll();
          claudePollRef.current = setInterval(claudeResumePoll, 2000);
        }
      } catch {}
      // If a scan is still running for this project, resume polling
      api.dastScans().then((r: any) => {
        const active = (r?.scans ?? []).find((s: any) => s.project_id === id && s.status === "running" && !s.scan_id?.startsWith("claude-"));
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
        // Also check for active Claude scans (fallback if sessionStorage was cleared)
        const activeClaude = (r?.scans ?? []).find((s: any) => s.project_id === id && s.status === "running" && s.scan_id?.startsWith("claude-"));
        if (activeClaude?.scan_id && !sessionStorage.getItem(`dast_claude_job_${id}`)) {
          setClaudeScanId(activeClaude.scan_id);
          setClaudeScanning(true);
          setDastActiveTab("claude");
          sessionStorage.setItem(`dast_claude_job_${id}`, activeClaude.scan_id);
          const claudeFallbackPoll = async () => {
            try {
              const prog = await api.claudeDastScanProgress(activeClaude.scan_id);
              setClaudeProgress(prog);
              if (prog.live_crawl_results?.length > 0) {
                setClaudeCrawlResults((prev: any[]) => {
                  const urls = new Set((prev || []).map((p: any) => p.url));
                  const newItems = prog.live_crawl_results.filter((r: any) => !urls.has(r.url));
                  return newItems.length > 0 ? [...(prev || []), ...newItems] : prev;
                });
              }
              if (prog.status === "completed" || prog.status === "error" || prog.status === "stopped") {
                sessionStorage.removeItem(`dast_claude_job_${id}`);
                sessionStorage.removeItem(`dast_claude_progress_${id}`);
                setClaudeScanning(false);
                if (claudePollRef.current) { clearInterval(claudePollRef.current); claudePollRef.current = null; }
                if (prog.status === "completed") {
                  toast.success(`Scan complete: ${prog.total_findings || 0} findings`);
                  api.claudeDastHistory(id as string).then(setClaudeHistory).catch(() => {});
                  api.claudeDastCrawlResults(id as string).then(setClaudeCrawlResults).catch(() => {});
                  api.claudeDastSession(id as string).then(setClaudeSession).catch(() => {});
                }
              }
            } catch {}
          };
          claudeFallbackPoll();
          claudePollRef.current = setInterval(claudeFallbackPoll, 2000);
        }
      }).catch(() => {});
    }
  }, [id]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      if (claudePollRef.current) clearInterval(claudePollRef.current);
      if (exhaustivePollRef.current) clearInterval(exhaustivePollRef.current);
      if (recursiveDirPollRef.current) clearInterval(recursiveDirPollRef.current);
      if (crawlPollRef.current) clearInterval(crawlPollRef.current);
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

  const discoveredPaths = (() => {
    const dirCheck = (scanResult?.results || []).find((r: any) => r.check_id === "DAST-DIR-02");
    return (dirCheck?.details?.discovered || []) as { path: string; status: number }[];
  })();

  const handleRunExhaustive = async () => {
    const target = scanResult?.target_url || project?.application_url;
    if (!target || !id) return;
    setFfufExhaustiveScanning(true);
    setFfufExhaustiveJobId(null);
    try {
      const res = await api.dastFfufExhaustive({ project_id: id as string, target_url: target, base_path: "/" }) as { job_id: string };
      setFfufExhaustiveJobId(res.job_id);
      try { sessionStorage.setItem(`dast_exhaustive_job_${id}`, res.job_id); } catch {}
      const poll = async () => {
        try {
          const prog = await api.dastFfufExhaustiveProgress(res.job_id) as { status: string; discovered?: { path: string; status: number }[]; wordlists_used?: string[]; test_case_updated?: boolean };
          if (prog.status === "completed") {
            try { sessionStorage.removeItem(`dast_exhaustive_job_${id}`); } catch {}
            setFfufExhaustiveScanning(false);
            setFfufExhaustiveJobId(null);
            if (exhaustivePollRef.current) { clearInterval(exhaustivePollRef.current); exhaustivePollRef.current = null; }
            const disc = prog.discovered || [];
            setFfufResults(prev => ({ ...prev, "/": { discovered: disc, wordlist_used: (prog.wordlists_used || []).join(", ") } }));
            const msg = disc.length > 0
              ? (prog.test_case_updated ? `Found ${disc.length} path(s). Directory Discovery test case auto-marked.` : `Found ${disc.length} path(s)`)
              : (prog.test_case_updated ? `Directory bruteforce completed. No paths discovered. Test case auto-marked. (Tip: Ensure ffuf is installed and target is reachable.)` : `Directory bruteforce completed. No paths discovered. (Tip: Install ffuf for better results.)`);
            toast.success(msg);
          } else if (prog.status === "error") {
            try { sessionStorage.removeItem(`dast_exhaustive_job_${id}`); } catch {}
            setFfufExhaustiveScanning(false);
            setFfufExhaustiveJobId(null);
            if (exhaustivePollRef.current) { clearInterval(exhaustivePollRef.current); exhaustivePollRef.current = null; }
            toast.error((prog as any).error || "Exhaustive scan failed");
          }
        } catch (_) {}
      };
      poll();
      exhaustivePollRef.current = setInterval(poll, 2000);
    } catch (e) {
      setFfufExhaustiveScanning(false);
      toast.error(e instanceof Error ? e.message : "Failed to start exhaustive scan");
    }
  };

  useEffect(() => () => { if (exhaustivePollRef.current) clearInterval(exhaustivePollRef.current); }, []);

  const handleRunFullWordlist = async (basePath: string) => {
    const target = scanResult?.target_url || project?.application_url;
    if (!target) return;
    setFfufScanning(basePath);
    try {
      const res = await api.dastFfufScan({
        target_url: target,
        base_path: basePath,
        wordlist: "small",
      }) as { success: boolean; discovered: { path: string; status: number }[]; wordlist_used: string; error?: string };
      if (res.success) {
        setFfufResults(prev => ({ ...prev, [basePath]: { discovered: res.discovered, wordlist_used: res.wordlist_used } }));
        const count = res.discovered.length;
        toast.success(count > 0 ? `Found ${count} path(s) under ${basePath}` : `No paths discovered under ${basePath}. (Ensure ffuf is installed and target is reachable.)`);
      } else {
        toast.error(res.error || "ffuf scan failed");
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "ffuf scan failed");
    } finally {
      setFfufScanning(null);
    }
  };

  // Build auth config from UI state
  const buildAuthConfig = () => {
    if (authType === "none") return null;
    if (authType === "header") return { type: "header", name: authHeaderName, value: authHeaderValue };
    if (authType === "cookie") return { type: "cookie", value: authCookieValue };
    if (authType === "custom_headers") {
      try {
        const parsed = JSON.parse(authCustomHeaders || "{}");
        return { type: "custom_headers", headers: parsed };
      } catch { return { type: "custom_headers", headers: {} }; }
    }
    return null;
  };

  // Start crawl
  const handleStartCrawl = async () => {
    if (!project) return;
    setCrawling(true);
    setCrawlProgress(null);
    setCrawlResult(null);
    setCrawlId(null);
    if (crawlPollRef.current) { clearInterval(crawlPollRef.current); crawlPollRef.current = null; }
    try {
      const res = await api.dastCrawl({
        project_id: id as string,
        auth_config: buildAuthConfig(),
        max_depth: crawlDepth,
        crawl_scope: crawlScope,
        run_param_discovery: runParamDiscovery,
        use_playwright: usePlaywright,
      }) as { crawl_id: string };
      setCrawlId(res.crawl_id);
      const poll = async () => {
        try {
          const prog = await api.dastCrawlProgress(res.crawl_id) as any;
          setCrawlProgress(prog);
          if (prog.status === "completed") {
            setCrawling(false);
            if (crawlPollRef.current) { clearInterval(crawlPollRef.current); crawlPollRef.current = null; }
            setCrawlResult(prog);
            toast.success(`Crawl complete! ${prog.stats?.total_urls || 0} URLs discovered`);
            api.dastCrawlHistory(id as string, 20).then((r: any) => setCrawlHistory(r?.sessions ?? [])).catch(() => {});
          } else if (prog.status === "error") {
            setCrawling(false);
            if (crawlPollRef.current) { clearInterval(crawlPollRef.current); crawlPollRef.current = null; }
            toast.error(prog.error || "Crawl failed");
          }
        } catch (_) {}
      };
      poll();
      crawlPollRef.current = setInterval(poll, 2000);
    } catch (err: any) {
      setCrawling(false);
      toast.error(err?.message || "Crawl failed");
    }
  };

  // Load crawl history on mount
  useEffect(() => {
    if (id) {
      api.dastCrawlHistory(id as string, 20).then((r: any) => setCrawlHistory(r?.sessions ?? [])).catch(() => {});
      api.dastCrawlLatest(id as string).then((r: any) => {
        setCrawlResult({
          urls: r.urls || [], api_endpoints: r.api_endpoints || [], parameters: r.parameters || [],
          forms: r.forms || [], js_files: r.js_files || [], pages: r.pages || [],
          deeplinks: r.deeplinks || [], js_sca: r.js_sca, retire_results: r.retire_results, crawler_used: r.crawler_used,
          stats: {
            total_urls: r.total_urls, api_endpoints: r.total_endpoints, parameters: r.total_parameters,
            forms: r.forms?.length || 0, js_files: r.total_js_files || r.js_files?.length || 0,
            total_deeplinks: r.deeplinks?.length || 0, total_hidden_urls: r.stats?.total_hidden_urls || 0,
            crawler_used: r.crawler_used, total_secrets_found: r.stats?.total_secrets_found || 0,
          },
          created_at: r.created_at, crawl_type: r.crawl_type, auth_type: r.auth_type,
        });
      }).catch(() => {});
    }
  }, [id]);

  useEffect(() => () => {
    if (crawlPollRef.current) clearInterval(crawlPollRef.current);
    if (recursiveDirPollRef.current) clearInterval(recursiveDirPollRef.current);
  }, []);

  // Recursive directory scan
  const handleRecursiveDirScan = async () => {
    const target = scanResult?.target_url || project?.application_url;
    if (!target || !id) return;
    setRecursiveDirScanning(true);
    setRecursiveDirResult(null);
    setRecursiveDirJobId(null);
    try {
      const res = await api.dastDirScan({
        project_id: id as string,
        target_url: target,
        base_path: "/",
        max_depth: recursiveDirDepth,
        wordlist: "small",
        auth_config: buildAuthConfig(),
      }) as { job_id: string };
      setRecursiveDirJobId(res.job_id);
      try { sessionStorage.setItem(`dast_recursive_job_${id}`, res.job_id); } catch {}
      const poll = async () => {
        try {
          const prog = await api.dastDirScanProgress(res.job_id) as any;
          if (prog.status === "completed") {
            try { sessionStorage.removeItem(`dast_recursive_job_${id}`); } catch {}
            setRecursiveDirScanning(false);
            if (recursiveDirPollRef.current) { clearInterval(recursiveDirPollRef.current); recursiveDirPollRef.current = null; }
            setRecursiveDirResult(prog);
            toast.success(`Recursive scan complete! ${prog.total_found || 0} paths found across ${prog.depths_scanned || 0} depth levels`);
          } else if (prog.status === "error") {
            try { sessionStorage.removeItem(`dast_recursive_job_${id}`); } catch {}
            setRecursiveDirScanning(false);
            if (recursiveDirPollRef.current) { clearInterval(recursiveDirPollRef.current); recursiveDirPollRef.current = null; }
            toast.error(prog.error || "Recursive scan failed");
          }
        } catch (_) {}
      };
      poll();
      recursiveDirPollRef.current = setInterval(poll, 2000);
    } catch (err: any) {
      setRecursiveDirScanning(false);
      toast.error(err?.message || "Failed to start recursive scan");
    }
  };

  // Fetch URL content
  const handleFetchUrl = async (url: string) => {
    if (urlContent[url]) return; // Already fetched
    setFetchingUrl(url);
    try {
      const res = await api.dastFetchUrl({ url, auth_config: buildAuthConfig() }) as any;
      setUrlContent(prev => ({ ...prev, [url]: res }));
    } catch (err: any) {
      setUrlContent(prev => ({ ...prev, [url]: { error: err?.message || "Failed to fetch" } }));
    } finally {
      setFetchingUrl(null);
    }
  };

  // Auto-expand all checks when results first load so request/response/payload visible for each; default filter to failed
  useEffect(() => {
    if (scanResult?.results && !initialExpandDone) {
      const results = scanResult.results as any[];
      const allIds = new Set(results.map((r: any) => r.check_id));
      setExpandedResults(prev => new Set([...Array.from(prev), ...Array.from(allIds)]));
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

  const loadSchedule = useCallback(async () => {
    if (!id) return;
    setScheduleLoading(true);
    try {
      const data = await api.dastGetSchedule(id as string);
      setSchedule(data);
      if (data?.cron_expression) setCronExpression(data.cron_expression);
    } catch { setSchedule(null); }
    finally { setScheduleLoading(false); }
  }, [id]);

  const loadBaselines = useCallback(async () => {
    if (!id) return;
    setBaselinesLoading(true);
    try {
      const data = await api.dastBaselines(id as string);
      setBaselines(data?.baselines || []);
    } catch { setBaselines([]); }
    finally { setBaselinesLoading(false); }
  }, [id]);

  if (!user) return null;

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-5xl mx-auto p-6 space-y-6">
        {/* Project Sub-Navigation */}
        <ProjectSubNav
          projectId={id as string}
          projectName={project?.application_name}
          projectUrl={project?.application_url}
          sastEnabled={orgSettings.sast_enabled}
        />
        {/* DAST Controls */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>
              DAST Automated Scan
            </h2>
            <div className="flex items-center gap-3 mt-1 flex-wrap">
              {project?.app_owner_name && <span className="text-xs" style={{ color: "var(--text-muted)" }}>Owner: {project.app_owner_name}</span>}
              {project?.testing_type && <><span className="text-[#374151]">|</span><span className="text-xs" style={{ color: "var(--text-muted)" }}>Type: {project.testing_type.replace("_", " ")}</span></>}
              {project?.environment && <><span className="text-[#374151]">|</span><span className="text-xs" style={{ color: "var(--text-muted)" }}>Env: {project.environment}</span></>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => { setShowSchedule(!showSchedule); if (!schedule) loadSchedule(); }}
              className="p-2 rounded-lg border hover:bg-white/5 transition-colors"
              style={{ borderColor: showSchedule ? "#8b5cf633" : "var(--border-subtle)", color: showSchedule ? "#8b5cf6" : "var(--text-secondary)" }}
              title="Scan Schedule"
            >
              <Calendar size={16} />
            </button>
            <button
              onClick={() => { setShowBaselines(!showBaselines); if (baselines.length === 0) loadBaselines(); }}
              className="p-2 rounded-lg border hover:bg-white/5 transition-colors"
              style={{ borderColor: showBaselines ? "#06b6d433" : "var(--border-subtle)", color: showBaselines ? "#06b6d4" : "var(--text-secondary)" }}
              title="Baselines & Trends"
            >
              <Activity size={16} />
            </button>
            <button
              onClick={async () => {
                setAiSuggestLoading(true);
                try {
                  const res = await api.dastAiSuggestChecks({ project_id: id as string, target_url: project?.application_url });
                  setAiSuggestedChecks(res);
                  if (res.priority_checks?.length) {
                    const matching = res.priority_checks.filter((c: string) => availableChecks.some((ac: any) => ac.id === c));
                    if (matching.length) { setSelectedChecks(matching); toast.success(`AI selected ${matching.length} priority checks`); }
                  }
                } catch (e: any) { toast.error("AI suggest failed"); }
                setAiSuggestLoading(false);
              }}
              disabled={aiSuggestLoading || scanning}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium disabled:opacity-50 transition-all hover:scale-105"
              style={{ background: "rgba(124,58,237,0.15)", color: "#c4b5fd", border: "1px solid rgba(124,58,237,0.3)" }}
            >
              {aiSuggestLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              AI Suggest
            </button>
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
        </div>
        {/* AI Suggested Checks Reasoning */}
        {aiSuggestedChecks?.reasoning && (
          <div className="rounded-xl p-3" style={{ background: "rgba(124,58,237,0.06)", border: "1px solid rgba(124,58,237,0.15)" }}>
            <div className="flex items-start gap-2">
              <Zap className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" style={{ color: "#7c3aed" }} />
              <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{aiSuggestedChecks.reasoning}</p>
            </div>
          </div>
        )}

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
                  <button
                    key={s.id || s.scan_id}
                    type="button"
                    onClick={async () => {
                      try {
                        const data = await api.dastProjectScan(id as string, s.scan_id);
                        setScanResult(data);
                        setDastActiveTab("results");
                        hasSetFilterForScan.current = null;
                        setInitialExpandDone(false);
                        toast.success("Loaded scan from " + (s.created_at ? new Date(s.created_at).toLocaleString() : "history"));
                      } catch (e) {
                        toast.error("Failed to load scan");
                      }
                    }}
                    className="w-full flex gap-4 py-1.5 px-2 text-xs rounded hover:bg-white/10 cursor-pointer text-left transition-colors"
                    style={{ borderBottom: "1px solid var(--border-subtle)" }}
                    title={`Click to view vulnerabilities — ${s.target_url || ""}`}
                  >
                    <span className="flex-1 min-w-[130px]" style={{ color: "var(--text-secondary)" }}>{s.created_at ? new Date(s.created_at).toLocaleString() : "—"}</span>
                    <span className="w-10" style={{ color: "var(--text-primary)" }}>{s.total_checks ?? "-"}</span>
                    <span className="w-8" style={{ color: "#16a34a" }}>{s.passed ?? 0}</span>
                    <span className="w-8" style={{ color: "#dc2626" }}>{s.failed ?? 0}</span>
                    <span className="w-10" style={{ color: "var(--text-muted)" }}>{s.duration_seconds ?? 0}s</span>
                  </button>
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

        {/* Results - Scan Complete: Always show tabs when project loaded so Directory Bruteforce & Spider are accessible */}
        {project && (
          <div className="space-y-4">
            {/* Tabs: Scan Results | Directory Bruteforce | Spider / Crawl — scroll on narrow screens */}
            <div className="flex flex-nowrap overflow-x-auto gap-1 p-1 rounded-xl" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
              <button
                onClick={() => setDastActiveTab("results")}
                className={`flex-shrink-0 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${dastActiveTab === "results" ? "text-white" : ""}`}
                style={{
                  background: dastActiveTab === "results" ? "var(--accent-indigo)" : "transparent",
                  color: dastActiveTab === "results" ? "white" : "var(--text-secondary)",
                }}
              >
                <Shield className="w-4 h-4" />
                Scan Results
              </button>
              <button
                onClick={() => setDastActiveTab("directories")}
                className={`flex-shrink-0 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${dastActiveTab === "directories" ? "text-white" : ""}`}
                style={{
                  background: dastActiveTab === "directories" ? "var(--accent-indigo)" : "transparent",
                  color: dastActiveTab === "directories" ? "white" : "var(--text-secondary)",
                }}
              >
                <Folder className="w-4 h-4" />
                Directory Bruteforce
                {allDiscoveredPaths.length > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-xs" style={{ background: dastActiveTab === "directories" ? "rgba(255,255,255,0.25)" : "rgba(37,99,235,0.2)", color: "inherit" }}>{allDiscoveredPaths.length}</span>
                )}
              </button>
              <button
                onClick={() => setDastActiveTab("crawl")}
                className={`flex-shrink-0 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${dastActiveTab === "crawl" ? "text-white" : ""}`}
                style={{
                  background: dastActiveTab === "crawl" ? "#7c3aed" : "transparent",
                  color: dastActiveTab === "crawl" ? "white" : "var(--text-secondary)",
                }}
              >
                <Bug className="w-4 h-4" />
                Spider / Crawl
                {crawlResult?.stats?.total_urls > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-xs" style={{ background: dastActiveTab === "crawl" ? "rgba(255,255,255,0.25)" : "rgba(124,58,237,0.2)", color: "inherit" }}>{crawlResult.stats.total_urls}</span>
                )}
              </button>
              <button
                onClick={() => {
                  setDastActiveTab("claude");
                  if (!claudeSession && id) {
                    api.claudeDastSession(id as string).then(setClaudeSession).catch(() => {});
                    api.claudeDastHistory(id as string).then(setClaudeHistory).catch(() => {});
                    api.claudeDastCostEstimate({ scan_mode: claudeScanMode, target_url: project?.application_url || "" }).then(setClaudeCostEstimate).catch(() => {});
                  }
                }}
                className={`flex-shrink-0 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${dastActiveTab === "claude" ? "text-white" : ""}`}
                style={{
                  background: dastActiveTab === "claude" ? "linear-gradient(135deg, #d97706 0%, #ea580c 100%)" : "transparent",
                  color: dastActiveTab === "claude" ? "white" : "var(--text-secondary)",
                }}
              >
                <Brain className="w-4 h-4" />
                Claude AI DAST
                {claudeScanning && (
                  <Loader2 className="w-3 h-3 animate-spin" />
                )}
              </button>
            </div>

            {/* ─── Crawl Tab ─── */}
            {dastActiveTab === "crawl" && (
              <div className="space-y-4">
                {/* Auth Configuration */}
                <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                  <div className="p-4 space-y-4">
                    <div className="flex items-center justify-between flex-wrap gap-3">
                      <div>
                        <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                          <Bug className="w-4 h-4" style={{ color: "#7c3aed" }} />
                          Spider / Crawler Engine
                        </h2>
                        <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                          Powered by Katana + Arjun — discovers all URLs, API endpoints, parameters, forms, and JS files
                        </p>
                      </div>
                      <button
                        onClick={handleStartCrawl}
                        disabled={crawling}
                        className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium text-white transition-all"
                        style={{ background: crawling ? "#4b5563" : "#7c3aed" }}
                      >
                        {crawling ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                        {crawling ? "Crawling..." : "Start Crawl"}
                      </button>
                    </div>

                    {/* Settings Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div>
                        <label className="text-xs font-medium mb-1 block" style={{ color: "var(--text-secondary)" }}>Crawl Depth</label>
                        <select value={crawlDepth} onChange={(e) => setCrawlDepth(Number(e.target.value))} className="w-full px-3 py-2 rounded-lg text-sm" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}>
                          {[1,2,3,4,5].map(d => <option key={d} value={d}>Depth {d}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="text-xs font-medium mb-1 block" style={{ color: "var(--text-secondary)" }}>Crawl Scope</label>
                        <select value={crawlScope} onChange={(e) => setCrawlScope(e.target.value)} className="w-full px-3 py-2 rounded-lg text-sm" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}>
                          <option value="host">Same Host Only</option>
                          <option value="subdomain">Include Subdomains</option>
                          <option value="all">All Domains</option>
                        </select>
                      </div>
                      <div className="flex flex-col gap-2">
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input type="checkbox" checked={runParamDiscovery} onChange={(e) => setRunParamDiscovery(e.target.checked)} className="rounded" />
                          <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>Parameter Discovery (Arjun)</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input type="checkbox" checked={usePlaywright} onChange={(e) => setUsePlaywright(e.target.checked)} className="rounded" />
                          <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>JS/SPA (Playwright)</span>
                        </label>
                      </div>
                    </div>

                    {/* Authentication Section */}
                    <div className="rounded-lg p-3 space-y-3" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                      <div className="flex items-center gap-2">
                        <Key className="w-4 h-4" style={{ color: "#7c3aed" }} />
                        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Authentication</span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {[
                          { key: "none", label: "No Auth", icon: Globe },
                          { key: "header", label: "Auth Header", icon: Key },
                          { key: "cookie", label: "Cookie", icon: Cookie },
                          { key: "custom_headers", label: "Custom Headers", icon: Braces },
                        ].map(opt => (
                          <button key={opt.key} onClick={() => setAuthType(opt.key)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
                            style={{
                              background: authType === opt.key ? "rgba(124,58,237,0.15)" : "var(--bg-primary)",
                              border: `1px solid ${authType === opt.key ? "rgba(124,58,237,0.4)" : "var(--border-subtle)"}`,
                              color: authType === opt.key ? "#7c3aed" : "var(--text-secondary)",
                            }}>
                            <opt.icon className="w-3 h-3" /> {opt.label}
                          </button>
                        ))}
                      </div>
                      {authType === "header" && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          <input type="text" placeholder="Header Name (e.g. Authorization)" value={authHeaderName} onChange={(e) => setAuthHeaderName(e.target.value)}
                            className="px-3 py-2 rounded-lg text-xs" style={{ background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }} />
                          <input type="text" placeholder="Header Value (e.g. Bearer eyJ...)" value={authHeaderValue} onChange={(e) => setAuthHeaderValue(e.target.value)}
                            className="px-3 py-2 rounded-lg text-xs" style={{ background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }} />
                        </div>
                      )}
                      {authType === "cookie" && (
                        <input type="text" placeholder="Cookie string (e.g. session=abc123; token=xyz)" value={authCookieValue} onChange={(e) => setAuthCookieValue(e.target.value)}
                          className="w-full px-3 py-2 rounded-lg text-xs" style={{ background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }} />
                      )}
                      {authType === "custom_headers" && (
                        <textarea placeholder='JSON headers: {"X-API-Key": "xxx", "Cookie": "session=abc"}' value={authCustomHeaders} onChange={(e) => setAuthCustomHeaders(e.target.value)} rows={3}
                          className="w-full px-3 py-2 rounded-lg text-xs font-mono" style={{ background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }} />
                      )}
                    </div>
                  </div>
                </div>

                {/* Crawl Progress */}
                {crawling && crawlProgress && (
                  <div className="rounded-xl p-4 space-y-3" style={{ background: "var(--bg-card)", border: "1px solid rgba(124,58,237,0.3)" }}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Radio className="w-4 h-4 animate-pulse" style={{ color: "#7c3aed" }} />
                        <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Crawling in Progress</span>
                      </div>
                      <span className="text-xs" style={{ color: "var(--text-muted)" }}>{crawlProgress.pct || 0}%</span>
                    </div>
                    <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${crawlProgress.pct || 0}%`, background: "#7c3aed" }} />
                    </div>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>{crawlProgress.message || "Working..."}</p>
                    {crawlProgress.stats && (
                      <div className="flex flex-wrap gap-3 text-xs">
                        <span style={{ color: "#7c3aed" }}>{crawlProgress.stats.total_urls || 0} URLs</span>
                        <span style={{ color: "#16a34a" }}>{crawlProgress.stats.api_endpoints || 0} APIs</span>
                        <span style={{ color: "#ca8a04" }}>{crawlProgress.stats.parameters || 0} Params</span>
                        <span style={{ color: "#3b82f6" }}>{crawlProgress.stats.forms || 0} Forms</span>
                        <span style={{ color: "#ea580c" }}>{crawlProgress.stats.js_files || 0} JS</span>
                        {(crawlProgress.stats.total_secrets_found || 0) > 0 && (
                          <span style={{ color: "#dc2626" }}>{crawlProgress.stats.total_secrets_found} Secrets</span>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Crawl Results */}
                {crawlResult && (
                  <div className="space-y-3">
                    {/* Stats Bar */}
                    <div className="rounded-xl p-3 flex flex-wrap items-center gap-4" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                      <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Crawl Results</span>
                      {crawlResult.created_at && <span className="text-xs" style={{ color: "var(--text-muted)" }}>{new Date(crawlResult.created_at).toLocaleString()}</span>}
                      {crawlResult.crawler_used && (
                        <span className="px-2 py-0.5 rounded text-xs font-medium" style={{ background: "rgba(16,185,129,0.15)", color: "#10b981" }}>{crawlResult.crawler_used}</span>
                      )}
                      <div className="flex flex-wrap gap-3 text-xs ml-auto">
                        <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(124,58,237,0.1)", color: "#7c3aed" }}>
                          <Link2 className="w-3 h-3" /> {crawlResult.stats?.total_urls || crawlResult.urls?.length || 0} URLs
                        </span>
                        <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(22,163,74,0.1)", color: "#16a34a" }}>
                          <Globe className="w-3 h-3" /> {crawlResult.stats?.api_endpoints || crawlResult.api_endpoints?.length || 0} APIs
                        </span>
                        <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(202,138,4,0.1)", color: "#ca8a04" }}>
                          <Hash className="w-3 h-3" /> {crawlResult.stats?.parameters || crawlResult.parameters?.length || 0} Params
                        </span>
                        <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(59,130,246,0.1)", color: "#3b82f6" }}>
                          <FormInput className="w-3 h-3" /> {crawlResult.forms?.length || 0} Forms
                        </span>
                        <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(234,88,12,0.1)", color: "#ea580c" }}>
                          <Code className="w-3 h-3" /> {crawlResult.js_files?.length || 0} JS
                        </span>
                        {(crawlResult.stats?.total_secrets_found || 0) > 0 && (
                          <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(220,38,38,0.1)", color: "#dc2626" }}>
                            <Key className="w-3 h-3" /> {crawlResult.stats.total_secrets_found} Secrets
                          </span>
                        )}
                        {(crawlResult.stats?.total_deeplinks || crawlResult.deeplinks?.length || 0) > 0 && (
                          <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(139,92,246,0.1)", color: "#8b5cf6" }}>
                            <Link2 className="w-3 h-3" /> {crawlResult.stats?.total_deeplinks || crawlResult.deeplinks?.length || 0} Deeplinks
                          </span>
                        )}
                        {(crawlResult.stats?.total_hidden_urls || 0) > 0 && (
                          <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(99,102,241,0.1)", color: "#6366f1" }}>
                            <Link2 className="w-3 h-3" /> {crawlResult.stats?.total_hidden_urls || 0} Hidden URLs
                          </span>
                        )}
                        {crawlResult.retire_results?.total_vulns > 0 && (
                          <span className="flex items-center gap-1 px-2 py-1 rounded" style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444" }}>
                            <Layers className="w-3 h-3" /> {crawlResult.retire_results.total_vulns} Retire
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Sub-tabs */}
                    <div className="flex flex-wrap gap-1 p-1 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                      {([
                        { key: "urls", label: "All URLs", count: crawlResult.urls?.length || 0 },
                        { key: "api", label: "API Endpoints", count: crawlResult.api_endpoints?.length || 0 },
                        { key: "params", label: "Parameters", count: crawlResult.parameters?.length || 0 },
                        { key: "forms", label: "Forms", count: crawlResult.forms?.length || 0 },
                        { key: "js", label: "JS Files", count: crawlResult.js_files?.length || 0 },
                        { key: "deeplinks", label: "Deeplinks", count: crawlResult.deeplinks?.length || 0 },
                        { key: "sca", label: "JS SCA", count: (crawlResult.js_sca?.vulnerabilities?.length || 0) + (crawlResult.retire_results?.total_vulns || 0) || crawlResult.js_sca?.libraries?.length || 0 },
                        { key: "ai", label: "🤖 AI Analysis", count: aiCrawlAnalysis ? 1 : 0 },
                      ] as const).map(tab => (
                        <button key={tab.key} onClick={() => setCrawlActiveSubTab(tab.key)}
                          className="px-3 py-1.5 rounded text-xs font-medium transition-all"
                          style={{
                            background: crawlActiveSubTab === tab.key ? "#7c3aed" : "transparent",
                            color: crawlActiveSubTab === tab.key ? "white" : "var(--text-secondary)",
                          }}>
                          {tab.label} {tab.count > 0 && <span className="ml-1 opacity-75">({tab.count})</span>}
                        </button>
                      ))}
                    </div>

                    {/* Search */}
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                      <input type="text" placeholder="Filter URLs..." value={crawlUrlFilter} onChange={(e) => setCrawlUrlFilter(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 rounded-lg text-xs" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }} />
                    </div>

                    {/* Content */}
                    <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                      <div className="max-h-[500px] overflow-y-auto">
                        {crawlActiveSubTab === "urls" && (
                          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
                            {(crawlResult.urls || []).filter((u: any) => !crawlUrlFilter || (u.url || u).toLowerCase().includes(crawlUrlFilter.toLowerCase())).slice(0, 200).map((u: any, i: number) => {
                              const url = typeof u === "string" ? u : u.url;
                              const method = u.method || "GET";
                              const status = u.status_code;
                              return (
                                <div key={i} className="flex items-center gap-2 px-3 py-2 hover:bg-white/5 text-xs group">
                                  <span className="px-1.5 py-0.5 rounded font-mono font-medium shrink-0" style={{ background: method === "GET" ? "rgba(22,163,74,0.15)" : method === "POST" ? "rgba(59,130,246,0.15)" : "rgba(202,138,4,0.15)", color: method === "GET" ? "#16a34a" : method === "POST" ? "#3b82f6" : "#ca8a04", fontSize: "10px" }}>{method}</span>
                                  <span className="font-mono truncate flex-1 min-w-0" style={{ color: "var(--text-primary)" }}>{url}</span>
                                  {status && <span className="shrink-0 font-mono" style={{ color: status >= 200 && status < 300 ? "#16a34a" : status >= 400 ? "#dc2626" : "#ca8a04" }}>{status}</span>}
                                </div>
                              );
                            })}
                            {(crawlResult.urls || []).length === 0 && <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No URLs discovered yet. Start a crawl to discover endpoints.</div>}
                          </div>
                        )}
                        {crawlActiveSubTab === "api" && (
                          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
                            {(crawlResult.api_endpoints || []).filter((e: any) => !crawlUrlFilter || (e.url || "").toLowerCase().includes(crawlUrlFilter.toLowerCase())).map((ep: any, i: number) => (
                              <div key={i} className="px-3 py-2.5 hover:bg-white/5">
                                <div className="flex items-center gap-2">
                                  <span className="px-1.5 py-0.5 rounded font-mono font-bold shrink-0 text-xs" style={{ background: (ep.method || "GET") === "GET" ? "rgba(22,163,74,0.15)" : "rgba(59,130,246,0.15)", color: (ep.method || "GET") === "GET" ? "#16a34a" : "#3b82f6" }}>{ep.method || "GET"}</span>
                                  <span className="font-mono text-xs truncate flex-1" style={{ color: "var(--text-primary)" }}>{ep.url}</span>
                                  {ep.status_code && <span className="text-xs font-mono shrink-0" style={{ color: ep.status_code < 300 ? "#16a34a" : "#ca8a04" }}>{ep.status_code}</span>}
                                </div>
                                {(ep.parameters?.length > 0 || ep.body_params?.length > 0) && (
                                  <div className="flex flex-wrap gap-1 mt-1.5 ml-10">
                                    {(ep.parameters || []).map((p: string, j: number) => <span key={j} className="px-1.5 py-0.5 rounded font-mono" style={{ background: "rgba(202,138,4,0.1)", color: "#ca8a04", fontSize: "10px" }}>?{p}</span>)}
                                    {(ep.body_params || []).map((p: string, j: number) => <span key={`b-${j}`} className="px-1.5 py-0.5 rounded font-mono" style={{ background: "rgba(124,58,237,0.1)", color: "#7c3aed", fontSize: "10px" }}>{p}</span>)}
                                  </div>
                                )}
                              </div>
                            ))}
                            {(crawlResult.api_endpoints || []).length === 0 && <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No API endpoints discovered.</div>}
                          </div>
                        )}
                        {crawlActiveSubTab === "params" && (
                          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
                            {(crawlResult.parameters || []).filter((p: any) => !crawlUrlFilter || (p.name || "").toLowerCase().includes(crawlUrlFilter.toLowerCase()) || (p.url || "").toLowerCase().includes(crawlUrlFilter.toLowerCase())).map((param: any, i: number) => (
                              <div key={i} className="px-3 py-2 hover:bg-white/5 text-xs">
                                <div className="flex items-center gap-2">
                                  <Hash className="w-3 h-3 shrink-0" style={{ color: "#ca8a04" }} />
                                  <span className="font-mono font-medium" style={{ color: "#ca8a04" }}>{param.name}</span>
                                  <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>{param.source || "query"}</span>
                                </div>
                                <span className="font-mono ml-5 block truncate" style={{ color: "var(--text-muted)", fontSize: "10px" }}>{param.url}</span>
                              </div>
                            ))}
                            {(crawlResult.parameters || []).length === 0 && <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No parameters discovered.</div>}
                          </div>
                        )}
                        {crawlActiveSubTab === "forms" && (
                          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
                            {(crawlResult.forms || []).map((form: any, i: number) => (
                              <div key={i} className="px-3 py-2.5 hover:bg-white/5 text-xs">
                                <div className="flex items-center gap-2">
                                  <FormInput className="w-3.5 h-3.5 shrink-0" style={{ color: "#3b82f6" }} />
                                  <span className="px-1.5 py-0.5 rounded font-mono font-medium" style={{ background: "rgba(59,130,246,0.15)", color: "#3b82f6", fontSize: "10px" }}>{form.method || "POST"}</span>
                                  <span className="font-mono truncate flex-1" style={{ color: "var(--text-primary)" }}>{form.url || form.action}</span>
                                </div>
                                {form.parameters?.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1.5 ml-6">
                                    {form.parameters.map((p: any, j: number) => <span key={j} className="px-1.5 py-0.5 rounded font-mono" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", fontSize: "10px" }}>{typeof p === "string" ? p : `${p.name}${p.type ? ` [${p.type}]` : ""}`}</span>)}
                                  </div>
                                )}
                              </div>
                            ))}
                            {(crawlResult.forms || []).length === 0 && <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No forms discovered.</div>}
                          </div>
                        )}
                        {crawlActiveSubTab === "js" && (
                          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
                            {(crawlResult.js_files || []).filter((j: any) => !crawlUrlFilter || (j.url || j).toLowerCase().includes(crawlUrlFilter.toLowerCase())).map((js: any, i: number) => (
                              <details key={i} className="group">
                                <summary className="px-3 py-2.5 hover:bg-white/5 text-xs cursor-pointer list-none flex items-center gap-2">
                                  <ChevronRight className="w-3 h-3 shrink-0 transition-transform group-open:rotate-90" style={{ color: "var(--text-muted)" }} />
                                  <Code className="w-3.5 h-3.5 shrink-0" style={{ color: "#ea580c" }} />
                                  <a href={typeof js === "string" ? js : js.url} target="_blank" rel="noopener noreferrer" className="font-mono truncate flex-1 min-w-0 hover:underline" style={{ color: "#3b82f6" }} onClick={(e) => e.stopPropagation()}>{typeof js === "string" ? js : js.url}</a>
                                  {js.status_code && <span className="font-mono shrink-0" style={{ color: js.status_code < 300 ? "#16a34a" : "#ca8a04" }}>{js.status_code}</span>}
                                  {js.secrets_count > 0 && <span className="px-1.5 py-0.5 rounded font-medium shrink-0" style={{ background: "rgba(220,38,38,0.15)", color: "#dc2626" }}>{js.secrets_count} secret{js.secrets_count !== 1 ? "s" : ""}</span>}
                                  {js.retire_vulns?.length > 0 && <span className="px-1.5 py-0.5 rounded font-medium shrink-0" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>{js.retire_vulns.length} vuln{js.retire_vulns.length !== 1 ? "s" : ""}</span>}
                                </summary>
                                <div className="pl-6 pr-3 pb-2 space-y-2">
                                  {js.secrets?.length > 0 && (
                                    <div className="space-y-1">
                                      <span className="text-[10px] font-medium" style={{ color: "var(--text-muted)" }}>Secrets</span>
                                      {js.secrets.slice(0, 5).map((s: any, si: number) => (
                                        <div key={si} className="px-2 py-1 rounded" style={{ background: "rgba(220,38,38,0.08)", border: "1px solid rgba(220,38,38,0.2)" }}>
                                          <span className="font-medium" style={{ color: "#dc2626" }}>{s.rule_name}</span>
                                          <span className="block font-mono text-[10px] mt-0.5 truncate" style={{ color: "var(--text-muted)" }}>{s.match_preview}</span>
                                        </div>
                                      ))}
                                      {js.secrets.length > 5 && <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>+{js.secrets.length - 5} more</span>}
                                    </div>
                                  )}
                                  {js.retire_vulns?.length > 0 && (
                                    <div className="space-y-1">
                                      <span className="text-[10px] font-medium" style={{ color: "var(--text-muted)" }}>Retire.js</span>
                                      {js.retire_vulns.slice(0, 5).map((v: any, vi: number) => (
                                        <div key={vi} className="px-2 py-1 rounded" style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)" }}>
                                          <span className="font-medium" style={{ color: "#ef4444" }}>{v.library?.name || v.component} {v.version}</span>
                                          {v.identifiers?.CVE && <span className="block font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>{v.identifiers.CVE.join(", ")}</span>}
                                        </div>
                                      ))}
                                      {js.retire_vulns.length > 5 && <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>+{js.retire_vulns.length - 5} more</span>}
                                    </div>
                                  )}
                                  {js.hidden_urls?.length > 0 && (
                                    <div className="space-y-1">
                                      <span className="text-[10px] font-medium" style={{ color: "var(--text-muted)" }}>Hidden URLs</span>
                                      <div className="flex flex-wrap gap-1">
                                        {js.hidden_urls.slice(0, 8).map((u: any, ui: number) => (
                                          <a key={ui} href={u.url || u} target="_blank" rel="noopener noreferrer" className="px-1.5 py-0.5 rounded font-mono text-[10px] truncate max-w-[200px] hover:underline" style={{ background: "var(--bg-elevated)", color: "#6366f1" }}>{u.url || u}</a>
                                        ))}
                                        {js.hidden_urls.length > 8 && <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>+{js.hidden_urls.length - 8} more</span>}
                                      </div>
                                    </div>
                                  )}
                                  {js.deeplinks?.length > 0 && (
                                    <div className="space-y-1">
                                      <span className="text-[10px] font-medium" style={{ color: "var(--text-muted)" }}>Deeplinks</span>
                                      <div className="flex flex-wrap gap-1">
                                        {js.deeplinks.slice(0, 5).map((d: string, di: number) => (
                                          <span key={di} className="px-1.5 py-0.5 rounded font-mono text-[10px]" style={{ background: "rgba(139,92,246,0.15)", color: "#8b5cf6" }}>{d}</span>
                                        ))}
                                        {js.deeplinks.length > 5 && <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>+{js.deeplinks.length - 5} more</span>}
                                      </div>
                                    </div>
                                  )}
                                  {js.libraries?.length > 0 && (
                                    <div className="space-y-1">
                                      <span className="text-[10px] font-medium" style={{ color: "var(--text-muted)" }}>Libraries</span>
                                      <div className="flex flex-wrap gap-1">
                                        {js.libraries.map((lib: any, li: number) => (
                                          <span key={li} className="px-1.5 py-0.5 rounded font-mono text-[10px]" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>{lib.name}@{lib.version}</span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </details>
                            ))}
                            {(crawlResult.js_files || []).length === 0 && <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No JavaScript files discovered.</div>}
                          </div>
                        )}
                        {crawlActiveSubTab === "deeplinks" && (
                          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
                            {(crawlResult.deeplinks || []).map((d: string, i: number) => (
                              <div key={i} className="flex items-center gap-2 px-3 py-2 hover:bg-white/5 text-xs group">
                                <Link2 className="w-3.5 h-3.5 shrink-0" style={{ color: "#8b5cf6" }} />
                                <span className="font-mono truncate flex-1" style={{ color: "var(--text-primary)" }}>{d}</span>
                                <button onClick={() => { navigator.clipboard.writeText(d); toast.success("Copied"); }} className="opacity-0 group-hover:opacity-100 px-2 py-0.5 rounded text-[10px]" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>Copy</button>
                              </div>
                            ))}
                            {(crawlResult.deeplinks || []).length === 0 && <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No deeplinks discovered.</div>}
                          </div>
                        )}
                        {crawlActiveSubTab === "sca" && (
                          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
                            {crawlResult.js_sca?.vulnerabilities?.map((v: any, i: number) => (
                              <div key={`sca-${i}`} className="px-3 py-2.5 hover:bg-white/5">
                                <div className="flex items-center gap-2">
                                  <Layers className="w-3.5 h-3.5 shrink-0" style={{ color: "#ef4444" }} />
                                  <span className="font-mono font-medium" style={{ color: "#ef4444" }}>{v.name}@{v.version}</span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>vulnerable</span>
                                </div>
                                <div className="ml-6 mt-1 font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>{(v.cves || []).join(", ")}</div>
                              </div>
                            ))}
                            {(crawlResult.retire_results?.data || []).flatMap((d: any, di: number) => (d.vulnerabilities || []).map((v: any, vi: number) => (
                              <div key={`retire-${di}-${vi}`} className="px-3 py-2.5 hover:bg-white/5">
                                <div className="flex items-center gap-2">
                                  <Layers className="w-3.5 h-3.5 shrink-0" style={{ color: "#ef4444" }} />
                                  <span className="font-mono font-medium" style={{ color: "#ef4444" }}>{v.library?.name || v.component} {v.version}</span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>Retire.js</span>
                                </div>
                                <div className="ml-6 mt-1 font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>{v.identifiers?.CVE?.join(", ") || v.info?.join?.(" ") || d.file || ""}</div>
                              </div>
                            )))}
                            {(crawlResult.js_sca?.libraries || []).filter((l: any) => !(crawlResult.js_sca?.vulnerabilities || []).some((v: any) => v.name === l.name && v.version === l.version)).map((lib: any, i: number) => (
                              <div key={`lib-${i}`} className="px-3 py-2 hover:bg-white/5 text-xs">
                                <span className="font-mono" style={{ color: "var(--text-secondary)" }}>{lib.name}@{lib.version}</span>
                                <span className="ml-2 text-[10px]" style={{ color: "var(--text-muted)" }}>no known vulns</span>
                              </div>
                            ))}
                            {(!crawlResult.js_sca?.libraries?.length && !crawlResult.js_sca?.vulnerabilities?.length && !crawlResult.retire_results?.total_vulns) && (
                              <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No JS libraries or vulnerabilities found.</div>
                            )}
                          </div>
                        )}

                        {/* AI Analysis Tab */}
                        {crawlActiveSubTab === "ai" && (
                          <div className="p-4 space-y-4">
                            {!aiCrawlAnalysis && !aiCrawlAnalysisLoading && (
                              <div className="text-center py-8">
                                <Zap className="w-8 h-8 mx-auto mb-3" style={{ color: "#7c3aed" }} />
                                <p className="text-sm font-medium mb-2" style={{ color: "var(--text-primary)" }}>AI-Powered Attack Surface Analysis</p>
                                <p className="text-xs mb-4 max-w-md mx-auto" style={{ color: "var(--text-muted)" }}>
                                  Analyze crawl output with Gemini AI to identify high-value targets, parameter risks, and recommended security checks.
                                </p>
                                <button
                                  onClick={async () => {
                                    setAiCrawlAnalysisLoading(true);
                                    try {
                                      const res = await api.dastAiAnalyzeCrawl({ project_id: id as string });
                                      setAiCrawlAnalysis(res);
                                    } catch (e: any) { toast.error("AI analysis failed"); }
                                    setAiCrawlAnalysisLoading(false);
                                  }}
                                  className="px-5 py-2.5 rounded-lg text-sm font-medium transition-all hover:scale-105"
                                  style={{ background: "rgba(124,58,237,0.2)", color: "#c4b5fd", border: "1px solid rgba(124,58,237,0.3)" }}>
                                  Analyze with AI
                                </button>
                              </div>
                            )}
                            {aiCrawlAnalysisLoading && (
                              <div className="text-center py-8">
                                <Loader2 className="w-6 h-6 mx-auto animate-spin" style={{ color: "#7c3aed" }} />
                                <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>Analyzing attack surface with Gemini...</p>
                              </div>
                            )}
                            {aiCrawlAnalysis && (
                              <div className="space-y-4">
                                <div className="flex items-center gap-3">
                                  <span className="text-[10px] px-2 py-1 rounded-full font-bold uppercase" style={{
                                    background: aiCrawlAnalysis.attack_surface_score === "critical" ? "rgba(220,38,38,0.2)" : aiCrawlAnalysis.attack_surface_score === "high" ? "rgba(234,88,12,0.2)" : "rgba(202,138,4,0.2)",
                                    color: aiCrawlAnalysis.attack_surface_score === "critical" ? "#fca5a5" : aiCrawlAnalysis.attack_surface_score === "high" ? "#fdba74" : "#fde047",
                                  }}>{aiCrawlAnalysis.attack_surface_score} attack surface</span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded-full" style={{ background: "rgba(124,58,237,0.2)", color: "#c4b5fd" }}>Gemini</span>
                                </div>
                                <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{aiCrawlAnalysis.summary}</p>

                                {aiCrawlAnalysis.high_value_targets?.length > 0 && (
                                  <div>
                                    <span className="text-[10px] font-semibold uppercase" style={{ color: "var(--text-muted)" }}>High-Value Targets</span>
                                    <div className="mt-1 space-y-2">
                                      {aiCrawlAnalysis.high_value_targets.map((t: any, i: number) => (
                                        <div key={i} className="rounded-lg p-2.5" style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.12)" }}>
                                          <div className="text-xs font-mono font-medium" style={{ color: "#f87171" }}>{t.url}</div>
                                          <div className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>{t.reason}</div>
                                          {t.suggested_tests?.length > 0 && (
                                            <div className="flex flex-wrap gap-1 mt-1">
                                              {t.suggested_tests.map((test: string, j: number) => (
                                                <span key={j} className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: "rgba(124,58,237,0.1)", color: "#a78bfa" }}>{test}</span>
                                              ))}
                                            </div>
                                          )}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {aiCrawlAnalysis.parameter_risks?.length > 0 && (
                                  <div>
                                    <span className="text-[10px] font-semibold uppercase" style={{ color: "var(--text-muted)" }}>Parameter Risks</span>
                                    <div className="mt-1 space-y-1">
                                      {aiCrawlAnalysis.parameter_risks.map((p: any, i: number) => (
                                        <div key={i} className="flex items-center gap-2 text-xs">
                                          <code className="px-1.5 py-0.5 rounded text-[10px]" style={{ background: "var(--bg-elevated)", color: "#f87171" }}>{p.name}</code>
                                          <span style={{ color: "var(--text-muted)" }}>{p.risk}</span>
                                          <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "rgba(124,58,237,0.1)", color: "#a78bfa" }}>{p.test_type}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {aiCrawlAnalysis.recommended_checks?.length > 0 && (
                                  <div>
                                    <span className="text-[10px] font-semibold uppercase" style={{ color: "var(--text-muted)" }}>Recommended DAST Checks</span>
                                    <div className="flex flex-wrap gap-1.5 mt-1">
                                      {aiCrawlAnalysis.recommended_checks.map((c: string, i: number) => (
                                        <span key={i} className="text-[10px] px-2 py-1 rounded-lg font-medium" style={{ background: "rgba(37,99,235,0.1)", color: "#93c5fd" }}>{c}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Crawl History */}
                {crawlHistory.length > 0 && (
                  <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                    <details>
                      <summary className="p-3 flex items-center gap-2 cursor-pointer hover:bg-white/5">
                        <History className="w-4 h-4" style={{ color: "#7c3aed" }} />
                        <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Crawl History</span>
                        <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>{crawlHistory.length}</span>
                      </summary>
                      <div className="px-3 pb-3 space-y-1 max-h-48 overflow-y-auto" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                        {crawlHistory.map((s: any) => (
                          <button key={s.crawl_id} onClick={async () => {
                            try {
                              const data = await api.dastCrawlSession(id as string, s.crawl_id) as any;
                              setCrawlResult({
                ...data,
                deeplinks: data.deeplinks || [],
                js_sca: data.js_sca,
                retire_results: data.retire_results,
                crawler_used: data.crawler_used,
                stats: {
                  total_urls: data.total_urls,
                  api_endpoints: data.total_endpoints,
                  parameters: data.total_parameters,
                  forms: data.forms?.length || 0,
                  js_files: data.total_js_files || data.js_files?.length || 0,
                  total_deeplinks: data.deeplinks?.length || 0,
                  total_hidden_urls: data.stats?.total_hidden_urls || 0,
                  crawler_used: data.crawler_used,
                  total_secrets_found: data.stats?.total_secrets_found || 0,
                },
              });
                              toast.success("Loaded crawl session");
                            } catch { toast.error("Failed to load session"); }
                          }} className="w-full flex items-center justify-between p-2 rounded hover:bg-white/5 text-xs text-left">
                            <span style={{ color: "var(--text-secondary)" }}>{s.created_at ? new Date(s.created_at).toLocaleString() : "—"}</span>
                            <div className="flex gap-3">
                              <span style={{ color: "#7c3aed" }}>{s.total_urls} URLs</span>
                              <span style={{ color: "#16a34a" }}>{s.total_endpoints} APIs</span>
                              <span style={{ color: "var(--text-muted)" }}>{s.duration_seconds}s</span>
                              {s.auth_type && s.auth_type !== "none" && <span className="px-1.5 py-0.5 rounded" style={{ background: "rgba(124,58,237,0.1)", color: "#7c3aed" }}>{s.auth_type}</span>}
                            </div>
                          </button>
                        ))}
                      </div>
                    </details>
                  </div>
                )}

                {/* Empty State */}
                {!crawlResult && !crawling && (
                  <div className="text-center py-12 rounded-xl" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                    <Bug className="w-12 h-12 mx-auto mb-3" style={{ color: "var(--text-secondary)", opacity: 0.4 }} />
                    <p className="font-medium" style={{ color: "var(--text-primary)" }}>Ready to Crawl</p>
                    <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
                      Configure authentication if needed, then click &quot;Start Crawl&quot; to discover all URLs, APIs, and parameters
                    </p>
                  </div>
                )}
              </div>
            )}

            {dastActiveTab === "directories" ? (
              /* Directory Bruteforce Tab - Tree View */
              <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <div className="p-3 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div>
                      <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                        <Folder className="w-4 h-4" style={{ color: "var(--accent-indigo)" }} />
                        Discovered Directories & Files
                      </h2>
                      <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                        Tree view of paths from directory discovery and ffuf scans. Run full wordlist on any path for deeper discovery.
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      {/* Depth control */}
                      <select value={recursiveDirDepth} onChange={(e) => setRecursiveDirDepth(Number(e.target.value))}
                        className="px-2 py-1.5 rounded-lg text-xs" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}>
                        {[1,2,3,4,5].map(d => <option key={d} value={d}>Depth {d}</option>)}
                      </select>
                      <button
                        onClick={handleRecursiveDirScan}
                        disabled={recursiveDirScanning || !project?.application_url}
                        className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium"
                        style={{ background: recursiveDirScanning ? "#4b5563" : "#2563eb", color: "white" }}
                      >
                        {recursiveDirScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Layers className="w-4 h-4" />}
                        {recursiveDirScanning ? "Recursive scan..." : "Recursive Scan"}
                      </button>
                      <button
                        onClick={handleRunExhaustive}
                        disabled={ffufExhaustiveScanning || !project?.application_url}
                        className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium"
                        style={{ background: ffufExhaustiveScanning ? "#4b5563" : "#7c3aed", color: "white" }}
                      >
                        {ffufExhaustiveScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                        {ffufExhaustiveScanning ? "Exhaustive scan running..." : "Run Exhaustive (all wordlists)"}
                      </button>
                    </div>
                  </div>
                </div>
                {/* Recursive scan progress */}
                {recursiveDirScanning && (
                  <div className="mx-3 p-2.5 rounded-lg flex items-center gap-2" style={{ background: "rgba(37,99,235,0.1)", border: "1px solid rgba(37,99,235,0.3)" }}>
                    <Loader2 className="w-4 h-4 animate-spin" style={{ color: "#2563eb" }} />
                    <span className="text-xs" style={{ color: "#2563eb" }}>Recursive directory scan in progress...</span>
                  </div>
                )}
                {/* Recursive scan results */}
                {recursiveDirResult?.tree && recursiveDirResult.tree.length > 0 && (
                  <div className="mx-3 p-2.5 rounded-lg" style={{ background: "rgba(22,163,74,0.08)", border: "1px solid rgba(22,163,74,0.2)" }}>
                    <p className="text-xs font-medium mb-1" style={{ color: "#16a34a" }}>
                      Recursive scan found {recursiveDirResult.total_found} paths across {recursiveDirResult.depths_scanned} depth levels ({recursiveDirResult.duration_seconds}s)
                    </p>
                  </div>
                )}
                <div className="p-3 max-h-[500px] overflow-y-auto">
                  {!pathTreeRoot || pathTreeRoot.children.length === 0 ? (
                    <div className="py-12 text-center" style={{ color: "var(--text-muted)" }}>
                      <Folder className="w-12 h-12 mx-auto mb-2 opacity-50" />
                      <p className="text-sm">No directories or files discovered yet</p>
                      <p className="text-xs mt-1 max-w-md mx-auto">
                        Run &quot;Run Exhaustive&quot; (ffuf) or &quot;Recursive Scan&quot; to discover paths. Requires ffuf installed for exhaustive scan. Target: {project?.application_url || "—"}
                      </p>
                      {(ffufExhaustiveScanning || recursiveDirScanning) && (
                        <div className="mt-3 flex items-center justify-center gap-2 text-sm" style={{ color: "#7c3aed" }}>
                          <Loader2 className="w-4 h-4 animate-spin" /> Scan running in background — results persist; refresh or return later to see them
                        </div>
                      )}
                      <div className="mt-4 flex flex-wrap gap-2 justify-center">
                        <button
                          onClick={handleRunExhaustive}
                          disabled={ffufExhaustiveScanning || !project?.application_url}
                          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium"
                          style={{ background: ffufExhaustiveScanning ? "#4b5563" : "#7c3aed", color: "white" }}
                        >
                          {ffufExhaustiveScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                          {ffufExhaustiveScanning ? "Scanning..." : "Run Exhaustive"}
                        </button>
                        <button
                          onClick={handleRecursiveDirScan}
                          disabled={recursiveDirScanning || !project?.application_url}
                          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium"
                          style={{ background: recursiveDirScanning ? "#4b5563" : "#2563eb", color: "white" }}
                        >
                          {recursiveDirScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Layers className="w-4 h-4" />}
                          {recursiveDirScanning ? "Scanning..." : "Recursive Scan"}
                        </button>
                      </div>
                    </div>
                  ) : (
                    (() => {
                      const toggleDir = (fp: string) => setDirTreeExpanded((s) => { const n = new Set(s); if (n.has(fp)) n.delete(fp); else n.add(fp); return n; });
                      const renderNode = (node: any, depth: number, isLast: boolean, prefix: string) => {
                        const fp = node.fullPath || "/";
                        const hasChildren = node.children && node.children.length > 0;
                        const expanded = dirTreeExpanded.has(fp);
                        const Icon = hasChildren ? Folder : File;
                        const statusColor = node.status ? (node.status >= 200 && node.status < 300 ? "#16a34a" : node.status >= 400 ? "#dc2626" : "#ca8a04") : "var(--text-muted)";
                        const ffufData = ffufResults[fp];
                        const isScanning = ffufScanning === fp;
                        return (
                          <div key={fp} className="select-none">
                            <div className="flex items-center gap-2 py-1 group" style={{ paddingLeft: `${depth * 16}px` }}>
                              <span className="text-xs font-mono w-4 shrink-0" style={{ color: "var(--text-muted)" }}>{prefix}</span>
                              <button
                                onClick={() => hasChildren && toggleDir(fp)}
                                className="p-0.5 rounded hover:bg-white/5"
                                style={{ color: "var(--text-muted)" }}
                              >
                                {hasChildren ? <ChevronRight className={`w-3.5 h-3.5 transition-transform ${expanded ? "rotate-90" : ""}`} /> : <span className="w-3.5 inline-block" />}
                              </button>
                              <Icon className="w-4 h-4 shrink-0" style={{ color: hasChildren ? "var(--accent-indigo)" : "var(--text-secondary)" }} />
                              {node.status != null ? (
                                <a
                                  href={(() => { const base = (scanResult?.target_url || project?.application_url || "").replace(/\/$/, ""); return `${base}${node.fullPath}`; })()}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-xs font-mono truncate flex-1 min-w-0 hover:underline"
                                  style={{ color: node.status >= 200 && node.status < 400 ? "#3b82f6" : "var(--text-primary)" }}
                                  title={`Open ${(scanResult?.target_url || project?.application_url || "").replace(/\/$/, "")}${node.fullPath}`}
                                >
                                  {node.name}{hasChildren ? "/" : ""}
                                </a>
                              ) : (
                                <span className="text-xs font-mono truncate flex-1 min-w-0" style={{ color: "var(--text-primary)" }}>{node.name}{hasChildren ? "/" : ""}</span>
                              )}
                              {node.status != null && <span className="text-xs shrink-0" style={{ color: statusColor }}>HTTP {node.status}</span>}
                              {ffufData && <span className="text-xs shrink-0" style={{ color: "#16a34a" }}>+{ffufData.discovered.length}</span>}
                              <button
                                onClick={() => handleRunFullWordlist(fp === "/" ? "" : fp)}
                                disabled={isScanning}
                                className="opacity-0 group-hover:opacity-100 px-2 py-0.5 rounded text-xs font-medium shrink-0 transition-opacity"
                                style={{ background: "var(--accent-indigo)", color: "white" }}
                              >
                                {isScanning ? <Loader2 className="w-3 h-3 animate-spin inline" /> : "Run Wordlist"}
                              </button>
                              {!hasChildren && node.status != null && (
                                <button
                                  onClick={() => { const fullUrl = `${(scanResult?.target_url || project?.application_url || "").replace(/\/$/, "")}${fp}`; handleFetchUrl(fullUrl); }}
                                  disabled={fetchingUrl !== null}
                                  className="opacity-0 group-hover:opacity-100 px-2 py-0.5 rounded text-xs font-medium shrink-0 transition-opacity flex items-center gap-1"
                                  style={{ background: "#16a34a", color: "white" }}
                                  title="View request/response"
                                >
                                  {fetchingUrl ? <Loader2 className="w-3 h-3 animate-spin inline" /> : <Eye className="w-3 h-3 inline" />}
                                  View
                                </button>
                              )}
                            </div>
                            {hasChildren && expanded && node.children.map((child: any, i: number) => {
                              const isLastChild = i === node.children.length - 1;
                              const line = depth === 0 ? (isLastChild ? "└──" : "├──") : (isLastChild ? "└──" : "├──");
                              return renderNode(child, depth + 1, isLastChild, line);
                            })}
                          </div>
                        );
                      };
                      return (
                        <div className="font-mono text-sm">
                          {pathTreeRoot.children.map((child: any, i: number) => {
                            const isLast = i === pathTreeRoot.children.length - 1;
                            return renderNode(child, 0, isLast, isLast ? "└──" : "├──");
                          })}
                        </div>
                      );
                    })()
                  )}
                </div>
                {/* URL Content Viewer */}
                {Object.keys(urlContent).length > 0 && (
                  <div className="p-3 border-t space-y-2" style={{ borderColor: "var(--border-subtle)" }}>
                    <p className="text-xs font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                      <Eye className="w-3.5 h-3.5" style={{ color: "#16a34a" }} /> File Content Viewer
                    </p>
                    {Object.entries(urlContent).map(([url, data]) => (
                      <div key={url} className="rounded-lg overflow-hidden" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                        <div className="p-2 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                          <span className="text-xs font-mono truncate" style={{ color: "var(--text-primary)" }}>{url}</span>
                          {data.status && <span className="text-xs font-mono shrink-0" style={{ color: data.status < 300 ? "#16a34a" : "#dc2626" }}>HTTP {data.status}</span>}
                          <button onClick={() => setUrlContent(prev => { const next = {...prev}; delete next[url]; return next; })} className="text-xs px-1.5 py-0.5 rounded shrink-0" style={{ color: "var(--text-muted)" }}>x</button>
                        </div>
                        {data.error ? (
                          <p className="p-2 text-xs" style={{ color: "#dc2626" }}>{data.error}</p>
                        ) : (
                          <div className="p-2 space-y-2">
                            {data.content_type && <p className="text-xs" style={{ color: "var(--text-muted)" }}>Content-Type: {data.content_type} | Size: {data.size || 0} bytes</p>}
                            {data.request_raw && (
                              <details className="text-xs"><summary className="cursor-pointer font-medium" style={{ color: "var(--accent-indigo)" }}>Request</summary>
                                <pre className="mt-1 p-2 rounded overflow-x-auto max-h-24 overflow-y-auto font-mono" style={{ background: "var(--bg-primary)", color: "var(--text-secondary)", fontSize: "10px" }}>{data.request_raw}</pre>
                              </details>
                            )}
                            {data.response_raw && (
                              <details className="text-xs" open><summary className="cursor-pointer font-medium" style={{ color: "var(--accent-indigo)" }}>Response</summary>
                                <pre className="mt-1 p-2 rounded overflow-x-auto max-h-48 overflow-y-auto font-mono whitespace-pre-wrap break-all" style={{ background: "var(--bg-primary)", color: "var(--text-secondary)", fontSize: "10px" }}>{data.response_raw}</pre>
                              </details>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : dastActiveTab === "results" ? (
            <>
            {/* AI Scan Summary */}
            {scanResult && scanResult.results?.length > 0 && (
              <div className="rounded-xl p-4 space-y-3" style={{ background: "linear-gradient(135deg, rgba(124,58,237,0.08), rgba(59,130,246,0.08))", border: "1px solid rgba(124,58,237,0.2)" }}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Zap className="w-4 h-4" style={{ color: "#7c3aed" }} />
                    <span className="text-sm font-semibold" style={{ color: "#a78bfa" }}>AI Scan Summary</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium" style={{ background: "rgba(124,58,237,0.2)", color: "#c4b5fd" }}>Gemini</span>
                  </div>
                  {!aiScanSummary && !aiScanSummaryLoading && (
                    <button
                      onClick={async () => {
                        setAiScanSummaryLoading(true);
                        try {
                          const res = await api.dastAiSummarizeScan({ project_id: id as string, scan_id: scanResult.scan_id || scanId || undefined });
                          setAiScanSummary(res);
                        } catch (e: any) { toast.error("AI summary failed"); }
                        setAiScanSummaryLoading(false);
                      }}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all hover:scale-105"
                      style={{ background: "rgba(124,58,237,0.2)", color: "#c4b5fd", border: "1px solid rgba(124,58,237,0.3)" }}>
                      Generate AI Summary
                    </button>
                  )}
                  {aiScanSummaryLoading && <Loader2 className="w-4 h-4 animate-spin" style={{ color: "#7c3aed" }} />}
                </div>
                {aiScanSummary && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase" style={{
                        background: aiScanSummary.risk_level === "critical" ? "rgba(220,38,38,0.2)" : aiScanSummary.risk_level === "high" ? "rgba(234,88,12,0.2)" : aiScanSummary.risk_level === "medium" ? "rgba(202,138,4,0.2)" : "rgba(22,163,74,0.2)",
                        color: aiScanSummary.risk_level === "critical" ? "#fca5a5" : aiScanSummary.risk_level === "high" ? "#fdba74" : aiScanSummary.risk_level === "medium" ? "#fde047" : "#86efac",
                      }}>{aiScanSummary.risk_level} risk</span>
                    </div>
                    <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{aiScanSummary.summary}</p>
                    {aiScanSummary.top_issues?.length > 0 && (
                      <div>
                        <span className="text-[10px] font-semibold uppercase" style={{ color: "var(--text-muted)" }}>Top Issues</span>
                        <ul className="mt-1 space-y-1">
                          {aiScanSummary.top_issues.map((issue: string, i: number) => (
                            <li key={i} className="flex items-start gap-1.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                              <XCircle className="w-3 h-3 mt-0.5 flex-shrink-0" style={{ color: "#ef4444" }} />
                              {issue}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {aiScanSummary.recommendations?.length > 0 && (
                      <div>
                        <span className="text-[10px] font-semibold uppercase" style={{ color: "var(--text-muted)" }}>Recommendations</span>
                        <ul className="mt-1 space-y-1">
                          {aiScanSummary.recommendations.map((rec: string, i: number) => (
                            <li key={i} className="flex items-start gap-1.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                              <CheckCircle className="w-3 h-3 mt-0.5 flex-shrink-0" style={{ color: "#22c55e" }} />
                              {rec}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

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

            {/* Discovered Directories - Run Full Wordlist */}
            {discoveredPaths.length > 0 && (
              <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <button onClick={() => setDirsSectionExpanded(!dirsSectionExpanded)} className="w-full flex items-center justify-between p-2.5 text-left hover:bg-white/5">
                  <div className="flex items-center gap-2">
                    <ChevronRight className={`w-4 h-4 transition-transform ${dirsSectionExpanded ? "rotate-90" : ""}`} style={{ color: "var(--text-muted)" }} />
                    <Folder className="w-4 h-4" style={{ color: "var(--accent-indigo)" }} />
                    <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Discovered Directories</span>
                    <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "rgba(37, 99, 235, 0.15)", color: "var(--accent-indigo)" }}>{discoveredPaths.length} paths</span>
                  </div>
                </button>
                {dirsSectionExpanded && (
                  <div className="px-3 pb-3 pt-0 border-t" style={{ borderColor: "var(--border-subtle)" }}>
                    <p className="text-xs mt-2 mb-2" style={{ color: "var(--text-muted)" }}>Run full ffuf wordlist on any path for deeper discovery</p>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {discoveredPaths.map((d: { path: string; status: number }) => {
                        const path = d.path.replace(/\/$/, "") || "/";
                        const key = path || "/";
                        const isScanning = ffufScanning === key;
                        const subResults = ffufResults[key];
                        return (
                          <div key={key} className="flex items-center justify-between gap-2 p-2 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                            <div className="min-w-0 flex-1">
                              <span className="text-xs font-mono truncate block" style={{ color: "var(--text-primary)" }}>{path || "/"}</span>
                              <span className="text-xs" style={{ color: "var(--text-muted)" }}>HTTP {d.status}</span>
                              {subResults && (
                                <p className="text-xs mt-0.5" style={{ color: "#16a34a" }}>
                                  +{subResults.discovered.length} subpaths (wordlist: {subResults.wordlist_used})
                                </p>
                              )}
                            </div>
                            <button
                              onClick={() => handleRunFullWordlist(key)}
                              disabled={isScanning}
                              className="px-2 py-1 rounded text-xs font-medium whitespace-nowrap flex items-center gap-1"
                              style={{ background: "var(--accent-indigo)", color: "white", opacity: isScanning ? 0.7 : 1 }}
                            >
                              {isScanning ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
                              {isScanning ? "Scanning..." : "Run Full Wordlist"}
                            </button>
                          </div>
                        );
                      })}
                    </div>
                    {Object.keys(ffufResults).length > 0 && (
                      <details className="mt-2">
                        <summary className="text-xs cursor-pointer" style={{ color: "var(--accent-indigo)" }}>View ffuf subpath results</summary>
                        <div className="mt-1 space-y-2 max-h-32 overflow-y-auto">
                          {Object.entries(ffufResults).map(([base, data]) => (
                            <div key={base} className="text-xs">
                              <p className="font-medium mb-0.5" style={{ color: "var(--text-primary)" }}>{base}</p>
                              <div className="flex flex-wrap gap-1">
                                {data.discovered.slice(0, 20).map((s: { path: string; status: number }) => (
                                  <span key={s.path} className="px-1.5 py-0.5 rounded font-mono" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>{s.path} ({s.status})</span>
                                ))}
                                {data.discovered.length > 20 && <span style={{ color: "var(--text-muted)" }}>+{data.discovered.length - 20} more</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                )}
              </div>
            )}

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
                          {/* Payload / What was tested - shown for all (passed/failed/error) */}
                          {(check.details?.payload_tested || check.evidence) && (
                            <div className="p-2.5 rounded-lg" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                              <p className="text-xs font-semibold mb-1" style={{ color: "var(--accent-indigo)" }}>Payload / What was tested</p>
                              <p className="text-xs font-mono" style={{ color: "var(--text-secondary)" }}>{check.details?.payload_tested || check.evidence}</p>
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
            </>
            ) : dastActiveTab === "claude" ? (
            <div className="space-y-4">
              {/* Claude AI DAST Dashboard */}
              <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <div className="p-4 space-y-4">
                  {/* Header */}
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <div className="flex items-center gap-2">
                      <Brain className="w-5 h-5" style={{ color: "#d97706" }} />
                      <span className="font-semibold" style={{ color: "var(--text-primary)" }}>Claude AI Pentester</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium" style={{ background: "rgba(217,119,6,0.2)", color: "#f59e0b" }}>AI-Native DAST</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {claudeSession?.has_session && (
                        <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                          Session Active ({claudeSession.scan_count || 0} scans)
                        </span>
                      )}
                      {claudeSession?.has_session && (
                        <button
                          onClick={async () => {
                            if (confirm("Clear session context? This removes all accumulated knowledge for this project.")) {
                              await api.claudeDastSessionClear(id as string);
                              setClaudeSession(null);
                              toast.success("Session cleared");
                            }
                          }}
                          className="text-[10px] px-2 py-0.5 rounded-full hover:opacity-80"
                          style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}
                        >
                          Clear Context
                        </button>
                      )}
                      {/* Export Dropdown */}
                      <div className="relative">
                        <button
                          onClick={() => setShowExportMenu(!showExportMenu)}
                          className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full hover:opacity-80"
                          style={{ background: "rgba(59,130,246,0.15)", color: "#3b82f6" }}
                        >
                          <FileDown className="w-3 h-3" /> Export <ChevronDown className="w-3 h-3" />
                        </button>
                        {showExportMenu && (
                          <div
                            className="absolute right-0 top-full mt-1 z-50 rounded-lg shadow-lg py-1 min-w-[160px]"
                            style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}
                          >
                            {[
                              { label: "Burp XML", fn: () => api.dastExportBurpXml(id as string) },
                              { label: "JSON", fn: () => api.dastExportJson(id as string) },
                              { label: "CSV", fn: () => api.dastExportCsv(id as string) },
                              { label: "HAR (Crawl)", fn: () => api.dastExportHar(id as string) },
                            ].map((opt) => (
                              <button
                                key={opt.label}
                                onClick={async () => {
                                  setShowExportMenu(false);
                                  try {
                                    await opt.fn();
                                    toast.success(`Exported as ${opt.label}`);
                                  } catch (e: any) {
                                    toast.error(e.message || `Export failed: ${opt.label}`);
                                  }
                                }}
                                className="w-full text-left px-3 py-1.5 text-xs hover:opacity-80"
                                style={{ color: "var(--text-primary)" }}
                              >
                                {opt.label}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Scan Configuration */}
                  {!claudeScanning && (
                    <div className="space-y-3">
                      <div className="flex flex-wrap items-end gap-3">
                        <div>
                          <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Scan Mode</label>
                          <select
                            value={claudeScanMode}
                            onChange={(e) => {
                              const mode = e.target.value as "quick" | "standard" | "deep";
                              setClaudeScanMode(mode);
                              api.claudeDastCostEstimate({ scan_mode: mode, target_url: project?.application_url || "" }).then(setClaudeCostEstimate).catch(() => {});
                            }}
                            className="rounded-lg px-3 py-1.5 text-sm"
                            style={{ background: "var(--bg-elevated)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                          >
                            <option value="quick">Quick ($)</option>
                            <option value="standard">Standard ($$)</option>
                            <option value="deep">Deep ($$$)</option>
                          </select>
                        </div>
                        <label className="flex items-center gap-1.5 text-xs cursor-pointer" style={{ color: "var(--text-secondary)" }}>
                          <input type="checkbox" checked={claudeIncludeSubdomains} onChange={(e) => setClaudeIncludeSubdomains(e.target.checked)} />
                          Include Subdomains
                        </label>
                        <div className="flex items-center gap-2">
                          <input
                            type="text"
                            className="input-field text-xs flex-1"
                            placeholder="Proxy URL (e.g., socks5://127.0.0.1:1080 or http://proxy:8080)"
                            value={claudeProxyUrl}
                            onChange={(e) => setClaudeProxyUrl(e.target.value)}
                            style={{ maxWidth: 320 }}
                          />
                          {claudeProxyUrl && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "rgba(59,130,246,0.15)", color: "#3b82f6" }}>
                              VPN/Internal
                            </span>
                          )}
                        </div>
                        {claudeCostEstimate && (
                          <span className="text-[10px] px-2 py-1 rounded-lg" style={{ background: "rgba(217,119,6,0.1)", color: "#d97706" }}>
                            <DollarSign className="w-3 h-3 inline" />
                            Est. ${(claudeCostEstimate.estimated_cost_low_usd ?? 0).toFixed(2)} - ${(claudeCostEstimate.estimated_cost_high_usd ?? 0).toFixed(2)}
                          </span>
                        )}
                      </div>

                      {/* Auth Configuration Panel */}
                      <div className="rounded-lg p-3 space-y-2" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                        <div className="flex items-center gap-2 mb-1">
                          <Key className="w-3.5 h-3.5" style={{ color: "var(--text-secondary)" }} />
                          <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>Authentication Config</span>
                        </div>
                        <div>
                          <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Auth Type</label>
                          <select
                            value={claudeAuthType}
                            onChange={(e) => setClaudeAuthType(e.target.value)}
                            className="rounded-lg px-3 py-1.5 text-sm w-full"
                            style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                          >
                            <option value="none">None</option>
                            <option value="bearer">Bearer Token</option>
                            <option value="cookie">Cookie</option>
                            <option value="basic">Basic Auth</option>
                            <option value="api_key">API Key</option>
                            <option value="custom_header">Custom Header</option>
                          </select>
                        </div>
                        {claudeAuthType === "bearer" && (
                          <div>
                            <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Bearer Token</label>
                            <input
                              type="password"
                              value={claudeAuthToken}
                              onChange={(e) => setClaudeAuthToken(e.target.value)}
                              placeholder="Enter bearer token"
                              className="rounded-lg px-3 py-1.5 text-sm w-full"
                              style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                            />
                          </div>
                        )}
                        {claudeAuthType === "cookie" && (
                          <div>
                            <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Cookie Value</label>
                            <input
                              type="text"
                              value={claudeAuthToken}
                              onChange={(e) => setClaudeAuthToken(e.target.value)}
                              placeholder="session=abc123; token=xyz"
                              className="rounded-lg px-3 py-1.5 text-sm w-full"
                              style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                            />
                          </div>
                        )}
                        {claudeAuthType === "basic" && (
                          <div className="flex gap-2">
                            <div className="flex-1">
                              <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Username</label>
                              <input
                                type="text"
                                value={claudeAuthUsername}
                                onChange={(e) => setClaudeAuthUsername(e.target.value)}
                                placeholder="Username"
                                className="rounded-lg px-3 py-1.5 text-sm w-full"
                                style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                              />
                            </div>
                            <div className="flex-1">
                              <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Password</label>
                              <input
                                type="password"
                                value={claudeAuthPassword}
                                onChange={(e) => setClaudeAuthPassword(e.target.value)}
                                placeholder="Password"
                                className="rounded-lg px-3 py-1.5 text-sm w-full"
                                style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                              />
                            </div>
                          </div>
                        )}
                        {claudeAuthType === "api_key" && (
                          <div className="flex gap-2">
                            <div className="flex-1">
                              <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Header Name</label>
                              <input
                                type="text"
                                value={claudeAuthHeaderName}
                                onChange={(e) => setClaudeAuthHeaderName(e.target.value)}
                                placeholder="X-API-Key"
                                className="rounded-lg px-3 py-1.5 text-sm w-full"
                                style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                              />
                            </div>
                            <div className="flex-1">
                              <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>API Key</label>
                              <input
                                type="password"
                                value={claudeAuthHeaderValue}
                                onChange={(e) => setClaudeAuthHeaderValue(e.target.value)}
                                placeholder="Your API key"
                                className="rounded-lg px-3 py-1.5 text-sm w-full"
                                style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                              />
                            </div>
                          </div>
                        )}
                        {claudeAuthType === "custom_header" && (
                          <div className="flex gap-2">
                            <div className="flex-1">
                              <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Header Name</label>
                              <input
                                type="text"
                                value={claudeAuthHeaderName}
                                onChange={(e) => setClaudeAuthHeaderName(e.target.value)}
                                placeholder="X-Custom-Auth"
                                className="rounded-lg px-3 py-1.5 text-sm w-full"
                                style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                              />
                            </div>
                            <div className="flex-1">
                              <label className="text-[10px] block mb-1" style={{ color: "var(--text-secondary)" }}>Header Value</label>
                              <input
                                type="password"
                                value={claudeAuthHeaderValue}
                                onChange={(e) => setClaudeAuthHeaderValue(e.target.value)}
                                placeholder="Header value"
                                className="rounded-lg px-3 py-1.5 text-sm w-full"
                                style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                              />
                            </div>
                          </div>
                        )}
                      </div>

                      <button
                        onClick={async () => {
                          setClaudeScanning(true);
                          try {
                            // Build auth_config based on selected type
                            let authConfig: any = undefined;
                            if (claudeAuthType !== "none") {
                              authConfig = { type: claudeAuthType };
                              if (claudeAuthType === "bearer") {
                                authConfig.token = claudeAuthToken;
                              } else if (claudeAuthType === "cookie") {
                                authConfig.cookie = claudeAuthToken;
                              } else if (claudeAuthType === "basic") {
                                authConfig.username = claudeAuthUsername;
                                authConfig.password = claudeAuthPassword;
                              } else if (claudeAuthType === "api_key") {
                                authConfig.header_name = claudeAuthHeaderName;
                                authConfig.header_value = claudeAuthHeaderValue;
                              } else if (claudeAuthType === "custom_header") {
                                authConfig.header_name = claudeAuthHeaderName;
                                authConfig.header_value = claudeAuthHeaderValue;
                              }
                            }
                            const res = await api.claudeDastScanWithAuth({
                              project_id: id as string,
                              scan_mode: claudeScanMode,
                              include_subdomains: claudeIncludeSubdomains,
                              auth_config: authConfig,
                              proxy_url: claudeProxyUrl || undefined,
                            });
                            setClaudeScanId(res.scan_id);
                            sessionStorage.setItem(`dast_claude_job_${id}`, res.scan_id);
                            toast.success("Claude AI scan started");
                            const poll = async () => {
                              try {
                                const prog = await api.claudeDastScanProgress(res.scan_id);
                                setClaudeProgress(prog);
                                // Persist progress snapshot for tab-switch recovery
                                try {
                                  sessionStorage.setItem(`dast_claude_progress_${id}`, JSON.stringify({
                                    current_phase: prog.current_phase, current_activity: prog.current_activity,
                                    findings_so_far: prog.findings_so_far, pages_crawled: prog.pages_crawled,
                                    cost: prog.cost, activity_log: prog.activity_log, findings_by_severity: prog.findings_by_severity,
                                    checks_completed: prog.checks_completed, tool_calls_used: prog.tool_calls_used,
                                    progress_pct: prog.progress_pct, eta_seconds: prog.eta_seconds,
                                    live_crawl_results: prog.live_crawl_results,
                                  }));
                                } catch {}
                                // Update live crawl results as they come in
                                if (prog.live_crawl_results?.length > 0) {
                                  setClaudeCrawlResults((prev: any[]) => {
                                    const urls = new Set((prev || []).map((p: any) => p.url));
                                    const newItems = prog.live_crawl_results.filter((r: any) => !urls.has(r.url));
                                    return newItems.length > 0 ? [...(prev || []), ...newItems] : prev;
                                  });
                                }
                                if (prog.status === "completed" || prog.status === "error" || prog.status === "stopped") {
                                  if (claudePollRef.current) clearInterval(claudePollRef.current);
                                  setClaudeScanning(false);
                                  sessionStorage.removeItem(`dast_claude_job_${id}`);
                                  sessionStorage.removeItem(`dast_claude_progress_${id}`);
                                  if (prog.status === "completed") {
                                    toast.success(`Scan complete: ${prog.total_findings || 0} findings`);
                                    api.claudeDastHistory(id as string).then(setClaudeHistory).catch(() => {});
                                    api.claudeDastCrawlResults(id as string).then(setClaudeCrawlResults).catch(() => {});
                                    api.claudeDastSession(id as string).then(setClaudeSession).catch(() => {});
                                  } else if (prog.status === "error") {
                                    toast.error(prog.error || "Scan failed");
                                  }
                                }
                              } catch { /* polling continues */ }
                            };
                            claudePollRef.current = setInterval(poll, 2000);
                            poll();
                          } catch (e: any) {
                            toast.error(e.message || "Failed to start scan");
                            setClaudeScanning(false);
                          }
                        }}
                        disabled={claudeScanning}
                        className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-medium text-white"
                        style={{ background: "linear-gradient(135deg, #d97706 0%, #ea580c 100%)" }}
                      >
                        <Play className="w-4 h-4" /> Start AI Scan
                      </button>
                    </div>
                  )}

                  {/* Live Progress — Enhanced Terminal View */}
                  {claudeScanning && claudeProgress && (
                    <div className="space-y-3">
                      {/* Header with phase, stop button, elapsed time */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="relative">
                            <Radio className="w-4 h-4 text-red-500 animate-pulse" />
                            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-red-500 rounded-full animate-ping" />
                          </div>
                          <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                            {claudeProgress.current_phase || "Initializing"}
                          </span>
                          <span className="text-[10px] px-2 py-0.5 rounded-full font-medium animate-pulse" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>
                            LIVE
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {claudeProgress.cost && (
                            <span className="text-[10px] px-2 py-0.5 rounded border font-mono" style={{ color: "var(--text-muted)", borderColor: "var(--border-subtle)" }}>
                              ${(claudeProgress.cost.total_cost_usd || 0).toFixed(3)}
                            </span>
                          )}
                          <button
                            onClick={async () => {
                              if (claudeScanId) {
                                await api.claudeDastScanStop(claudeScanId);
                                toast.success("Scan stop requested");
                              }
                            }}
                            className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition-colors hover:bg-red-500/20"
                            style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}
                          >
                            <Square className="w-3 h-3" /> Stop Scan
                          </button>
                        </div>
                      </div>

                      {/* Current activity */}
                      <div className="rounded-lg p-2.5" style={{ background: "rgba(217,119,6,0.05)", border: "1px solid rgba(217,119,6,0.15)" }}>
                        <p className="text-xs font-medium" style={{ color: "#f59e0b" }}>
                          {claudeProgress.current_activity || "Processing..."}
                        </p>
                      </div>

                      {/* Progress bar + ETA */}
                      <div className="space-y-1">
                        <div className="w-full rounded-full h-2" style={{ background: "var(--bg-elevated)" }}>
                          <div className="h-2 rounded-full transition-all duration-500" style={{ width: `${claudeProgress.progress_pct || 5}%`, background: "linear-gradient(90deg, #d97706 0%, #ea580c 100%)" }} />
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                            {claudeProgress.progress_pct ? `${claudeProgress.progress_pct}%` : "Starting..."}
                          </span>
                          {claudeProgress.eta_seconds != null && claudeProgress.eta_seconds > 0 && (
                            <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                              ETA: ~{claudeProgress.eta_seconds >= 60 ? `${Math.ceil(claudeProgress.eta_seconds / 60)}min` : `${claudeProgress.eta_seconds}s`}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Stats row */}
                      <div className="grid grid-cols-4 gap-2">
                        <div className="rounded-lg p-2 text-center" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                          <div className="text-lg font-bold" style={{ color: "#3b82f6" }}>{claudeProgress.pages_crawled || 0}</div>
                          <div className="text-[9px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Pages</div>
                        </div>
                        <div className="rounded-lg p-2 text-center" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                          <div className="text-lg font-bold" style={{ color: claudeProgress.findings_so_far > 0 ? "#ef4444" : "var(--text-primary)" }}>{claudeProgress.findings_so_far || 0}</div>
                          <div className="text-[9px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Findings</div>
                        </div>
                        <div className="rounded-lg p-2 text-center" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                          <div className="text-lg font-bold" style={{ color: "#22c55e" }}>{claudeProgress.checks_completed || 0}</div>
                          <div className="text-[9px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Checks</div>
                        </div>
                        <div className="rounded-lg p-2 text-center" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                          <div className="text-lg font-bold" style={{ color: "#d97706" }}>{claudeProgress.tool_calls_used || 0}</div>
                          <div className="text-[9px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Tool Calls</div>
                        </div>
                      </div>

                      {/* Severity breakdown */}
                      {claudeProgress.findings_by_severity && (
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(claudeProgress.findings_by_severity as Record<string, number>).filter(([, v]) => v > 0).map(([sev, count]) => (
                            <span key={sev} className="text-[10px] px-2 py-0.5 rounded-full font-semibold" style={{ background: `${SEVERITY_COLORS[sev]}22`, color: SEVERITY_COLORS[sev], border: `1px solid ${SEVERITY_COLORS[sev]}44` }}>
                              {count} {sev}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Live Terminal */}
                      {claudeProgress.activity_log && claudeProgress.activity_log.length > 0 && (
                        <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border-subtle)" }}>
                          <div className="px-3 py-1.5 flex items-center gap-2" style={{ background: "var(--bg-elevated)", borderBottom: "1px solid var(--border-subtle)" }}>
                            <Activity className="w-3 h-3" style={{ color: "#d97706" }} />
                            <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Live Activity Feed</span>
                            <span className="text-[9px] ml-auto font-mono" style={{ color: "var(--text-muted)" }}>{(claudeProgress.activity_log as any[]).length} events</span>
                          </div>
                          <div
                            className="max-h-64 overflow-y-auto space-y-0.5 p-2 font-mono"
                            style={{ background: "rgba(0,0,0,0.4)" }}
                            ref={(el) => { if (el) el.scrollTop = el.scrollHeight; }}
                          >
                            {(claudeProgress.activity_log as any[]).map((entry: any, i: number) => {
                              const typeColors: Record<string, string> = {
                                finding: "#22c55e",
                                tool: "#3b82f6",
                                error: "#ef4444",
                                phase: "#d97706",
                                info: "#94a3b8",
                                rate_limit: "#eab308",
                                retry: "#eab308",
                              };
                              const typeBadges: Record<string, string> = {
                                finding: "VULN",
                                tool: "TOOL",
                                error: "ERR",
                                phase: "PHASE",
                                info: "INFO",
                                rate_limit: "WAIT",
                                retry: "RETRY",
                              };
                              const color = typeColors[entry.type] || "#94a3b8";
                              return (
                                <div key={i} className="flex items-start gap-2 text-[10px] leading-relaxed">
                                  <span className="shrink-0 opacity-40 tabular-nums">{new Date(entry.ts * 1000).toLocaleTimeString()}</span>
                                  <span
                                    className="shrink-0 px-1 py-0 rounded text-[8px] font-bold uppercase"
                                    style={{ background: `${color}22`, color, border: `1px solid ${color}44`, minWidth: "36px", textAlign: "center" }}
                                  >
                                    {typeBadges[entry.type] || entry.type?.toUpperCase() || "LOG"}
                                  </span>
                                  <span style={{ color }}>{entry.msg}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* Pentest Options */}
                      {claudeProgress.pending_pentest_options && (claudeProgress.pending_pentest_options as any[]).filter((o: any) => !o.user_selected).length > 0 && (
                        <div className="rounded-lg p-3 space-y-2" style={{ background: "rgba(217,119,6,0.08)", border: "1px solid rgba(217,119,6,0.2)" }}>
                          <span className="text-xs font-semibold flex items-center gap-1.5" style={{ color: "#d97706" }}>
                            <Sparkles className="w-3 h-3" /> Penetration Options Available
                          </span>
                          {(claudeProgress.pending_pentest_options as any[]).filter((o: any) => !o.user_selected).map((opt: any, i: number) => (
                            <div key={i} className="flex flex-wrap items-center gap-2 text-xs">
                              <span style={{ color: "var(--text-primary)" }}>{opt.title || opt.description}</span>
                              {(opt.options || []).map((action: string, j: number) => (
                                <button
                                  key={j}
                                  onClick={async () => {
                                    if (claudeScanId) {
                                      await api.claudeDastPentestOption(claudeScanId, { option_id: opt.option_id || String(i), selected_action: action });
                                      toast.success(`Selected: ${action}`);
                                    }
                                  }}
                                  className="px-2 py-0.5 rounded text-[10px] font-medium transition-colors hover:bg-amber-500/20"
                                  style={{ background: "rgba(217,119,6,0.15)", color: "#f59e0b" }}
                                >
                                  {action}
                                </button>
                              ))}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Sub-tabs */}
              <div className="flex gap-1 p-1 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                {(["dashboard", "crawled", "history", "session"] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => {
                      setClaudeActiveSubTab(tab);
                      if (tab === "crawled" && claudeCrawlResults.length === 0 && id) api.claudeDastCrawlResults(id as string).then(setClaudeCrawlResults).catch(() => {});
                      if (tab === "history" && claudeHistory.length === 0 && id) api.claudeDastHistory(id as string).then(setClaudeHistory).catch(() => {});
                      if (tab === "session" && id) api.claudeDastSession(id as string).then(setClaudeSession).catch(() => {});
                    }}
                    className="px-3 py-1.5 rounded-md text-xs font-medium"
                    style={{
                      background: claudeActiveSubTab === tab ? "rgba(217,119,6,0.2)" : "transparent",
                      color: claudeActiveSubTab === tab ? "#f59e0b" : "var(--text-secondary)",
                    }}
                  >
                    {tab === "dashboard" ? "Dashboard" : tab === "crawled" ? "AI Crawled" : tab === "history" ? "Scan History" : "Session"}
                  </button>
                ))}
              </div>

              {/* Dashboard — latest scan results summary */}
              {claudeActiveSubTab === "dashboard" && claudeProgress && claudeProgress.status === "completed" && (
                <div className="rounded-xl p-4 space-y-3" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="w-4 h-4" style={{ color: "#22c55e" }} />
                    <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Scan Complete</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[
                      { label: "Findings", value: claudeProgress.total_findings || 0 },
                      { label: "Pages Crawled", value: claudeProgress.pages_crawled || 0 },
                      { label: "Cost", value: `$${(claudeProgress.cost?.total_cost_usd || 0).toFixed(2)}` },
                      { label: "Duration", value: `${claudeProgress.duration_seconds || 0}s` },
                    ].map((stat) => (
                      <div key={stat.label} className="rounded-lg p-3 text-center" style={{ background: "var(--bg-elevated)" }}>
                        <div className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>{stat.value}</div>
                        <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>{stat.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Crawled — Full Sub-Tabs */}
              {claudeActiveSubTab === "crawled" && (
                <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                  <div className="p-4 space-y-3">
                    {claudeCrawlResults.length === 0 ? (
                      <div className="text-center py-8">
                        <Globe className="w-8 h-8 mx-auto mb-2" style={{ color: "var(--text-secondary)", opacity: 0.5 }} />
                        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>No AI crawl results yet. Run a Claude AI scan to discover pages.</p>
                      </div>
                    ) : (() => {
                      const cr = claudeCrawlResults[0];
                      const crawlSubTabs = [
                        { id: "pages" as const, label: "Pages", count: cr.total_pages || (cr.crawled_pages || []).length },
                        { id: "apis" as const, label: "APIs", count: (cr.api_endpoints || []).length },
                        { id: "hidden_paths" as const, label: "Hidden Paths", count: (cr.hidden_paths || []).length },
                        { id: "hidden_params" as const, label: "Hidden Params", count: (cr.hidden_parameters || []).length },
                        { id: "forms" as const, label: "Forms", count: (cr.forms_discovered || []).length },
                        { id: "subdomains" as const, label: "Subdomains", count: (cr.subdomains || []).length },
                        { id: "js_analysis" as const, label: "JS Analysis", count: (cr.js_files || []).length },
                        { id: "sca" as const, label: "SCA", count: (cr.sca_results || []).length },
                        { id: "technology" as const, label: "Technology", count: Object.keys(cr.technology_stack || {}).length },
                        { id: "attack_surface" as const, label: "Attack Surface", count: cr.attack_surface_summary ? 1 : 0 },
                      ];
                      return (
                        <div className="space-y-3">
                          <div className="flex items-center gap-2 text-[10px]" style={{ color: "var(--text-secondary)" }}>
                            Scan: {cr.scan_id} | {cr.total_pages || 0} pages | {cr.total_endpoints || 0} endpoints | {cr.total_parameters || 0} params | {cr.duration_seconds || 0}s
                          </div>
                          {/* Crawl Sub-Tab Bar */}
                          <div className="flex gap-1 flex-wrap">
                            {crawlSubTabs.map((st) => (
                              <button
                                key={st.id}
                                onClick={() => setClaudeCrawlSubTab(st.id)}
                                className="px-2 py-1 rounded text-[10px] font-medium transition-all"
                                style={{
                                  background: claudeCrawlSubTab === st.id ? "rgba(217,119,6,0.2)" : "var(--bg-elevated)",
                                  color: claudeCrawlSubTab === st.id ? "#f59e0b" : "var(--text-secondary)",
                                  border: claudeCrawlSubTab === st.id ? "1px solid rgba(217,119,6,0.3)" : "1px solid transparent",
                                }}
                              >
                                {st.label} {st.count > 0 && <span className="ml-0.5 opacity-70">({st.count})</span>}
                              </button>
                            ))}
                          </div>

                          {/* Pages */}
                          {claudeCrawlSubTab === "pages" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-1">
                              {(cr.crawled_pages || []).slice(0, 200).map((page: any, pi: number) => (
                                <details key={pi} className="rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                  <summary className="flex items-center gap-2 text-xs p-2 cursor-pointer">
                                    <span className="px-1 py-0.5 rounded text-[10px] font-mono" style={{ background: (page.status_code || 200) < 400 ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)", color: (page.status_code || 200) < 400 ? "#22c55e" : "#ef4444" }}>
                                      {page.status_code || 200}
                                    </span>
                                    <span className="px-1 py-0.5 rounded text-[10px] font-mono" style={{ background: "rgba(59,130,246,0.1)", color: "#3b82f6" }}>{page.method || "GET"}</span>
                                    <span className="truncate" style={{ color: "var(--text-primary)" }}>{page.url || page.path}</span>
                                    {page.content_type && <span className="ml-auto text-[10px] shrink-0" style={{ color: "var(--text-secondary)" }}>{page.content_type}</span>}
                                  </summary>
                                  <div className="px-3 pb-2 space-y-2">
                                    {page.technology_detected && page.technology_detected.length > 0 && (
                                      <div className="flex flex-wrap gap-1">
                                        {(page.technology_detected as string[]).map((t: string, ti: number) => (
                                          <span key={ti} className="text-[10px] px-1 py-0.5 rounded" style={{ background: "rgba(139,92,246,0.1)", color: "#8b5cf6" }}>{t}</span>
                                        ))}
                                      </div>
                                    )}
                                    {page.forms && page.forms.length > 0 && <div className="text-[10px]" style={{ color: "#f59e0b" }}>Forms: {page.forms.length}</div>}
                                    {page.links && <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>Links: {page.links.length}</div>}
                                    {page.interesting_findings && page.interesting_findings.length > 0 && (
                                      <div className="space-y-0.5">
                                        {(page.interesting_findings as string[]).map((f: string, fi: number) => (
                                          <div key={fi} className="text-[10px] px-1.5 py-1 rounded" style={{ background: "rgba(239,68,68,0.06)", color: "#f87171" }}>{f}</div>
                                        ))}
                                      </div>
                                    )}
                                    {page.response_body_preview && (
                                      <pre className="text-[10px] p-2 rounded overflow-x-auto max-h-32" style={{ background: "var(--bg-primary)", color: "var(--text-secondary)" }}>
                                        {page.response_body_preview}
                                      </pre>
                                    )}
                                  </div>
                                </details>
                              ))}
                            </div>
                          )}

                          {/* API Endpoints */}
                          {claudeCrawlSubTab === "apis" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-1">
                              {(cr.api_endpoints || []).length === 0 ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No API endpoints discovered</p>
                              ) : (cr.api_endpoints as any[]).map((ep: any, ei: number) => (
                                <div key={ei} className="p-2.5 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                  <div className="flex items-center gap-2">
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold" style={{ background: "rgba(59,130,246,0.15)", color: "#3b82f6" }}>{ep.method || "GET"}</span>
                                    <span className="text-xs font-mono truncate" style={{ color: "var(--text-primary)" }}>{ep.url}</span>
                                    {ep.auth_required && <span className="text-[10px] px-1 py-0.5 rounded ml-auto" style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444" }}>Auth</span>}
                                  </div>
                                  {ep.params && ep.params.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-1.5">
                                      {(ep.params as string[]).map((p: string, pi: number) => (
                                        <span key={pi} className="text-[10px] px-1 py-0.5 rounded font-mono" style={{ background: "rgba(34,197,94,0.1)", color: "#22c55e" }}>{p}</span>
                                      ))}
                                    </div>
                                  )}
                                  {ep.schema && <div className="text-[10px] mt-1" style={{ color: "var(--text-secondary)" }}>Schema: {typeof ep.schema === "string" ? ep.schema : JSON.stringify(ep.schema).slice(0, 120)}</div>}
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Hidden Paths */}
                          {claudeCrawlSubTab === "hidden_paths" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-1">
                              {(cr.hidden_paths || []).length === 0 ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No hidden paths discovered</p>
                              ) : (cr.hidden_paths as any[]).map((hp: any, hi: number) => (
                                <div key={hi} className="flex items-center gap-2 p-2 rounded-lg text-xs" style={{ background: "var(--bg-elevated)" }}>
                                  <span className="px-1 py-0.5 rounded text-[10px] font-mono" style={{ background: hp.status < 400 ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)", color: hp.status < 400 ? "#22c55e" : "#ef4444" }}>
                                    {hp.status}
                                  </span>
                                  <span className="font-mono truncate" style={{ color: "var(--text-primary)" }}>{hp.path}</span>
                                  <span className="ml-auto text-[10px] shrink-0" style={{ color: "var(--text-secondary)" }}>{hp.how_found || hp.wordlist_used || ""}</span>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Hidden Parameters */}
                          {claudeCrawlSubTab === "hidden_params" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-1">
                              {(cr.hidden_parameters || []).length === 0 ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No hidden parameters discovered</p>
                              ) : (cr.hidden_parameters as any[]).map((hp: any, hi: number) => (
                                <div key={hi} className="p-2 rounded-lg text-xs" style={{ background: "var(--bg-elevated)" }}>
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono font-bold" style={{ color: "#f59e0b" }}>{hp.param}</span>
                                    <span className="text-[10px] px-1 py-0.5 rounded" style={{ background: "rgba(139,92,246,0.1)", color: "#8b5cf6" }}>{hp.type || "query"}</span>
                                  </div>
                                  <div className="text-[10px] mt-0.5" style={{ color: "var(--text-secondary)" }}>
                                    {hp.url} {hp.how_found && <span>| Found via: {hp.how_found}</span>}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Forms */}
                          {claudeCrawlSubTab === "forms" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-2">
                              {(cr.forms_discovered || []).length === 0 ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No forms discovered</p>
                              ) : (cr.forms_discovered as any[]).map((form: any, fi: number) => (
                                <div key={fi} className="p-3 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                  <div className="flex items-center gap-2 mb-2">
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold" style={{ background: "rgba(217,119,6,0.15)", color: "#d97706" }}>{form.method || "POST"}</span>
                                    <span className="text-xs font-mono truncate" style={{ color: "var(--text-primary)" }}>{form.action || form.url}</span>
                                  </div>
                                  <div className="text-[10px] mb-1" style={{ color: "var(--text-secondary)" }}>Page: {form.url}</div>
                                  {form.fields && form.fields.length > 0 && (
                                    <div className="flex flex-wrap gap-1">
                                      {(form.fields as any[]).map((field: any, ffi: number) => (
                                        <span key={ffi} className="text-[10px] px-1.5 py-0.5 rounded font-mono" style={{ background: "rgba(59,130,246,0.08)", color: "#3b82f6" }}>
                                          {field.name || field}: {field.type || "text"}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Subdomains */}
                          {claudeCrawlSubTab === "subdomains" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-1">
                              {(cr.subdomains || []).length === 0 ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No subdomains discovered</p>
                              ) : (cr.subdomains as any[]).map((sd: any, si: number) => (
                                <div key={si} className="p-2 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                  <div className="flex items-center gap-2">
                                    <span className="text-xs font-mono font-medium" style={{ color: "var(--text-primary)" }}>{sd.subdomain}</span>
                                    {sd.ip && <span className="text-[10px] font-mono" style={{ color: "var(--text-secondary)" }}>{sd.ip}</span>}
                                    {sd.status && (
                                      <span className="text-[10px] px-1 py-0.5 rounded ml-auto" style={{ background: sd.status === "active" ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)", color: sd.status === "active" ? "#22c55e" : "#ef4444" }}>
                                        {sd.status}
                                      </span>
                                    )}
                                  </div>
                                  {sd.technologies && sd.technologies.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {(sd.technologies as string[]).map((t: string, ti: number) => (
                                        <span key={ti} className="text-[10px] px-1 py-0.5 rounded" style={{ background: "rgba(139,92,246,0.1)", color: "#8b5cf6" }}>{t}</span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}

                          {/* JS Analysis */}
                          {claudeCrawlSubTab === "js_analysis" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-2">
                              {(cr.js_files || []).length === 0 ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No JavaScript files analyzed</p>
                              ) : (cr.js_files as any[]).map((js: any, ji: number) => (
                                <details key={ji} className="rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                  <summary className="p-2.5 cursor-pointer text-xs">
                                    <span className="font-mono" style={{ color: "var(--text-primary)" }}>{js.url}</span>
                                    <span className="ml-2 text-[10px]" style={{ color: "var(--text-secondary)" }}>{js.size ? `${(js.size / 1024).toFixed(0)}KB` : ""}</span>
                                    {(js.secrets || []).length > 0 && <span className="ml-2 text-[10px] px-1 py-0.5 rounded" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>{js.secrets.length} secrets</span>}
                                    {(js.endpoints_found || []).length > 0 && <span className="ml-1 text-[10px] px-1 py-0.5 rounded" style={{ background: "rgba(59,130,246,0.1)", color: "#3b82f6" }}>{js.endpoints_found.length} endpoints</span>}
                                  </summary>
                                  <div className="px-3 pb-3 space-y-2">
                                    {(js.secrets || []).length > 0 && (
                                      <div>
                                        <div className="text-[10px] font-medium mb-1" style={{ color: "#ef4444" }}>Secrets</div>
                                        {(js.secrets as any[]).map((s: any, si: number) => (
                                          <div key={si} className="text-[10px] p-1 rounded mb-0.5" style={{ background: "rgba(239,68,68,0.06)" }}>
                                            <span style={{ color: "#ef4444" }}>{typeof s === "string" ? s : s.type || "secret"}</span>
                                            {s.value_preview && <span style={{ color: "var(--text-secondary)" }}> — {s.value_preview}</span>}
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                    {(js.endpoints_found || []).length > 0 && (
                                      <div>
                                        <div className="text-[10px] font-medium mb-1" style={{ color: "#3b82f6" }}>Endpoints Found</div>
                                        <div className="flex flex-wrap gap-1">
                                          {(js.endpoints_found as string[]).map((ep: string, ei: number) => (
                                            <span key={ei} className="text-[10px] px-1 py-0.5 rounded font-mono" style={{ background: "rgba(59,130,246,0.08)", color: "#3b82f6" }}>{ep}</span>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                    {(js.libraries || []).length > 0 && (
                                      <div>
                                        <div className="text-[10px] font-medium mb-1" style={{ color: "#22c55e" }}>Libraries</div>
                                        <div className="flex flex-wrap gap-1">
                                          {(js.libraries as any[]).map((lib: any, li: number) => (
                                            <span key={li} className="text-[10px] px-1 py-0.5 rounded" style={{ background: "rgba(34,197,94,0.08)", color: "#22c55e" }}>
                                              {typeof lib === "string" ? lib : `${lib.name}${lib.version ? `@${lib.version}` : ""}`}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </details>
                              ))}
                            </div>
                          )}

                          {/* SCA */}
                          {claudeCrawlSubTab === "sca" && (
                            <div className="max-h-[500px] overflow-y-auto space-y-2">
                              {(cr.sca_results || []).length === 0 ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No SCA results. Libraries found in JS Analysis tab may have version info.</p>
                              ) : (cr.sca_results as any[]).map((sca: any, si: number) => (
                                <div key={si} className="p-2.5 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                  <div className="flex items-center gap-2">
                                    <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{sca.library || sca.name}</span>
                                    {sca.version && <span className="text-[10px] font-mono" style={{ color: "var(--text-secondary)" }}>v{sca.version}</span>}
                                    {sca.severity && (
                                      <span className="text-[10px] px-1.5 py-0.5 rounded ml-auto" style={{
                                        background: sca.severity === "critical" ? "rgba(239,68,68,0.15)" : sca.severity === "high" ? "rgba(249,115,22,0.15)" : "rgba(234,179,8,0.15)",
                                        color: sca.severity === "critical" ? "#ef4444" : sca.severity === "high" ? "#f97316" : "#eab308",
                                      }}>
                                        {sca.severity}
                                      </span>
                                    )}
                                  </div>
                                  {sca.cve && <div className="text-[10px] font-mono mt-1" style={{ color: "#ef4444" }}>{Array.isArray(sca.cve) ? sca.cve.join(", ") : sca.cve}</div>}
                                  {sca.description && <div className="text-[10px] mt-1" style={{ color: "var(--text-secondary)" }}>{sca.description}</div>}
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Technology Stack */}
                          {claudeCrawlSubTab === "technology" && (
                            <div className="space-y-3">
                              {(!cr.technology_stack || Object.keys(cr.technology_stack).length === 0) ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No technology stack detected yet</p>
                              ) : (
                                <div className="grid grid-cols-2 gap-2">
                                  {Object.entries(cr.technology_stack as Record<string, string>).map(([key, val]) => (
                                    <div key={key} className="p-3 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                      <div className="text-[10px] uppercase tracking-wider mb-1" style={{ color: "var(--text-secondary)" }}>{key}</div>
                                      <div className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{val || "Unknown"}</div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}

                          {/* Attack Surface */}
                          {claudeCrawlSubTab === "attack_surface" && (
                            <div className="space-y-3">
                              {!cr.attack_surface_summary ? (
                                <p className="text-xs py-4 text-center" style={{ color: "var(--text-secondary)" }}>No attack surface analysis available</p>
                              ) : (
                                <div className="p-4 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                                  <div className="text-xs font-medium mb-2" style={{ color: "#d97706" }}>AI Attack Surface Analysis</div>
                                  <div className="text-xs whitespace-pre-wrap leading-relaxed" style={{ color: "var(--text-primary)" }}>{cr.attack_surface_summary}</div>
                                </div>
                              )}
                              {/* Quick stats */}
                              <div className="grid grid-cols-3 gap-2">
                                {[
                                  { label: "Pages", value: cr.total_pages || 0 },
                                  { label: "Endpoints", value: cr.total_endpoints || 0 },
                                  { label: "Parameters", value: cr.total_parameters || 0 },
                                  { label: "Forms", value: cr.total_forms || 0 },
                                  { label: "JS Files", value: cr.total_js_files || 0 },
                                  { label: "Subdomains", value: cr.total_subdomains || 0 },
                                ].map((s) => (
                                  <div key={s.label} className="p-2 rounded-lg text-center" style={{ background: "var(--bg-elevated)" }}>
                                    <div className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>{s.value}</div>
                                    <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>{s.label}</div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* History */}
              {claudeActiveSubTab === "history" && (
                <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                  <div className="p-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <History className="w-4 h-4" style={{ color: "#d97706" }} />
                      <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Claude Scan History</span>
                    </div>
                    {claudeHistory.length === 0 ? (
                      <p className="text-xs" style={{ color: "var(--text-secondary)" }}>No Claude AI scans yet for this project.</p>
                    ) : (
                      <div className="space-y-2">
                        {claudeHistory.map((s: any, i: number) => (
                          <div key={i} className="flex items-center justify-between p-3 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{s.scan_mode} scan</span>
                                <span className="text-[10px] px-1.5 py-0.5 rounded-full"
                                  style={{ background: s.status === "completed" ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)", color: s.status === "completed" ? "#22c55e" : "#ef4444" }}
                                >
                                  {s.status}
                                </span>
                              </div>
                              <div className="flex gap-3 text-[10px]" style={{ color: "var(--text-secondary)" }}>
                                <span>{s.total_findings} findings</span>
                                <span>{s.pages_crawled} pages</span>
                                <span>${(s.total_cost_usd || 0).toFixed(2)}</span>
                                <span>{s.duration_seconds}s</span>
                              </div>
                            </div>
                            <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>
                              {s.created_at ? new Date(s.created_at).toLocaleDateString() : ""}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Session */}
              {claudeActiveSubTab === "session" && (
                <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                  <div className="p-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <Sparkles className="w-4 h-4" style={{ color: "#d97706" }} />
                      <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Session Context</span>
                    </div>
                    {!claudeSession?.has_session ? (
                      <p className="text-xs" style={{ color: "var(--text-secondary)" }}>No active session. Context will be created on first Claude AI scan.</p>
                    ) : (
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                          <div className="rounded-lg p-2.5" style={{ background: "var(--bg-elevated)" }}>
                            <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>Scans</div>
                            <div className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{claudeSession.scan_count || 0}</div>
                          </div>
                          <div className="rounded-lg p-2.5" style={{ background: "var(--bg-elevated)" }}>
                            <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>Endpoints Discovered</div>
                            <div className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{claudeSession.discovered_endpoints_count || 0}</div>
                          </div>
                        </div>
                        {claudeSession.technology_stack && Object.keys(claudeSession.technology_stack).length > 0 && (
                          <div>
                            <div className="text-[10px] mb-1" style={{ color: "var(--text-secondary)" }}>Detected Technology</div>
                            <div className="flex flex-wrap gap-1">
                              {Object.entries(claudeSession.technology_stack as Record<string, string>).map(([k, v]) => (
                                <span key={k} className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "rgba(59,130,246,0.15)", color: "#3b82f6" }}>
                                  {k}: {v}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        {claudeSession.waf_detected && (
                          <div className="text-xs" style={{ color: "#f59e0b" }}>WAF Detected: {claudeSession.waf_detected}</div>
                        )}
                        {claudeSession.interesting_behaviors && claudeSession.interesting_behaviors.length > 0 && (
                          <div>
                            <div className="text-[10px] mb-1" style={{ color: "var(--text-secondary)" }}>Interesting Behaviors</div>
                            <div className="space-y-1">
                              {(claudeSession.interesting_behaviors as string[]).map((b: string, i: number) => (
                                <div key={i} className="text-xs p-1.5 rounded" style={{ background: "rgba(217,119,6,0.08)", color: "#d97706" }}>{b}</div>
                              ))}
                            </div>
                          </div>
                        )}
                        {claudeSession.summary && (
                          <div className="text-xs" style={{ color: "var(--text-secondary)" }}>{claudeSession.summary}</div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            ) : null}
          </div>
        )}

        {!scanResult && !scanning && dastActiveTab !== "crawl" && dastActiveTab !== "claude" && (
          <div className="text-center py-16 rounded-xl" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
            <Shield className="w-12 h-12 mx-auto mb-3" style={{ color: "var(--text-secondary)", opacity: 0.5 }} />
            <p className="font-medium" style={{ color: "var(--text-primary)" }}>Ready to Scan</p>
            <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
              Select checks and click &quot;Run Scan&quot; to start automated security testing
            </p>
          </div>
        )}

        {/* ====== SCHEDULING SECTION ====== */}
        {showSchedule && (
          <div className="mt-6 rounded-xl border p-6" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Calendar size={20} style={{ color: "#8b5cf6" }} />
                <h3 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>Scan Schedule</h3>
              </div>
              <button onClick={() => setShowSchedule(false)} className="p-1 rounded hover:bg-white/10" style={{ color: "var(--text-secondary)" }}>
                <span className="text-xs">Close</span>
              </button>
            </div>

            {schedule ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                    <p className="text-xs mb-1" style={{ color: "var(--text-secondary)" }}>Schedule</p>
                    <p className="text-sm font-mono font-semibold" style={{ color: "var(--text-primary)" }}>{schedule.cron_expression}</p>
                  </div>
                  <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                    <p className="text-xs mb-1" style={{ color: "var(--text-secondary)" }}>Status</p>
                    <p className="text-sm font-semibold" style={{ color: schedule.is_active ? "#16a34a" : "#6b7280" }}>
                      {schedule.is_active ? "Active" : "Paused"}
                    </p>
                  </div>
                  <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                    <p className="text-xs mb-1" style={{ color: "var(--text-secondary)" }}>Last Run</p>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                      {schedule.last_run_at ? new Date(schedule.last_run_at).toLocaleString() : "Never"}
                    </p>
                  </div>
                  <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                    <p className="text-xs mb-1" style={{ color: "var(--text-secondary)" }}>Next Run</p>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                      {schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleString() : "—"}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={async () => {
                      try {
                        await api.dastDeleteSchedule(id as string);
                        setSchedule(null);
                        toast.success("Schedule removed");
                      } catch { toast.error("Failed to remove schedule"); }
                    }}
                    className="px-3 py-1.5 rounded-lg text-xs font-medium border hover:bg-red-500/10 transition-colors"
                    style={{ color: "#dc2626", borderColor: "#dc262633" }}
                  >
                    Remove Schedule
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  Set up automated recurring scans. Scans will run on the configured schedule automatically.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium mb-1.5 block" style={{ color: "var(--text-secondary)" }}>
                      Cron Expression
                    </label>
                    <input
                      type="text"
                      value={cronExpression}
                      onChange={(e) => setCronExpression(e.target.value)}
                      placeholder="0 2 * * 1"
                      className="w-full px-3 py-2 rounded-lg text-sm font-mono border"
                      style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium mb-1.5 block" style={{ color: "var(--text-secondary)" }}>
                      Quick Presets
                    </label>
                    <div className="flex flex-wrap gap-1.5">
                      {[
                        { label: "Daily 2AM", cron: "0 2 * * *" },
                        { label: "Weekly Mon", cron: "0 2 * * 1" },
                        { label: "Monthly 1st", cron: "0 2 1 * *" },
                        { label: "Every 6h", cron: "0 */6 * * *" },
                      ].map((p) => (
                        <button
                          key={p.cron}
                          onClick={() => setCronExpression(p.cron)}
                          className="px-2.5 py-1 rounded text-xs border hover:bg-white/5 transition-colors"
                          style={{
                            color: cronExpression === p.cron ? "#8b5cf6" : "var(--text-secondary)",
                            borderColor: cronExpression === p.cron ? "#8b5cf633" : "var(--border-subtle)",
                            backgroundColor: cronExpression === p.cron ? "#8b5cf611" : "transparent",
                          }}
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <button
                  onClick={async () => {
                    setScheduleLoading(true);
                    try {
                      const data = await api.dastCreateSchedule({
                        project_id: id as string,
                        cron_expression: cronExpression,
                        enabled: true,
                      });
                      setSchedule(data);
                      toast.success("Scan schedule created");
                    } catch (e: any) {
                      toast.error(e?.message || "Failed to create schedule");
                    } finally { setScheduleLoading(false); }
                  }}
                  disabled={scheduleLoading || !cronExpression}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium text-white bg-gradient-to-r from-purple-600 to-violet-600 hover:from-purple-700 hover:to-violet-700 transition-all disabled:opacity-50"
                >
                  {scheduleLoading ? <Loader2 size={14} className="animate-spin" /> : <Calendar size={14} />}
                  Create Schedule
                </button>
              </div>
            )}
          </div>
        )}

        {/* ====== BASELINES SECTION ====== */}
        {showBaselines && (
          <div className="mt-6 rounded-xl border p-6" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Activity size={20} style={{ color: "#06b6d4" }} />
                <h3 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>Scan Baselines & Trends</h3>
              </div>
              <button onClick={() => setShowBaselines(false)} className="p-1 rounded hover:bg-white/10" style={{ color: "var(--text-secondary)" }}>
                <span className="text-xs">Close</span>
              </button>
            </div>

            {baselinesLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 size={24} className="animate-spin text-cyan-400" />
              </div>
            ) : baselines.length === 0 ? (
              <div className="text-center py-10">
                <Activity size={32} className="mx-auto mb-3" style={{ color: "var(--text-secondary)" }} />
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  No baseline data available. Baselines are created automatically from scheduled scans.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  {baselines.length > 0 && (() => {
                    const latest = baselines[0];
                    return (
                      <>
                        <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "#16a34a33" }}>
                          <p className="text-xs mb-1" style={{ color: "var(--text-secondary)" }}>Fixed Since Last</p>
                          <p className="text-2xl font-bold" style={{ color: "#16a34a" }}>{latest.fixed_findings || 0}</p>
                        </div>
                        <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "#dc262633" }}>
                          <p className="text-xs mb-1" style={{ color: "var(--text-secondary)" }}>New Issues</p>
                          <p className="text-2xl font-bold" style={{ color: "#dc2626" }}>{latest.new_findings || 0}</p>
                        </div>
                        <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                          <p className="text-xs mb-1" style={{ color: "var(--text-secondary)" }}>Unchanged</p>
                          <p className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{latest.unchanged_findings || 0}</p>
                        </div>
                      </>
                    );
                  })()}
                </div>

                <div className="rounded-xl border overflow-hidden" style={{ borderColor: "var(--border-subtle)" }}>
                  <table className="w-full text-sm">
                    <thead>
                      <tr style={{ backgroundColor: "var(--bg-primary)", borderBottom: "1px solid var(--border-subtle)" }}>
                        <th className="text-left px-4 py-2.5 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>Date</th>
                        <th className="text-center px-4 py-2.5 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>Total</th>
                        <th className="text-center px-4 py-2.5 text-xs font-semibold uppercase" style={{ color: "#dc2626" }}>Critical</th>
                        <th className="text-center px-4 py-2.5 text-xs font-semibold uppercase" style={{ color: "#ea580c" }}>High</th>
                        <th className="text-center px-4 py-2.5 text-xs font-semibold uppercase" style={{ color: "#ca8a04" }}>Medium</th>
                        <th className="text-center px-4 py-2.5 text-xs font-semibold uppercase" style={{ color: "#16a34a" }}>New</th>
                        <th className="text-center px-4 py-2.5 text-xs font-semibold uppercase" style={{ color: "#3b82f6" }}>Fixed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {baselines.map((b: any, idx: number) => {
                        const sev = b.findings_by_severity || {};
                        return (
                          <tr key={b.id || idx} className="hover:bg-white/[0.02]" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                            <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-primary)" }}>
                              {b.created_at ? new Date(b.created_at).toLocaleString() : "—"}
                            </td>
                            <td className="px-4 py-2.5 text-center text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
                              {b.total_findings || 0}
                            </td>
                            <td className="px-4 py-2.5 text-center text-xs font-semibold" style={{ color: "#dc2626" }}>
                              {sev.critical || 0}
                            </td>
                            <td className="px-4 py-2.5 text-center text-xs font-semibold" style={{ color: "#ea580c" }}>
                              {sev.high || 0}
                            </td>
                            <td className="px-4 py-2.5 text-center text-xs font-semibold" style={{ color: "#ca8a04" }}>
                              {sev.medium || 0}
                            </td>
                            <td className="px-4 py-2.5 text-center text-xs font-semibold" style={{ color: "#16a34a" }}>
                              {b.new_findings || 0}
                            </td>
                            <td className="px-4 py-2.5 text-center text-xs font-semibold" style={{ color: "#3b82f6" }}>
                              {b.fixed_findings || 0}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
