"use client";
import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import Link from "next/link";
import ProjectSubNav from "@/components/ProjectSubNav";
import {
  Shield, Upload, Play, StopCircle, CheckCircle, XCircle, AlertTriangle,
  Loader2, ArrowLeft, ChevronDown, ChevronRight, FileText, Folder, FolderOpen,
  File, Search, Filter, Copy, Code, GitBranch, Github, Clock, Calendar,
  Sparkles, Brain, Download, ExternalLink, Eye, Settings2, RefreshCw,
  Terminal, BookOpen, Hash, Layers, ChevronUp, X, Plus, Trash2, Link2,
  FileCode, Bug, Info, BarChart3, Activity, Webhook, Package, Scale,
  Container, ShieldAlert, FileJson, Database, TrendingUp, Zap, KeyRound,
} from "lucide-react";

/* ---------- constants ---------- */
const POLL_MS = 2000;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  info: "#3b82f6",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  open: { label: "Open", color: "#3b82f6" },
  confirmed: { label: "Confirmed", color: "#dc2626" },
  false_positive: { label: "False Positive", color: "#6b7280" },
  fixed: { label: "Fixed", color: "#16a34a" },
  ignored: { label: "Ignored", color: "#9ca3af" },
  wont_fix: { label: "Won't Fix", color: "#6b7280" },
};

const SCAN_STATUS_COLORS: Record<string, string> = {
  completed: "#16a34a",
  running: "#ca8a04",
  failed: "#dc2626",
  stopped: "#6b7280",
  cancelled: "#6b7280",
  queued: "#3b82f6",
};

const PHASE_LABELS: Record<string, string> = {
  extracting: "Extracting files",
  language_detection: "Detecting languages",
  semgrep_scan: "Running Semgrep",
  iac_scanning: "IaC scanning",
  container_scanning: "Container analysis",
  js_analyzing: "JS/TS deep analysis",
  secret_scan: "Scanning for secrets",
  secret_scan_history: "Scanning git history",
  secret_verification: "Verifying secrets",
  sca_scanning: "Dependency scanning (SCA)",
  claude_reviewing: "Claude security review",
  scanning: "Scanning source code",
  ai_analysis: "AI analysis",
  ai_analyzing: "AI analysis",
  analyzing: "AI analysis",
  cve_enrichment: "CVE intelligence",
  sbom_generation: "Generating SBOM",
  storing_results: "Saving results",
  completing: "Finalizing scan",
  done: "Complete",
};

type Tab = "upload" | "repos" | "history" | "results" | "cicd";
type ResultsSubTab = "findings" | "secrets" | "dependencies" | "sbom" | "cve" | "breakdown";

/* ---------- helpers ---------- */
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatDuration(seconds: number): string {
  if (!seconds || seconds < 0) return "--";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function formatDate(iso: string): string {
  if (!iso) return "--";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function severityBadge(sev: string) {
  const color = SEVERITY_COLORS[sev] || "#6b7280";
  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-semibold uppercase"
      style={{ backgroundColor: color + "22", color, border: `1px solid ${color}44` }}
    >
      {sev}
    </span>
  );
}

function statusBadge(status: string) {
  const cfg = STATUS_LABELS[status] || { label: status, color: "#6b7280" };
  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-medium"
      style={{ backgroundColor: cfg.color + "22", color: cfg.color, border: `1px solid ${cfg.color}44` }}
    >
      {cfg.label}
    </span>
  );
}

function getThreatLevel(counts: Record<string, number>) {
  if ((counts.critical || 0) > 0) return { label: "Critical", color: "#dc2626" };
  if ((counts.high || 0) > 0) return { label: "High", color: "#ea580c" };
  if ((counts.medium || 0) > 0) return { label: "Medium", color: "#ca8a04" };
  if ((counts.low || 0) > 0) return { label: "Low", color: "#16a34a" };
  return { label: "Informational", color: "#3b82f6" };
}

/* ---------- file tree builder ---------- */
interface TreeNode {
  name: string;
  path: string;
  children: TreeNode[];
  issueCount: number;
  isFile: boolean;
}

function buildFileTree(findings: any[]): TreeNode {
  const root: TreeNode = { name: "/", path: "/", children: [], issueCount: 0, isFile: false };
  for (const f of findings) {
    const fp = (f.file_path || "unknown").replace(/\\/g, "/");
    const parts = fp.split("/").filter(Boolean);
    let node = root;
    let currentPath = "";
    for (let i = 0; i < parts.length; i++) {
      currentPath += "/" + parts[i];
      const isLast = i === parts.length - 1;
      let child = node.children.find((c) => c.name === parts[i]);
      if (!child) {
        child = { name: parts[i], path: currentPath, children: [], issueCount: 0, isFile: isLast };
        node.children.push(child);
      }
      child.issueCount++;
      node = child;
    }
    root.issueCount++;
  }
  const sortTree = (n: TreeNode) => {
    n.children.sort((a, b) => {
      if (!a.isFile && b.isFile) return -1;
      if (a.isFile && !b.isFile) return 1;
      return a.name.localeCompare(b.name);
    });
    n.children.forEach(sortTree);
  };
  sortTree(root);
  return root;
}

/* ---------- FileTreeNode component ---------- */
function FileTreeNode({
  node,
  depth,
  selectedPath,
  onSelect,
  expandedPaths,
  onToggle,
}: {
  node: TreeNode;
  depth: number;
  selectedPath: string | null;
  onSelect: (path: string | null) => void;
  expandedPaths: Set<string>;
  onToggle: (path: string) => void;
}) {
  const isExpanded = expandedPaths.has(node.path);
  const isSelected = selectedPath === node.path;

  if (node.isFile) {
    return (
      <button
        onClick={() => onSelect(isSelected ? null : node.path)}
        className="flex items-center gap-1.5 w-full text-left px-2 py-1 text-xs rounded hover:bg-white/5 transition-colors"
        style={{
          paddingLeft: `${depth * 16 + 8}px`,
          backgroundColor: isSelected ? "rgba(234,88,12,0.15)" : undefined,
          color: isSelected ? "#fb923c" : "var(--text-secondary)",
        }}
      >
        <FileCode size={14} className="shrink-0" style={{ color: isSelected ? "#fb923c" : "var(--text-secondary)" }} />
        <span className="truncate flex-1">{node.name}</span>
        <span
          className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold shrink-0"
          style={{ backgroundColor: "#ea580c22", color: "#ea580c" }}
        >
          {node.issueCount}
        </span>
      </button>
    );
  }

  return (
    <div>
      <button
        onClick={() => {
          onToggle(node.path);
          onSelect(isSelected ? null : node.path);
        }}
        className="flex items-center gap-1.5 w-full text-left px-2 py-1 text-xs rounded hover:bg-white/5 transition-colors"
        style={{
          paddingLeft: `${depth * 16 + 8}px`,
          backgroundColor: isSelected ? "rgba(234,88,12,0.1)" : undefined,
          color: isSelected ? "#fb923c" : "var(--text-primary)",
        }}
      >
        {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {isExpanded ? (
          <FolderOpen size={14} className="shrink-0 text-amber-500" />
        ) : (
          <Folder size={14} className="shrink-0 text-amber-500/70" />
        )}
        <span className="truncate flex-1 font-medium">{node.name}</span>
        <span
          className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold shrink-0"
          style={{ backgroundColor: "#ea580c22", color: "#ea580c" }}
        >
          {node.issueCount}
        </span>
      </button>
      {isExpanded && node.children.map((child) => (
        <FileTreeNode
          key={child.path}
          node={child}
          depth={depth + 1}
          selectedPath={selectedPath}
          onSelect={onSelect}
          expandedPaths={expandedPaths}
          onToggle={onToggle}
        />
      ))}
    </div>
  );
}

/* =================================================================
   SAST PAGE COMPONENT
   ================================================================= */
export default function SASTPage() {
  const router = useRouter();
  const { id: projectId } = useParams<{ id: string }>();
  const { user, hydrate, orgSettings } = useAuthStore();

  /* ---- core state ---- */
  const [project, setProject] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<Tab>("upload");

  /* ---- upload scan ---- */
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState(true);
  const [exhaustive, setExhaustive] = useState(false);
  const [gitleaksEnabled, setGitleaksEnabled] = useState(false);
  const [scanGitHistory, setScanGitHistory] = useState(false);
  const [excludePatterns, setExcludePatterns] = useState("");
  const [ruleSets, setRuleSets] = useState<string[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<any>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const handledGithubHandoffRef = useRef(false);

  /* ---- repos ---- */
  const [repos, setRepos] = useState<any[]>([]);
  const [connectModal, setConnectModal] = useState(false);
  const [githubToken, setGithubToken] = useState("");
  const [githubRepos, setGithubRepos] = useState<any[]>([]);
  const [githubLoading, setGithubLoading] = useState(false);
  const [githubPage, setGithubPage] = useState(1);
  const [githubStatus, setGithubStatus] = useState<any>(null);
  const [githubConnectMode, setGithubConnectMode] = useState<"github_app" | "oauth" | "pat">("github_app");
  const [githubAppInstallation, setGithubAppInstallation] = useState<any>(null);
  const [repoScanBranch, setRepoScanBranch] = useState<Record<string, string>>({});
  const [repoBranches, setRepoBranches] = useState<Record<string, string[]>>({});
  const [repoScanning, setRepoScanning] = useState<string | null>(null);

  /* ---- scan history ---- */
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  /* ---- results ---- */
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [aiExplaining, setAiExplaining] = useState<string | null>(null);
  const [aiExplanations, setAiExplanations] = useState<Record<string, string>>({});
  const [creatingPrId, setCreatingPrId] = useState<string | null>(null);
  const [sourceLoadingId, setSourceLoadingId] = useState<string | null>(null);
  const [sourceViewer, setSourceViewer] = useState<any | null>(null);
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterConfidence, setFilterConfidence] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [filterFilePath, setFilterFilePath] = useState("");
  const [breakdownFilterSource, setBreakdownFilterSource] = useState<string | null>(null);
  const [selectedTreePath, setSelectedTreePath] = useState<string | null>(null);
  const [expandedTreePaths, setExpandedTreePaths] = useState<Set<string>>(new Set(["/"]) );

  /* ---- results sub-tabs ---- */
  const [resultsSubTab, setResultsSubTab] = useState<ResultsSubTab>("findings");
  const [dependencies, setDependencies] = useState<any[]>([]);
  const [depPagination, setDepPagination] = useState<{ total: number; page: number; per_page: number; total_pages: number; total_vulnerable?: number; total_outdated?: number; total_secure?: number }>({ total: 0, page: 1, per_page: 20, total_pages: 1 });
  const [depFilters, setDepFilters] = useState<{ name: string; ecosystem: string; vulnerable: string }>({ name: "", ecosystem: "", vulnerable: "" });
  const [licenses, setLicenses] = useState<any>(null);
  const [cveSummary, setCveSummary] = useState<any>(null);
  const [secDataLoading, setSecDataLoading] = useState(false);
  const [claudeReviewLoading, setClaudeReviewLoading] = useState(false);

  /* ---- CI/CD ---- */
  const [webhookConfig, setWebhookConfig] = useState<any>(null);
  const [cicdLoading, setCicdLoading] = useState(false);

  /* ---- init ---- */
  useEffect(() => { hydrate(); }, [hydrate]);

  useEffect(() => {
    if (!projectId) return;
    api.getProject(projectId).then(setProject).catch(() => toast.error("Failed to load project"));
  }, [projectId]);

  /* cleanup polling on unmount */
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  /* ---- tab data loaders ---- */
  const loadRepos = useCallback(() => {
    if (!projectId) return;
    api.sastListRepos(projectId).then((r: any) => setRepos(r?.repositories || r || [])).catch(() => {});
  }, [projectId]);

  const loadGithubStatus = useCallback(async () => {
    if (!projectId) return;
    try {
      const status = await api.sastGithubStatus(projectId);
      setGithubStatus(status);
      setGithubAppInstallation(status?.github_app_installation || null);
      if (status?.github_app_connected && status?.github_app_installation && status?.github_app_configured) {
        setGithubConnectMode("github_app");
      } else if (status?.oauth_connected) {
        setGithubConnectMode("oauth");
      } else if (status?.pat_connected) {
        setGithubConnectMode("pat");
      } else {
        setGithubConnectMode(status?.github_app_configured ? "github_app" : "pat");
      }
    } catch {
      setGithubStatus(null);
    }
  }, [projectId]);

  const loadHistory = useCallback(() => {
    if (!projectId) return;
    setHistoryLoading(true);
    api.sastScanHistory(projectId)
      .then((r: any) => setScanHistory(r?.scans || r || []))
      .catch(() => toast.error("Failed to load scan history"))
      .finally(() => setHistoryLoading(false));
  }, [projectId]);

  const loadWebhookConfig = useCallback(() => {
    if (!projectId) return;
    setCicdLoading(true);
    api.sastGetWebhookConfig(projectId)
      .then(setWebhookConfig)
      .catch(() => {})
      .finally(() => setCicdLoading(false));
  }, [projectId]);

  useEffect(() => {
    if (activeTab === "repos") loadRepos();
    if (activeTab === "history") loadHistory();
    if (activeTab === "cicd") loadWebhookConfig();
  }, [activeTab, loadRepos, loadHistory, loadWebhookConfig]);

  useEffect(() => {
    if (connectModal) {
      loadGithubStatus();
    }
  }, [connectModal, loadGithubStatus]);

  /* ---- load results for a scan ---- */
  const loadScanResults = useCallback(async (sid: string) => {
    setResultsLoading(true);
    setSelectedScanId(sid);
    setActiveTab("results");
    try {
      const filters: any = {};
      if (filterSeverity) filters.severity = filterSeverity;
      if (filterStatus) filters.status = filterStatus;
      if (filterFilePath) filters.file_path = filterFilePath;
      const [results, findingsRes] = await Promise.all([
        api.sastScanResults(sid, filters),
        api.sastListFindings(sid, {
          severity: filterSeverity || undefined,
          status: filterStatus || undefined,
          confidence: filterConfidence || undefined,
          file_path: filterFilePath || undefined,
        }),
      ]);
      setScanResults(results);
      setFindings(findingsRes?.findings || findingsRes || []);
    } catch {
      toast.error("Failed to load scan results");
    } finally {
      setResultsLoading(false);
    }
  }, [filterSeverity, filterStatus, filterConfidence, filterFilePath]);

  /* reload findings when filters change */
  useEffect(() => {
    if (selectedScanId && activeTab === "results") {
      loadScanResults(selectedScanId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterSeverity, filterStatus, filterConfidence, filterFilePath]);

  /* load security sub-tab data on demand */
  const loadSecurityData = useCallback(async (tab: ResultsSubTab, sid: string, opts?: { page?: number }) => {
    if (!sid) return;
    setSecDataLoading(true);
    try {
      if (tab === "dependencies") {
        const page = opts?.page ?? depPagination.page;
        const perPage = depPagination.per_page;
        const name = depFilters.name.trim() || undefined;
        const ecosystem = depFilters.ecosystem.trim() || undefined;
        const vulnerable = depFilters.vulnerable === "yes" ? true : depFilters.vulnerable === "no" ? false : undefined;
        const res = await api.sastDependencies(sid, { page, per_page: perPage, name, ecosystem, vulnerable });
        setDependencies(res?.dependencies || []);
        setDepPagination(prev => ({
          ...prev,
          total: res?.total ?? 0,
          page: res?.page ?? 1,
          per_page: res?.per_page ?? 20,
          total_pages: res?.total_pages ?? 1,
          total_vulnerable: res?.total_vulnerable,
          total_outdated: res?.total_outdated,
          total_secure: res?.total_secure,
        }));
      } else if (tab === "sbom") {
        const res = await api.sastLicenses(sid);
        setLicenses(res);
      } else if (tab === "cve") {
        const res = await api.sastCveSummary(sid);
        setCveSummary(res);
      }
    } catch {
      // silently ignore — these endpoints may return 404 if scan didn't include SCA
    } finally {
      setSecDataLoading(false);
    }
  }, [depPagination.page, depPagination.per_page, depFilters.name, depFilters.ecosystem, depFilters.vulnerable]);

  useEffect(() => {
    if (selectedScanId && resultsSubTab !== "findings" && resultsSubTab !== "secrets" && resultsSubTab !== "breakdown") {
      loadSecurityData(resultsSubTab, selectedScanId);
    }
  }, [resultsSubTab, selectedScanId, loadSecurityData]);

  useEffect(() => {
    if (resultsSubTab === "dependencies") {
      setDepPagination((p) => ({ ...p, page: 1 }));
    }
  }, [resultsSubTab, selectedScanId]);

  /* ---- upload scan ---- */
  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) setSelectedFile(file);
  };

  const buildScanConfig = () => {
    const cfg: Record<string, unknown> = {};
    if (exhaustive) cfg.exhaustive = true;
    if (gitleaksEnabled) cfg.gitleaks_enabled = true;
    if (scanGitHistory) cfg.scan_git_history = true;
    if (ruleSets.length) cfg.rule_sets = ruleSets;
    const patterns = excludePatterns.split(",").map((s) => s.trim()).filter(Boolean);
    if (patterns.length) cfg.exclude_patterns = patterns;
    return cfg;
  };

  const startUploadScan = async () => {
    if (!selectedFile || !projectId) return;
    setScanning(true);
    setScanProgress(null);
    try {
      const res = await api.sastUploadScan(projectId, selectedFile, aiAnalysis, buildScanConfig());
      const sid = res?.scan_id;
      if (!sid) throw new Error("No scan ID returned");
      setScanId(sid);
      toast.success("Scan started");
      // start polling
      pollRef.current = setInterval(async () => {
        try {
          const prog = await api.sastScanProgress(sid);
          setScanProgress(prog);
          if (prog?.status === "completed" || prog?.status === "failed" || prog?.status === "stopped" || prog?.status === "cancelled") {
            if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
            setScanning(false);
              loadHistory();
            if (prog.status === "completed") {
              toast.success(`Scan complete: ${prog.total_findings || 0} issues found`);
              loadScanResults(sid);
            } else if (prog.status === "failed") {
              toast.error("Scan failed: " + (prog.error || "Unknown error"));
            }
          }
        } catch {
          if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
          setScanning(false);
        }
      }, POLL_MS);
    } catch (err: any) {
      toast.error(err.message || "Failed to start scan");
      setScanning(false);
    }
  };

  const stopScan = async () => {
    if (!scanId) return;
    try {
      await api.sastStopScan(scanId);
      toast.success("Scan stopped");
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
      setScanning(false);
    } catch {
      toast.error("Failed to stop scan");
    }
  };

  /* ---- repo scan ---- */
  const startRepoScan = async (repoId: string, branch?: string) => {
    if (!projectId) return;
    setRepoScanning(repoId);
    let started = false;
    try {
      const res = await api.sastRepoScan({
        project_id: projectId,
        repository_id: repoId,
        branch: branch || undefined,
        ai_analysis: aiAnalysis,
        scan_config: Object.keys(buildScanConfig()).length ? buildScanConfig() : undefined,
      });
      toast.success("Repository scan started");
      const sid = res?.scan_id;
      if (sid) {
        started = true;
        setScanId(sid);
        setScanning(true);
        setActiveTab("upload");
        pollRef.current = setInterval(async () => {
          try {
            const prog = await api.sastScanProgress(sid);
            setScanProgress(prog);
            if (prog?.status === "completed" || prog?.status === "failed" || prog?.status === "stopped" || prog?.status === "cancelled") {
              if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
              setScanning(false);
              setRepoScanning(null);
              loadHistory();
              if (prog.status === "completed") {
                toast.success(`Scan complete: ${prog.total_findings || 0} issues found`);
                loadScanResults(sid);
              }
            }
          } catch {
            if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
            setScanning(false);
            setRepoScanning(null);
          }
        }, POLL_MS);
      }
    } catch (err: any) {
      toast.error(err.message || "Failed to start scan");
    } finally {
      if (!started) setRepoScanning(null);
    }
  };

  /* ---- github connect ---- */
  const fetchGithubRepos = async (page?: number) => {
    if (!githubToken.trim() || !projectId) return;
    setGithubLoading(true);
    try {
      setGithubConnectMode("pat");
      const res = await api.sastGithubListRepos(projectId, githubToken, page ?? githubPage);
      setGithubRepos(res?.repos || res || []);
      await loadGithubStatus();
      toast.success("Organization GitHub PAT validated");
    } catch (err: any) {
      toast.error(err.message || "Failed to fetch repos");
    } finally {
      setGithubLoading(false);
    }
  };

  const fetchStoredPatRepos = async () => {
    if (!projectId) return;
    setGithubLoading(true);
    try {
      const res = await api.sastGithubPatRepos(projectId);
      setGithubConnectMode("pat");
      setGithubRepos(res?.repos || []);
      toast.success("Loaded repositories from organization PAT");
    } catch (err: any) {
      toast.error(err.message || "Failed to load organization PAT repositories");
    } finally {
      setGithubLoading(false);
    }
  };

  const fetchGithubAppRepos = async () => {
    if (!projectId) return;
    setGithubLoading(true);
    try {
      const res = await api.sastGithubAppRepos(projectId);
      setGithubConnectMode("github_app");
      setGithubAppInstallation(res?.installation || null);
      setGithubRepos(res?.repos || []);
      toast.success("Loaded repositories from GitHub App installation");
    } catch (err: any) {
      toast.error(err.message || "Failed to load GitHub App repositories");
    } finally {
      setGithubLoading(false);
    }
  };

  const fetchGithubOAuthRepos = async () => {
    if (!projectId) return;
    setGithubLoading(true);
    try {
      const res = await api.sastGithubOAuthRepos(projectId);
      setGithubConnectMode("oauth");
      setGithubRepos(res?.repos || []);
      toast.success("Loaded repositories from GitHub OAuth");
    } catch (err: any) {
      toast.error(err.message || "Failed to load GitHub OAuth repositories");
    } finally {
      setGithubLoading(false);
    }
  };

  useEffect(() => {
    if (!projectId || handledGithubHandoffRef.current) return;
    const params = new URLSearchParams(window.location.search);
    const shouldOpenConnect = params.get("open_connect") === "1";
    const authMode = params.get("github_auth_mode");
    const githubAppSuccess = params.get("github_app") === "success";
    const githubOauthSuccess = params.get("github_oauth") === "success";
    if (!shouldOpenConnect && !githubAppSuccess && !githubOauthSuccess) return;

    handledGithubHandoffRef.current = true;
    setActiveTab("repos");
    setConnectModal(true);
    const run = async () => {
      await loadGithubStatus();
      if (authMode === "github_app" || githubAppSuccess) {
        await fetchGithubAppRepos();
      } else if (authMode === "oauth" || githubOauthSuccess) {
        await fetchGithubOAuthRepos();
      }
      router.replace(`/projects/${projectId}/sast`);
    };
    void run();
  }, [projectId, loadGithubStatus, router, fetchGithubAppRepos, fetchGithubOAuthRepos]);

  const connectRepo = async (repo: any) => {
    if (!projectId) return;
    try {
      const authMode = githubConnectMode;
      await api.sastConnectRepo({
        project_id: projectId,
        provider: "github",
        repo_url: repo.html_url || repo.url,
        repo_name: repo.name,
        repo_owner: repo.owner?.login || repo.owner,
        default_branch: repo.default_branch || "main",
        auth_mode: authMode,
        access_token: authMode === "pat" && githubToken ? githubToken : undefined,
        installation_id: authMode === "github_app" ? githubAppInstallation?.installation_id : undefined,
        account_login: authMode === "github_app" ? githubAppInstallation?.account_login : undefined,
      });
      toast.success(`Connected ${repo.full_name || repo.name}`);
      setConnectModal(false);
      setGithubToken("");
      setGithubRepos([]);
      setGithubAppInstallation(null);
      loadRepos();
    } catch (err: any) {
      toast.error(err.message || "Failed to connect repository");
    }
  };

  const disconnectRepo = async (repoId: string) => {
    try {
      await api.sastDisconnectRepo(repoId);
      toast.success("Repository disconnected");
      loadRepos();
    } catch {
      toast.error("Failed to disconnect");
    }
  };

  const loadRepoBranches = async (repo: any) => {
    if (!projectId || repoBranches[repo.id]?.length) return;
    try {
      const res = await api.sastGithubBranches(
        projectId,
        repo.repo_owner,
        repo.repo_name,
        (repo.auth_mode || "github_app") as "pat" | "oauth" | "github_app",
      );
      setRepoBranches((prev) => ({ ...prev, [repo.id]: res?.branches || [] }));
    } catch {
      // Branch discovery is a UX enhancement; keep manual input available.
    }
  };

  /* ---- finding actions ---- */
  const toggleFinding = (id: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const aiExplain = async (findingId: string) => {
    setAiExplaining(findingId);
    try {
      const res = await api.sastAiExplain(findingId);
      setAiExplanations((prev) => ({ ...prev, [findingId]: res?.explanation || res?.content || JSON.stringify(res) }));
    } catch {
      toast.error("AI analysis failed");
    } finally {
      setAiExplaining(null);
    }
  };

  const createFixPr = async (findingId: string) => {
    setCreatingPrId(findingId);
    try {
      const payload = repos.length === 1 ? { repository_id: repos[0].id } : undefined;
      const res = await api.sastCreateFixPr(findingId, payload);
      const prUrl = res?.pr?.url;
      toast.success(prUrl ? "AI fix PR created" : "AI fix branch created");
      if (prUrl) window.open(prUrl, "_blank", "noopener,noreferrer");
    } catch (err: any) {
      toast.error(err.message || "Failed to create AI fix PR");
    } finally {
      setCreatingPrId(null);
    }
  };

  const openFindingSource = async (finding: any) => {
    setSourceLoadingId(finding.id);
    try {
      const payload = repos.length === 1 ? { repository_id: repos[0].id } : undefined;
      const res = await api.sastFindingSource(finding.id, payload);
      setSourceViewer(res);
    } catch (err: any) {
      toast.error(err.message || "Failed to load source file");
    } finally {
      setSourceLoadingId(null);
    }
  };

  const startBulkRepoScan = async () => {
    if (!projectId || repos.length === 0) return;
    try {
      const res = await api.sastBulkRepoScan({
        project_id: projectId,
        repository_ids: repos.map((repo) => repo.id),
        ai_analysis: aiAnalysis,
        scan_config: Object.keys(buildScanConfig()).length ? buildScanConfig() : undefined,
      });
      toast.success(`Started ${res?.count || repos.length} repository scans`);
      loadHistory();
      setActiveTab("history");
    } catch (err: any) {
      toast.error(err.message || "Failed to start bulk repository scan");
    }
  };

  const updateFindingStatus = async (findingId: string, status: string) => {
    try {
      await api.sastUpdateFindingStatus(findingId, status);
      setFindings((prev) => prev.map((f) => (f.id === findingId ? { ...f, status } : f)));
      toast.success("Status updated");
    } catch {
      toast.error("Failed to update status");
    }
  };

  /* ---- export ---- */
  const exportSarif = async () => {
    if (!selectedScanId) return;
    try {
      const data = await api.sastExportSarif(selectedScanId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sast-${selectedScanId.slice(0, 8)}.sarif.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("SARIF exported");
    } catch {
      toast.error("Export failed");
    }
  };

  const exportCsv = async () => {
    if (!selectedScanId) return;
    try {
      await api.sastExportCsv(selectedScanId);
      toast.success("CSV exported");
    } catch {
      toast.error("Export failed");
    }
  };

  /* ---- file tree helpers ---- */
  const toggleTreePath = (path: string) => {
    setExpandedTreePaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path); else next.add(path);
      return next;
    });
  };

  /* ---- breakdown filter: filter findings by scanner/source (must be first: others depend on it) ---- */
  const findingsForDisplay = useMemo(() => {
    if (!breakdownFilterSource) return findings;
    const secretSources = ["secret_scan", "trufflehog", "gitleaks"];
    if (breakdownFilterSource === "secrets") return findings.filter((f: any) => secretSources.includes(f.rule_source || ""));
    if (breakdownFilterSource === "semgrep") return findings.filter((f: any) => !f.rule_source || f.rule_source === "semgrep");
    return findings.filter((f: any) => (f.rule_source || "") === breakdownFilterSource);
  }, [findings, breakdownFilterSource]);

  /* ---- filtered findings for tree selection (uses findingsForDisplay) ---- */
  const displayedFindings = useMemo(() => {
    if (!selectedTreePath || selectedTreePath === "/") return findingsForDisplay;
    return findingsForDisplay.filter((f: any) => {
      const fp = "/" + (f.file_path || "").replace(/\\/g, "/").replace(/^\//, "");
      return fp === selectedTreePath || fp.startsWith(selectedTreePath + "/");
    });
  }, [findingsForDisplay, selectedTreePath]);

  const fileTree = useMemo(() => {
    if (!findingsForDisplay.length) return null;
    return buildFileTree(findingsForDisplay);
  }, [findingsForDisplay]);

  /* ---- summary counts ---- */
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findingsForDisplay) {
      const s = (f.severity || "info").toLowerCase();
      if (counts[s] !== undefined) counts[s]++;
    }
    return counts;
  }, [findingsForDisplay]);

  const threatLevel = useMemo(() => getThreatLevel(severityCounts), [severityCounts]);

  /* ---- scan progress bar ---- */
  const progressPct = scanProgress?.progress_pct ?? scanProgress?.progress ?? 0;
  const currentPhase = scanProgress?.phase || scanProgress?.current_phase || "extracting";

  /* ============================================================
     TABS DEFINITION
     ============================================================ */
  const TABS: { key: Tab; label: string; icon: any }[] = [
    { key: "upload", label: "Upload Scan", icon: Upload },
    { key: "repos", label: "Repository Scan", icon: GitBranch },
    { key: "history", label: "Scan History", icon: Clock },
    { key: "results", label: "Results", icon: Bug },
    { key: "cicd", label: "CI/CD", icon: Webhook },
  ];

  /* ============================================================
     RENDER
     ============================================================ */
  return (
    <div className="min-h-screen" style={{ backgroundColor: "var(--bg-primary)" }}>
      <Navbar />
      <main className="max-w-[1400px] mx-auto px-4 sm:px-6 py-6">
        {/* Header */}
        <ProjectSubNav
          projectId={projectId as string}
          projectName={project?.application_name}
          projectUrl={project?.application_url}
          sastEnabled={orgSettings.sast_enabled}
        />

        {/* Tab bar */}
        <div
          className="flex gap-1 mb-6 p-1 rounded-xl border overflow-x-auto"
          style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
        >
          {TABS.map((t) => {
            const Icon = t.icon;
            const isActive = activeTab === t.key;
            return (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
                  isActive ? "shadow-sm" : "hover:bg-white/5"
                }`}
                style={{
                  backgroundColor: isActive ? "rgba(234,88,12,0.15)" : undefined,
                  color: isActive ? "#fb923c" : "var(--text-secondary)",
                }}
              >
                <Icon size={16} />
                {t.label}
              </button>
            );
          })}
        </div>

        {/* ====== UPLOAD SCAN TAB ====== */}
        {activeTab === "upload" && (
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
            <div
              className="rounded-xl border p-6"
              style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
            >
              <h2 className="text-lg font-semibold mb-4" style={{ color: "var(--text-primary)" }}>
                Upload Source Code
              </h2>

              {/* Drop zone */}
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`relative flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-10 cursor-pointer transition-all ${
                  dragOver ? "border-orange-400 bg-orange-500/5" : "border-[var(--border-subtle)] hover:border-orange-400/50 hover:bg-white/[0.02]"
                }`}
              >
                <Upload size={40} style={{ color: dragOver ? "#fb923c" : "var(--text-secondary)" }} />
                <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                  Drag &amp; drop a ZIP file here, or click to browse
                </p>
                <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  Supported: .zip archives containing source code
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) setSelectedFile(f);
                  }}
                />
              </div>

              {/* Selected file info */}
              {selectedFile && (
                <div
                  className="flex items-center gap-3 mt-4 p-3 rounded-lg border"
                  style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}
                >
                  <FileText size={20} className="text-orange-400 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color: "var(--text-primary)" }}>
                      {selectedFile.name}
                    </p>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                      {formatBytes(selectedFile.size)}
                    </p>
                  </div>
                  <button
                    onClick={() => setSelectedFile(null)}
                    className="p-1 rounded hover:bg-white/10 transition-colors"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <X size={16} />
                  </button>
                </div>
              )}

              {/* AI toggle */}
              <div className="flex items-center justify-between mt-5 gap-4 flex-wrap">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={aiAnalysis}
                    onChange={(e) => setAiAnalysis(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-orange-500 focus:ring-orange-500"
                  />
                  <Sparkles size={16} className="text-orange-400" />
                  <span className="text-sm" style={{ color: "var(--text-primary)" }}>
                    Enable AI Analysis
                  </span>
                </label>

                <div className="flex items-center gap-2">
                  {scanning && (
                    <button
                      onClick={stopScan}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-red-400 border border-red-500/30 hover:bg-red-500/10 transition-colors"
                    >
                      <StopCircle size={16} /> Stop
                    </button>
                  )}
                  <button
                    onClick={startUploadScan}
                    disabled={!selectedFile || scanning}
                    className="flex items-center gap-2 px-6 py-2 rounded-lg text-sm font-semibold text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 shadow-lg shadow-orange-500/20"
                  >
                    {scanning ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
                    {scanning ? "Scanning..." : "Start Scan"}
                  </button>
                </div>
              </div>

              {/* Scan options: exhaustive, Gitleaks, extra rule sets */}
              <div className="mt-4 p-4 rounded-lg border space-y-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Scan options</p>
                <div className="flex flex-wrap gap-4">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={exhaustive}
                      onChange={(e) => setExhaustive(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-orange-500 focus:ring-orange-500"
                    />
                    <span className="text-sm" style={{ color: "var(--text-primary)" }}>Max coverage / Exhaustive</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={gitleaksEnabled}
                      onChange={(e) => setGitleaksEnabled(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-orange-500 focus:ring-orange-500"
                    />
                    <span className="text-sm" style={{ color: "var(--text-primary)" }}>Gitleaks (secret scan)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={scanGitHistory}
                      onChange={(e) => setScanGitHistory(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-orange-500 focus:ring-orange-500"
                    />
                    <span className="text-sm" style={{ color: "var(--text-primary)" }}>Scan git history (secrets)</span>
                  </label>
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: "var(--text-secondary)" }}>Exclude paths (comma-separated, e.g. vendor, *.min.js)</label>
                  <input
                    type="text"
                    value={excludePatterns}
                    onChange={(e) => setExcludePatterns(e.target.value)}
                    placeholder="optional"
                    className="w-full max-w-md px-3 py-1.5 rounded border text-sm bg-transparent"
                    style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                  />
                </div>
                <p className="text-xs" style={{ color: "var(--text-secondary)" }}>These options also apply to repository and bulk scans.</p>
                <div>
                  <p className="text-xs mb-2" style={{ color: "var(--text-secondary)" }}>Extra Semgrep rule sets (optional)</p>
                  <div className="flex flex-wrap gap-2">
                    {["secure-defaults", "r2c-security-audit", "brakeman", "flawfinder", "gitleaks", "xss", "sql-injection", "jwt"].map((id) => (
                      <label key={id} className="inline-flex items-center gap-1.5 cursor-pointer select-none px-2.5 py-1.5 rounded border text-xs" style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}>
                        <input
                          type="checkbox"
                          checked={ruleSets.includes(id)}
                          onChange={(e) => setRuleSets((prev) => e.target.checked ? [...prev, id] : prev.filter((r) => r !== id))}
                          className="w-3.5 h-3.5 rounded border-gray-600 bg-gray-800 text-orange-500 focus:ring-orange-500"
                        />
                        {id}
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              {/* Progress */}
              {scanning && scanProgress && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  className="mt-6"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                      {PHASE_LABELS[currentPhase] || currentPhase}
                    </span>
                    <span className="text-sm font-mono" style={{ color: "var(--text-secondary)" }}>
                      {Math.round(progressPct)}%
                    </span>
                  </div>
                  <div className="w-full h-2.5 rounded-full overflow-hidden" style={{ backgroundColor: "var(--bg-primary)" }}>
                    <motion.div
                      className="h-full rounded-full bg-gradient-to-r from-orange-500 to-amber-500"
                      initial={{ width: 0 }}
                      animate={{ width: `${progressPct}%` }}
                      transition={{ duration: 0.5 }}
                    />
                  </div>
                  {/* Scan details grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
                    <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                      <p className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Files</p>
                      <p className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>{scanProgress.files_scanned || 0} / {scanProgress.total_files || 0}</p>
                    </div>
                    <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                      <p className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Issues Found</p>
                      <p className="text-lg font-bold" style={{ color: (scanProgress.issues_found || 0) > 0 ? "#ea580c" : "#16a34a" }}>{scanProgress.issues_found || 0}</p>
                    </div>
                    {scanProgress.languages && (
                      <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                        <p className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Languages</p>
                        <p className="text-xs font-medium mt-1 truncate" style={{ color: "var(--text-primary)" }}>{scanProgress.languages.join(", ")}</p>
                      </div>
                    )}
                    <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
                      <p className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Phase</p>
                      <p className="text-xs font-medium mt-1 truncate" style={{ color: "#fb923c" }}>{PHASE_LABELS[currentPhase] || currentPhase}</p>
                    </div>
                  </div>
                  {/* Phase pipeline */}
                  <div className="flex flex-wrap items-center gap-1 mt-3">
                    {Object.entries(PHASE_LABELS).filter(([k]) => k !== "done").map(([key, label]) => {
                      const phases = Object.keys(PHASE_LABELS);
                      const currentIdx = phases.indexOf(currentPhase);
                      const thisIdx = phases.indexOf(key);
                      const isDone = thisIdx < currentIdx;
                      const isCurrent = key === currentPhase;
                      if (!isDone && !isCurrent) return null;
                      return (
                        <span
                          key={key}
                          className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium"
                          style={{
                            backgroundColor: isDone ? "#16a34a15" : "#ea580c15",
                            color: isDone ? "#4ade80" : "#fb923c",
                            border: `1px solid ${isDone ? "#16a34a33" : "#ea580c33"}`,
                          }}
                        >
                          {isDone ? <CheckCircle size={10} /> : <Loader2 size={10} className="animate-spin" />}
                          {label}
                        </span>
                      );
                    })}
                  </div>
                </motion.div>
              )}
            </div>
          </motion.div>
        )}

        {/* ====== REPOSITORY SCAN TAB ====== */}
        {activeTab === "repos" && (
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
                Connected Repositories
              </h2>
              <div className="flex items-center gap-2">
                {repos.length > 1 && (
                  <button
                    onClick={() => startBulkRepoScan()}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold border transition-all"
                    style={{ color: "var(--text-primary)", borderColor: "var(--border-subtle)", background: "var(--bg-card)" }}
                  >
                    <Play size={16} /> Scan All Repositories
                  </button>
                )}
                <button
                  onClick={() => setConnectModal(true)}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 shadow-lg shadow-orange-500/20 transition-all"
                >
                  <Plus size={16} /> Connect Repository
                </button>
              </div>
            </div>

            <div className="mb-4 p-3 rounded-lg border flex flex-wrap items-center gap-2" style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}>
              <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>Scan options:</span>
              <span className="text-xs" style={{ color: "var(--text-primary)" }}>
                {exhaustive ? "Max coverage ✓" : "Standard"}
                {gitleaksEnabled && " · Gitleaks ✓"}
                {scanGitHistory && " · Git history ✓"}
                {ruleSets.length > 0 && ` · ${ruleSets.length} rule set(s)`}
                {excludePatterns.trim() && " · Excludes set"}
              </span>
              <button
                type="button"
                onClick={() => setActiveTab("upload")}
                className="text-xs font-medium px-2 py-1 rounded border transition-colors"
                style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}
              >
                Edit in Upload tab
              </button>
            </div>

            {repos.length === 0 ? (
              <div
                className="rounded-xl border p-10 text-center"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <GitBranch size={40} className="mx-auto mb-3" style={{ color: "var(--text-secondary)" }} />
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  No repositories connected. Click &ldquo;Connect Repository&rdquo; to get started.
                </p>
              </div>
            ) : (
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {repos.map((repo: any) => (
                  <div
                    key={repo.id}
                    className="rounded-xl border p-5 transition-colors hover:border-orange-500/30"
                    style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                  >
                    <div className="flex items-start gap-3">
                      <Github size={24} className="text-gray-400 mt-0.5 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>
                          {repo.repo_owner ? `${repo.repo_owner}/` : ""}{repo.repo_name || repo.name}
                        </p>
                        <div className="flex items-center gap-2 mt-1">
                          <GitBranch size={12} style={{ color: "var(--text-secondary)" }} />
                          <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                            {repo.default_branch || "main"}
                          </span>
                          <span
                            className="text-[10px] px-1.5 py-0.5 rounded-full uppercase tracking-wide"
                            style={{ background: "rgba(99,102,241,0.12)", color: "#818cf8" }}
                          >
                            {repo.auth_mode === "github_app" ? "GitHub App" : repo.auth_mode === "oauth" ? "OAuth" : "PAT"}
                          </span>
                        </div>
                        {repo.last_scan_at && (
                          <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                            Last scan: {formatDate(repo.last_scan_at)}
                          </p>
                        )}
                      </div>
                    </div>
                    {/* Branch selector */}
                    <div className="mt-3">
                      <input
                        type="text"
                        placeholder="Branch (default: main)"
                        value={repoScanBranch[repo.id] || ""}
                        list={`repo-branches-${repo.id}`}
                        onFocus={() => loadRepoBranches(repo)}
                        onChange={(e) => setRepoScanBranch((prev) => ({ ...prev, [repo.id]: e.target.value }))}
                        className="w-full px-3 py-1.5 rounded-lg text-xs border bg-transparent focus:outline-none focus:border-orange-500 transition-colors"
                        style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                      />
                      {repoBranches[repo.id]?.length > 0 && (
                        <datalist id={`repo-branches-${repo.id}`}>
                          {repoBranches[repo.id].map((branch) => (
                            <option key={branch} value={branch} />
                          ))}
                        </datalist>
                      )}
                    </div>
                    <div className="flex items-center gap-2 mt-3">
                      <button
                        onClick={() => startRepoScan(repo.id, repoScanBranch[repo.id] || repo.default_branch)}
                        disabled={repoScanning === repo.id}
                        className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 disabled:opacity-40 transition-all"
                      >
                        {repoScanning === repo.id ? (
                          <Loader2 size={14} className="animate-spin" />
                        ) : (
                          <Play size={14} />
                        )}
                        Scan
                      </button>
                      <button
                        onClick={() => disconnectRepo(repo.id)}
                        className="p-1.5 rounded-lg text-red-400 hover:bg-red-500/10 border border-red-500/20 transition-colors"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Connect Modal */}
            <AnimatePresence>
              {connectModal && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
                  onClick={(e) => { if (e.target === e.currentTarget) setConnectModal(false); }}
                >
                  <motion.div
                    initial={{ scale: 0.95, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.95, opacity: 0 }}
                    className="w-full max-w-lg rounded-xl border p-6 max-h-[80vh] overflow-y-auto"
                    style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                  >
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
                        Connect GitHub Repository
                      </h3>
                      <button onClick={() => setConnectModal(false)} className="p-1 rounded hover:bg-white/10" style={{ color: "var(--text-secondary)" }}>
                        <X size={18} />
                      </button>
                    </div>

                    <div className="space-y-4">
                      {githubStatus?.github_app_configured && (
                        <button
                          onClick={async () => {
                            try {
                              setGithubLoading(true);
                              const res = await api.sastGithubAppStart(projectId!);
                              if (res?.install_url) {
                                const popup = window.open(res.install_url, "github_app_install", "width=760,height=820,scrollbars=yes");
                                const handler = async (e: MessageEvent) => {
                                  if (e.data?.type === "github_app_success") {
                                    window.removeEventListener("message", handler);
                                    await loadGithubStatus();
                                    await fetchGithubAppRepos();
                                    setGithubLoading(false);
                                  }
                                };
                                window.addEventListener("message", handler);
                                const checkClosed = setInterval(() => {
                                  if (popup?.closed) { clearInterval(checkClosed); setGithubLoading(false); }
                                }, 500);
                              }
                            } catch (err: any) {
                              toast.error(err.message || "GitHub App setup failed");
                              setGithubLoading(false);
                            }
                          }}
                          disabled={githubLoading}
                          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-white bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 disabled:opacity-40 transition-all"
                        >
                          <Github size={16} />
                          {githubLoading && githubConnectMode === "github_app" ? "Opening GitHub App..." : "Install / Use GitHub App"}
                        </button>
                      )}

                      <button
                        onClick={async () => {
                          try {
                            setGithubLoading(true);
                            const res = await api.sastGithubOAuthStart(projectId!);
                            if (res?.authorize_url) {
                              const popup = window.open(res.authorize_url, "github_oauth", "width=600,height=700,scrollbars=yes");
                              const handler = async (e: MessageEvent) => {
                                if (e.data?.type === "github_oauth_success") {
                                  window.removeEventListener("message", handler);
                                  try {
                                    const repoRes = await api.sastGithubOAuthRepos(projectId!);
                                    setGithubConnectMode("oauth");
                                    setGithubRepos(repoRes?.repos || []);
                                    await loadGithubStatus();
                                    toast.success("GitHub connected via OAuth");
                                  } catch {
                                    toast.error("Failed to fetch repos after OAuth");
                                  } finally {
                                    setGithubLoading(false);
                                  }
                                }
                              };
                              window.addEventListener("message", handler);
                              const checkClosed = setInterval(() => {
                                if (popup?.closed) { clearInterval(checkClosed); setGithubLoading(false); }
                              }, 500);
                            }
                          } catch {
                            toast.error("GitHub OAuth is not configured on the backend yet. Open Admin Settings > GitHub or use PAT as a temporary fallback.");
                            setGithubLoading(false);
                          }
                        }}
                        disabled={githubLoading}
                        className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-white bg-gray-800 hover:bg-gray-700 border border-gray-600 disabled:opacity-40 transition-all"
                      >
                        <Github size={16} />
                        {githubLoading && githubConnectMode === "oauth" ? "Connecting..." : "Connect with GitHub OAuth"}
                      </button>

                      {githubStatus && (
                        <div
                          className="rounded-lg border px-3 py-2 text-xs"
                          style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <span>GitHub App</span>
                            <span style={{ color: githubStatus.github_app_connected ? "#22c55e" : (githubStatus.github_app_configured ? "#f59e0b" : "#ef4444") }}>
                              {githubStatus.github_app_connected ? "Connected" : (githubStatus.github_app_configured ? "Configured" : "Not configured")}
                            </span>
                          </div>
                          <div className="flex items-center justify-between gap-3 mt-1">
                            <span>OAuth</span>
                            <span style={{ color: githubStatus.oauth_connected ? "#22c55e" : (githubStatus.oauth_configured ? "#f59e0b" : "#ef4444") }}>
                              {githubStatus.oauth_connected ? "Connected" : (githubStatus.oauth_configured ? "Configured" : "Not configured")}
                            </span>
                          </div>
                          <div className="flex items-center justify-between gap-3 mt-1">
                            <span>PAT</span>
                            <span style={{ color: githubStatus.pat_connected ? "#22c55e" : "#94a3b8" }}>
                              {githubStatus.pat_connected ? "Connected" : "Not connected"}
                            </span>
                          </div>
                          {githubAppInstallation?.installation_id && (
                            <div className="mt-2" style={{ color: "var(--text-primary)" }}>
                              App installation: {githubAppInstallation.account_login || "connected"} (#{githubAppInstallation.installation_id})
                            </div>
                          )}
                          {githubStatus.oauth_account_login && (
                            <div className="mt-1" style={{ color: "var(--text-primary)" }}>
                              OAuth account: {githubStatus.oauth_account_login}
                            </div>
                          )}
                          {githubStatus.pat_account_login && (
                            <div className="mt-1" style={{ color: "var(--text-primary)" }}>
                              PAT account: {githubStatus.pat_account_login}
                            </div>
                          )}
                        </div>
                      )}

                      <div className="flex items-center gap-3">
                        <div className="flex-1 h-px" style={{ background: "var(--border-subtle)" }} />
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>or use Personal Access Token</span>
                        <div className="flex-1 h-px" style={{ background: "var(--border-subtle)" }} />
                      </div>

                      <div>
                        <label className="text-xs font-medium mb-1 block" style={{ color: "var(--text-secondary)" }}>
                          GitHub Personal Access Token
                        </label>
                        <input
                          type="password"
                          value={githubToken}
                          onChange={(e) => setGithubToken(e.target.value)}
                          placeholder="ghp_xxxxxxxxxxxx"
                          className="w-full px-3 py-2 rounded-lg text-sm border bg-transparent focus:outline-none focus:border-orange-500 transition-colors"
                          style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                        />
                      </div>
                      <button
                        onClick={() => fetchGithubRepos()}
                        disabled={!githubToken.trim() || githubLoading}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 disabled:opacity-40 transition-all"
                      >
                        {githubLoading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                        Validate PAT And Load Repositories
                      </button>

                      {githubStatus?.pat_connected && (
                        <button
                          onClick={() => fetchStoredPatRepos()}
                          disabled={githubLoading}
                          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-all"
                          style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)", background: "var(--bg-elevated)" }}
                        >
                          {githubLoading && githubConnectMode === "pat" ? <Loader2 size={14} className="animate-spin" /> : <Github size={14} />}
                          Use Stored Organization PAT
                        </button>
                      )}

                      {githubRepos.length > 0 && (
                        <div className="space-y-2 mt-2">
                          <p className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                            Select a repository to connect:
                          </p>
                          {githubRepos.map((r: any) => (
                            <button
                              key={r.id || r.full_name}
                              onClick={() => connectRepo(r)}
                              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border text-left hover:border-orange-500/30 transition-colors"
                              style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)" }}
                            >
                              <Github size={16} style={{ color: "var(--text-secondary)" }} />
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate" style={{ color: "var(--text-primary)" }}>
                                  {r.full_name || r.name}
                                </p>
                                <p className="text-xs truncate" style={{ color: "var(--text-secondary)" }}>
                                  {r.description || "No description"}
                                </p>
                              </div>
                              <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                                {r.default_branch || "main"}
                              </span>
                            </button>
                          ))}
                          <div className="flex items-center gap-2 mt-2">
                            <button
                              onClick={() => {
                                setGithubPage((p) => {
                                  const newPage = Math.max(1, p - 1);
                                  fetchGithubRepos(newPage);
                                  return newPage;
                                });
                              }}
                              disabled={githubPage <= 1}
                              className="px-3 py-1 rounded text-xs border disabled:opacity-30 hover:bg-white/5 transition-colors"
                              style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}
                            >
                              Prev
                            </button>
                            <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                              Page {githubPage}
                            </span>
                            <button
                              onClick={() => {
                                setGithubPage((p) => {
                                  const newPage = p + 1;
                                  fetchGithubRepos(newPage);
                                  return newPage;
                                });
                              }}
                              className="px-3 py-1 rounded text-xs border hover:bg-white/5 transition-colors"
                              style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}
                            >
                              Next
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        )}

        {/* ====== SCAN HISTORY TAB ====== */}
        {activeTab === "history" && (
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
                Scan History
              </h2>
              <button
                onClick={loadHistory}
                disabled={historyLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm border hover:bg-white/5 transition-colors"
                style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}
              >
                <RefreshCw size={14} className={historyLoading ? "animate-spin" : ""} />
                Refresh
              </button>
            </div>

            <div
              className="rounded-xl border overflow-hidden"
              style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
            >
              {scanHistory.length === 0 ? (
                <div className="p-10 text-center">
                  <Clock size={32} className="mx-auto mb-2" style={{ color: "var(--text-secondary)" }} />
                  <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                    No scans yet. Upload a ZIP or scan a repository to get started.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                        {["Date", "Repository", "Type", "Status", "Issues", "Duration", "Actions"].map((h) => (
                          <th
                            key={h}
                            className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider"
                            style={{ color: "var(--text-secondary)" }}
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {scanHistory.map((scan: any) => (
                        <tr
                          key={scan.id || scan.scan_id}
                          className="cursor-pointer hover:bg-white/[0.03] transition-colors"
                          style={{ borderBottom: "1px solid var(--border-subtle)" }}
                          onClick={() => loadScanResults(scan.id || scan.scan_id)}
                        >
                          <td className="px-4 py-3" style={{ color: "var(--text-primary)" }}>
                            <div className="flex items-center gap-2">
                              <Calendar size={14} style={{ color: "var(--text-secondary)" }} />
                              {formatDate(scan.created_at || scan.started_at)}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="text-xs" style={{ color: "var(--text-primary)" }}>
                              <div className="font-medium">{scan.source_info?.repo_name || "ZIP Upload"}</div>
                              {scan.source_info?.branch && (
                                <div style={{ color: "var(--text-secondary)" }}>{scan.source_info.branch}</div>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className="px-2 py-0.5 rounded text-xs font-medium"
                              style={{
                                backgroundColor: "var(--bg-primary)",
                                color: "var(--text-secondary)",
                                border: "1px solid var(--border-subtle)",
                              }}
                            >
                              {(scan.scan_type || scan.type || "zip").toUpperCase()}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className="px-2 py-0.5 rounded text-xs font-semibold"
                              style={{
                                backgroundColor: (SCAN_STATUS_COLORS[scan.status] || "#6b7280") + "22",
                                color: SCAN_STATUS_COLORS[scan.status] || "#6b7280",
                              }}
                            >
                              {scan.status}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-xs" style={{ color: "var(--text-primary)" }}>
                            {scan.total_issues ?? "--"}
                          </td>
                          <td className="px-4 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
                            {formatDuration(scan.scan_duration_seconds)}
                          </td>
                          <td className="px-4 py-3">
                            <button
                              onClick={(e) => { e.stopPropagation(); loadScanResults(scan.id || scan.scan_id); }}
                              className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium text-orange-400 hover:bg-orange-500/10 transition-colors"
                            >
                              <Eye size={12} /> View
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ====== RESULTS TAB ====== */}
        {activeTab === "results" && (
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
            {!selectedScanId ? (
              <div
                className="rounded-xl border p-10 text-center"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <BarChart3 size={40} className="mx-auto mb-3" style={{ color: "var(--text-secondary)" }} />
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  Select a scan from the History tab or run a new scan to see results.
                </p>
              </div>
            ) : resultsLoading ? (
              <div className="flex items-center justify-center py-20">
                <Loader2 size={32} className="animate-spin text-orange-400" />
              </div>
            ) : (
              <>
                {scanResults?.scan?.error_message && (
                  <div
                    className="rounded-xl border p-4 mb-4"
                    style={{ backgroundColor: "rgba(245,158,11,0.08)", borderColor: "rgba(245,158,11,0.25)" }}
                  >
                    <div className="flex items-start gap-3">
                      <AlertTriangle size={18} className="text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                          Scan completed with analyzer warnings
                        </p>
                        <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                          {scanResults.scan.error_message}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Results Sub-Tab Navigation */}
                <div
                  className="flex items-center gap-1 mb-4 p-1 rounded-xl border overflow-x-auto"
                  style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                >
                  {([
                    { key: "findings" as ResultsSubTab, label: "Findings", icon: Bug, count: findingsForDisplay.length },
                    { key: "secrets" as ResultsSubTab, label: "Secrets", icon: KeyRound, count: findings.filter((f: any) => ["secret_scan", "trufflehog", "gitleaks"].includes(f.rule_source || "")).length },
                    { key: "dependencies" as ResultsSubTab, label: "Dependencies", icon: Package, count: scanResults?.scan?.sca_issues || 0 },
                    { key: "sbom" as ResultsSubTab, label: "SBOM & Licenses", icon: Scale },
                    { key: "cve" as ResultsSubTab, label: "CVE Intelligence", icon: ShieldAlert },
                    { key: "breakdown" as ResultsSubTab, label: "Scanner Breakdown", icon: BarChart3 },
                  ]).map((t) => {
                    const Icon = t.icon;
                    const active = resultsSubTab === t.key;
                    return (
                      <button
                        key={t.key}
                        onClick={() => setResultsSubTab(t.key)}
                        className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all"
                        style={{
                          backgroundColor: active ? "rgba(234,88,12,0.15)" : "transparent",
                          color: active ? "#fb923c" : "var(--text-secondary)",
                          border: active ? "1px solid rgba(234,88,12,0.3)" : "1px solid transparent",
                        }}
                      >
                        <Icon size={14} />
                        {t.label}
                        {t.count !== undefined && t.count > 0 && (
                          <span
                            className="px-1.5 py-0.5 rounded-full text-[10px] font-bold"
                            style={{ backgroundColor: active ? "#ea580c33" : "var(--bg-primary)", color: active ? "#fb923c" : "var(--text-secondary)" }}
                          >
                            {t.count}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* === FINDINGS SUB-TAB (existing) === */}
                {resultsSubTab === "findings" && (
                <>
                <div
                  className="rounded-xl border p-4 mb-4"
                  style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                >
                  <div className="flex flex-wrap items-center gap-3 justify-between">
                    <div>
                      <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                        {scanResults?.scan?.source_info?.repo_name || "Scan Results"}
                      </p>
                      <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                        {scanResults?.scan?.source_info?.branch ? `Branch: ${scanResults.scan.source_info.branch}` : "Repository branch unavailable"}
                        {scanResults?.scan?.source_info?.repo_url ? ` | ${scanResults.scan.source_info.repo_url}` : ""}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className="px-2.5 py-1 rounded-full text-xs font-semibold uppercase"
                        style={{ background: `${threatLevel.color}22`, color: threatLevel.color, border: `1px solid ${threatLevel.color}44` }}
                      >
                        Threat Level: {threatLevel.label}
                      </span>
                      <div className="flex gap-1">
                        <button
                          onClick={() => {
                            if (selectedScanId) api.sastExportJson(selectedScanId).then((data: any) => {
                              const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                              const url = URL.createObjectURL(blob); const a = document.createElement("a");
                              a.href = url; a.download = `sast-report-${selectedScanId.slice(0, 8)}.json`; a.click();
                              URL.revokeObjectURL(url); toast.success("JSON exported");
                            }).catch(() => toast.error("Export failed"));
                          }}
                          className="px-2 py-1 rounded-lg text-[10px] font-medium border transition-colors hover:bg-white/5"
                          style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}
                        >
                          <Download size={10} className="inline mr-1" />JSON
                        </button>
                        <button
                          onClick={() => { if (selectedScanId) api.sastExportCsv(selectedScanId); }}
                          className="px-2 py-1 rounded-lg text-[10px] font-medium border transition-colors hover:bg-white/5"
                          style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}
                        >
                          <Download size={10} className="inline mr-1" />CSV
                        </button>
                        <button
                          onClick={() => {
                            if (selectedScanId) api.sastExportJson(selectedScanId).then((data: any) => {
                              const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                              const url = URL.createObjectURL(blob); const a = document.createElement("a");
                              a.href = url; a.download = `sast-${selectedScanId.slice(0, 8)}.sarif.json`; a.click();
                              URL.revokeObjectURL(url); toast.success("SARIF exported");
                            }).catch(() => toast.error("Export failed"));
                          }}
                          className="px-2 py-1 rounded-lg text-[10px] font-medium border transition-colors hover:bg-white/5"
                          style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}
                        >
                          <Download size={10} className="inline mr-1" />SARIF
                        </button>
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 grid gap-2">
                    {SEVERITY_ORDER.map((sev) => {
                      const total = findingsForDisplay.length || 1;
                      const count = severityCounts[sev] || 0;
                      const pct = Math.round((count / total) * 100);
                      return (
                        <div key={sev} className="flex items-center gap-3">
                          <span className="w-16 text-xs uppercase" style={{ color: SEVERITY_COLORS[sev] }}>{sev}</span>
                          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ backgroundColor: "var(--bg-primary)" }}>
                            <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: SEVERITY_COLORS[sev] }} />
                          </div>
                          <span className="w-14 text-right text-xs" style={{ color: "var(--text-secondary)" }}>{count} ({pct}%)</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Summary cards */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
                  {/* Total */}
                  <div
                    className="rounded-xl border p-4"
                    style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                  >
                    <p className="text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
                      Total Issues
                    </p>
                    <p className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>
                      {findingsForDisplay.length}
                    </p>
                  </div>
                  {SEVERITY_ORDER.map((sev) => (
                    <div
                      key={sev}
                      className="rounded-xl border p-4"
                      style={{
                        backgroundColor: "var(--bg-card)",
                        borderColor: SEVERITY_COLORS[sev] + "33",
                      }}
                    >
                      <p className="text-xs font-medium mb-1 uppercase" style={{ color: SEVERITY_COLORS[sev] }}>
                        {sev}
                      </p>
                      <p className="text-2xl font-bold" style={{ color: SEVERITY_COLORS[sev] }}>
                        {severityCounts[sev]}
                      </p>
                    </div>
                  ))}
                </div>

                {/* Filter bar */}
                <div
                  className="flex flex-wrap items-center gap-3 mb-4 p-3 rounded-xl border"
                  style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                >
                  {breakdownFilterSource && (
                    <button
                      type="button"
                      onClick={() => setBreakdownFilterSource(null)}
                      className="flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium"
                      style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
                    >
                      Source: {breakdownFilterSource} <X size={12} />
                    </button>
                  )}
                  <Filter size={16} style={{ color: "var(--text-secondary)" }} />
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="px-2 py-1 rounded-lg text-xs border bg-transparent focus:outline-none focus:border-orange-500"
                    style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                  >
                    <option value="">All Severities</option>
                    {SEVERITY_ORDER.map((s) => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                  <select
                    value={filterConfidence}
                    onChange={(e) => setFilterConfidence(e.target.value)}
                    className="px-2 py-1 rounded-lg text-xs border bg-transparent focus:outline-none focus:border-orange-500"
                    style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                  >
                    <option value="">All Confidence</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className="px-2 py-1 rounded-lg text-xs border bg-transparent focus:outline-none focus:border-orange-500"
                    style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                  >
                    <option value="">All Statuses</option>
                    {Object.entries(STATUS_LABELS).map(([k, v]) => (
                      <option key={k} value={k}>{v.label}</option>
                    ))}
                  </select>
                  <div className="flex items-center gap-1 flex-1 min-w-[200px]">
                    <Search size={14} style={{ color: "var(--text-secondary)" }} />
                    <input
                      type="text"
                      placeholder="Filter by file path..."
                      value={filterFilePath}
                      onChange={(e) => setFilterFilePath(e.target.value)}
                      className="flex-1 px-2 py-1 rounded-lg text-xs bg-transparent border-none focus:outline-none"
                      style={{ color: "var(--text-primary)" }}
                    />
                  </div>
                </div>

                {/* Split: file tree + findings */}
                <div className="flex gap-4" style={{ minHeight: "500px" }}>
                  {/* File tree sidebar */}
                  <div
                    className="rounded-xl border p-3 overflow-y-auto shrink-0 hidden md:block"
                    style={{
                      backgroundColor: "var(--bg-card)",
                      borderColor: "var(--border-subtle)",
                      width: "280px",
                      maxHeight: "calc(100vh - 300px)",
                    }}
                  >
                    <div className="flex items-center gap-2 mb-3 px-2">
                      <Layers size={14} style={{ color: "var(--text-secondary)" }} />
                      <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                        File Tree
                      </span>
                    </div>
                    <button
                      onClick={() => setSelectedTreePath(null)}
                      className={`flex items-center gap-1.5 w-full text-left px-2 py-1 text-xs rounded hover:bg-white/5 transition-colors mb-1 ${
                        !selectedTreePath ? "font-semibold" : ""
                      }`}
                      style={{
                        color: !selectedTreePath ? "#fb923c" : "var(--text-secondary)",
                        backgroundColor: !selectedTreePath ? "rgba(234,88,12,0.1)" : undefined,
                      }}
                    >
                      All Files ({findingsForDisplay.length})
                    </button>
                    {fileTree && fileTree.children.map((child) => (
                      <FileTreeNode
                        key={child.path}
                        node={child}
                        depth={0}
                        selectedPath={selectedTreePath}
                        onSelect={setSelectedTreePath}
                        expandedPaths={expandedTreePaths}
                        onToggle={toggleTreePath}
                      />
                    ))}
                  </div>

                  {/* Findings list */}
                  <div className="flex-1 space-y-3 overflow-y-auto" style={{ maxHeight: "calc(100vh - 300px)" }}>
                    {displayedFindings.length === 0 ? (
                      <div
                        className="rounded-xl border p-10 text-center"
                        style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                      >
                        <CheckCircle size={32} className="mx-auto mb-2 text-green-400" />
                        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                          No findings match the current filters.
                        </p>
                      </div>
                    ) : (
                      displayedFindings.map((finding: any) => {
                        const isExpanded = expandedFindings.has(finding.id);
                        return (
                          <motion.div
                            key={finding.id}
                            layout
                            className="rounded-xl border overflow-hidden transition-colors"
                            style={{
                              backgroundColor: "var(--bg-card)",
                              borderColor: isExpanded
                                ? (SEVERITY_COLORS[finding.severity] || "var(--border-subtle)") + "55"
                                : "var(--border-subtle)",
                            }}
                          >
                            {/* Finding header */}
                            <button
                              onClick={() => toggleFinding(finding.id)}
                              className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.02] transition-colors"
                            >
                              {isExpanded ? (
                                <ChevronDown size={16} style={{ color: "var(--text-secondary)" }} />
                              ) : (
                                <ChevronRight size={16} style={{ color: "var(--text-secondary)" }} />
                              )}
                              {severityBadge(finding.severity)}
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate" style={{ color: "var(--text-primary)" }}>
                                  {finding.title || finding.rule_id || "Untitled Finding"}
                                </p>
                                <p className="text-xs mt-0.5 font-mono truncate" style={{ color: "var(--text-secondary)" }}>
                                  {finding.file_path}
                                  {finding.line_start ? `:${finding.line_start}` : ""}
                                </p>
                              </div>
                              {statusBadge(finding.status || "open")}
                            </button>

                            {/* Finding code snippet (always visible) */}
                            {finding.code_snippet && !isExpanded && (
                              <div className="px-4 pb-3">
                                <pre
                                  className="text-xs font-mono p-2 rounded-lg overflow-x-auto"
                                  style={{
                                    backgroundColor: "var(--bg-primary)",
                                    color: "var(--text-secondary)",
                                    border: "1px solid var(--border-subtle)",
                                    maxHeight: "60px",
                                  }}
                                >
                                  {finding.code_snippet}
                                </pre>
                              </div>
                            )}

                            {/* Expanded details */}
                            <AnimatePresence>
                              {isExpanded && (
                                <motion.div
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: "auto", opacity: 1 }}
                                  exit={{ height: 0, opacity: 0 }}
                                  transition={{ duration: 0.2 }}
                                  className="overflow-hidden"
                                >
                                  <div
                                    className="px-4 pb-4 space-y-4"
                                    style={{ borderTop: "1px solid var(--border-subtle)" }}
                                  >
                                    {/* Code snippet full */}
                                    {finding.code_snippet && (
                                      <div className="mt-4">
                                        <p className="text-xs font-semibold mb-1.5 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                          Code
                                        </p>
                                        <pre
                                          className="text-xs font-mono p-3 rounded-lg overflow-x-auto"
                                          style={{
                                            backgroundColor: "var(--bg-primary)",
                                            color: "var(--text-primary)",
                                            border: "1px solid var(--border-subtle)",
                                          }}
                                        >
                                          {finding.code_snippet}
                                        </pre>
                                      </div>
                                    )}

                                    {/* Description */}
                                    {finding.description && (
                                      <div>
                                        <p className="text-xs font-semibold mb-1 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                          Description
                                        </p>
                                        <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                                          {finding.description}
                                        </p>
                                      </div>
                                    )}

                                    {(finding.message || finding.file_path) && (
                                      <div className="grid gap-3 md:grid-cols-2">
                                        {finding.message && (
                                          <div>
                                            <p className="text-xs font-semibold mb-1 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                              Rule Message
                                            </p>
                                            <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                                              {finding.message}
                                            </p>
                                          </div>
                                        )}
                                        <div>
                                          <p className="text-xs font-semibold mb-1 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                            Location
                                          </p>
                                          <p className="text-sm font-mono" style={{ color: "var(--text-primary)" }}>
                                            {finding.file_path}
                                            {finding.line_start ? `:${finding.line_start}` : ""}
                                            {finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}
                                          </p>
                                        </div>
                                      </div>
                                    )}

                                    {/* CWE / OWASP */}
                                    <div className="flex flex-wrap gap-3">
                                      {finding.cwe_id && (
                                        <div>
                                          <p className="text-xs font-semibold mb-0.5 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                            CWE
                                          </p>
                                          <a
                                            href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace(/\D/g, "")}.html`}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-sm text-blue-400 hover:underline"
                                          >
                                            {finding.cwe_id}
                                          </a>
                                        </div>
                                      )}
                                      {finding.owasp_category && (
                                        <div>
                                          <p className="text-xs font-semibold mb-0.5 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                            OWASP
                                          </p>
                                          <span className="text-sm" style={{ color: "var(--text-primary)" }}>
                                            {finding.owasp_category}
                                          </span>
                                        </div>
                                      )}
                                      {finding.confidence && (
                                        <div>
                                          <p className="text-xs font-semibold mb-0.5 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                            Confidence
                                          </p>
                                          <span className="text-sm capitalize" style={{ color: "var(--text-primary)" }}>
                                            {finding.confidence}
                                          </span>
                                        </div>
                                      )}
                                    </div>

                                    {/* Fix suggestion */}
                                    {finding.fix_suggestion && (
                                      <div>
                                        <p className="text-xs font-semibold mb-1 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                          Suggested Fix
                                        </p>
                                        <pre
                                          className="text-xs font-mono p-3 rounded-lg overflow-x-auto whitespace-pre-wrap"
                                          style={{
                                            backgroundColor: "#16a34a11",
                                            color: "#4ade80",
                                            border: "1px solid #16a34a33",
                                          }}
                                        >
                                          {finding.fix_suggestion}
                                        </pre>
                                      </div>
                                    )}

                                    {finding.fixed_code && (
                                      <div>
                                        <p className="text-xs font-semibold mb-1 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                          Fixed Code
                                        </p>
                                        <pre
                                          className="text-xs font-mono p-3 rounded-lg overflow-x-auto whitespace-pre-wrap"
                                          style={{
                                            backgroundColor: "#2563eb11",
                                            color: "#93c5fd",
                                            border: "1px solid #2563eb33",
                                          }}
                                        >
                                          {finding.fixed_code}
                                        </pre>
                                      </div>
                                    )}

                                    {/* AI Analysis — remediation, attack scenario */}
                                    {finding.ai_analysis && typeof finding.ai_analysis === "object" && !finding.ai_analysis.error && (
                                      <div className="space-y-3 pt-2" style={{ borderTop: "1px solid rgba(124,58,237,0.15)" }}>
                                        <div className="flex items-center gap-1.5">
                                          <Brain size={14} style={{ color: "#a78bfa" }} />
                                          <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "#a78bfa" }}>
                                            AI Security Analysis
                                          </p>
                                          {finding.ai_analysis.is_false_positive && (
                                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold ml-2" style={{ backgroundColor: "#6b728022", color: "#9ca3af" }}>
                                              LIKELY FALSE POSITIVE
                                            </span>
                                          )}
                                        </div>
                                        {finding.ai_analysis.explanation && (
                                          <div>
                                            <p className="text-xs font-semibold mb-1" style={{ color: "var(--text-secondary)" }}>Explanation</p>
                                            <p className="text-sm" style={{ color: "var(--text-primary)" }}>{finding.ai_analysis.explanation}</p>
                                          </div>
                                        )}
                                        {finding.ai_analysis.remediation && (
                                          <div>
                                            <p className="text-xs font-semibold mb-1" style={{ color: "#16a34a" }}>Remediation</p>
                                            <div className="text-sm p-3 rounded-lg whitespace-pre-wrap" style={{ backgroundColor: "#16a34a11", color: "#4ade80", border: "1px solid #16a34a33" }}>
                                              {finding.ai_analysis.remediation}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    )}

                                    {/* References */}
                                    {finding.references && Array.isArray(finding.references) && finding.references.length > 0 && (
                                      <div>
                                        <p className="text-xs font-semibold mb-1 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                          References
                                        </p>
                                        <div className="flex flex-wrap gap-1.5">
                                          {finding.references.slice(0, 5).map((ref: any, i: number) => {
                                            const url = typeof ref === "string" ? ref : ref?.url;
                                            return url ? (
                                              <a
                                                key={i}
                                                href={url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-xs text-blue-400 hover:underline flex items-center gap-1"
                                              >
                                                <ExternalLink size={10} />
                                                {new URL(url).hostname}
                                              </a>
                                            ) : null;
                                          })}
                                        </div>
                                      </div>
                                    )}

                                    {/* AI Explanation (on-demand) */}
                                    {aiExplanations[finding.id] && (
                                      <div>
                                        <p className="text-xs font-semibold mb-1 uppercase tracking-wider flex items-center gap-1" style={{ color: "#a78bfa" }}>
                                          <Brain size={12} /> AI Deep Analysis
                                        </p>
                                        <div
                                          className="text-sm p-3 rounded-lg whitespace-pre-wrap"
                                          style={{
                                            backgroundColor: "#7c3aed11",
                                            color: "var(--text-primary)",
                                            border: "1px solid #7c3aed33",
                                          }}
                                        >
                                          {aiExplanations[finding.id]}
                                        </div>
                                      </div>
                                    )}

                                    {/* Actions */}
                                    <div className="flex flex-wrap items-center gap-2 pt-2" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                                      <button
                                        onClick={() => openFindingSource(finding)}
                                        disabled={sourceLoadingId === finding.id}
                                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:bg-sky-500/10 disabled:opacity-50"
                                        style={{ color: "#38bdf8", borderColor: "#0ea5e933" }}
                                      >
                                        {sourceLoadingId === finding.id ? (
                                          <Loader2 size={12} className="animate-spin" />
                                        ) : (
                                          <Code size={12} />
                                        )}
                                        Open Source
                                      </button>

                                      <button
                                        onClick={() => aiExplain(finding.id)}
                                        disabled={aiExplaining === finding.id}
                                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:bg-purple-500/10"
                                        style={{ color: "#a78bfa", borderColor: "#7c3aed33" }}
                                      >
                                        {aiExplaining === finding.id ? (
                                          <Loader2 size={12} className="animate-spin" />
                                        ) : (
                                          <Brain size={12} />
                                        )}
                                        AI Analyze
                                      </button>

                                      <button
                                        onClick={() => createFixPr(finding.id)}
                                        disabled={creatingPrId === finding.id || (!finding.fixed_code && !finding.fix_suggestion)}
                                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:bg-emerald-500/10 disabled:opacity-50"
                                        style={{ color: "#34d399", borderColor: "#10b98133" }}
                                      >
                                        {creatingPrId === finding.id ? (
                                          <Loader2 size={12} className="animate-spin" />
                                        ) : (
                                          <Github size={12} />
                                        )}
                                        Create Fix PR
                                      </button>

                                      <select
                                        value={finding.status || "open"}
                                        onChange={(e) => updateFindingStatus(finding.id, e.target.value)}
                                        className="px-2 py-1.5 rounded-lg text-xs border bg-transparent focus:outline-none focus:border-orange-500"
                                        style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                                      >
                                        {Object.entries(STATUS_LABELS).map(([k, v]) => (
                                          <option key={k} value={k}>{v.label}</option>
                                        ))}
                                      </select>
                                    </div>
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </motion.div>
                        );
                      })
                    )}
                  </div>
                </div>
                </>
                )}

                {/* === SECRETS SUB-TAB === */}
                {resultsSubTab === "secrets" && (() => {
                  const SECRET_SOURCES = ["secret_scan", "trufflehog", "gitleaks"];
                  const secretFindings = findings.filter((f: any) => SECRET_SOURCES.includes(f.rule_source || ""));
                  const secretTypes: Record<string, string> = {
                    "api_key": "API Key", "apikey": "API Key", "password": "Password", "secret": "Token",
                    "token": "Token", "private_key": "Private Key", "privatekey": "Private Key",
                    "aws": "AWS Key", "generic": "Secret",
                  };
                  const inferSecretType = (ruleId: string) => {
                    const lower = (ruleId || "").toLowerCase();
                    for (const [k, label] of Object.entries(secretTypes))
                      if (lower.includes(k)) return label;
                    return "Secret";
                  };
                  const highCrit = secretFindings.filter((f: any) => ["critical", "high"].includes((f.severity || "").toLowerCase()));
                  const filesAffected = new Set(secretFindings.map((f: any) => f.file_path)).size;
                  const byType: Record<string, any[]> = {};
                  secretFindings.forEach((f: any) => {
                    const t = inferSecretType(f.rule_id || "");
                    if (!byType[t]) byType[t] = [];
                    byType[t].push(f);
                  });
                  return (
                    <div className="space-y-6">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                          <p className="text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>Total Secrets</p>
                          <p className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{secretFindings.length}</p>
                        </div>
                        <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#dc262633" }}>
                          <p className="text-xs font-medium mb-1" style={{ color: "#dc2626" }}>High / Critical</p>
                          <p className="text-2xl font-bold" style={{ color: "#dc2626" }}>{highCrit.length}</p>
                        </div>
                        <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                          <p className="text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>Files Affected</p>
                          <p className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{filesAffected}</p>
                        </div>
                        <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#16a34a33" }}>
                          <p className="text-xs font-medium mb-1" style={{ color: "#16a34a" }}>Verified</p>
                          <p className="text-2xl font-bold" style={{ color: "#16a34a" }}>{secretFindings.filter((f: any) => (f.rule_id || "").toLowerCase().includes("verified") || (f.message || "").toLowerCase().includes("verified")).length}</p>
                        </div>
                      </div>
                      {secretFindings.length === 0 ? (
                        <div className="rounded-xl border p-10 text-center" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                          <KeyRound size={36} className="mx-auto mb-3" style={{ color: "var(--text-secondary)" }} />
                          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>No secrets detected in this scan.</p>
                        </div>
                      ) : (
                        <div className="space-y-6">
                          {Object.entries(byType).map(([typeLabel, items]) => (
                            <div key={typeLabel} className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                                <KeyRound size={16} /> {typeLabel} ({items.length})
                              </h3>
                              <ul className="space-y-2">
                                {items.map((f: any, idx: number) => (
                                  <li key={f.id || `${f.file_path}-${f.line_start}-${idx}`} className="flex flex-wrap items-center gap-2 p-3 rounded-lg" style={{ backgroundColor: "var(--bg-primary)" }}>
                                    <span className="text-xs font-mono truncate max-w-[180px]" style={{ color: "var(--text-secondary)" }} title={f.code_snippet || f.message}>
                                      {((f.code_snippet || f.message || "").slice(0, 40) || "—").replace(/./g, "•")}
                                    </span>
                                    {(f.rule_id || "").toLowerCase().includes("verified") || (f.message || "").toLowerCase().includes("verified") ? (
                                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: "#16a34a22", color: "#16a34a" }}>Verified</span>
                                    ) : null}
                                    <span className="text-xs" style={{ color: "var(--text-secondary)" }}>{f.file_path}:{f.line_start ?? "—"}</span>
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: (SEVERITY_COLORS[f.severity] || "#6b7280") + "22", color: SEVERITY_COLORS[f.severity] || "#6b7280" }}>{f.severity || "info"}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* === DEPENDENCIES SUB-TAB === */}
                {resultsSubTab === "dependencies" && (
                  <div className="space-y-4">
                    {secDataLoading ? (
                      <div className="flex items-center justify-center py-16">
                        <Loader2 size={28} className="animate-spin text-orange-400" />
                      </div>
                    ) : depPagination.total === 0 ? (
                      <div
                        className="rounded-xl border p-10 text-center"
                        style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                      >
                        <Package size={36} className="mx-auto mb-3" style={{ color: "var(--text-secondary)" }} />
                        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                          No dependency data available. SCA scanning may not have been enabled for this scan.
                        </p>
                      </div>
                    ) : (
                      <>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>Total Dependencies</p>
                            <p className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{depPagination.total}</p>
                          </div>
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#dc262633" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "#dc2626" }}>Vulnerable</p>
                            <p className="text-2xl font-bold" style={{ color: "#dc2626" }}>
                              {typeof depPagination.total_vulnerable === "number" ? depPagination.total_vulnerable : (depFilters.vulnerable === "yes" ? depPagination.total : dependencies.filter((d: any) => d.is_vulnerable).length)}
                            </p>
                          </div>
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#ca8a0433" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "#ca8a04" }}>Outdated</p>
                            <p className="text-2xl font-bold" style={{ color: "#ca8a04" }}>
                              {typeof depPagination.total_outdated === "number" ? depPagination.total_outdated : dependencies.filter((d: any) => d.latest_version && d.latest_version !== d.version).length}
                            </p>
                          </div>
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#16a34a33" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "#16a34a" }}>Secure</p>
                            <p className="text-2xl font-bold" style={{ color: "#16a34a" }}>
                              {typeof depPagination.total_secure === "number" ? depPagination.total_secure : (depFilters.vulnerable === "no" ? depPagination.total : dependencies.filter((d: any) => !d.is_vulnerable).length)}
                            </p>
                          </div>
                        </div>

                        <div className="flex flex-wrap items-center gap-3 py-2" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                          <input
                            type="text"
                            placeholder="Filter by name..."
                            value={depFilters.name}
                            onChange={(e) => setDepFilters((f) => ({ ...f, name: e.target.value }))}
                            onKeyDown={(e) => e.key === "Enter" && selectedScanId && loadSecurityData("dependencies", selectedScanId)}
                            className="px-3 py-1.5 rounded-lg border text-sm w-48"
                            style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                          />
                          <select
                            value={depFilters.ecosystem}
                            onChange={(e) => setDepFilters((f) => ({ ...f, ecosystem: e.target.value }))}
                            className="px-3 py-1.5 rounded-lg border text-sm"
                            style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                          >
                            <option value="">All ecosystems</option>
                            <option value="npm">npm</option>
                            <option value="pypi">pypi</option>
                            <option value="go">go</option>
                            <option value="maven">maven</option>
                            <option value="cargo">cargo</option>
                            <option value="nuget">nuget</option>
                            <option value="rubygems">rubygems</option>
                            <option value="packagist">packagist</option>
                          </select>
                          <select
                            value={depFilters.vulnerable}
                            onChange={(e) => setDepFilters((f) => ({ ...f, vulnerable: e.target.value }))}
                            className="px-3 py-1.5 rounded-lg border text-sm"
                            style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                          >
                            <option value="">All</option>
                            <option value="yes">Vulnerable only</option>
                            <option value="no">Secure only</option>
                          </select>
                          <button
                            type="button"
                            onClick={() => {
                              setDepPagination((p) => ({ ...p, page: 1 }));
                              selectedScanId && loadSecurityData("dependencies", selectedScanId, { page: 1 });
                            }}
                            className="px-3 py-1.5 rounded-lg text-sm font-medium"
                            style={{ backgroundColor: "var(--orange)", color: "#fff" }}
                          >
                            Apply filters
                          </button>
                          <span className="text-xs ml-auto" style={{ color: "var(--text-secondary)" }}>
                            Page {depPagination.page} of {depPagination.total_pages || 1} ({depPagination.total} total)
                          </span>
                          <div className="flex gap-1">
                            <button
                              type="button"
                              disabled={depPagination.page <= 1}
                              onClick={() => { setDepPagination((p) => ({ ...p, page: p.page - 1 })); }}
                              className="px-2 py-1 rounded text-sm disabled:opacity-50"
                              style={{ backgroundColor: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                            >
                              Prev
                            </button>
                            <button
                              type="button"
                              disabled={depPagination.page >= depPagination.total_pages}
                              onClick={() => { setDepPagination((p) => ({ ...p, page: p.page + 1 })); }}
                              className="px-2 py-1 rounded text-sm disabled:opacity-50"
                              style={{ backgroundColor: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                            >
                              Next
                            </button>
                          </div>
                        </div>

                        <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                          <table className="w-full text-sm">
                            <thead>
                              <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Package</th>
                                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Version</th>
                                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>License</th>
                                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Ecosystem</th>
                                <th className="text-center px-4 py-3 text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Status</th>
                                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>CVEs</th>
                              </tr>
                            </thead>
                            <tbody>
                              {dependencies.map((dep: any, idx: number) => (
                                <tr
                                  key={dep.id || idx}
                                  className="hover:bg-white/[0.02] transition-colors"
                                  style={{ borderBottom: "1px solid var(--border-subtle)" }}
                                >
                                  <td className="px-4 py-3 font-mono text-xs" style={{ color: "var(--text-primary)" }}>{dep.name}</td>
                                  <td className="px-4 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
                                    {dep.version}
                                    {dep.latest_version && dep.latest_version !== dep.version && (
                                      <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full" style={{ backgroundColor: "#ca8a0422", color: "#ca8a04" }}>
                                        → {dep.latest_version}
                                      </span>
                                    )}
                                  </td>
                                  <td className="px-4 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>{dep.license || "—"}</td>
                                  <td className="px-4 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>{dep.ecosystem || "—"}</td>
                                  <td className="px-4 py-3 text-center">
                                    {dep.is_vulnerable ? (
                                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold" style={{ backgroundColor: "#dc262622", color: "#dc2626" }}>VULNERABLE</span>
                                    ) : (
                                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold" style={{ backgroundColor: "#16a34a22", color: "#16a34a" }}>SECURE</span>
                                    )}
                                  </td>
                                  <td className="px-4 py-3 text-xs font-mono" style={{ color: dep.cve_ids ? "#dc2626" : "var(--text-secondary)" }}>
                                    {dep.cve_ids || "—"}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </>
                    )}
                  </div>
                )}

                {/* === SBOM & LICENSES SUB-TAB === */}
                {resultsSubTab === "sbom" && (
                  <div className="space-y-4">
                    {secDataLoading ? (
                      <div className="flex items-center justify-center py-16">
                        <Loader2 size={28} className="animate-spin text-orange-400" />
                      </div>
                    ) : (
                      <>
                        <div className="flex flex-wrap gap-3 mb-2">
                          <button
                            onClick={async () => {
                              if (!selectedScanId) return;
                              try {
                                const data = await api.sastSbomCyclonedx(selectedScanId);
                                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = `sbom-cyclonedx-${selectedScanId.slice(0, 8)}.json`;
                                a.click();
                                URL.revokeObjectURL(url);
                                toast.success("CycloneDX SBOM downloaded");
                              } catch { toast.error("Failed to export CycloneDX SBOM"); }
                            }}
                            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium border transition-colors hover:bg-sky-500/10"
                            style={{ color: "#38bdf8", borderColor: "#0ea5e933" }}
                          >
                            <Download size={14} /> Export CycloneDX
                          </button>
                          <button
                            onClick={async () => {
                              if (!selectedScanId) return;
                              try {
                                const data = await api.sastSbomSpdx(selectedScanId);
                                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = `sbom-spdx-${selectedScanId.slice(0, 8)}.json`;
                                a.click();
                                URL.revokeObjectURL(url);
                                toast.success("SPDX SBOM downloaded");
                              } catch { toast.error("Failed to export SPDX SBOM"); }
                            }}
                            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium border transition-colors hover:bg-emerald-500/10"
                            style={{ color: "#34d399", borderColor: "#10b98133" }}
                          >
                            <Download size={14} /> Export SPDX
                          </button>
                        </div>

                        {licenses ? (
                          <>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                              <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                                <p className="text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>Total Packages</p>
                                <p className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{licenses.total_packages || 0}</p>
                              </div>
                              <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#16a34a33" }}>
                                <p className="text-xs font-medium mb-1" style={{ color: "#16a34a" }}>Compliant</p>
                                <p className="text-2xl font-bold" style={{ color: "#16a34a" }}>{licenses.compliant || 0}</p>
                              </div>
                              <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#dc262633" }}>
                                <p className="text-xs font-medium mb-1" style={{ color: "#dc2626" }}>Blocked</p>
                                <p className="text-2xl font-bold" style={{ color: "#dc2626" }}>{licenses.blocked || 0}</p>
                              </div>
                              <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#ca8a0433" }}>
                                <p className="text-xs font-medium mb-1" style={{ color: "#ca8a04" }}>Unknown License</p>
                                <p className="text-2xl font-bold" style={{ color: "#ca8a04" }}>{licenses.unknown || 0}</p>
                              </div>
                            </div>

                            {licenses.license_breakdown && (
                              <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                                <p className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                                  License Distribution
                                </p>
                                <div className="space-y-2">
                                  {Object.entries(licenses.license_breakdown).sort((a: any, b: any) => b[1] - a[1]).map(([license, count]: any) => {
                                    const total = licenses.total_packages || 1;
                                    const pct = Math.round((count / total) * 100);
                                    const isBlocked = licenses.blocked_list?.includes(license);
                                    return (
                                      <div key={license} className="flex items-center gap-3">
                                        <span className="w-28 text-xs truncate" style={{ color: isBlocked ? "#dc2626" : "var(--text-primary)" }}>
                                          {license} {isBlocked && "⛔"}
                                        </span>
                                        <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ backgroundColor: "var(--bg-primary)" }}>
                                          <div
                                            className="h-full rounded-full"
                                            style={{ width: `${pct}%`, backgroundColor: isBlocked ? "#dc2626" : "#3b82f6" }}
                                          />
                                        </div>
                                        <span className="w-16 text-right text-xs" style={{ color: "var(--text-secondary)" }}>{count} ({pct}%)</span>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </>
                        ) : (
                          <div
                            className="rounded-xl border p-10 text-center"
                            style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                          >
                            <Scale size={36} className="mx-auto mb-3" style={{ color: "var(--text-secondary)" }} />
                            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                              No license data available. Enable SCA scanning to generate SBOM and license reports.
                            </p>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {/* === CVE INTELLIGENCE SUB-TAB === */}
                {resultsSubTab === "cve" && (
                  <div className="space-y-4">
                    {secDataLoading ? (
                      <div className="flex items-center justify-center py-16">
                        <Loader2 size={28} className="animate-spin text-orange-400" />
                      </div>
                    ) : cveSummary ? (
                      <>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>Total CVEs</p>
                            <p className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{cveSummary.total_cves || 0}</p>
                          </div>
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#dc262633" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "#dc2626" }}>CISA KEV Listed</p>
                            <p className="text-2xl font-bold" style={{ color: "#dc2626" }}>{cveSummary.kev_count || 0}</p>
                          </div>
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#ea580c33" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "#ea580c" }}>High EPSS (&gt;0.5)</p>
                            <p className="text-2xl font-bold" style={{ color: "#ea580c" }}>{cveSummary.high_epss_count || 0}</p>
                          </div>
                          <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#7c3aed33" }}>
                            <p className="text-xs font-medium mb-1" style={{ color: "#7c3aed" }}>Avg CVSS</p>
                            <p className="text-2xl font-bold" style={{ color: "#7c3aed" }}>{(cveSummary.avg_cvss || 0).toFixed(1)}</p>
                          </div>
                        </div>

                        {cveSummary.prioritized && cveSummary.prioritized.length > 0 && (
                          <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                            <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                              <p className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5" style={{ color: "#ea580c" }}>
                                <Zap size={14} /> Prioritized Vulnerabilities
                              </p>
                            </div>
                            <table className="w-full text-sm">
                              <thead>
                                <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                                  <th className="text-left px-4 py-2 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>CVE</th>
                                  <th className="text-left px-4 py-2 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>Package</th>
                                  <th className="text-center px-4 py-2 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>CVSS</th>
                                  <th className="text-center px-4 py-2 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>EPSS</th>
                                  <th className="text-center px-4 py-2 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>KEV</th>
                                  <th className="text-center px-4 py-2 text-xs font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>Priority</th>
                                </tr>
                              </thead>
                              <tbody>
                                {cveSummary.prioritized.map((v: any, idx: number) => (
                                  <tr key={idx} className="hover:bg-white/[0.02]" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                                    <td className="px-4 py-2.5">
                                      <a
                                        href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-xs font-mono text-blue-400 hover:underline"
                                      >
                                        {v.cve_id}
                                      </a>
                                    </td>
                                    <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-primary)" }}>{v.package || "—"}</td>
                                    <td className="px-4 py-2.5 text-center">
                                      <span
                                        className="px-2 py-0.5 rounded text-xs font-bold"
                                        style={{
                                          backgroundColor: (v.cvss || 0) >= 9 ? "#dc262622" : (v.cvss || 0) >= 7 ? "#ea580c22" : "#ca8a0422",
                                          color: (v.cvss || 0) >= 9 ? "#dc2626" : (v.cvss || 0) >= 7 ? "#ea580c" : "#ca8a04",
                                        }}
                                      >
                                        {(v.cvss || 0).toFixed(1)}
                                      </span>
                                    </td>
                                    <td className="px-4 py-2.5 text-center">
                                      <span className="text-xs font-mono" style={{ color: (v.epss || 0) > 0.5 ? "#dc2626" : "var(--text-secondary)" }}>
                                        {((v.epss || 0) * 100).toFixed(1)}%
                                      </span>
                                    </td>
                                    <td className="px-4 py-2.5 text-center">
                                      {v.in_kev ? (
                                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold" style={{ backgroundColor: "#dc262622", color: "#dc2626" }}>
                                          YES
                                        </span>
                                      ) : (
                                        <span className="text-xs" style={{ color: "var(--text-secondary)" }}>No</span>
                                      )}
                                    </td>
                                    <td className="px-4 py-2.5 text-center">
                                      <span
                                        className="px-2 py-0.5 rounded text-xs font-bold uppercase"
                                        style={{
                                          backgroundColor: v.priority === "critical" ? "#dc262622" : v.priority === "high" ? "#ea580c22" : "#ca8a0422",
                                          color: v.priority === "critical" ? "#dc2626" : v.priority === "high" ? "#ea580c" : "#ca8a04",
                                        }}
                                      >
                                        {v.priority || "—"}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </>
                    ) : (
                      <div
                        className="rounded-xl border p-10 text-center"
                        style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
                      >
                        <ShieldAlert size={36} className="mx-auto mb-3" style={{ color: "var(--text-secondary)" }} />
                        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                          No CVE intelligence data available. Enable SCA scanning for CVE enrichment.
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {/* === SCANNER BREAKDOWN SUB-TAB === */}
                {resultsSubTab === "breakdown" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                      {[
                        { label: "Semgrep", source: "semgrep" as string | null, value: findings.filter((f: any) => !f.rule_source || f.rule_source === "semgrep").length, icon: Code, color: "#3b82f6" },
                        { label: "Secrets", source: "secrets", value: findings.filter((f: any) => ["secret_scan", "trufflehog", "gitleaks"].includes(f.rule_source || "")).length, icon: KeyRound, color: "#dc2626" },
                        { label: "SCA", source: "sca", value: scanResults?.scan?.sca_issues ?? findings.filter((f: any) => f.rule_source === "sca").length, icon: Package, color: "#ea580c" },
                        { label: "IaC", source: "iac", value: scanResults?.scan?.iac_issues ?? findings.filter((f: any) => f.rule_source === "iac").length, icon: FileJson, color: "#8b5cf6" },
                        { label: "Container", source: "container", value: scanResults?.scan?.container_issues ?? findings.filter((f: any) => f.rule_source === "container").length, icon: Container, color: "#06b6d4" },
                        { label: "JS/TS", source: "js_deep", value: scanResults?.scan?.js_deep_issues ?? findings.filter((f: any) => f.rule_source === "js_deep").length, icon: Zap, color: "#f59e0b" },
                        { label: "Licenses", source: "license", value: scanResults?.scan?.license_issues ?? findings.filter((f: any) => (f.rule_source || "").toLowerCase().includes("license")).length, icon: Scale, color: "#ef4444" },
                        { label: "Claude Review", source: null, value: scanResults?.scan?.claude_review_findings_count || 0, icon: Brain, color: "#a78bfa" },
                      ].map((card) => {
                        const Icon = card.icon;
                        const isClaude = card.label === "Claude Review";
                        const clickable = !isClaude && card.source;
                        return (
                          <button
                            key={card.label}
                            type="button"
                            onClick={() => {
                              if (clickable && card.source) {
                                setBreakdownFilterSource(card.source);
                                setResultsSubTab("findings");
                              }
                            }}
                            className={`rounded-xl border p-4 text-left transition-all ${clickable ? "cursor-pointer hover:opacity-90 hover:border-opacity-60" : "cursor-default"}`}
                            style={{ backgroundColor: "var(--bg-card)", borderColor: card.color + "33" }}
                          >
                            <div className="flex items-center gap-2 mb-2">
                              <Icon size={16} style={{ color: card.color }} />
                              <p className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>{card.label}</p>
                            </div>
                            <p className="text-2xl font-bold" style={{ color: card.value > 0 ? card.color : "var(--text-secondary)" }}>
                              {card.value}
                            </p>
                            {clickable && <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>Click to filter</p>}
                          </button>
                        );
                      })}
                    </div>

                    {scanResults?.scan?.claude_review_enabled && (
                      <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#a78bfa33" }}>
                        <div className="flex items-center gap-2 mb-3">
                          <Brain size={16} style={{ color: "#a78bfa" }} />
                          <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Claude AI Security Review</p>
                        </div>
                        <div className="grid grid-cols-3 gap-4">
                          <div>
                            <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Status</p>
                            <p className="text-sm font-semibold" style={{ color: "#16a34a" }}>Completed</p>
                          </div>
                          <div>
                            <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Findings</p>
                            <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                              {scanResults.scan.claude_review_findings_count || 0}
                            </p>
                          </div>
                          <div>
                            <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Cost</p>
                            <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                              ${(scanResults.scan.claude_review_cost_usd || 0).toFixed(4)}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}

                    {!scanResults?.scan?.claude_review_enabled && (
                      <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "#a78bfa33" }}>
                        <div className="flex items-center gap-2">
                          <Brain size={16} style={{ color: "#a78bfa" }} />
                          <div>
                            <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Claude AI Security Review</p>
                            <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                              Enable Claude Review in Admin → AI Usage to run semantic AI analysis on findings.
                            </p>
                          </div>
                        </div>
                        {selectedScanId && (
                          <div className="mt-3 flex items-center gap-2">
                            <button
                              onClick={async () => {
                                if (!selectedScanId) return;
                                setClaudeReviewLoading(true);
                                try {
                                  await api.sastTriggerClaudeReview(selectedScanId);
                                  toast.success("Claude review triggered. Findings will appear when complete.");
                                } catch (e: any) {
                                  toast.error(e?.message || "Failed to trigger Claude review");
                                } finally {
                                  setClaudeReviewLoading(false);
                                }
                              }}
                              disabled={claudeReviewLoading}
                              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium text-white bg-gradient-to-r from-purple-600 to-violet-600 hover:from-purple-700 hover:to-violet-700 transition-all disabled:opacity-50"
                            >
                              {claudeReviewLoading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                              Run Claude Review
                            </button>
                          </div>
                        )}
                      </div>
                    )}

                    {scanResults?.scan?.policy_result && (
                      <div
                        className="rounded-xl border p-4"
                        style={{
                          backgroundColor: "var(--bg-card)",
                          borderColor: scanResults.scan.policy_result.passed ? "#16a34a33" : "#dc262633",
                        }}
                      >
                        <div className="flex items-center gap-2 mb-3">
                          <Shield size={16} style={{ color: scanResults.scan.policy_result.passed ? "#16a34a" : "#dc2626" }} />
                          <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Policy Evaluation</p>
                          <span
                            className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase"
                            style={{
                              backgroundColor: scanResults.scan.policy_result.passed ? "#16a34a22" : "#dc262622",
                              color: scanResults.scan.policy_result.passed ? "#16a34a" : "#dc2626",
                            }}
                          >
                            {scanResults.scan.policy_result.passed ? "PASSED" : "FAILED"}
                          </span>
                        </div>
                        {scanResults.scan.policy_result.violations && scanResults.scan.policy_result.violations.length > 0 && (
                          <div className="space-y-1 mt-2">
                            {scanResults.scan.policy_result.violations.map((v: string, i: number) => (
                              <div key={i} className="flex items-start gap-2">
                                <XCircle size={12} className="shrink-0 mt-0.5" style={{ color: "#dc2626" }} />
                                <p className="text-xs" style={{ color: "var(--text-primary)" }}>{v}</p>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    <div className="rounded-xl border p-4" style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                      <p className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
                        Scan Metadata
                      </p>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        <div>
                          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Total Files</p>
                          <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{scanResults?.scan?.total_files || 0}</p>
                        </div>
                        <div>
                          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Files Scanned</p>
                          <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{scanResults?.scan?.files_scanned || 0}</p>
                        </div>
                        <div>
                          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Duration</p>
                          <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{formatDuration(scanResults?.scan?.scan_duration_seconds)}</p>
                        </div>
                        <div>
                          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>AI Cost</p>
                          <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                            ${((scanResults?.scan?.ai_cost_usd || 0) + (scanResults?.scan?.claude_review_cost_usd || 0)).toFixed(4)}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

              </>
            )}
          </motion.div>
        )}

        {/* ====== CI/CD TAB ====== */}
        {activeTab === "cicd" && (
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
            <div className="space-y-6">
              {/* Webhook URL */}
              <div
                className="rounded-xl border p-6"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <h2 className="text-lg font-semibold mb-3" style={{ color: "var(--text-primary)" }}>
                  Webhook Configuration
                </h2>
                <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
                  Use this webhook URL to trigger SAST scans from your CI/CD pipeline.
                </p>
                <div className="flex items-center gap-2">
                  <div
                    className="flex-1 px-4 py-2.5 rounded-lg text-sm font-mono truncate border"
                    style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                  >
                    {webhookConfig?.webhook_url || cicdLoading ? (
                      webhookConfig?.webhook_url || "Loading..."
                    ) : (
                      `${typeof window !== "undefined" ? window.location.origin : ""}/api/sast/webhook/${projectId}`
                    )}
                  </div>
                  <button
                    onClick={() => {
                      const url = webhookConfig?.webhook_url || `${window.location.origin}/api/sast/webhook/${projectId}`;
                      navigator.clipboard.writeText(url);
                      toast.success("Copied to clipboard");
                    }}
                    className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg text-sm font-medium text-white bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 transition-all shrink-0"
                  >
                    <Copy size={14} /> Copy
                  </button>
                </div>
                {webhookConfig?.token && (
                  <div className="mt-3">
                    <p className="text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
                      API Key (include in X-API-Key header)
                    </p>
                    <div className="flex items-center gap-2">
                      <code
                        className="flex-1 px-3 py-2 rounded-lg text-xs font-mono truncate border"
                        style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                      >
                        {webhookConfig.token}
                      </code>
                      <button
                        onClick={() => { navigator.clipboard.writeText(webhookConfig.token); toast.success("API key copied"); }}
                        className="p-2 rounded-lg hover:bg-white/5 transition-colors"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        <Copy size={14} />
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* GitHub Actions */}
              <div
                className="rounded-xl border p-6"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <Github size={20} style={{ color: "var(--text-primary)" }} />
                  <h3 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>
                    GitHub Actions
                  </h3>
                </div>
                <p className="text-xs mb-3" style={{ color: "var(--text-secondary)" }}>
                  Add this to <code className="text-orange-400">.github/workflows/sast.yml</code>
                </p>
                <div className="relative">
                  <pre
                    className="text-xs font-mono p-4 rounded-lg overflow-x-auto"
                    style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                  >
{`name: SAST Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create source archive
        run: zip -r source.zip . -x '.git/*'

      - name: Run SAST Scan
        run: |
          curl -X POST \\
            -H "X-API-Key: \${{ secrets.SAST_API_KEY }}" \\
            -F "file=@source.zip" \\
            -F "project_id=${projectId}" \\
            -F "ai_analysis=true" \\
            ${typeof window !== "undefined" ? window.location.origin : "https://your-domain.com"}/api/sast/scan/upload`}
                  </pre>
                  <button
                    onClick={() => {
                      const origin = typeof window !== "undefined" ? window.location.origin : "https://your-domain.com";
                      const snippet = `name: SAST Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create source archive
        run: zip -r source.zip . -x '.git/*'

      - name: Run SAST Scan
        run: |
          curl -X POST \\
            -H "X-API-Key: \${{ secrets.SAST_API_KEY }}" \\
            -F "file=@source.zip" \\
            -F "project_id=${projectId}" \\
            -F "ai_analysis=true" \\
            ${origin}/api/sast/scan/upload`;
                      navigator.clipboard.writeText(snippet);
                      toast.success("Copied");
                    }}
                    className="absolute top-2 right-2 p-1.5 rounded-lg hover:bg-white/10 transition-colors"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <Copy size={14} />
                  </button>
                </div>
              </div>

              {/* GitLab CI */}
              <div
                className="rounded-xl border p-6"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <GitBranch size={20} style={{ color: "var(--text-primary)" }} />
                  <h3 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>
                    GitLab CI
                  </h3>
                </div>
                <p className="text-xs mb-3" style={{ color: "var(--text-secondary)" }}>
                  Add this to <code className="text-orange-400">.gitlab-ci.yml</code>
                </p>
                <pre
                  className="text-xs font-mono p-4 rounded-lg overflow-x-auto"
                  style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                >
{`sast_scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl zip
  script:
    - zip -r source.zip . -x '.git/*'
    - |
      curl -X POST \\
        -H "X-API-Key: $SAST_API_KEY" \\
        -F "file=@source.zip" \\
        -F "project_id=${projectId}" \\
        -F "ai_analysis=true" \\
        ${typeof window !== "undefined" ? window.location.origin : "https://your-domain.com"}/api/sast/scan/upload
  only:
    - main
    - merge_requests`}
                </pre>
              </div>

              {/* Jenkins */}
              <div
                className="rounded-xl border p-6"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <Terminal size={20} style={{ color: "var(--text-primary)" }} />
                  <h3 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>
                    Jenkins Pipeline
                  </h3>
                </div>
                <p className="text-xs mb-3" style={{ color: "var(--text-secondary)" }}>
                  Add this stage to your <code className="text-orange-400">Jenkinsfile</code>
                </p>
                <pre
                  className="text-xs font-mono p-4 rounded-lg overflow-x-auto"
                  style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                >
{`pipeline {
    agent any
    stages {
        stage('SAST Scan') {
            steps {
                sh 'zip -r source.zip . -x ".git/*"'
                sh """
                    curl -X POST \\
                      -H "X-API-Key: \${SAST_API_KEY}" \\
                      -F "file=@source.zip" \\
                      -F "project_id=${projectId}" \\
                      -F "ai_analysis=true" \\
                      ${typeof window !== "undefined" ? window.location.origin : "https://your-domain.com"}/api/sast/scan/upload
                """
            }
        }
    }
}`}
                </pre>
              </div>

              {/* PR Review Webhook */}
              <div
                className="rounded-xl border p-6"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <GitBranch size={20} style={{ color: "#a78bfa" }} />
                  <h3 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>
                    PR Security Review
                  </h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold" style={{ backgroundColor: "#a78bfa22", color: "#a78bfa" }}>
                    AI-POWERED
                  </span>
                </div>
                <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
                  Automatically scan pull requests for security vulnerabilities. Claude AI will review code changes
                  and post inline comments on your PRs with findings.
                </p>

                <div className="space-y-3 mb-4">
                  <div className="flex items-center justify-between p-3 rounded-lg" style={{ backgroundColor: "var(--bg-primary)", border: "1px solid var(--border-subtle)" }}>
                    <div>
                      <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>PR Webhook URL</p>
                      <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                        Add this to your repository webhook settings (push events for pull requests)
                      </p>
                    </div>
                    <button
                      onClick={() => {
                        const url = `${window.location.origin}/api/sast/webhook/pr/${projectId}`;
                        navigator.clipboard.writeText(url);
                        toast.success("PR webhook URL copied");
                      }}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border hover:bg-white/5"
                      style={{ color: "var(--text-primary)", borderColor: "var(--border-subtle)" }}
                    >
                      <Copy size={12} /> Copy URL
                    </button>
                  </div>
                </div>

                <div className="relative">
                  <p className="text-xs font-medium mb-2" style={{ color: "var(--text-secondary)" }}>
                    GitHub Actions PR Review Workflow
                  </p>
                  <pre
                    className="text-xs font-mono p-4 rounded-lg overflow-x-auto"
                    style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                  >
{`name: Security PR Review
on:
  pull_request:
    branches: [main, develop]

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - name: Create source archive
        run: zip -r source.zip . -x '.git/*'

      - name: Run PR Security Review
        run: |
          curl -X POST \\
            -H "X-API-Key: \${{ secrets.SAST_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{"project_id": "${projectId}", "pr_number": "\${{ github.event.pull_request.number }}", "base_ref": "\${{ github.base_ref }}", "head_ref": "\${{ github.head_ref }}"}' \\
            ${typeof window !== "undefined" ? window.location.origin : "https://your-domain.com"}/api/sast/scan/diff`}
                  </pre>
                  <button
                    onClick={() => {
                      const origin = typeof window !== "undefined" ? window.location.origin : "https://your-domain.com";
                      const snippet = `name: Security PR Review
on:
  pull_request:
    branches: [main, develop]

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - name: Create source archive
        run: zip -r source.zip . -x '.git/*'

      - name: Run PR Security Review
        run: |
          curl -X POST \\
            -H "X-API-Key: \${{ secrets.SAST_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{"project_id": "${projectId}", "pr_number": "${"$"}{{ github.event.pull_request.number }}", "base_ref": "${"$"}{{ github.base_ref }}", "head_ref": "${"$"}{{ github.head_ref }}"}' \\
            ${origin}/api/sast/scan/diff`;
                      navigator.clipboard.writeText(snippet);
                      toast.success("Copied");
                    }}
                    className="absolute top-8 right-2 p-1.5 rounded-lg hover:bg-white/10 transition-colors"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <Copy size={14} />
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        <AnimatePresence>
          {sourceViewer && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
              onClick={(e) => { if (e.target === e.currentTarget) setSourceViewer(null); }}
            >
              <motion.div
                initial={{ scale: 0.96, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.96, opacity: 0 }}
                className="w-full max-w-6xl rounded-xl border overflow-hidden"
                style={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-subtle)" }}
              >
                <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>
                      {sourceViewer.file_path}
                    </p>
                    <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                      {sourceViewer.repo_owner}/{sourceViewer.repo_name} | {sourceViewer.branch}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {sourceViewer.html_url && (
                      <a
                        href={sourceViewer.html_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border hover:bg-white/5"
                        style={{ color: "var(--text-primary)", borderColor: "var(--border-subtle)" }}
                      >
                        <ExternalLink size={12} /> Open in GitHub
                      </a>
                    )}
                    <button onClick={() => setSourceViewer(null)} className="p-1 rounded hover:bg-white/10" style={{ color: "var(--text-secondary)" }}>
                      <X size={18} />
                    </button>
                  </div>
                </div>
                <div className="max-h-[75vh] overflow-auto" style={{ backgroundColor: "var(--bg-primary)" }}>
                  <div className="min-w-[720px] font-mono text-xs">
                    {(sourceViewer.content || "").split("\n").map((line: string, idx: number) => {
                      const lineNo = idx + 1;
                      const start = sourceViewer.line_start || 0;
                      const end = sourceViewer.line_end || sourceViewer.line_start || 0;
                      const highlighted = start > 0 && lineNo >= start && lineNo <= end;
                      return (
                        <div
                          key={`${lineNo}-${line}`}
                          className="grid grid-cols-[72px_1fr]"
                          style={{
                            backgroundColor: highlighted ? "rgba(234,88,12,0.12)" : undefined,
                            borderLeft: highlighted ? "3px solid #f97316" : "3px solid transparent",
                          }}
                        >
                          <div
                            className="px-3 py-1.5 text-right select-none"
                            style={{ color: highlighted ? "#fdba74" : "var(--text-secondary)", borderRight: "1px solid var(--border-subtle)" }}
                          >
                            {lineNo}
                          </div>
                          <pre className="px-3 py-1.5 whitespace-pre-wrap break-words" style={{ color: "var(--text-primary)" }}>
                            {line || " "}
                          </pre>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
