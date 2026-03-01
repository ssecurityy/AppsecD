"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import toast from "react-hot-toast";
import { 
  Shield, Play, CheckCircle, XCircle, AlertTriangle, Loader2, 
  ArrowLeft, RefreshCw, ChevronDown, ChevronUp, Globe, Lock,
  Cookie, Server, FileText, Folder, ExternalLink, Zap, Clock,
  Code, Database, BookOpen, Layers, Wrench, HardDrive, FormInput
} from "lucide-react";
import Link from "next/link";

const CHECK_ICONS: Record<string, any> = {
  security_headers: Shield, ssl_tls: Lock, cookie_security: Cookie,
  cors: Globe, info_disclosure: Server, http_methods: Zap,
  robots_txt: FileText, directory_listing: Folder, open_redirect: ExternalLink,
  rate_limiting: Clock, xss_basic: Code, sqli_error: Database,
  api_docs_exposure: BookOpen, host_header_injection: Layers, crlf_injection: Wrench,
  sensitive_data: HardDrive, sri: Shield, cache_control: Clock,
  form_autocomplete: FormInput, backup_files: FileText, directory_discovery: Folder, dir: Folder,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#16a34a", info: "#3b82f6",
};

export default function DastScanPage() {
  const { id } = useParams();
  const router = useRouter();
  const { user, hydrate } = useAuthStore();
  const [project, setProject] = useState<any>(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [availableChecks, setAvailableChecks] = useState<any[]>([]);
  const [selectedChecks, setSelectedChecks] = useState<string[]>([]);
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set());

  useEffect(() => { hydrate(); }, [hydrate]);

  useEffect(() => {
    if (id) {
      api.getProject(id as string).then(setProject).catch(() => toast.error("Failed to load project"));
      api.dastChecks().then((r: any) => {
        setAvailableChecks(r.checks || []);
        setSelectedChecks((r.checks || []).map((c: any) => c.id));
      }).catch(() => {});
      try {
        const saved = localStorage.getItem(`dast_result_${id}`);
        if (saved) setScanResult(JSON.parse(saved));
      } catch {}
    }
  }, [id]);

  const handleScan = async () => {
    if (!project) return;
    setScanning(true);
    setScanResult(null);
    try {
      const result = await api.dastScan({
        project_id: id as string,
        checks: selectedChecks.length < availableChecks.length ? selectedChecks : undefined,
      });
      setScanResult(result);
      try { localStorage.setItem(`dast_result_${id}`, JSON.stringify(result)); } catch {}
      if (result.findings_created > 0) {
        toast.success(`Scan complete! ${result.findings_created} finding(s) auto-created.`);
      } else if (result.failed === 0) {
        toast.success("All checks passed!");
      } else {
        toast(`Scan complete: ${result.failed} issue(s) found`, { icon: "⚠️" });
      }
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
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

        {/* Results */}
        {scanResult && (
          <div className="space-y-4">
            {/* Summary */}
            <div className="rounded-xl p-4" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              <div className="flex items-center justify-between mb-2">
                <h2 className="font-semibold" style={{ color: "var(--text-primary)" }}>Scan Results</h2>
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
                    <div className="px-4 pb-4 space-y-2 text-sm" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                      {check.evidence && (
                        <div><strong style={{ color: "var(--text-primary)" }}>Evidence:</strong><pre className="mt-1 p-2 rounded text-xs overflow-x-auto" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>{check.evidence}</pre></div>
                      )}
                      {check.request_raw && (
                        <div>
                          <strong style={{ color: "var(--text-primary)" }}>Request:</strong>
                          <pre className="mt-1 p-2 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all font-mono" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", borderLeft: check.status === "failed" ? "3px solid #dc2626" : undefined }}>{check.request_raw}</pre>
                        </div>
                      )}
                      {check.response_raw && (
                        <div>
                          <strong style={{ color: "var(--text-primary)" }}>Response:</strong>
                          <pre className="mt-1 p-2 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all font-mono max-h-48 overflow-y-auto" style={{ background: check.status === "failed" ? "rgba(220, 38, 38, 0.08)" : "var(--bg-elevated)", color: "var(--text-secondary)", borderLeft: check.status === "failed" ? "3px solid #dc2626" : undefined }}>{check.response_raw}</pre>
                          {check.status === "failed" && (
                            <span className="text-xs font-medium mt-1 inline-block" style={{ color: "#dc2626" }}>Anomaly detected — review response above</span>
                          )}
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
