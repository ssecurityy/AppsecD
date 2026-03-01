"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import Link from "next/link";
import {
  ArrowLeft, Shield, ShieldCheck, ShieldAlert, ShieldX, Clock, AlertTriangle,
  ChevronDown, ChevronUp, FileDown, Filter, RefreshCw, CheckCircle2, XCircle,
  Calendar, User, MessageSquare, History, ExternalLink, Square, CheckSquare, Loader2,
} from "lucide-react";

const RECHECK_STATUSES = [
  { value: "pending", label: "Pending", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20", icon: Clock },
  { value: "resolved", label: "Resolved", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", icon: CheckCircle2 },
  { value: "not_fixed", label: "Not Fixed", color: "text-red-400 bg-red-500/10 border-red-500/20", icon: XCircle },
  { value: "partially_fixed", label: "Partially Fixed", color: "text-orange-400 bg-orange-500/10 border-orange-500/20", icon: ShieldAlert },
  { value: "exception", label: "Exception", color: "text-purple-400 bg-purple-500/10 border-purple-500/20", icon: Shield },
  { value: "deferred", label: "Deferred", color: "text-slate-400 bg-slate-500/10 border-slate-500/20", icon: Calendar },
  { value: "retest_needed", label: "Retest Needed", color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20", icon: RefreshCw },
];

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_BADGE: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

function getRecheckConfig(status: string) {
  return RECHECK_STATUSES.find(s => s.value === status) || RECHECK_STATUSES[0];
}

function FindingCard({ finding, onUpdate, selectable, selected, onToggleSelect }: { finding: any; onUpdate: () => void; selectable?: boolean; selected?: boolean; onToggleSelect?: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [recheckNotes, setRecheckNotes] = useState("");
  const [newStatus, setNewStatus] = useState(finding.recheck_status || "pending");
  const [showHistory, setShowHistory] = useState(false);

  const rc = getRecheckConfig(finding.recheck_status || "pending");
  const RcIcon = rc.icon;

  const handleRecheck = async () => {
    if (!newStatus) return;
    setUpdating(true);
    try {
      await api.updateRecheckStatus(finding.id, {
        recheck_status: newStatus,
        recheck_notes: recheckNotes,
      });
      toast.success(`Status updated to ${newStatus.replace(/_/g, " ")}`);
      setRecheckNotes("");
      onUpdate();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Update failed");
    } finally {
      setUpdating(false);
    }
  };

  const history = finding.recheck_history || [];

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="border rounded-xl overflow-hidden transition-all"
      style={{ background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)" }}
    >
      {/* Header row */}
      <div
        className="p-4 cursor-pointer flex items-start gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        {selectable && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggleSelect?.(finding.id);
            }}
            className="mt-0.5 shrink-0"
          >
            {selected ? (
              <CheckSquare className="w-5 h-5 text-indigo-400" />
            ) : (
              <Square className="w-5 h-5" style={{ color: "var(--text-muted)" }} />
            )}
          </button>
        )}
        <div className={`mt-0.5 p-1.5 rounded-lg border ${rc.color}`}>
          <RcIcon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{finding.title}</span>
            <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${SEVERITY_BADGE[finding.severity] || SEVERITY_BADGE.info}`}>
              {finding.severity}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${rc.color}`}>
              {rc.label}
            </span>
            {finding.jira_key && (
              <a
                href={finding.jira_url || "#"}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="text-xs px-2 py-0.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 font-medium hover:bg-blue-500/20 transition-colors flex items-center gap-1"
              >
                <ExternalLink className="w-2.5 h-2.5" />
                {finding.jira_key}
              </a>
            )}
            {finding.jira_status && (
              <span className="text-[10px] px-1.5 py-0.5 rounded border border-blue-500/20 bg-blue-500/5 text-blue-300 font-medium">
                {finding.jira_status}
              </span>
            )}
            {finding.recheck_count > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded border" style={{ color: "var(--text-muted)", background: "var(--bg-elevated)", borderColor: "var(--border-subtle)" }}>
                {finding.recheck_count}x rechecked
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-1 text-xs" style={{ color: "var(--text-muted)" }}>
            {finding.affected_url && <span className="truncate max-w-[200px]" title={finding.affected_url}>{finding.affected_url}</span>}
            {finding.owasp_category && <span>{finding.owasp_category}</span>}
            {finding.cwe_id && <span>CWE-{finding.cwe_id}</span>}
            {finding.cvss_score && <span>CVSS: {finding.cvss_score}</span>}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {finding.remediation_deadline && (
            <span className="text-xs flex items-center gap-1" style={{ color: "var(--text-muted)" }}>
              <Calendar className="w-3 h-3" />
              {new Date(finding.remediation_deadline).toLocaleDateString()}
            </span>
          )}
          <div style={{ color: "var(--text-muted)" }}>
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </div>
      </div>

      {/* Expanded content */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: "auto" }}
            exit={{ height: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 pt-4 space-y-4" style={{ borderTop: "1px solid var(--border-subtle)" }}>
              {/* Finding details */}
              <div className="grid md:grid-cols-2 gap-4">
                {finding.description && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: "var(--text-secondary)" }}>Description</h4>
                    <p className="text-xs p-3 rounded-lg break-words" style={{ color: "var(--text-secondary)", background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>{finding.description}</p>
                  </div>
                )}
                {finding.impact && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: "var(--text-secondary)" }}>Impact</h4>
                    <p className="text-xs p-3 rounded-lg break-words" style={{ color: "var(--text-secondary)", background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>{finding.impact}</p>
                  </div>
                )}
                {finding.reproduction_steps && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: "var(--text-secondary)" }}>Reproduction Steps</h4>
                    <pre className="text-xs p-3 rounded-lg whitespace-pre-wrap break-words font-mono" style={{ color: "var(--text-secondary)", background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>{finding.reproduction_steps}</pre>
                  </div>
                )}
                {finding.recommendation && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: "var(--text-secondary)" }}>Recommendation</h4>
                    <p className="text-xs p-3 rounded-lg break-words" style={{ color: "var(--text-secondary)", background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>{finding.recommendation}</p>
                  </div>
                )}
              </div>

              {/* Previous recheck notes */}
              {finding.recheck_notes && (
                <div className="rounded-lg p-3" style={{ background: "var(--bg-elevated)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                  <div className="flex items-center gap-2 mb-1">
                    <MessageSquare className="w-3 h-3 text-indigo-400" />
                    <span className="text-xs font-semibold text-indigo-400">Last Recheck Notes</span>
                  </div>
                  <p className="text-xs break-words" style={{ color: "var(--text-secondary)" }}>{finding.recheck_notes}</p>
                  {finding.recheck_date && (
                    <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
                      {new Date(finding.recheck_date).toLocaleString()}
                    </p>
                  )}
                </div>
              )}

              {/* Recheck action panel */}
              <div className="bg-gradient-to-r from-indigo-500/5 to-purple-500/5 rounded-xl p-4 border border-indigo-500/10">
                <h4 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                  <RefreshCw className="w-4 h-4 text-indigo-400" />
                  Update Recheck Status
                </h4>
                <div className="flex flex-wrap gap-2 mb-3">
                  {RECHECK_STATUSES.map(s => {
                    const SIcon = s.icon;
                    return (
                      <button
                        key={s.value}
                        onClick={() => setNewStatus(s.value)}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                          newStatus === s.value
                            ? s.color + " ring-1 ring-current"
                            : ""
                        }`}
                        style={newStatus !== s.value ? { color: "var(--text-muted)", background: "var(--bg-elevated)", borderColor: "var(--border-subtle)" } : undefined}
                      >
                        <SIcon className="w-3 h-3" />
                        {s.label}
                      </button>
                    );
                  })}
                </div>
                <textarea
                  className="input-field text-xs h-16 resize-none mb-3"
                  placeholder="Add recheck notes (evidence found, remediation verified, etc.)..."
                  value={recheckNotes}
                  onChange={e => setRecheckNotes(e.target.value)}
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleRecheck}
                    disabled={updating || newStatus === finding.recheck_status}
                    className="btn-primary text-xs disabled:opacity-50 flex items-center gap-1.5"
                  >
                    {updating ? (
                      <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    ) : (
                      <CheckCircle2 className="w-3 h-3" />
                    )}
                    Update Status
                  </button>
                  <button
                    onClick={async () => {
                      try {
                        const res = await api.createJiraIssue(finding.id);
                        toast.success(`Created ${res.jira_key}`);
                        if (res.jira_url) window.open(res.jira_url, "_blank");
                      } catch (err: unknown) {
                        toast.error(err instanceof Error ? err.message : "JIRA not configured");
                      }
                    }}
                    className="btn-secondary text-xs flex items-center gap-1.5"
                  >
                    <ExternalLink className="w-3 h-3" />
                    Create JIRA
                  </button>
                </div>
              </div>

              {/* Recheck history */}
              {history.length > 0 && (
                <div>
                  <button
                    onClick={() => setShowHistory(!showHistory)}
                    className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 mb-2"
                  >
                    <History className="w-3 h-3" />
                    {showHistory ? "Hide" : "Show"} Recheck History ({history.length})
                  </button>
                  <AnimatePresence>
                    {showHistory && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                      >
                        <div className="relative pl-4 space-y-3" style={{ borderLeft: "2px solid var(--border-subtle)" }}>
                          {history.slice().reverse().map((h: any, i: number) => {
                            const fromConf = getRecheckConfig(h.old_status);
                            const toConf = getRecheckConfig(h.new_status);
                            return (
                              <div key={i} className="relative">
                                <div className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full border-2 border-indigo-500" style={{ background: "var(--bg-elevated)" }} />
                                <div className="rounded-lg p-3" style={{ background: "var(--bg-elevated)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                                  <div className="flex items-center gap-2 text-xs mb-1">
                                    <span className={`px-1.5 py-0.5 rounded border ${fromConf.color}`}>{fromConf.label}</span>
                                    <span style={{ color: "var(--text-muted)" }}>&rarr;</span>
                                    <span className={`px-1.5 py-0.5 rounded border ${toConf.color}`}>{toConf.label}</span>
                                    <span className="ml-auto" style={{ color: "var(--text-muted)" }}>{new Date(h.date).toLocaleString()}</span>
                                  </div>
                                  {h.notes && <p className="text-xs mt-1 break-words" style={{ color: "var(--text-secondary)" }}>{h.notes}</p>}
                                  {h.by_name && (
                                    <p className="text-[10px] mt-1 flex items-center gap-1" style={{ color: "var(--text-muted)" }}>
                                      <User className="w-2.5 h-2.5" /> {h.by_name}
                                    </p>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function VulnerabilityManagement() {
  const { id } = useParams() as { id: string };
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [project, setProject] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>("");
  const [filterStatus, setFilterStatus] = useState<string>("");
  const [showFilters, setShowFilters] = useState(false);
  const [bulkMode, setBulkMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkCreating, setBulkCreating] = useState(false);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (!user && !loading) router.replace("/login"); }, [user, router, loading]);

  const loadData = async () => {
    try {
      const [proj, findingsRes, summ] = await Promise.all([
        api.getProject(id),
        api.getFindings(id),
        api.getVulnSummary(id),
      ]);
      setProject(proj);
      setFindings(findingsRes?.items ?? (Array.isArray(findingsRes) ? findingsRes : []));
      setSummary(summ);
    } catch {
      toast.error("Failed to load vulnerability data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, [id]);

  const filteredFindings = findings.filter(f => {
    if (filterSeverity && f.severity !== filterSeverity) return false;
    if (filterStatus && (f.recheck_status || "pending") !== filterStatus) return false;
    return true;
  }).sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity);
    const bi = SEVERITY_ORDER.indexOf(b.severity);
    return ai - bi;
  });

  if (loading) return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="flex items-center justify-center py-32" style={{ color: "var(--text-secondary)" }}>Loading vulnerability data...</div>
    </div>
  );

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />

      <div className="max-w-6xl mx-auto p-4 md:p-6">
        {/* Breadcrumb */}
        <div className="flex items-center gap-2 text-sm mb-6" style={{ color: "var(--text-muted)" }}>
          <Link href="/projects" className="hover:text-white transition-colors">Projects</Link>
          <span>/</span>
          <Link href={`/projects/${id}`} className="hover:text-white transition-colors">{project?.application_name || "Project"}</Link>
          <span>/</span>
          <span style={{ color: "var(--text-primary)" }}>Vulnerability Management</span>
        </div>

        {/* Page header */}
        <div className="flex items-start justify-between gap-4 mb-6 flex-wrap">
          <div className="min-w-0">
            <h1 className="text-2xl font-bold flex items-center gap-3" style={{ color: "var(--text-primary)" }}>
              <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/20 shrink-0">
                <ShieldCheck className="w-6 h-6 text-indigo-400" />
              </div>
              Vulnerability Management
            </h1>
            <p className="text-sm mt-1 truncate" style={{ color: "var(--text-muted)" }}>{project?.application_name} &mdash; Track, recheck, and resolve security findings</p>
          </div>
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            <Link
              href={`/projects/${id}`}
              className="btn-secondary text-xs flex items-center gap-1.5"
            >
              <ArrowLeft className="w-3 h-3" /> Back to Testing
            </Link>
            <button
              onClick={() => {
                setBulkMode(!bulkMode);
                if (bulkMode) setSelectedIds(new Set());
              }}
              className={`text-xs flex items-center gap-1.5 px-3 py-1.5 rounded border transition-colors ${
                bulkMode
                  ? "border-blue-500/50 text-blue-400 bg-blue-500/10"
                  : "border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
              }`}
            >
              <ExternalLink className="w-3 h-3" /> {bulkMode ? "Cancel Bulk" : "Bulk JIRA"}
            </button>
            {bulkMode && selectedIds.size > 0 && (
              <button
                onClick={async () => {
                  setBulkCreating(true);
                  try {
                    const res = await api.bulkCreateJira({ finding_ids: Array.from(selectedIds) });
                    toast.success(`Created ${res.created || selectedIds.size} JIRA tickets`);
                    setBulkMode(false);
                    setSelectedIds(new Set());
                    loadData();
                  } catch (err: unknown) {
                    toast.error(err instanceof Error ? err.message : "Bulk JIRA creation failed");
                  } finally {
                    setBulkCreating(false);
                  }
                }}
                disabled={bulkCreating}
                className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50"
              >
                {bulkCreating ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <ExternalLink className="w-3 h-3" />
                )}
                Create {selectedIds.size} JIRA Ticket{selectedIds.size !== 1 ? "s" : ""}
              </button>
            )}
            <button
              onClick={async () => {
                try {
                  await api.downloadReport(id, "pdf", `AppSecD_VulnReport_${project?.application_name?.replace(/\s/g, "_")}.pdf`);
                  toast.success("Report downloaded");
                } catch (e: unknown) {
                  toast.error(e instanceof Error ? e.message : "Download failed");
                }
              }}
              className="btn-primary text-xs flex items-center gap-1.5"
            >
              <FileDown className="w-3 h-3" /> Download Report
            </button>
          </div>
        </div>

        {/* Summary cards */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
            {[
              { label: "Total", value: summary.total, color: "text-white", bg: "from-slate-500/10 to-slate-500/5" },
              { label: "Pending", value: summary.pending, color: "text-yellow-400", bg: "from-yellow-500/10 to-yellow-500/5" },
              { label: "Resolved", value: summary.resolved, color: "text-emerald-400", bg: "from-emerald-500/10 to-emerald-500/5" },
              { label: "Not Fixed", value: summary.not_fixed, color: "text-red-400", bg: "from-red-500/10 to-red-500/5" },
              { label: "Partial", value: summary.partially_fixed, color: "text-orange-400", bg: "from-orange-500/10 to-orange-500/5" },
              { label: "Exception", value: summary.exception, color: "text-purple-400", bg: "from-purple-500/10 to-purple-500/5" },
              { label: "Deferred", value: summary.deferred, color: "text-slate-400", bg: "from-slate-500/10 to-slate-500/5" },
            ].map(s => (
              <motion.div
                key={s.label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className={`bg-gradient-to-br ${s.bg} rounded-xl p-3 border text-center`}
                style={{ borderColor: "var(--border-subtle)" }}
              >
                <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-[10px] uppercase tracking-wider mt-0.5" style={{ color: "var(--text-muted)" }}>{s.label}</div>
              </motion.div>
            ))}
          </div>
        )}

        {/* Resolution rate bar */}
        {summary && summary.total > 0 && (
          <div className="card p-4 mb-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Resolution Progress</span>
              <span className="text-sm font-bold text-emerald-400">{summary.resolution_rate}%</span>
            </div>
            <div className="h-3 rounded-full overflow-hidden flex" style={{ background: "var(--bg-elevated)" }}>
              {summary.resolved > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(summary.resolved / summary.total) * 100}%` }}
                  transition={{ duration: 0.8, ease: "easeOut" }}
                  className="h-full bg-emerald-500 rounded-l-full"
                  title={`Resolved: ${summary.resolved}`}
                />
              )}
              {summary.partially_fixed > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(summary.partially_fixed / summary.total) * 100}%` }}
                  transition={{ duration: 0.8, delay: 0.1, ease: "easeOut" }}
                  className="h-full bg-orange-500"
                  title={`Partially fixed: ${summary.partially_fixed}`}
                />
              )}
              {summary.exception > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(summary.exception / summary.total) * 100}%` }}
                  transition={{ duration: 0.8, delay: 0.2, ease: "easeOut" }}
                  className="h-full bg-purple-500"
                  title={`Exception: ${summary.exception}`}
                />
              )}
              {summary.not_fixed > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(summary.not_fixed / summary.total) * 100}%` }}
                  transition={{ duration: 0.8, delay: 0.3, ease: "easeOut" }}
                  className="h-full bg-red-500"
                  title={`Not fixed: ${summary.not_fixed}`}
                />
              )}
            </div>
            <div className="flex items-center gap-4 mt-2 text-[10px]" style={{ color: "var(--text-muted)" }}>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" /> Resolved</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> Partial</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-purple-500" /> Exception</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Not Fixed</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full" style={{ background: "var(--bg-elevated)" }} /> Pending</span>
            </div>
          </div>
        )}

        {/* Severity breakdown */}
        {summary && summary.by_severity && Object.keys(summary.by_severity).length > 0 && (
          <div className="card p-4 mb-6">
            <h3 className="text-sm font-semibold mb-3" style={{ color: "var(--text-primary)" }}>Severity Distribution</h3>
            <div className="flex items-end gap-2 h-24">
              {SEVERITY_ORDER.map(sev => {
                const count = summary.by_severity[sev] || 0;
                const maxCount = Math.max(...Object.values(summary.by_severity as Record<string, number>), 1);
                const heightPct = (count / maxCount) * 100;
                const colors: Record<string, string> = {
                  critical: "bg-red-500",
                  high: "bg-orange-500",
                  medium: "bg-yellow-500",
                  low: "bg-emerald-500",
                  info: "bg-sky-500",
                };
                return (
                  <div key={sev} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs font-bold" style={{ color: "var(--text-primary)" }}>{count}</span>
                    <motion.div
                      initial={{ height: 0 }}
                      animate={{ height: `${Math.max(heightPct, 4)}%` }}
                      transition={{ duration: 0.6, ease: "easeOut" }}
                      className={`w-full rounded-t-lg ${colors[sev]} min-h-[4px]`}
                    />
                    <span className="text-[10px] capitalize" style={{ color: "var(--text-muted)" }}>{sev}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="flex items-center justify-between gap-3 mb-4">
          <h2 className="text-lg font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <AlertTriangle className="w-5 h-5 text-indigo-400" />
            Findings ({filteredFindings.length})
          </h2>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`btn-secondary text-xs flex items-center gap-1.5 ${showFilters ? "border-indigo-500/50" : ""}`}
          >
            <Filter className="w-3 h-3" /> Filters
          </button>
        </div>

        <AnimatePresence>
          {showFilters && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden mb-4"
            >
              <div className="card p-4 flex flex-wrap gap-4">
                <div>
                  <label className="text-xs mb-1 block" style={{ color: "var(--text-muted)" }}>Severity</label>
                  <select
                    className="input-field text-xs w-36"
                    value={filterSeverity}
                    onChange={e => setFilterSeverity(e.target.value)}
                  >
                    <option value="">All Severities</option>
                    {SEVERITY_ORDER.map(s => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: "var(--text-muted)" }}>Recheck Status</label>
                  <select
                    className="input-field text-xs w-44"
                    value={filterStatus}
                    onChange={e => setFilterStatus(e.target.value)}
                  >
                    <option value="">All Statuses</option>
                    {RECHECK_STATUSES.map(s => (
                      <option key={s.value} value={s.value}>{s.label}</option>
                    ))}
                  </select>
                </div>
                {(filterSeverity || filterStatus) && (
                  <button
                    onClick={() => { setFilterSeverity(""); setFilterStatus(""); }}
                    className="self-end text-xs text-indigo-400 hover:text-indigo-300 pb-2"
                  >
                    Clear filters
                  </button>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Findings list */}
        <div className="space-y-3">
          {filteredFindings.length === 0 ? (
            <div className="card p-12 text-center">
              <ShieldX className="w-12 h-12 mx-auto mb-3" style={{ color: "var(--border-subtle)" }} />
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                {findings.length === 0
                  ? "No vulnerabilities found yet. Start testing to identify findings."
                  : "No findings match the current filters."}
              </p>
            </div>
          ) : (
            filteredFindings.map((f, i) => (
              <motion.div
                key={f.id}
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.03, duration: 0.3 }}
              >
                <FindingCard
                  finding={f}
                  onUpdate={loadData}
                  selectable={bulkMode}
                  selected={selectedIds.has(f.id)}
                  onToggleSelect={(id) => {
                    const next = new Set(selectedIds);
                    if (next.has(id)) next.delete(id);
                    else next.add(id);
                    setSelectedIds(next);
                  }}
                />
              </motion.div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
