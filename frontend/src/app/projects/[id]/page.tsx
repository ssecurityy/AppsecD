"use client";
import { useEffect, useState, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import Navbar from "@/components/Navbar";
import { api, getApiBase } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import {
  CheckCircle, XCircle, Circle, MinusCircle, ChevronDown, ChevronUp,
  Terminal, BookOpen, AlertTriangle, Zap, Target, Flag, Users, X, FileDown, FileText, Upload
} from "lucide-react";
import Link from "next/link";

const PHASE_INFO: Record<string, { label: string; color: string }> = {
  recon: { label: "Recon", color: "blue" },
  pre_auth: { label: "Pre-Auth", color: "yellow" },
  auth: { label: "Auth", color: "orange" },
  post_auth: { label: "Post-Auth", color: "purple" },
  business: { label: "Business", color: "pink" },
  api: { label: "API", color: "cyan" },
  client: { label: "Client", color: "indigo" },
  transport: { label: "Transport", color: "teal" },
  infra: { label: "Infra", color: "gray" },
  tools: { label: "Tools", color: "green" },
};

const STATUS_CONFIG = {
  passed: { icon: CheckCircle, color: "text-green-400", bg: "bg-green-900/20 border-green-800" },
  failed: { icon: XCircle, color: "text-red-400", bg: "bg-red-900/20 border-red-800" },
  not_started: { icon: Circle, color: "text-[#6B7280]", bg: "bg-[#1F2937] border-[#374151]" },
  in_progress: { icon: Target, color: "text-blue-400", bg: "bg-blue-900/20 border-blue-800" },
  na: { icon: MinusCircle, color: "text-[#9CA3AF]", bg: "bg-[#111827] border-[#1F2937]" },
  blocked: { icon: Flag, color: "text-orange-400", bg: "bg-orange-900/20 border-orange-800" },
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-700",
  high: "bg-orange-900/40 text-orange-300 border-orange-700",
  medium: "bg-yellow-900/40 text-yellow-300 border-yellow-700",
  low: "bg-green-900/40 text-green-300 border-green-700",
  info: "bg-blue-900/40 text-blue-300 border-blue-700",
};

const replaceTarget = (text: string, url: string) => {
  if (!url) return text;
  const clean = url.replace(/\/$/, "");
  return String(text).replace(/\bTARGET\b/gi, clean);
};

const IMAGE_EXTS = [".png", ".jpg", ".jpeg", ".gif", ".webp"];
function EvidenceItem({ e, onRemove, getApiBase }: { e: { filename: string; url: string }; onRemove: () => void; getApiBase: () => string }) {
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const blobRef = useRef<string | null>(null);
  const isImage = IMAGE_EXTS.some(ext => e.filename.toLowerCase().endsWith(ext) || e.url.toLowerCase().includes(ext));
  useEffect(() => {
    if (!isImage) return;
    api.getEvidenceBlobUrl(e.url).then((url) => { blobRef.current = url; setPreviewUrl(url); }).catch(() => {});
    return () => { if (blobRef.current) { URL.revokeObjectURL(blobRef.current); blobRef.current = null; } };
  }, [e.url, isImage]);
  return (
    <div className="flex items-center gap-2 bg-[#0D1424] rounded px-2 py-1 border border-[#1F2937] text-xs">
      {previewUrl && (
        <a href={previewUrl} target="_blank" rel="noopener noreferrer" className="shrink-0">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={previewUrl} alt={e.filename} className="w-10 h-10 object-cover rounded border border-[#374151]" />
        </a>
      )}
      <a href={isImage && previewUrl ? previewUrl : `${getApiBase()}${e.url}`} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline truncate max-w-[120px]">{e.filename}</a>
      <button onClick={onRemove} className="text-red-400 hover:text-red-300 shrink-0">×</button>
    </div>
  );
}

function TestCaseCard({ tc, projectId, applicationUrl, onUpdate }: { tc: any; projectId: string; applicationUrl: string; onUpdate: () => void }) {
  const { setUser } = useAuthStore();
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [notes, setNotes] = useState(tc.notes || "");
  const [payloadUsed, setPayloadUsed] = useState(tc.payload_used || "");
  const [evidence, setEvidence] = useState<{ filename: string; url: string; description?: string }[]>(tc.evidence || []);
  const [uploadingEvidence, setUploadingEvidence] = useState(false);
  const [showFindingForm, setShowFindingForm] = useState(false);
  const [aiSuggesting, setAiSuggesting] = useState(false);
  const [finding, setFinding] = useState({
    title: tc.title,
    severity: tc.severity,
    affected_url: applicationUrl || "",
    description: "",
    reproduction_steps: "",
    impact: "",
    recommendation: tc.remediation || "",
    cwe_id: "",
    cvss_score: "",
  });

  const statusConf = STATUS_CONFIG[tc.result_status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.not_started;
  const StatusIcon = statusConf.icon;

  const updateStatus = async (status: string) => {
    setUpdating(true);
    try {
      const res = await api.updateResult(tc.result_id, { status, notes, payload_used: payloadUsed, evidence });
      if (res.phase_completed) {
        toast.success(
          `Zone complete — +100 XP. You've mastered ${res.phase_completed.replace(/_/g, " ")}.`,
          { duration: 5000 }
        );
      } else if (res.xp_earned > 0) {
        toast.success(
          status === "passed"
            ? `Well done — +${res.xp_earned} XP`
            : `Finding documented — +${res.xp_earned} XP earned`,
          { duration: 4000 }
        );
      }
      onUpdate();
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setUpdating(false);
    }
  };

  const submitFinding = async () => {
    try {
      const res = await api.createFinding({
        ...finding,
        project_id: projectId,
        test_result_id: tc.result_id,
      });
      if (res.badges_earned?.length) {
        toast.success(`New badge${res.badges_earned.length > 1 ? "s" : ""}: ${res.badges_earned.map((b: string) => b.replace(/_/g, " ")).join(", ")}`, { duration: 5000 });
        api.me().then((u) => setUser(u)).catch(() => {});
      } else {
        toast.success("Finding documented");
      }
      setShowFindingForm(false);
      updateStatus("failed");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to save finding");
    }
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`border rounded-lg overflow-hidden transition-all ${statusConf.bg}`}
    >
      <div className="p-4 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-start gap-3">
          <StatusIcon className={`w-5 h-5 mt-0.5 shrink-0 ${statusConf.color}`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-white">{tc.title}</span>
              <span className={`text-xs px-1.5 py-0.5 rounded border ${SEVERITY_BADGE[tc.severity] || SEVERITY_BADGE.info}`}>
                {tc.severity}
              </span>
              {tc.owasp_ref && (
                <span className="text-xs text-[#9CA3AF] bg-[#0D1424] px-1.5 py-0.5 rounded border border-[#1F2937]">
                  {tc.owasp_ref}
                </span>
              )}
              {tc.module_id && <span className="text-xs text-[#6B7280]">{tc.module_id}</span>}
            </div>
            {tc.description && (
              <p className="text-xs text-[#9CA3AF] mt-1 line-clamp-1">{tc.description}</p>
            )}
          </div>
          <div className="flex items-center gap-1 shrink-0">
            {!updating ? (
              <>
                <button onClick={e => { e.stopPropagation(); updateStatus("passed"); }}
                  title="Mark Passed"
                  className="p-1.5 rounded bg-green-900/30 hover:bg-green-900/60 text-green-400 transition-colors">
                  <CheckCircle className="w-4 h-4" />
                </button>
                <button onClick={e => { e.stopPropagation(); setExpanded(true); setShowFindingForm(true); }}
                  title="Mark Failed + Add Finding"
                  className="p-1.5 rounded bg-red-900/30 hover:bg-red-900/60 text-red-400 transition-colors">
                  <XCircle className="w-4 h-4" />
                </button>
                <button onClick={e => { e.stopPropagation(); updateStatus("na"); }}
                  title="Not Applicable"
                  className="p-1.5 rounded bg-[#1F2937] hover:bg-[#374151] text-[#9CA3AF] transition-colors">
                  <MinusCircle className="w-3.5 h-3.5" />
                </button>
              </>
            ) : (
              <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
            )}
            <div className="ml-1 text-[#6B7280]">
              {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }}
            className="overflow-hidden">
            <div className="px-4 pb-4 border-t border-[#1F2937] pt-4 space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                {tc.where_to_test && (
                  <div>
                    <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-1">📍 Where to Test</h4>
                    <p className="text-xs text-[#D1D5DB] bg-[#0D1424] p-2 rounded">{tc.where_to_test}</p>
                  </div>
                )}
                {tc.what_to_test && (
                  <div>
                    <h4 className="text-xs font-semibold text-yellow-400 uppercase tracking-wider mb-1">🎯 What to Test</h4>
                    <p className="text-xs text-[#D1D5DB] bg-[#0D1424] p-2 rounded">{tc.what_to_test}</p>
                  </div>
                )}
              </div>

              {tc.how_to_test && (
                <div>
                  <h4 className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1">📋 How to Test</h4>
                  <pre className="text-xs text-[#D1D5DB] bg-[#0D1424] p-3 rounded font-mono whitespace-pre-wrap overflow-x-auto">{replaceTarget(tc.how_to_test, applicationUrl)}</pre>
                </div>
              )}

              {tc.payloads?.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2">💉 Payloads (TARGET → your URL)</h4>
                  <div className="space-y-1">
                    {tc.payloads.slice(0, 8).map((p: string, i: number) => {
                      const resolved = replaceTarget(p, applicationUrl);
                      return (
                        <div key={i} className="flex items-center gap-2">
                          <code className="text-xs text-[#A5F3FC] bg-[#0D1424] px-2 py-1 rounded font-mono flex-1 overflow-x-auto">{resolved}</code>
                          <button onClick={() => { navigator.clipboard.writeText(resolved); toast.success("Copied! Ready to paste."); }}
                            className="text-[#6B7280] hover:text-white text-xs px-2 py-1 bg-[#1F2937] rounded shrink-0">
                            Copy
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {tc.tool_commands?.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                    <Terminal className="w-3 h-3" /> Tool Commands (TARGET → your URL)
                  </h4>
                  <div className="space-y-2">
                    {tc.tool_commands.map((cmd: { tool?: string; command?: string; description?: string }, i: number) => {
                      const resolvedCmd = replaceTarget(cmd.command || "", applicationUrl);
                      return (
                        <div key={i} className="bg-[#0D1424] rounded p-2 border border-[#1F2937]">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-bold text-orange-400">{cmd.tool}</span>
                            <button onClick={() => { navigator.clipboard.writeText(resolvedCmd); toast.success("Command copied! Run in terminal."); }}
                              className="text-xs text-[#6B7280] hover:text-white bg-[#1F2937] px-2 py-0.5 rounded">
                              Copy
                            </button>
                          </div>
                          <code className="text-xs text-[#A5F3FC] font-mono block overflow-x-auto whitespace-pre">{resolvedCmd}</code>
                          {cmd.description && <p className="text-xs text-[#6B7280] mt-1">{cmd.description}</p>}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div className="grid md:grid-cols-2 gap-4">
                {tc.pass_indicators && (
                  <div>
                    <h4 className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1">✅ Pass Indicators</h4>
                    <p className="text-xs text-[#D1D5DB] bg-green-900/10 border border-green-900/30 p-2 rounded">{tc.pass_indicators}</p>
                  </div>
                )}
                {tc.fail_indicators && (
                  <div>
                    <h4 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-1">❌ Fail Indicators</h4>
                    <p className="text-xs text-[#D1D5DB] bg-red-900/10 border border-red-900/30 p-2 rounded">{tc.fail_indicators}</p>
                  </div>
                )}
              </div>

              {tc.remediation && (
                <div>
                  <h4 className="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-1">🔧 Remediation</h4>
                  <p className="text-xs text-[#D1D5DB] bg-purple-900/10 border border-purple-900/30 p-2 rounded">{tc.remediation}</p>
                </div>
              )}

              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-[#9CA3AF] uppercase tracking-wider">📎 Evidence</h4>
                <div className="flex flex-wrap gap-2">
                  {evidence.map((e, i) => (
                    <EvidenceItem
                      key={i}
                      e={e}
                      onRemove={async () => {
                        const next = evidence.filter((_, j) => j !== i);
                        setEvidence(next);
                        try {
                          await api.updateResult(tc.result_id, { evidence: next });
                          onUpdate();
                        } catch {}
                      }}
                      getApiBase={getApiBase}
                    />
                  ))}
                  <label className="cursor-pointer">
                    <input type="file" className="hidden" accept=".png,.jpg,.jpeg,.gif,.webp,.pdf,.txt,.json,.xml,.har"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        setUploadingEvidence(true);
                        try {
                          const r = await api.uploadEvidence(projectId, file);
                          setEvidence([...evidence, { filename: r.filename, url: r.url }]);
                          await api.updateResult(tc.result_id, { evidence: [...evidence, { filename: r.filename, url: r.url }] });
                          toast.success("Evidence uploaded");
                          onUpdate();
                        } catch (err: any) {
                          toast.error(err.message || "Upload failed");
                        } finally {
                          setUploadingEvidence(false);
                          e.target.value = "";
                        }
                      }}
                      disabled={uploadingEvidence} />
                    <span className={`inline-block px-3 py-1.5 rounded border text-xs ${uploadingEvidence ? "opacity-50 cursor-not-allowed" : "border-blue-600 text-blue-400 hover:bg-blue-900/20"}`}>
                      {uploadingEvidence ? "Uploading..." : "+ Add evidence"}
                    </span>
                  </label>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-[#9CA3AF] uppercase tracking-wider">📝 Tester Notes</h4>
                <textarea className="input-field text-xs h-16 resize-none" placeholder="Add notes about this test case..."
                  value={notes} onChange={e => setNotes(e.target.value)} />
              </div>

              {showFindingForm && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                  className="bg-red-900/10 border border-red-800 rounded-lg p-4 space-y-3">
                  <h4 className="text-red-400 font-semibold text-sm flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> Document Security Finding
                  </h4>
                  <input className="input-field text-sm" placeholder="Finding title" value={finding.title}
                    onChange={e => setFinding({ ...finding, title: e.target.value })} />
                  <div className="grid grid-cols-2 gap-2">
                    <select className="input-field text-sm" value={finding.severity}
                      onChange={e => setFinding({ ...finding, severity: e.target.value })}>
                      {["critical", "high", "medium", "low", "info"].map(s => (
                        <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                      ))}
                    </select>
                    <input className="input-field text-sm" placeholder="Affected URL"
                      value={finding.affected_url} onChange={e => setFinding({ ...finding, affected_url: e.target.value })} />
                  </div>
                  <textarea className="input-field text-sm h-16 resize-none" placeholder="Description & impact..."
                    value={finding.description} onChange={e => setFinding({ ...finding, description: e.target.value })} />
                  <textarea className="input-field text-sm h-16 resize-none" placeholder="Reproduction steps..."
                    value={finding.reproduction_steps} onChange={e => setFinding({ ...finding, reproduction_steps: e.target.value })} />
                  <button
                    type="button"
                    onClick={async () => {
                      setAiSuggesting(true);
                      try {
                        const s = await api.suggestFinding({ title: finding.title, description: finding.description, severity: finding.severity });
                        setFinding({ ...finding, severity: s.severity, impact: s.impact, recommendation: s.recommendation, cwe_id: s.cwe_id || finding.cwe_id, cvss_score: s.cvss_score || finding.cvss_score });
                        toast.success("AI suggestions applied");
                      } catch {
                        toast.error("AI suggest failed");
                      } finally {
                        setAiSuggesting(false);
                      }
                    }}
                    disabled={aiSuggesting || !finding.title}
                    className="text-xs px-3 py-1.5 rounded border border-cyan-600 text-cyan-400 hover:bg-cyan-900/20 disabled:opacity-50"
                  >
                    {aiSuggesting ? "..." : "✨ AI Suggest CWE/Remediation"}
                  </button>
                  <div className="flex gap-2">
                    <button onClick={submitFinding} className="btn-primary text-sm flex-1">Save Finding & Mark Failed</button>
                    <button onClick={() => setShowFindingForm(false)} className="btn-secondary text-sm px-3">Cancel</button>
                  </div>
                </motion.div>
              )}

              <div className="flex gap-2 flex-wrap">
                {tc.result_status !== "passed" && (
                  <button onClick={() => updateStatus("passed")} className="btn-primary text-xs flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" /> Mark Passed (+10 XP)
                  </button>
                )}
                {!showFindingForm && tc.result_status !== "failed" && (
                  <button onClick={() => setShowFindingForm(true)} className="bg-red-800 hover:bg-red-700 text-white text-xs px-3 py-1.5 rounded flex items-center gap-1">
                    <XCircle className="w-3 h-3" /> Mark Failed + Finding (+50 XP)
                  </button>
                )}
                {tc.result_status !== "na" && (
                  <button onClick={() => updateStatus("na")} className="btn-secondary text-xs flex items-center gap-1">
                    <MinusCircle className="w-3 h-3" /> Not Applicable
                  </button>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function ProjectDetail() {
  const { id } = useParams() as { id: string };
  const { hydrate, user, token } = useAuthStore();
  const router = useRouter();
  const [project, setProject] = useState<any>(null);
  const [progress, setProgress] = useState<any>(null);
  const [testCases, setTestCases] = useState<any[]>([]);
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showPassedNa, setShowPassedNa] = useState(false); // Hide passed/NA by default — psychology: focus on what's left
  const [showMembers, setShowMembers] = useState(false);
  const [members, setMembers] = useState<any[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [membersError, setMembersError] = useState<string | null>(null);
  const [addUser, setAddUser] = useState({ user_id: "", role: "tester" });
  const [users, setUsers] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [showFindings, setShowFindings] = useState(false);
  const [importing, setImporting] = useState(false);
  const [asyncReportTask, setAsyncReportTask] = useState<string | null>(null);
  const [asyncReportFormat, setAsyncReportFormat] = useState<string>("");
  const selectedPhaseRef = useRef<string | null>(null);
  selectedPhaseRef.current = selectedPhase;

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (!user && !loading) router.replace("/login"); }, [user, router, loading]);

  const loadData = async () => {
    try {
      const [proj, prog] = await Promise.all([api.getProject(id), api.getProjectProgress(id)]);
      setProject(proj);
      setProgress(prog);
      if (!selectedPhase && prog.phases?.length > 0) {
        setSelectedPhase(prog.phases[0].phase);
      }
    } catch {}
  };

  const loadFindings = async () => {
    try {
      const list = await api.getFindings(id);
      setFindings(list);
    } catch {}
  };

  const loadTestCases = async (phase: string) => {
    try {
      const tcs = await api.getProjectTestCases(id, phase);
      setTestCases(tcs);
    } catch {}
  };

  useEffect(() => {
    loadData().finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    if (selectedPhase) loadTestCases(selectedPhase);
  }, [selectedPhase, id]);

  // WebSocket for real-time updates
  useEffect(() => {
    if (!id || !token) return;
    const wsBase = getApiBase().replace(/^http/, 'ws');
    const ws = new WebSocket(`${wsBase}/ws/project/${id}?token=${token}`);

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "test_updated" || msg.type === "finding_created" || msg.type === "finding_updated" || msg.type === "progress_update") {
          loadData();
          loadFindings();
          if (selectedPhaseRef.current) loadTestCases(selectedPhaseRef.current);
        }
      } catch {}
    };

    ws.onclose = () => {};
    ws.onerror = () => {};

    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "ping" }));
      }
    }, 30000);

    return () => {
      clearInterval(pingInterval);
      ws.close();
    };
  }, [id, token]);

  const handleUpdate = async () => {
    await loadData();
    if (selectedPhase) await loadTestCases(selectedPhase);
  };

  const loadMembers = async () => {
    setMembersLoading(true);
    setMembersError(null);
    try {
      const [list, available] = await Promise.all([
        api.listProjectMembers(id),
        api.getAvailableUsersForProject(id),
      ]);
      setMembers(list);
      setUsers(available);
    } catch (e: any) {
      setMembersError(e.message);
      setMembers([]);
      setUsers([]);
    } finally {
      setMembersLoading(false);
    }
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!addUser.user_id) return;
    try {
      await api.addProjectMember(id, { user_id: addUser.user_id, role: addUser.role });
      toast.success("Member added");
      loadMembers();
      setAddUser({ user_id: "", role: "tester" });
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleRemoveMember = async (memberId: string) => {
    if (!confirm("Remove this member from the project?")) return;
    try {
      await api.removeProjectMember(id, memberId);
      toast.success("Member removed");
      loadMembers();
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const openMembersModal = () => {
    setShowMembers(true);
    loadMembers();
  };

  const openFindingsPanel = () => {
    setShowFindings(true);
    loadFindings();
  };

  const handleBurpImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImporting(true);
    try {
      const result = await api.importBurpXml(id as string, file);
      toast.success(`Imported ${result.imported} findings from Burp XML`);
      const f = await api.getFindings(id as string);
      setFindings(f);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Import failed");
    } finally {
      setImporting(false);
      e.target.value = "";
    }
  };

  const handleAsyncDownload = async (format: "docx" | "pdf") => {
    try {
      toast.loading(`Generating ${format.toUpperCase()} report...`, { id: "async-report" });
      const { task_id } = await api.startAsyncReport(id as string, format);
      setAsyncReportTask(task_id);
      setAsyncReportFormat(format);

      const poll = async () => {
        try {
          const result = await api.getAsyncReportStatus(id as string, task_id);
          if (result.status === "ready" && result.blob) {
            const url = URL.createObjectURL(result.blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `VAPT_Report.${format}`;
            a.click();
            URL.revokeObjectURL(url);
            toast.success(`${format.toUpperCase()} report downloaded!`, { id: "async-report" });
            setAsyncReportTask(null);
          } else {
            setTimeout(poll, 2000);
          }
        } catch {
          toast.error("Report generation failed", { id: "async-report" });
          setAsyncReportTask(null);
        }
      };
      setTimeout(poll, 2000);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to start report generation", { id: "async-report" });
    }
  };

  if (loading) return <div className="min-h-screen flex items-center justify-center text-[#9CA3AF]">Loading project...</div>;
  if (!project) return <div className="min-h-screen flex items-center justify-center text-[#9CA3AF]">Project not found</div>;

  const pct = progress?.completion_pct || 0;
  const applicable = progress?.total_applicable || 0;
  const tested = progress?.tested || 0;

  return (
    <div className="min-h-screen">
      <Navbar />

      {/* Global progress bar */}
      <div className="sticky top-14 z-40 bg-[#0A0F1E] border-b border-[#1F2937] px-4 py-2">
        <div className="max-w-6xl mx-auto flex items-center gap-3">
          <span className="text-xs text-[#9CA3AF] shrink-0">{pct}% Complete</span>
          <div className="flex-1 h-2 bg-[#1F2937] rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${pct}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
              className={`h-full rounded-full transition-all ${
                pct === 100 ? "bg-green-500" : pct > 75 ? "bg-blue-400" : pct > 50 ? "bg-blue-500" : "bg-blue-700"
              }`}
            />
          </div>
          <span className="text-xs text-[#9CA3AF] shrink-0">{tested}/{applicable} tested</span>
          {pct > 0 && (
            <motion.span
              animate={{ scale: [1, 1.08, 1] }}
              transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
              className="text-xs font-medium text-yellow-400"
            >
              {pct < 25 ? "🔥 Just started!" : pct < 50 ? "⚡ Building momentum!" : pct < 75 ? "🌟 Halfway there!" : pct < 100 ? "🔥 Almost done!" : "🏆 Mission Complete!"}
            </motion.span>
          )}
        </div>
      </div>

      <div className="max-w-6xl mx-auto p-4 flex gap-4">
        {/* Phase sidebar */}
        <div className="w-52 shrink-0 hidden md:block">
          <div className="card p-3 sticky top-28">
            <h3 className="text-xs text-[#9CA3AF] uppercase tracking-wider mb-3 px-1">Testing Phases</h3>
            <div className="space-y-1">
              {(progress?.phases || []).map((phase: any) => {
                const info = PHASE_INFO[phase.phase] || { label: "Phase", color: "blue" };
                const phasePct = phase.total > 0
                  ? Math.round(((phase.passed + phase.failed + phase.na) / phase.total) * 100)
                  : 0;
                return (
                  <button key={phase.phase}
                    onClick={() => setSelectedPhase(phase.phase)}
                    className={`w-full text-left px-2 py-2 rounded text-xs transition-all ${
                      selectedPhase === phase.phase
                        ? "bg-blue-600/20 text-blue-400 border border-blue-800"
                        : "text-[#9CA3AF] hover:text-white hover:bg-[#1F2937]"
                    }`}>
                    <div className="flex items-center justify-between mb-1">
                      <span>{info.label}</span>
                      <span className={phasePct === 100 ? "text-green-400" : ""}>{phasePct}%</span>
                    </div>
                    <div className="h-1 bg-[#374151] rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${phasePct === 100 ? "bg-green-500" : "bg-blue-600"}`}
                        style={{ width: `${phasePct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0">
          <div className="card p-4 mb-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h1 className="text-xl font-bold text-white">{project.application_name}</h1>
                <p className="text-[#9CA3AF] text-sm">{project.application_url}</p>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <span className="text-xs text-[#9CA3AF]">Owner: {project.app_owner_name || "—"}</span>
                  <span className="text-[#374151]">•</span>
                  <span className="text-xs text-[#9CA3AF]">SPOC: {project.app_spoc_name || "—"}</span>
                  <span className="text-[#374151]">•</span>
                  <span className="text-xs text-[#9CA3AF]">{project.testing_type}</span>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Link
                  href={`/projects/${id}/report`}
                  className="flex items-center gap-2 px-3 py-1.5 rounded border border-blue-600/50 text-blue-400 hover:bg-blue-900/20 transition-colors text-sm"
                >
                  <FileText className="w-4 h-4" /> Live Report
                </Link>
                <div className="relative group">
                  <button
                    className="flex items-center gap-2 px-3 py-1.5 rounded border border-[#374151] text-[#9CA3AF] hover:text-white hover:border-blue-600 transition-colors text-sm"
                  >
                    <FileDown className="w-4 h-4" /> Download <ChevronDown className="w-3 h-3" />
                  </button>
                  <div className="absolute right-0 mt-1 top-full hidden group-hover:block w-48 bg-[#0D1424] border border-[#1F2937] rounded-lg shadow-xl z-50 py-1">
                    {(["html", "pdf", "docx", "json", "csv"] as const).map((fmt) => (
                      <button
                        key={fmt}
                        onClick={async () => {
                          try {
                            await api.downloadReport(id, fmt, `VAPT_Report_${project.application_name.replace(/\s/g, "_")}.${fmt === "html" ? "html" : fmt}`);
                            toast.success(`Downloaded ${fmt.toUpperCase()} report`);
                          } catch (e: any) {
                            toast.error(e.message || "Download failed");
                          }
                        }}
                        className="w-full text-left px-3 py-2 text-sm text-[#D1D5DB] hover:bg-[#1F2937] hover:text-white transition-colors"
                      >
                        Download {fmt.toUpperCase()}
                      </button>
                    ))}
                    <div className="border-t border-[#1F2937] my-1" />
                    {(["docx", "pdf"] as const).map((fmt) => (
                      <button
                        key={`async-${fmt}`}
                        disabled={!!asyncReportTask}
                        onClick={() => handleAsyncDownload(fmt)}
                        className="w-full text-left px-3 py-2 text-sm text-[#9CA3AF] hover:bg-[#1F2937] hover:text-white transition-colors disabled:opacity-50"
                      >
                        {asyncReportTask && asyncReportFormat === fmt ? "Generating..." : `${fmt.toUpperCase()} (Async)`}
                      </button>
                    ))}
                  </div>
                </div>
                <button
                  onClick={openFindingsPanel}
                  className="flex items-center gap-2 px-3 py-1.5 rounded border border-[#374151] text-[#9CA3AF] hover:text-white hover:border-blue-600 transition-colors text-sm"
                >
                  <AlertTriangle className="w-4 h-4" /> Findings ({progress?.failed || 0})
                </button>
                <label className="cursor-pointer px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white text-xs font-medium rounded flex items-center gap-1">
                  <Upload className="w-3 h-3" />
                  {importing ? "Importing..." : "Import Burp XML"}
                  <input type="file" accept=".xml" className="hidden" onChange={handleBurpImport} disabled={importing} />
                </label>
                <button
                  onClick={openMembersModal}
                  className="flex items-center gap-2 px-3 py-1.5 rounded border border-[#374151] text-[#9CA3AF] hover:text-white hover:border-blue-600 transition-colors text-sm"
                >
                  <Users className="w-4 h-4" /> Team
                </button>
                <div className="text-right">
                  <div className="text-2xl font-bold text-red-400">{progress?.failed || 0}</div>
                  <div className="text-xs text-[#9CA3AF]">findings</div>
                </div>
              </div>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-4 gap-3 mt-4">
              {[
                { label: "Applicable", value: applicable, color: "blue" },
                { label: "Passed", value: progress?.passed || 0, color: "green" },
                { label: "Failed", value: progress?.failed || 0, color: "red" },
                { label: "Not Started", value: progress?.not_started || 0, color: "gray" },
              ].map(({ label, value, color }) => (
                <div key={label} className="text-center bg-[#0D1424] rounded-lg p-2 border border-[#1F2937]">
                  <div className={`text-xl font-bold text-${color}-400`}>{value}</div>
                  <div className="text-xs text-[#9CA3AF]">{label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Findings panel */}
          {showFindings && (
            <div className="card p-4 mb-4">
              <div className="flex justify-between items-center mb-3">
                <h3 className="font-bold text-white">Remediation Tracking</h3>
                <button onClick={() => setShowFindings(false)} className="text-[#9CA3AF] hover:text-white">×</button>
              </div>
              <div className="space-y-2">
                {findings.map((f) => (
                  <div key={f.id} className="flex items-center gap-3 p-3 bg-[#0D1424] rounded border border-[#1F2937]">
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-white truncate">{f.title}</div>
                      <div className="text-xs text-[#9CA3AF]">{f.severity} • {f.affected_url || "-"}</div>
                    </div>
                    <select
                      value={f.status || "open"}
                      onChange={async (e) => {
                        try {
                          await api.updateFinding(f.id, { status: e.target.value });
                          loadFindings();
                          toast.success("Status updated");
                        } catch (err: any) {
                          toast.error(err.message);
                        }
                      }}
                      className="input-field text-xs w-32"
                    >
                      {["open", "confirmed", "mitigated", "fixed", "accepted_risk", "fp"].map((s) => (
                        <option key={s} value={s}>{s.replace("_", " ")}</option>
                      ))}
                    </select>
                    <button
                      onClick={async () => {
                        try {
                          const res = await api.createJiraIssue(f.id);
                          toast.success(`Created ${res.jira_key}`);
                          if (res.jira_url) window.open(res.jira_url, "_blank");
                        } catch (err: any) {
                          toast.error(err.message || "JIRA integration not configured");
                        }
                      }}
                      className="text-xs px-2 py-1 rounded border border-[#374151] text-[#9CA3AF] hover:text-blue-400 hover:border-blue-600 transition-colors"
                      title="Create JIRA issue"
                    >
                      JIRA
                    </button>
                  </div>
                ))}
                {findings.length === 0 && <p className="text-[#9CA3AF] text-sm">No findings yet</p>}
              </div>
            </div>
          )}

          {/* Phase selector mobile */}
          <div className="md:hidden flex gap-2 overflow-x-auto pb-2 mb-4">
            {(progress?.phases || []).map((phase: any) => {
              const info = PHASE_INFO[phase.phase] || { icon: "🔍", color: "blue" };
              return (
                <button key={phase.phase}
                  onClick={() => setSelectedPhase(phase.phase)}
                  className={`shrink-0 px-3 py-1.5 rounded text-xs transition-all ${
                    selectedPhase === phase.phase
                      ? "bg-blue-600 text-white"
                      : "bg-[#111827] text-[#9CA3AF] border border-[#1F2937]"
                  }`}>
                  {info.label}
                </button>
              );
            })}
          </div>

          {/* Test cases */}
          {selectedPhase && (
            <div>
              <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <span className="text-lg font-semibold">{PHASE_INFO[selectedPhase]?.label || "Phase"}</span>
                  <h2 className="text-lg font-bold text-white capitalize">
                    {selectedPhase.replace("_", "-")} Testing
                  </h2>
                  <span className="text-xs text-[#9CA3AF]">
                    ({testCases.filter(t => !showPassedNa ? !["passed", "na"].includes(t.result_status) : true).length} to do
                    {!showPassedNa && (() => {
                      const hidden = testCases.filter(t => ["passed", "na"].includes(t.result_status)).length;
                      return hidden > 0 ? `, ${hidden} done ✓` : "";
                    })()})
                  </span>
                </div>
                <button
                  onClick={() => setShowPassedNa(!showPassedNa)}
                  className="text-xs px-3 py-1.5 rounded border border-[#374151] text-[#9CA3AF] hover:text-white hover:border-blue-600 transition-colors"
                >
                  {showPassedNa ? "🙈 Hide passed/NA" : "👁 Show passed/NA"}
                </button>
              </div>

              {testCases.length === 0 ? (
                <div className="card p-8 text-center text-[#9CA3AF]">
                  No test cases in this phase
                </div>
              ) : (
                <div className="space-y-2">
                  {testCases
                    .filter(tc => showPassedNa || !["passed", "na"].includes(tc.result_status))
                    .map((tc, idx) => (
                      <motion.div
                        key={tc.result_id}
                        initial={{ opacity: 0, x: -12 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.04, duration: 0.35 }}
                      >
                        <TestCaseCard
                        key={tc.result_id}
                        tc={tc}
                        projectId={id}
                        applicationUrl={project?.application_url || ""}
                        onUpdate={handleUpdate}
                      />
                      </motion.div>
                    ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Team modal */}
      {showMembers && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setShowMembers(false)}>
          <div className="bg-[#0D1424] border border-[#1F2937] rounded-lg max-w-lg w-full max-h-[90vh] overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-[#1F2937]">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Users className="w-5 h-5 text-blue-400" /> Project Team
              </h2>
              <button onClick={() => setShowMembers(false)} className="text-[#9CA3AF] hover:text-white"
                ><X className="w-5 h-5" /></button>
            </div>
            <div className="p-4 overflow-y-auto max-h-[calc(90vh-8rem)]">
              {membersError && (
                <div className="mb-4 p-3 rounded bg-red-900/20 border border-red-800 text-red-400 text-sm">
                  {membersError}
                </div>
              )}
              {membersLoading ? (
                <div className="text-center text-[#9CA3AF] py-8">Loading...</div>
              ) : (
                <>
                  <div className="space-y-2 mb-6">
                    {members.map((m) => (
                      <div key={m.id} className="flex items-center justify-between p-3 rounded bg-[#111827] border border-[#1F2937]">
                        <div>
                          <div className="font-medium text-white">{m.full_name || m.username}</div>
                          <div className="text-xs text-[#9CA3AF]">@{m.username} · {m.role}</div>
                          <div className="flex gap-2 mt-1 flex-wrap">
                            {m.can_read && <span className="text-xs text-green-400">read</span>}
                            {m.can_write && <span className="text-xs text-blue-400">write</span>}
                            {m.can_download_report && <span className="text-xs text-purple-400">report</span>}
                            {m.can_manage_members && <span className="text-xs text-orange-400">manage</span>}
                          </div>
                        </div>
                        <button
                          onClick={() => handleRemoveMember(m.id)}
                          className="text-xs text-red-400 hover:text-red-300 px-2 py-1"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>

                  {!membersError && (
                    <form onSubmit={handleAddMember} className="space-y-2">
                      <h3 className="text-sm font-semibold text-white">Add member</h3>
                      {users.length === 0 ? (
                        <p className="text-xs text-[#9CA3AF]">All users are already members.</p>
                      ) : (
                      <div className="flex gap-2">
                        <select
                          className="input-field flex-1"
                          value={addUser.user_id}
                          onChange={(e) => setAddUser({ ...addUser, user_id: e.target.value })}
                        >
                          <option value="">Select user</option>
                          {users.map((u) => (
                            <option key={u.id} value={u.id}>{u.full_name} (@{u.username})</option>
                          ))}
                        </select>
                        <select
                          className="input-field w-28"
                          value={addUser.role}
                          onChange={(e) => setAddUser({ ...addUser, role: e.target.value })}
                        >
                          <option value="viewer">Viewer</option>
                          <option value="tester">Tester</option>
                          <option value="manager">Manager</option>
                        </select>
                        <button type="submit" className="btn-primary">Add</button>
                      </div>
                      )}
                    </form>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
