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
  Terminal, BookOpen, AlertTriangle, Zap, Target, Flag, Users, X, FileDown, FileText, ShieldCheck, Upload, Wand2, Copy, TrendingUp, Trash2, ArrowRightLeft
} from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
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
  ai_generated: { label: "AI Generated", color: "violet" },
};

const STATUS_CONFIG = {
  passed: { icon: CheckCircle, color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20" },
  failed: { icon: XCircle, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
  not_started: { icon: Circle, color: "text-[var(--text-muted)]", bg: "bg-[var(--bg-elevated)] border-[var(--border-subtle)]" },
  in_progress: { icon: Target, color: "text-indigo-400", bg: "bg-indigo-500/10 border-indigo-500/20" },
  na: { icon: MinusCircle, color: "text-[var(--text-muted)]", bg: "bg-[var(--bg-tertiary)] border-[var(--border-subtle)]" },
  blocked: { icon: Flag, color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" },
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
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
    <div className="flex items-center gap-2 rounded px-2 py-1 text-xs" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
      {previewUrl && (
        <a href={previewUrl} target="_blank" rel="noopener noreferrer" className="shrink-0">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={previewUrl} alt={e.filename} className="w-10 h-10 object-cover rounded" style={{ borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }} />
        </a>
      )}
      <a href={isImage && previewUrl ? previewUrl : `${getApiBase()}${e.url}`} target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:underline truncate max-w-[120px] break-all">{e.filename}</a>
      <button onClick={onRemove} className="text-red-400 hover:text-red-300 shrink-0">×</button>
    </div>
  );
}

function TestCaseCard({ tc, projectId, applicationUrl, onUpdate, craftingPayload, setCraftingPayload, craftedPayloads, setCraftedPayloads }: { tc: any; projectId: string; applicationUrl: string; onUpdate: () => void; craftingPayload: string | null; setCraftingPayload: (v: string | null) => void; craftedPayloads: Record<string, any[]>; setCraftedPayloads: (v: Record<string, any[]>) => void }) {
  const { setUser } = useAuthStore();
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [notes, setNotes] = useState(tc.notes || "");
  const [payloadUsed, setPayloadUsed] = useState(tc.payload_used || "");
  const [evidence, setEvidence] = useState<{ filename: string; url: string; description?: string }[]>(tc.evidence || []);
  const [uploadingEvidence, setUploadingEvidence] = useState(false);
  const [showFindingForm, setShowFindingForm] = useState(false);
  const [aiSuggesting, setAiSuggesting] = useState(false);
  const [showCraftedPayloads, setShowCraftedPayloads] = useState(false);
  const [generatingCommands, setGeneratingCommands] = useState(false);
  const [generatedCommands, setGeneratedCommands] = useState<any[]>([]);
  const [showGeneratedCommands, setShowGeneratedCommands] = useState(false);
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
              <span className="text-xs px-1.5 py-0.5 rounded border shrink-0" title={(tc.is_automated === true) ? "Can be automated via AppSecD DAST" : "Manual testing required"} style={(tc.is_automated === true) ? { background: "rgba(16, 185, 129, 0.15)", borderColor: "rgba(16, 185, 129, 0.4)", color: "#10b981" } : { background: "var(--bg-tertiary)", borderColor: "var(--border-subtle)", color: "var(--text-muted)" }}>
                {(tc.is_automated === true) ? "Automated" : "Manual"}
              </span>
              <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{tc.title}</span>
              <span className={`text-xs px-1.5 py-0.5 rounded border ${SEVERITY_BADGE[tc.severity] || SEVERITY_BADGE.info}`}>
                {tc.severity}
              </span>
              {tc.owasp_ref && (
                <span className="text-xs px-1.5 py-0.5 rounded" style={{ color: "var(--text-secondary)", background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                  {tc.owasp_ref}
                </span>
              )}
              {tc.module_id && <span className="text-xs" style={{ color: "var(--text-muted)" }}>{tc.module_id}</span>}
              {tc.tool_used && tc.tool_used.includes("DAST") && (
                <span className="text-[10px] px-1.5 py-0.5 rounded border shrink-0"
                  style={{ background: "rgba(217,119,6,0.15)", borderColor: "rgba(217,119,6,0.4)", color: "#d97706" }}>
                  DAST Evidence
                </span>
              )}
            </div>
            {tc.description && (
              <p className="text-xs mt-1 line-clamp-1" style={{ color: "var(--text-secondary)" }}>{tc.description}</p>
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
                  className="p-1.5 rounded transition-colors" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>
                  <MinusCircle className="w-3.5 h-3.5" />
                </button>
              </>
            ) : (
              <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
            )}
            <div className="ml-1" style={{ color: "var(--text-muted)" }}>
              {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }}
            className="overflow-hidden">
            <div className="px-4 pb-4 pt-4 space-y-4" style={{ borderTop: "1px solid var(--border-subtle)" }}>
              <div className="grid md:grid-cols-2 gap-4">
                {tc.where_to_test && (
                  <div>
                    <h4 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider mb-1">📍 Where to Test</h4>
                    <p className="text-xs text-[var(--text-secondary)] bg-[var(--bg-tertiary)] p-2 rounded break-words">{tc.where_to_test}</p>
                  </div>
                )}
                {tc.what_to_test && (
                  <div>
                    <h4 className="text-xs font-semibold text-yellow-400 uppercase tracking-wider mb-1">🎯 What to Test</h4>
                    <p className="text-xs text-[var(--text-secondary)] bg-[var(--bg-tertiary)] p-2 rounded break-words">{tc.what_to_test}</p>
                  </div>
                )}
              </div>

              {tc.how_to_test && (
                <div>
                  <h4 className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1">📋 How to Test</h4>
                  <pre className="text-xs text-[var(--text-secondary)] bg-[var(--bg-tertiary)] p-3 rounded font-mono whitespace-pre-wrap overflow-x-auto">{replaceTarget(tc.how_to_test, applicationUrl)}</pre>
                </div>
              )}

              {tc.payloads?.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">💉 Payloads (TARGET → your URL)</h4>
                    <button
                      onClick={async () => {
                        const tcId = tc.result_id || tc.id;
                        setCraftingPayload(tcId);
                        try {
                          const res = await api.craftPayload({
                            test_title: tc.title,
                            test_description: tc.description || tc.how_to_test || "",
                            existing_payloads: tc.payloads || [],
                            target_url: applicationUrl || undefined,
                            context: tc.owasp_id || tc.phase || "",
                          });
                          const payloads = res.payloads || res.enhanced_payloads || res.crafted_payloads || [];
                          setCraftedPayloads({ ...craftedPayloads, [tcId]: payloads });
                          setShowCraftedPayloads(true);
                          toast.success(`AI generated ${payloads.length} enhanced payloads`);
                        } catch (err: any) {
                          toast.error(err.message || "AI payload crafting failed");
                        } finally {
                          setCraftingPayload(null);
                        }
                      }}
                      disabled={craftingPayload === (tc.result_id || tc.id)}
                      className="flex items-center gap-1 text-xs px-2 py-1 rounded border border-purple-500/30 text-purple-400 hover:bg-purple-500/10 transition-colors disabled:opacity-50"
                    >
                      {craftingPayload === (tc.result_id || tc.id) ? (
                        <div className="w-3 h-3 border-2 border-purple-400/30 border-t-purple-400 rounded-full animate-spin" />
                      ) : (
                        <Wand2 className="w-3 h-3" />
                      )}
                      {craftingPayload === (tc.result_id || tc.id) ? "Crafting..." : "AI Enhance"}
                    </button>
                  </div>
                  <div className="space-y-1">
                    {tc.payloads.slice(0, 8).map((p: string, i: number) => {
                      const resolved = replaceTarget(p, applicationUrl);
                      return (
                        <div key={i} className="flex items-center gap-2">
                          <code className="text-xs bg-[var(--bg-tertiary)] px-2 py-1 rounded font-mono flex-1 min-w-0 overflow-x-auto block" style={{ color: "var(--text-code)" }}>{resolved}</code>
                          <button onClick={() => { navigator.clipboard.writeText(resolved); toast.success("Copied! Ready to paste."); }}
                            className="hover:text-white text-xs px-2 py-1 rounded shrink-0" style={{ color: "var(--text-muted)", background: "var(--bg-elevated)" }}>
                            Copy
                          </button>
                        </div>
                      );
                    })}
                  </div>

                  {/* AI-Enhanced Payloads Section */}
                  {craftedPayloads[tc.result_id || tc.id] && craftedPayloads[tc.result_id || tc.id].length > 0 && (
                    <div className="mt-3">
                      <button
                        onClick={() => setShowCraftedPayloads(!showCraftedPayloads)}
                        className="flex items-center gap-1.5 text-xs text-purple-400 hover:text-purple-300 mb-2"
                      >
                        <Wand2 className="w-3 h-3" />
                        {showCraftedPayloads ? "Hide" : "Show"} AI-Enhanced Payloads ({craftedPayloads[tc.result_id || tc.id].length})
                        {showCraftedPayloads ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>
                      <AnimatePresence>
                        {showCraftedPayloads && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="space-y-2 rounded-lg p-3" style={{ background: "rgba(139,92,246,0.05)", border: "1px solid rgba(139,92,246,0.15)" }}>
                              {craftedPayloads[tc.result_id || tc.id].map((cp: any, i: number) => {
                                const payloadText = typeof cp === "string" ? cp : cp.payload || cp.text || "";
                                const technique = typeof cp === "string" ? "" : cp.technique || cp.category || "";
                                const resolved = replaceTarget(payloadText, applicationUrl);
                                return (
                                  <div key={i} className="flex items-start gap-2 rounded p-2" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                                    <div className="flex-1 min-w-0">
                                      <code className="text-xs font-mono block overflow-x-auto whitespace-pre-wrap break-all" style={{ color: "var(--text-code)" }}>{resolved}</code>
                                      {technique && (
                                        <span className="text-[10px] mt-1 inline-block px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                                          {technique}
                                        </span>
                                      )}
                                    </div>
                                    <button
                                      onClick={() => { navigator.clipboard.writeText(resolved); toast.success("AI payload copied!"); }}
                                      className="shrink-0 p-1 rounded hover:bg-purple-500/10 text-purple-400 transition-colors"
                                      title="Copy payload"
                                    >
                                      <Copy className="w-3 h-3" />
                                    </button>
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
              )}

              {tc.tool_commands?.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <h4 className="text-xs font-semibold text-orange-400 uppercase tracking-wider flex items-center gap-1">
                      <Terminal className="w-3 h-3" /> Tool Commands (TARGET → your URL)
                    </h4>
                    <button
                      onClick={async () => {
                        setGeneratingCommands(true);
                        try {
                          const result = await api.generateCommands({
                            test_title: tc.title,
                            test_description: tc.description,
                            target_url: applicationUrl || "",
                            vuln_type: tc.owasp_ref || "",
                            project_id: projectId,
                          });
                          const cmds = result.commands || result.tool_commands || [];
                          setGeneratedCommands(cmds);
                          setShowGeneratedCommands(true);
                          toast.success("Commands generated!");
                        } catch {
                          toast.error("Failed to generate commands");
                        } finally {
                          setGeneratingCommands(false);
                        }
                      }}
                      disabled={generatingCommands}
                      className="text-xs px-2 py-1 rounded flex items-center gap-1 disabled:opacity-50"
                      style={{ color: "var(--accent-indigo)", background: "rgba(99, 102, 241, 0.1)" }}
                    >
                      {generatingCommands ? (
                        <div className="w-3 h-3 border-2 border-indigo-400/30 border-t-indigo-400 rounded-full animate-spin" />
                      ) : (
                        <Zap className="w-3 h-3" />
                      )}
                      {generatingCommands ? "Generating..." : "AI Commands"}
                    </button>
                  </div>
                  <div className="space-y-2">
                    {tc.tool_commands.map((cmd: { tool?: string; command?: string; description?: string }, i: number) => {
                      const resolvedCmd = replaceTarget(cmd.command || "", applicationUrl);
                      return (
                        <div key={i} className="rounded p-2" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-bold text-orange-400">{cmd.tool}</span>
                            <button onClick={() => { navigator.clipboard.writeText(resolvedCmd); toast.success("Command copied! Run in terminal."); }}
                              className="text-xs hover:text-white px-2 py-0.5 rounded" style={{ color: "var(--text-muted)", background: "var(--bg-elevated)" }}>
                              Copy
                            </button>
                          </div>
                          <code className="text-xs font-mono block overflow-x-auto whitespace-pre-wrap break-all" style={{ color: "var(--text-code)" }}>{resolvedCmd}</code>
                          {cmd.description && <p className="text-xs mt-1 break-words" style={{ color: "var(--text-muted)" }}>{cmd.description}</p>}
                        </div>
                      );
                    })}
                  </div>

                  {/* AI-Generated Commands Section */}
                  {generatedCommands.length > 0 && (
                    <div className="mt-3">
                      <button
                        onClick={() => setShowGeneratedCommands(!showGeneratedCommands)}
                        className="flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 mb-2"
                      >
                        <Zap className="w-3 h-3" />
                        {showGeneratedCommands ? "Hide" : "Show"} AI-Generated Commands ({generatedCommands.length})
                        {showGeneratedCommands ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>
                      <AnimatePresence>
                        {showGeneratedCommands && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="space-y-2 rounded-lg p-3" style={{ background: "rgba(99,102,241,0.05)", border: "1px solid rgba(99,102,241,0.15)" }}>
                              {generatedCommands.map((cmd: any, i: number) => {
                                const cmdText = typeof cmd === "string" ? cmd : cmd.command || cmd.text || "";
                                const toolName = typeof cmd === "string" ? "" : cmd.tool || cmd.tool_name || "";
                                const desc = typeof cmd === "string" ? "" : cmd.description || "";
                                const resolved = replaceTarget(cmdText, applicationUrl);
                                return (
                                  <div key={i} className="rounded p-2" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                                    {toolName && <span className="text-xs font-bold text-indigo-400 block mb-1">{toolName}</span>}
                                    <code className="text-xs font-mono block overflow-x-auto whitespace-pre-wrap break-all" style={{ color: "var(--text-code)" }}>{resolved}</code>
                                    {desc && <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>{desc}</p>}
                                    <button
                                      onClick={() => { navigator.clipboard.writeText(resolved); toast.success("AI command copied!"); }}
                                      className="text-xs mt-1 hover:text-white px-2 py-0.5 rounded"
                                      style={{ color: "var(--text-muted)", background: "var(--bg-elevated)" }}
                                    >
                                      Copy
                                    </button>
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
              )}

              <div className="grid md:grid-cols-2 gap-4">
                {tc.pass_indicators && (
                  <div>
                    <h4 className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1">✅ Pass Indicators</h4>
                    <p className="text-xs p-2 rounded break-words" style={{ color: "var(--text-secondary)", background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)" }}>{tc.pass_indicators}</p>
                  </div>
                )}
                {tc.fail_indicators && (
                  <div>
                    <h4 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-1">❌ Fail Indicators</h4>
                    <p className="text-xs p-2 rounded break-words" style={{ color: "var(--text-secondary)", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)" }}>{tc.fail_indicators}</p>
                  </div>
                )}
              </div>

              {tc.remediation && (
                <div>
                  <h4 className="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-1">🔧 Remediation</h4>
                  <p className="text-xs p-2 rounded break-words" style={{ color: "var(--text-secondary)", background: "rgba(139,92,246,0.08)", border: "1px solid rgba(139,92,246,0.2)" }}>{tc.remediation}</p>
                </div>
              )}

              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>📎 Evidence</h4>
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
                    <span className={`inline-block px-3 py-1.5 rounded border text-xs ${uploadingEvidence ? "opacity-50 cursor-not-allowed" : "border-indigo-500 text-indigo-400 hover:bg-indigo-500/10"}`}>
                      {uploadingEvidence ? "Uploading..." : "+ Add evidence"}
                    </span>
                  </label>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>📝 Tester Notes</h4>
                <textarea className="input-field text-xs h-16 resize-none" placeholder="Add notes about this test case..."
                  value={notes} onChange={e => setNotes(e.target.value)} />
              </div>

              {tc.result_status === "failed" && tc.tool_used?.includes("DAST") && (
                <div className="rounded-lg p-3 flex items-center gap-2" style={{ background: "rgba(217,119,6,0.08)", border: "1px solid rgba(217,119,6,0.2)" }}>
                  <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />
                  <span className="text-xs" style={{ color: "#d97706" }}>Vulnerability detected by automated DAST scan.</span>
                  <Link href={`/projects/${projectId}/vulnerabilities`}
                    className="text-xs text-orange-400 hover:underline ml-auto shrink-0 font-medium">
                    View Findings →
                  </Link>
                </div>
              )}

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
  const { hydrate, user } = useAuthStore();
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
  const [craftingPayload, setCraftingPayload] = useState<string | null>(null);
  const [craftedPayloads, setCraftedPayloads] = useState<Record<string, any[]>>({});
  const [enrichingFinding, setEnrichingFinding] = useState<string | null>(null);
  const [deduplicating, setDeduplicating] = useState(false);
  const [findingsTrend, setFindingsTrend] = useState<{ by_date: { date: string; total: number; dast: number; manual: number }[]; by_severity: Record<string, number> } | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [showTransferModal, setShowTransferModal] = useState(false);
  const [transferOrgId, setTransferOrgId] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [transferring, setTransferring] = useState(false);

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
      const [r, trend] = await Promise.all([
        api.getFindings(id),
        api.getProjectFindingsTrend(id).catch(() => ({ by_date: [], by_severity: {} })),
      ]);
      setFindings(r?.items ?? (Array.isArray(r) ? r : []));
      setFindingsTrend(trend);
    } catch {}
  };

  const loadTestCases = async (phase: string) => {
    try {
      const res = await api.getProjectTestCases(id, phase);
      setTestCases(res.items || res);
    } catch {}
  };

  useEffect(() => {
    loadData().finally(() => setLoading(false));
    loadFindings();
  }, [id]);

  useEffect(() => {
    if (selectedPhase) loadTestCases(selectedPhase);
  }, [selectedPhase, id]);

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
      const res = await api.importBurpXml(id, file);
      toast.success(`Imported ${res.imported} findings from Burp XML`);
      loadFindings();
      handleUpdate();
    } catch (err: any) {
      toast.error(err.message || "Import failed");
    } finally {
      setImporting(false);
      e.target.value = "";
    }
  };

  const handleDeleteProject = async () => {
    setDeleting(true);
    try {
      await api.deleteProject(id as string);
      toast.success("Project deleted");
      router.push("/projects");
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setDeleting(false);
      setShowDeleteConfirm(false);
    }
  };

  const handleTransferProject = async () => {
    if (!transferOrgId.trim()) return;
    setTransferring(true);
    try {
      await api.transferProject(id as string, transferOrgId.trim());
      toast.success("Project transferred");
      setShowTransferModal(false);
      setTransferOrgId("");
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setTransferring(false);
    }
  };

  if (loading) return <div className="min-h-screen flex items-center justify-center" style={{ color: "var(--text-secondary)" }}>Loading project...</div>;
  if (!project) return <div className="min-h-screen flex items-center justify-center" style={{ color: "var(--text-secondary)" }}>Project not found</div>;

  const pct = progress?.completion_pct || 0;
  const applicable = progress?.total_applicable || 0;
  const tested = progress?.tested || 0;

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />

      {/* Global progress bar */}
      <div className="sticky top-14 z-40 px-4 py-2" style={{ background: "var(--bg-primary)", borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="max-w-6xl mx-auto flex items-center gap-3">
          <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>{pct}% Complete</span>
          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${pct}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
              className={`h-full rounded-full transition-all ${
                pct === 100 ? "bg-green-500" : pct > 75 ? "bg-blue-400" : pct > 50 ? "bg-blue-500" : "bg-blue-700"
              }`}
            />
          </div>
          <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>{tested}/{applicable} tested</span>
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
            <h3 className="text-xs uppercase tracking-wider mb-3 px-1" style={{ color: "var(--text-secondary)" }}>Testing Phases</h3>
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
                        ? "bg-indigo-500/20 text-indigo-400 border border-indigo-500/20"
                        : "hover:text-white"
                    }`}
                    style={selectedPhase !== phase.phase ? { color: "var(--text-secondary)" } : undefined}>
                    <div className="flex items-center justify-between mb-1">
                      <span>{info.label}</span>
                      <span className={phasePct === 100 ? "text-green-400" : ""}>{phasePct}%</span>
                    </div>
                    <div className="h-1 bg-[#374151] rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${phasePct === 100 ? "bg-green-500" : "bg-indigo-500"}`}
                        style={{ width: `${phasePct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0 overflow-hidden">
          <div className="card p-4 mb-4 overflow-hidden">
            <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4 overflow-hidden">
              <div className="min-w-0 flex-1 overflow-hidden">
                <div className="flex items-center gap-3">
                  <h1 className="text-xl font-bold truncate" style={{ color: "var(--text-primary)" }}>{project.application_name}</h1>
                  {/* Threat Level Badge */}
                  {(() => {
                    const failed = progress?.failed || 0;
                    const critical = findings.filter((f: any) => f.severity === "critical").length;
                    const high = findings.filter((f: any) => f.severity === "high").length;
                    const threatLevel = critical > 0 ? "Critical" : high > 2 ? "High" : failed > 5 ? "Medium" : failed > 0 ? "Low" : "Secure";
                    const threatColors: Record<string, string> = {
                      Critical: "bg-red-500/20 text-red-400 border-red-500/30",
                      High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
                      Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
                      Low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
                      Secure: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
                    };
                    return (
                      <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${threatColors[threatLevel]}`}>
                        {threatLevel} Risk
                      </span>
                    );
                  })()}
                  {/* Status Badge */}
                  {project.status && (
                    <span className="px-2 py-0.5 rounded text-xs font-medium" style={{
                      background: project.status === "completed" ? "rgba(16,185,129,0.15)" : project.status === "in_progress" ? "rgba(99,102,241,0.15)" : "rgba(148,163,184,0.15)",
                      color: project.status === "completed" ? "#10b981" : project.status === "in_progress" ? "#818cf8" : "#94a3b8",
                    }}>
                      {project.status?.replace("_", " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}
                    </span>
                  )}
                </div>
                {/* Target URL */}
                <div className="flex items-center gap-2 mt-1">
                  <a href={project.application_url} target="_blank" rel="noopener noreferrer"
                    className="text-sm truncate max-w-lg hover:underline" style={{ color: "var(--accent)" }} title={project.application_url}>
                    {project.application_url}
                  </a>
                  {project.application_version && (
                    <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: "var(--bg-elevated)", color: "var(--text-muted)" }}>v{project.application_version}</span>
                  )}
                </div>
                {/* Info Row 1: Owner, SPOC, Testing Type, Environment */}
                <div className="flex items-center gap-3 mt-2 flex-wrap overflow-hidden">
                  <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                    <strong style={{ color: "var(--text-muted)" }}>Owner:</strong> {project.app_owner_name || "—"}
                  </span>
                  <span className="text-[#374151] shrink-0">|</span>
                  <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                    <strong style={{ color: "var(--text-muted)" }}>SPOC:</strong> {project.app_spoc_name || "—"}
                  </span>
                  <span className="text-[#374151] shrink-0">|</span>
                  <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                    <strong style={{ color: "var(--text-muted)" }}>Type:</strong> {project.testing_type?.replace("_", " ") || "—"}
                  </span>
                  {project.environment && (
                    <>
                      <span className="text-[#374151] shrink-0">|</span>
                      <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                        <strong style={{ color: "var(--text-muted)" }}>Env:</strong> {project.environment}
                      </span>
                    </>
                  )}
                  {project.classification && (
                    <>
                      <span className="text-[#374151] shrink-0">|</span>
                      <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                        <strong style={{ color: "var(--text-muted)" }}>Class:</strong> {project.classification}
                      </span>
                    </>
                  )}
                </div>
                {/* Info Row 2: Dates */}
                <div className="flex items-center gap-3 mt-1 flex-wrap overflow-hidden">
                  {project.created_at && (
                    <span className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>
                      Created: {new Date(project.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                    </span>
                  )}
                  {project.started_at && (
                    <>
                      <span className="text-[#374151] shrink-0">|</span>
                      <span className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>
                        Started: {new Date(project.started_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                      </span>
                    </>
                  )}
                  {project.target_completion_date && (
                    <>
                      <span className="text-[#374151] shrink-0">|</span>
                      <span className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>
                        Target: {new Date(project.target_completion_date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                      </span>
                    </>
                  )}
                  {project.organization_name && (
                    <>
                      <span className="text-[#374151] shrink-0">|</span>
                      <span className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>
                        Org: {project.organization_name}
                      </span>
                    </>
                  )}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 shrink-0 min-w-0">
                <Link
                  href={`/projects/${id}/report`}
                  className="flex items-center gap-2 px-3 py-1.5 rounded border border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 transition-colors text-sm shrink-0"
                  title="View live HTML report"
                >
                  <FileText className="w-4 h-4" /> Live Report
                </Link>
                <div className="relative group">
                  <button
                    className="flex items-center gap-2 px-3 py-1.5 rounded border hover:text-white hover:border-indigo-500 transition-colors text-sm"
                    style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                  >
                    <FileDown className="w-4 h-4" /> Download <ChevronDown className="w-3 h-3" />
                  </button>
                  <div className="absolute right-0 mt-1 top-full hidden group-hover:block w-48 rounded-lg shadow-xl z-50 py-1" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                    {(["html", "pdf", "docx", "json", "csv"] as const).map((fmt) => (
                      <button
                        key={fmt}
                        onClick={async () => {
                          try {
                            await api.downloadReport(id, fmt, `AppSecD_Report_${project.application_name.replace(/\s/g, "_")}.${fmt === "html" ? "html" : fmt}`);
                            toast.success(`Downloaded ${fmt.toUpperCase()} report`);
                          } catch (e: any) {
                            toast.error(e.message || "Download failed");
                          }
                        }}
                        className="w-full text-left px-3 py-2 text-sm hover:text-white transition-colors"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        Download {fmt.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
                <Link
                  href={`/projects/${id}/vulnerabilities`}
                  className="flex items-center gap-2 px-3 py-1.5 rounded border border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/10 transition-colors text-sm shrink-0"
                  title="Manage vulnerabilities, recheck status, create JIRA tickets"
                >
                  <ShieldCheck className="w-4 h-4" /> Vuln Management
                </Link>
                <Link
                  href={`/projects/${id}/dast`}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all shrink-0"
                  style={{ background: "rgba(16, 185, 129, 0.15)", color: "#10b981", border: "1px solid rgba(16, 185, 129, 0.3)" }}
                  title="Run automated DAST security scan"
                >
                  <Zap className="w-3.5 h-3.5" /> DAST Scan
                </Link>
                <button
                  onClick={openFindingsPanel}
                  className="flex items-center gap-2 px-3 py-1.5 rounded border hover:text-white hover:border-indigo-500 transition-colors text-sm shrink-0"
                  style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                  title="View findings only — remediation tracking panel"
                >
                  <AlertTriangle className="w-4 h-4" /> Findings ({findings.length})
                </button>
                <label className="cursor-pointer">
                  <input type="file" className="hidden" accept=".xml" onChange={handleBurpImport} disabled={importing} />
                  <span className={`flex items-center gap-2 px-3 py-1.5 rounded border text-sm transition-colors ${importing ? "opacity-50 cursor-not-allowed" : "hover:text-white hover:border-purple-500"}`}
                    style={{ borderColor: "var(--border-subtle)", color: "rgb(168, 85, 247)" }}>
                    <Upload className="w-4 h-4" /> {importing ? "Importing..." : "Import Burp XML"}
                  </span>
                </label>
                <button
                  onClick={openMembersModal}
                  className="flex items-center gap-2 px-3 py-1.5 rounded border hover:text-white hover:border-indigo-500 transition-colors text-sm shrink-0"
                  style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                  title="View and manage project team members"
                >
                  <Users className="w-4 h-4" /> Team
                </button>
                {user?.role === "super_admin" && (
                  <button
                    onClick={() => setShowTransferModal(true)}
                    className="flex items-center gap-2 px-3 py-1.5 rounded border hover:text-white hover:border-yellow-500 transition-colors text-sm shrink-0"
                    style={{ borderColor: "var(--border-subtle)", color: "rgb(234, 179, 8)" }}
                    title="Transfer project to another organization"
                  >
                    <ArrowRightLeft className="w-4 h-4" /> Transfer
                  </button>
                )}
                {(user?.role === "super_admin" || user?.role === "admin") && (
                  <button
                    onClick={() => setShowDeleteConfirm(true)}
                    className="flex items-center gap-2 px-3 py-1.5 rounded border hover:text-white hover:border-red-500 transition-colors text-sm shrink-0"
                    style={{ borderColor: "var(--border-subtle)", color: "rgb(239, 68, 68)" }}
                    title="Delete this project permanently"
                  >
                    <Trash2 className="w-4 h-4" /> Delete
                  </button>
                )}
                <div className="text-right shrink-0 min-w-[3rem]">
                  <div className="text-2xl font-bold text-red-400 truncate" title={`${findings.length} findings`}>{findings.length}</div>
                  <div className="text-xs truncate" style={{ color: "var(--text-secondary)" }}>findings</div>
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
                <div key={label} className="text-center rounded-lg p-3" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                  <div className={`text-xl font-bold text-${color}-400`}>{value}</div>
                  <div className="text-xs" style={{ color: "var(--text-secondary)" }}>{label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Findings trend chart */}
          {findingsTrend && (findingsTrend.by_date?.length > 0 || Object.keys(findingsTrend.by_severity || {}).length > 0) && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              className="card p-4 mb-4 overflow-hidden"
            >
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
                <TrendingUp className="w-4 h-4 text-indigo-400" /> Findings Trend
              </h3>
              <div className="grid md:grid-cols-2 gap-4">
                {findingsTrend.by_date && findingsTrend.by_date.length > 0 && (
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={findingsTrend.by_date} margin={{ top: 5, right: 5, left: 0, bottom: 0 }}>
                        <defs>
                          <linearGradient id="dastGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#10b981" stopOpacity={0.4} />
                            <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
                          </linearGradient>
                          <linearGradient id="manualGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#6366f1" stopOpacity={0.4} />
                            <stop offset="100%" stopColor="#6366f1" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                        <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="var(--text-muted)" />
                        <YAxis tick={{ fontSize: 10 }} stroke="var(--text-muted)" />
                        <Tooltip
                          contentStyle={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)", borderRadius: 8 }}
                          labelStyle={{ color: "var(--text-primary)" }}
                          formatter={(value: number | undefined) => [value ?? 0, ""]}
                          labelFormatter={(label) => `Date: ${label}`}
                        />
                        <Legend />
                        <Area type="monotone" dataKey="dast" name="DAST" stackId="1" stroke="#10b981" fill="url(#dastGrad)" strokeWidth={2} />
                        <Area type="monotone" dataKey="manual" name="Manual" stackId="1" stroke="#6366f1" fill="url(#manualGrad)" strokeWidth={2} />
                        <Area type="monotone" dataKey="total" name="Total" stroke="#f59e0b" strokeWidth={2} fill="transparent" strokeDasharray="4 4" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                )}
                {findingsTrend.by_severity && Object.keys(findingsTrend.by_severity).length > 0 && (
                  <div className="space-y-2 p-4" style={{ background: "var(--bg-tertiary)", borderRadius: 8 }}>
                    <div className="text-xs font-semibold mb-2" style={{ color: "var(--text-secondary)" }}>By Severity</div>
                    {["critical", "high", "medium", "low", "info"].filter(s => (findingsTrend?.by_severity || {})[s] > 0).map((sev, i) => {
                      const count = (findingsTrend?.by_severity || {})[sev] || 0;
                      const totalSev = Object.values(findingsTrend?.by_severity || {}).reduce((a, b) => a + b, 0) || 1;
                      const pct = (count / totalSev) * 100;
                      const colors: Record<string, string> = { critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#16a34a", info: "#3b82f6" };
                      return (
                        <motion.div key={sev} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}>
                          <div className="flex items-center gap-2">
                            <span className="text-xs capitalize w-16" style={{ color: "var(--text-muted)" }}>{sev}</span>
                            <div className="flex-1 h-5 rounded overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${pct}%` }}
                                transition={{ delay: i * 0.05 + 0.2, duration: 0.5 }}
                                className="h-full rounded"
                                style={{ background: colors[sev] }}
                              />
                            </div>
                            <span className="text-xs font-bold w-6" style={{ color: colors[sev] }}>{count}</span>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* Findings panel */}
          {showFindings && (
            <div className="card p-4 mb-4">
              <div className="flex justify-between items-center mb-3">
                <div className="flex items-center gap-2">
                  <h3 className="font-bold" style={{ color: "var(--text-primary)" }}>Remediation Tracking</h3>
                  <button
                    onClick={async () => {
                      setDeduplicating(true);
                      try {
                        const res = await api.deduplicateFindings({ project_id: id });
                        toast.success(res.message || `Deduplication complete: ${res.duplicates_found || 0} duplicates found`);
                        loadFindings();
                      } catch (err: unknown) {
                        toast.error(err instanceof Error ? err.message : "Deduplication failed");
                      } finally {
                        setDeduplicating(false);
                      }
                    }}
                    disabled={deduplicating}
                    className="text-xs px-2 py-1 rounded flex items-center gap-1 disabled:opacity-50"
                    style={{ color: "var(--accent-indigo)", background: "rgba(99, 102, 241, 0.1)" }}
                  >
                    {deduplicating ? (
                      <div className="w-3 h-3 border-2 border-indigo-400/30 border-t-indigo-400 rounded-full animate-spin" />
                    ) : (
                      <Zap className="w-3 h-3" />
                    )}
                    {deduplicating ? "Deduplicating..." : "AI Deduplicate"}
                  </button>
                </div>
                <button onClick={() => setShowFindings(false)} className="hover:text-white" style={{ color: "var(--text-secondary)" }}>×</button>
              </div>
              <div className="space-y-2 overflow-x-auto">
                {findings.map((f) => (
                  <div key={f.id} className="flex flex-col sm:flex-row sm:items-center gap-3 p-3 rounded overflow-hidden" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                    <div className="flex-1 min-w-0 order-1">
                      <div className="font-medium truncate" style={{ color: "var(--text-primary)" }} title={f.title}>{f.title}</div>
                      <div className="text-xs truncate mt-0.5" style={{ color: "var(--text-secondary)" }}>{f.severity} • {f.affected_url || "-"}</div>
                      <div className="flex flex-wrap gap-2 mt-2">
                        {f.jira_key && (
                          <a href={f.jira_url || "#"} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20">
                            Ticket: {f.jira_key}
                          </a>
                        )}
                        {f.jira_status && (
                          <span className="text-xs px-2 py-0.5 rounded border" style={{ background: "var(--bg-elevated)", borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}>
                            JIRA: {f.jira_status}
                          </span>
                        )}
                        {!f.jira_key && !f.jira_status && (
                          <span className="text-xs" style={{ color: "var(--text-muted)" }}>No ticket yet</span>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 sm:shrink-0 order-2">
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
                        setEnrichingFinding(f.id);
                        try {
                          const res = await api.enrichRemediation({
                            finding_title: f.title,
                            finding_description: f.description,
                            current_remediation: f.recommendation,
                            project_id: id,
                          });
                          if (res.remediation || res.enriched_remediation) {
                            await api.updateFinding(f.id, { recommendation: res.remediation || res.enriched_remediation });
                            toast.success("Remediation enriched with AI insights");
                            loadFindings();
                          } else {
                            toast.success("AI enrichment applied");
                          }
                        } catch (err: unknown) {
                          toast.error(err instanceof Error ? err.message : "Enrichment failed");
                        } finally {
                          setEnrichingFinding(null);
                        }
                      }}
                      disabled={enrichingFinding === f.id}
                      className="text-xs px-2 py-1 rounded flex items-center gap-1 disabled:opacity-50"
                      style={{ color: "var(--accent-indigo)", background: "rgba(99, 102, 241, 0.1)" }}
                      title="Enrich remediation with AI"
                    >
                      {enrichingFinding === f.id ? (
                        <div className="w-3 h-3 border-2 border-indigo-400/30 border-t-indigo-400 rounded-full animate-spin" />
                      ) : (
                        <Zap className="w-3 h-3" />
                      )}
                      Enrich
                    </button>
                    <button
                      onClick={async () => {
                        try {
                          const res = await api.createJiraIssue(f.id);
                          toast.success(`Created ${res.jira_key}`);
                          if (res.jira_url) window.open(res.jira_url, "_blank");
                          loadFindings();
                        } catch (err: any) {
                          toast.error(err.message || "JIRA integration not configured");
                        }
                      }}
                      className="text-xs px-2 py-1 rounded border hover:text-indigo-400 hover:border-indigo-500 transition-colors"
                      style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                      title="Create or link JIRA issue"
                    >
                      {f.jira_key ? "View JIRA" : "Create JIRA"}
                    </button>
                    </div>
                  </div>
                ))}
                {findings.length === 0 && <p className="text-sm" style={{ color: "var(--text-secondary)" }}>No findings yet</p>}
              </div>
            </div>
          )}

          {/* Test cases — shown only when Findings panel is closed */}
          {!showFindings && (
          <div>
          {/* Phase selector mobile */}
          <div className="md:hidden flex gap-2 overflow-x-auto pb-2 mb-4">
            {(progress?.phases || []).map((phase: any) => {
              const info = PHASE_INFO[phase.phase] || { icon: "🔍", color: "blue" };
              return (
                <button key={phase.phase}
                  onClick={() => setSelectedPhase(phase.phase)}
                  className={`shrink-0 px-3 py-1.5 rounded text-xs transition-all ${
                    selectedPhase === phase.phase
                      ? "bg-indigo-500 text-white"
                      : "border"
                  }`}
                  style={selectedPhase !== phase.phase ? { background: "var(--bg-tertiary)", color: "var(--text-secondary)", borderColor: "var(--border-subtle)" } : undefined}>
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
                  <h2 className="text-lg font-bold capitalize" style={{ color: "var(--text-primary)" }}>
                    {selectedPhase.replace("_", "-")} Testing
                  </h2>
                  <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                    ({testCases.filter(t => !showPassedNa ? !["passed", "na"].includes(t.result_status) : true).length} to do
                    {!showPassedNa && (() => {
                      const hidden = testCases.filter(t => ["passed", "na"].includes(t.result_status)).length;
                      return hidden > 0 ? `, ${hidden} done ✓` : "";
                    })()})
                  </span>
                </div>
                <button
                  onClick={() => setShowPassedNa(!showPassedNa)}
                  className="text-xs px-3 py-1.5 rounded border hover:text-white hover:border-indigo-500 transition-colors"
                  style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                >
                  {showPassedNa ? "🙈 Hide passed/NA" : "👁 Show passed/NA"}
                </button>
              </div>

              {testCases.length === 0 ? (
                <div className="card p-8 text-center" style={{ color: "var(--text-secondary)" }}>
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
                        craftingPayload={craftingPayload}
                        setCraftingPayload={setCraftingPayload}
                        craftedPayloads={craftedPayloads}
                        setCraftedPayloads={setCraftedPayloads}
                      />
                      </motion.div>
                    ))}
                </div>
              )}
            </div>
          )}
          </div>
          )}
        </div>
      </div>

      {/* Team modal */}
      {showMembers && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setShowMembers(false)}>
          <div className="rounded-lg max-w-lg w-full max-h-[90vh] overflow-auto" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
              <h2 className="text-lg font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <Users className="w-5 h-5 text-indigo-400" /> Project Team
              </h2>
              <button onClick={() => setShowMembers(false)} className="hover:text-white" style={{ color: "var(--text-secondary)" }}
                ><X className="w-5 h-5" /></button>
            </div>
            <div className="p-4 overflow-y-auto max-h-[calc(90vh-8rem)]">
              {membersError && (
                <div className="mb-4 p-3 rounded bg-red-900/20 border border-red-800 text-red-400 text-sm">
                  {membersError}
                </div>
              )}
              {membersLoading ? (
                <div className="text-center py-8" style={{ color: "var(--text-secondary)" }}>Loading...</div>
              ) : (
                <>
                  <div className="space-y-2 mb-6">
                    {members.map((m) => (
                      <div key={m.id} className="flex items-center justify-between p-3 rounded" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }}>
                        <div>
                          <div className="font-medium" style={{ color: "var(--text-primary)" }}>{m.full_name || m.username}</div>
                          <div className="text-xs" style={{ color: "var(--text-secondary)" }}>@{m.username} · {m.role}</div>
                          <div className="flex gap-2 mt-1 flex-wrap">
                            {m.can_read && <span className="text-xs text-green-400">read</span>}
                            {m.can_write && <span className="text-xs text-indigo-400">write</span>}
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
                      <h3 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Add member</h3>
                      {users.length === 0 ? (
                        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>All users are already members.</p>
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

      {/* Delete Project Confirmation Dialog */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => { setShowDeleteConfirm(false); setDeleteConfirmText(""); }}>
          <div className="rounded-lg max-w-md w-full" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <Trash2 className="w-5 h-5 text-red-400" /> Delete Project
              </h2>
              <button onClick={() => { setShowDeleteConfirm(false); setDeleteConfirmText(""); }} className="hover:text-white" style={{ color: "var(--text-secondary)" }}>
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div className="p-3 rounded-lg" style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.2)" }}>
                <p className="text-sm font-medium text-red-400">Warning: This action cannot be undone</p>
                <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                  This will permanently delete <strong style={{ color: "var(--text-primary)" }}>{project.application_name}</strong> and all associated data including test results, findings, evidence, DAST scan data, and crawl results.
                </p>
              </div>
              <div>
                <label className="text-xs font-medium block mb-1.5" style={{ color: "var(--text-secondary)" }}>
                  Type <strong style={{ color: "var(--text-primary)" }}>delete {project.application_name?.toLowerCase()}</strong> to confirm:
                </label>
                <input
                  type="text"
                  value={deleteConfirmText}
                  onChange={e => setDeleteConfirmText(e.target.value)}
                  className="w-full px-3 py-2 rounded text-sm"
                  style={{ background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                  placeholder={`delete ${project.application_name?.toLowerCase()}`}
                  autoFocus
                />
              </div>
              <div className="flex items-center justify-end gap-3">
                <button
                  onClick={() => { setShowDeleteConfirm(false); setDeleteConfirmText(""); }}
                  className="px-4 py-2 rounded border text-sm transition-colors hover:text-white"
                  style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeleteProject}
                  disabled={deleting || deleteConfirmText !== `delete ${project.application_name?.toLowerCase()}`}
                  className="px-4 py-2 rounded bg-red-600 hover:bg-red-700 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {deleting ? "Deleting..." : "Delete Project Permanently"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Transfer Project Modal */}
      {showTransferModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setShowTransferModal(false)}>
          <div className="rounded-lg max-w-md w-full" style={{ background: "var(--bg-tertiary)", borderWidth: 1, borderStyle: "solid", borderColor: "var(--border-subtle)" }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <ArrowRightLeft className="w-5 h-5 text-yellow-400" /> Transfer Project
              </h2>
              <button onClick={() => { setShowTransferModal(false); setTransferOrgId(""); }} className="hover:text-white" style={{ color: "var(--text-secondary)" }}>
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Transfer <strong style={{ color: "var(--text-primary)" }}>{project.application_name}</strong> to another organization. Enter the target organization ID below.
              </p>
              <input
                type="text"
                placeholder="Target Organization ID"
                value={transferOrgId}
                onChange={(e) => setTransferOrgId(e.target.value)}
                className="input-field w-full"
              />
              <div className="flex items-center justify-end gap-3">
                <button
                  onClick={() => { setShowTransferModal(false); setTransferOrgId(""); }}
                  className="px-4 py-2 rounded border text-sm transition-colors hover:text-white"
                  style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
                >
                  Cancel
                </button>
                <button
                  onClick={handleTransferProject}
                  disabled={transferring || !transferOrgId.trim()}
                  className="px-4 py-2 rounded bg-yellow-600 hover:bg-yellow-700 text-white text-sm font-medium transition-colors disabled:opacity-50"
                >
                  {transferring ? "Transferring..." : "Transfer Project"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
