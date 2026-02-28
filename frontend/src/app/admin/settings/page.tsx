"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
import toast from "react-hot-toast";
import { motion } from "framer-motion";
import {
  Settings, Key, CheckCircle, XCircle, Info, Save, Cpu, Building2,
  Zap, Globe, RefreshCw, ExternalLink, Shield
} from "lucide-react";

export default function AdminSettingsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingJira, setSavingJira] = useState(false);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState("");

  // LLM form
  const [llmProvider, setLlmProvider] = useState("openai");
  const [llmModel, setLlmModel] = useState("gpt-4o-mini");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [llmModels, setLlmModels] = useState<any[]>([]);

  // JIRA form
  const [jiraUrl, setJiraUrl] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraToken, setJiraToken] = useState("");
  const [jiraKey, setJiraKey] = useState("");

  const refreshStatus = (orgId?: string) => {
    setLoading(true);
    api.getSettingsStatus(orgId || selectedOrg || undefined)
      .then((s: any) => {
        setStatus(s);
        if (s?.ai?.provider) setLlmProvider(s.ai.provider);
        if (s?.ai?.model) setLlmModel(s.ai.model);
        if (s?.llm_models) setLlmModels(s.llm_models);
        if (s?.jira?.base_url) setJiraUrl(s.jira.base_url);
        if (s?.jira?.email) setJiraEmail(s.jira.email);
        if (s?.jira?.project_key) setJiraKey(s.jira.project_key);
      })
      .catch(() => toast.error("Failed to load settings"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && !isAdmin(user.role)) router.replace("/dashboard");
  }, [user, router]);

  useEffect(() => {
    if (user && isAdmin(user.role)) {
      refreshStatus();
      if (isSuperAdmin(user.role)) {
        api.listOrganizations().then((orgs: any[]) => {
          setOrgs(orgs);
          if (orgs.length > 0 && !selectedOrg) {
            setSelectedOrg(orgs[0].id);
            refreshStatus(orgs[0].id);
          }
        }).catch(() => {});
      }
    }
  }, [user]);

  const handleOrgChange = (orgId: string) => {
    setSelectedOrg(orgId);
    refreshStatus(orgId);
  };

  const handleSaveLlm = async () => {
    setSaving(true);
    try {
      const payload: any = { provider: llmProvider, model: llmModel };
      if (llmApiKey !== "") payload.api_key = llmApiKey;
      await api.updateLlmSettings(payload, selectedOrg || undefined);
      toast.success("AI settings saved");
      setLlmApiKey("");
      refreshStatus();
    } catch (e: any) {
      toast.error(e.message || "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  const handleSaveJira = async () => {
    setSavingJira(true);
    try {
      await api.updateJiraSettings({
        base_url: jiraUrl,
        email: jiraEmail,
        api_token: jiraToken,
        project_key: jiraKey,
      }, selectedOrg || undefined);
      toast.success("JIRA settings saved");
      setJiraToken("");
      refreshStatus();
    } catch (e: any) {
      toast.error(e.message || "Failed to save JIRA config");
    } finally {
      setSavingJira(false);
    }
  };

  const filteredModels = llmModels.filter((m: any) => m.provider === llmProvider);

  if (!user || !isAdmin(user.role)) return null;

  return (
    <div className="min-h-screen bg-[#09090b]">
      <Navbar />
      <div className="max-w-4xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Settings className="w-5 h-5 text-indigo-400" /> Platform Settings
            {isSuperAdmin(user.role) && <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded-full">Super Admin</span>}
          </h1>
          <p className="text-sm text-[#64748b] mt-1">
            {isSuperAdmin(user.role) ? "Configure integrations per organization" : "Configure integrations for your organization"}
          </p>
        </motion.div>

        {/* Org Selector (super_admin) */}
        {isSuperAdmin(user.role) && orgs.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            className="card p-4 flex items-center gap-4">
            <Building2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div className="flex-1">
              <label className="text-xs font-medium text-[#94a3b8] mb-1 block">Organization</label>
              <select className="input-field py-2 text-sm w-full" value={selectedOrg}
                onChange={e => handleOrgChange(e.target.value)}>
                {orgs.map((o: any) => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            </div>
            <div className="text-right shrink-0">
              {status?.organization_name && (
                <div className="text-sm text-white font-medium">{status.organization_name}</div>
              )}
            </div>
          </motion.div>
        )}

        {/* AI/LLM Configuration */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-indigo-400" /> AI Assist (LLM)
            </h2>
            {loading ? (
              <RefreshCw className="w-3.5 h-3.5 text-[#64748b] animate-spin" />
            ) : status?.ai?.mode === "llm" ? (
              <span className="flex items-center gap-1 text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                <CheckCircle className="w-3 h-3" /> LLM Active
              </span>
            ) : (
              <span className="flex items-center gap-1 text-xs text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full">
                <Info className="w-3 h-3" /> Rule-based
              </span>
            )}
          </div>

          <div className="space-y-4">
            {/* Provider */}
            <div>
              <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">Provider</label>
              <div className="flex gap-2">
                {["openai", "anthropic", "google"].map(p => (
                  <button key={p} onClick={() => { setLlmProvider(p); setLlmModel(""); }}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                      llmProvider === p
                        ? "bg-indigo-500 text-white"
                        : "bg-[#161922] text-[#94a3b8] hover:text-white border border-[#1e2330]"
                    }`}>
                    {p === "openai" ? "OpenAI" : p === "anthropic" ? "Anthropic" : "Google"}
                  </button>
                ))}
              </div>
            </div>

            {/* Model */}
            <div>
              <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">Model</label>
              <select value={llmModel} onChange={e => setLlmModel(e.target.value)}
                className="input-field py-2 text-sm w-full">
                <option value="">Select a model...</option>
                {filteredModels.map((m: any) => (
                  <option key={m.value} value={m.value}>{m.label}</option>
                ))}
                {filteredModels.length === 0 && (
                  <>
                    {llmProvider === "openai" && <>
                      <option value="gpt-4o-mini">gpt-4o-mini (fast)</option>
                      <option value="gpt-4o">gpt-4o</option>
                      <option value="gpt-4-turbo">gpt-4-turbo</option>
                    </>}
                    {llmProvider === "anthropic" && <>
                      <option value="claude-sonnet-4-20250514">Claude Sonnet 4</option>
                      <option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet</option>
                      <option value="claude-3-haiku-20240307">Claude 3 Haiku</option>
                    </>}
                    {llmProvider === "google" && <>
                      <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                      <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                    </>}
                  </>
                )}
              </select>
            </div>

            {/* API Key */}
            <div>
              <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">API Key</label>
              <input type="password" value={llmApiKey} onChange={e => setLlmApiKey(e.target.value)}
                placeholder="Enter API key (leave blank to keep current)"
                className="input-field py-2 text-sm w-full" />
              <p className="text-[10px] text-[#475569] mt-1">Keys are encrypted at rest. Leave blank to keep current key.</p>
            </div>

            <div className="flex gap-2 pt-1">
              <button onClick={handleSaveLlm} disabled={saving || !llmModel}
                className="btn-primary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                <Save className="w-3.5 h-3.5" /> {saving ? "Saving..." : "Save AI Settings"}
              </button>
              <button onClick={async () => {
                setSaving(true);
                try {
                  await api.updateLlmSettings({ provider: llmProvider, model: llmModel, api_key: "" }, selectedOrg || undefined);
                  toast.success("API key cleared");
                  refreshStatus();
                } catch { toast.error("Failed to clear"); }
                finally { setSaving(false); }
              }} disabled={saving}
                className="btn-secondary text-sm py-2 px-4 disabled:opacity-50">
                Clear Key
              </button>
            </div>
          </div>
        </motion.div>

        {/* JIRA Configuration */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <ExternalLink className="w-4 h-4 text-blue-400" /> JIRA Integration
            </h2>
            {!loading && (
              status?.jira?.configured ? (
                <span className="flex items-center gap-1 text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                  <CheckCircle className="w-3 h-3" /> Connected
                </span>
              ) : (
                <span className="flex items-center gap-1 text-xs text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full">
                  <XCircle className="w-3 h-3" /> Not configured
                </span>
              )
            )}
          </div>

          <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">JIRA Base URL</label>
                <input className="input-field py-2 text-sm w-full" placeholder="https://yourorg.atlassian.net"
                  value={jiraUrl} onChange={e => setJiraUrl(e.target.value)} />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">Email</label>
                <input className="input-field py-2 text-sm w-full" placeholder="your@email.com" type="email"
                  value={jiraEmail} onChange={e => setJiraEmail(e.target.value)} />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">API Token</label>
                <input className="input-field py-2 text-sm w-full" placeholder="Enter token (leave blank to keep current)" type="password"
                  value={jiraToken} onChange={e => setJiraToken(e.target.value)} />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">Project Key</label>
                <input className="input-field py-2 text-sm w-full" placeholder="PROJ"
                  value={jiraKey} onChange={e => setJiraKey(e.target.value)} />
              </div>
            </div>
            <button onClick={handleSaveJira} disabled={savingJira}
              className="btn-primary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
              <Save className="w-3.5 h-3.5" /> {savingJira ? "Saving..." : "Save JIRA Settings"}
            </button>
          </div>
        </motion.div>

        {/* Environment Fallbacks */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="card p-5 text-sm text-[#94a3b8]">
          <h3 className="font-semibold text-white mb-2 flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#64748b]" /> Environment Variable Fallbacks
          </h3>
          <p className="mb-3 text-xs">Settings configured above take priority. Environment variables serve as fallback.</p>
          <pre className="bg-[#09090b] p-3 rounded-lg text-xs overflow-x-auto border border-[#1e2330]">
{`# AI (optional fallback)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=...

# JIRA (optional fallback)
JIRA_BASE_URL=https://yourorg.atlassian.net
JIRA_EMAIL=your@email.com
JIRA_API_TOKEN=your_token
JIRA_PROJECT_KEY=PROJ`}
          </pre>
          <p className="mt-2 text-[10px] text-[#475569]">Restart backend after changing .env</p>
        </motion.div>
      </div>
    </div>
  );
}
