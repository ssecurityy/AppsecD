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
  RefreshCw, ExternalLink, Shield, Bell, Mail, MessageSquare, Globe, Send, Webhook
} from "lucide-react";

export default function AdminSettingsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingJira, setSavingJira] = useState(false);
  const [savingNotif, setSavingNotif] = useState(false);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [activeTab, setActiveTab] = useState<"ai" | "jira" | "notifications">("ai");

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

  // Notification form
  const [notif, setNotif] = useState({
    slack_webhook_url: "",
    smtp_host: "",
    smtp_port: 587,
    smtp_user: "",
    smtp_password: "",
    smtp_from: "",
    smtp_tls: true,
    notification_emails: "",
    webhook_url: "",
  });
  const [notifLoaded, setNotifLoaded] = useState(false);

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

  const loadNotificationSettings = (orgId?: string) => {
    api.getNotificationSettings(orgId || selectedOrg || undefined)
      .then((s: any) => {
        setNotif({
          slack_webhook_url: s.slack_webhook_url || "",
          smtp_host: s.smtp_host || "",
          smtp_port: s.smtp_port || 587,
          smtp_user: s.smtp_user || "",
          smtp_password: "",
          smtp_from: s.smtp_from || "",
          smtp_tls: s.smtp_tls !== false,
          notification_emails: s.notification_emails || "",
          webhook_url: s.webhook_url || "",
        });
        setNotifLoaded(true);
      })
      .catch(() => {});
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
            loadNotificationSettings(orgs[0].id);
          }
        }).catch(() => {});
      } else {
        loadNotificationSettings();
      }
    }
  }, [user]);

  const handleOrgChange = (orgId: string) => {
    setSelectedOrg(orgId);
    refreshStatus(orgId);
    loadNotificationSettings(orgId);
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

  const handleSaveNotifications = async () => {
    setSavingNotif(true);
    try {
      await api.updateNotificationSettings(notif, selectedOrg || undefined);
      toast.success("Notification settings saved");
      setNotif(prev => ({ ...prev, smtp_password: "" }));
    } catch (e: any) {
      toast.error(e.message || "Failed to save");
    } finally {
      setSavingNotif(false);
    }
  };

  const filteredModels = llmModels.filter((m: any) => m.provider === llmProvider);

  const settingsTabs = [
    { key: "ai" as const, label: "AI / LLM", icon: Cpu },
    { key: "jira" as const, label: "JIRA", icon: ExternalLink },
    { key: "notifications" as const, label: "Notifications", icon: Bell },
  ];

  if (!user || !isAdmin(user.role)) return null;

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-4xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="text-xl font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <Settings className="w-5 h-5 text-indigo-400" /> Platform Settings
            {isSuperAdmin(user.role) && <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded-full">Super Admin</span>}
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            {isSuperAdmin(user.role) ? "Configure integrations per organization" : "Configure integrations for your organization"}
          </p>
        </motion.div>

        {/* Org Selector (super_admin) */}
        {isSuperAdmin(user.role) && orgs.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            className="card p-4 flex items-center gap-4">
            <Building2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div className="flex-1">
              <label className="text-xs font-medium mb-1 block" style={{ color: "var(--text-secondary)" }}>Organization</label>
              <select className="input-field py-2 text-sm w-full" value={selectedOrg}
                onChange={e => handleOrgChange(e.target.value)}>
                {orgs.map((o: any) => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            </div>
          </motion.div>
        )}

        {/* Settings Tabs */}
        <div className="flex rounded-lg p-1" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)" }}>
          {settingsTabs.map(t => (
            <button key={t.key} onClick={() => { setActiveTab(t.key); if (t.key === "notifications" && !notifLoaded) loadNotificationSettings(); }}
              className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-all flex-1 justify-center ${
                activeTab === t.key ? "bg-indigo-500 text-white" : ""
              }`}
              style={activeTab !== t.key ? { color: "var(--text-secondary)" } : {}}>
              <t.icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          ))}
        </div>

        {/* AI/LLM Configuration */}
        {activeTab === "ai" && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <Cpu className="w-4 h-4 text-indigo-400" /> AI Assist (LLM)
              </h2>
              {loading ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" style={{ color: "var(--text-muted)" }} />
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
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Provider</label>
                <div className="flex gap-2">
                  {["openai", "anthropic", "google"].map(p => (
                    <button key={p} onClick={() => { setLlmProvider(p); setLlmModel(""); }}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                        llmProvider === p ? "bg-indigo-500 text-white" : ""
                      }`}
                      style={llmProvider !== p ? { background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" } : {}}>
                      {p === "openai" ? "OpenAI" : p === "anthropic" ? "Anthropic" : "Google"}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Model</label>
                <select value={llmModel} onChange={e => setLlmModel(e.target.value)} className="input-field py-2 text-sm w-full">
                  <option value="">Select a model...</option>
                  {filteredModels.map((m: any) => <option key={m.value} value={m.value}>{m.label}</option>)}
                  {filteredModels.length === 0 && (
                    <>
                      {llmProvider === "openai" && <><option value="gpt-4o-mini">gpt-4o-mini</option><option value="gpt-4o">gpt-4o</option></>}
                      {llmProvider === "anthropic" && <><option value="claude-sonnet-4-20250514">Claude Sonnet 4</option><option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet</option></>}
                      {llmProvider === "google" && <><option value="gemini-1.5-pro">Gemini 1.5 Pro</option><option value="gemini-1.5-flash">Gemini 1.5 Flash</option></>}
                    </>
                  )}
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>API Key</label>
                <input type="password" value={llmApiKey} onChange={e => setLlmApiKey(e.target.value)}
                  placeholder="Enter API key (leave blank to keep current)" className="input-field py-2 text-sm w-full" />
                <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>Keys are encrypted at rest.</p>
              </div>

              <div className="flex gap-2 pt-1">
                <button onClick={handleSaveLlm} disabled={saving || !llmModel}
                  className="btn-primary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                  <Save className="w-3.5 h-3.5" /> {saving ? "Saving..." : "Save"}
                </button>
              </div>
            </div>
          </motion.div>
        )}

        {/* JIRA Configuration */}
        {activeTab === "jira" && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
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
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>JIRA Base URL</label>
                  <input className="input-field py-2 text-sm w-full" placeholder="https://yourorg.atlassian.net"
                    value={jiraUrl} onChange={e => setJiraUrl(e.target.value)} />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Email</label>
                  <input className="input-field py-2 text-sm w-full" placeholder="your@email.com" type="email"
                    value={jiraEmail} onChange={e => setJiraEmail(e.target.value)} />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>API Token</label>
                  <input className="input-field py-2 text-sm w-full" placeholder="Enter token" type="password"
                    value={jiraToken} onChange={e => setJiraToken(e.target.value)} />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Project Key</label>
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
        )}

        {/* Notification Settings */}
        {activeTab === "notifications" && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
            {/* Slack */}
            <div className="card p-5">
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
                <MessageSquare className="w-4 h-4 text-purple-400" /> Slack Integration
              </h2>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Webhook URL</label>
                  <input className="input-field py-2 text-sm w-full" placeholder="https://hooks.slack.com/services/..."
                    value={notif.slack_webhook_url} onChange={e => setNotif({ ...notif, slack_webhook_url: e.target.value })} />
                  <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>Create an incoming webhook in your Slack workspace settings</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={async () => {
                    try {
                      await api.testSlackNotification(selectedOrg || undefined);
                      toast.success("Test notification sent to Slack");
                    } catch (e: any) { toast.error(e.message); }
                  }} disabled={!notif.slack_webhook_url}
                    className="btn-secondary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                    <Send className="w-3.5 h-3.5" /> Test Slack
                  </button>
                </div>
              </div>
            </div>

            {/* SMTP */}
            <div className="card p-5">
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
                <Mail className="w-4 h-4 text-blue-400" /> Email (SMTP) Notifications
              </h2>
              <div className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>SMTP Host</label>
                    <input className="input-field py-2 text-sm w-full" placeholder="smtp.gmail.com"
                      value={notif.smtp_host} onChange={e => setNotif({ ...notif, smtp_host: e.target.value })} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Port</label>
                    <input className="input-field py-2 text-sm w-full" placeholder="587" type="number"
                      value={notif.smtp_port} onChange={e => setNotif({ ...notif, smtp_port: parseInt(e.target.value) || 587 })} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Username</label>
                    <input className="input-field py-2 text-sm w-full" placeholder="your@email.com"
                      value={notif.smtp_user} onChange={e => setNotif({ ...notif, smtp_user: e.target.value })} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Password</label>
                    <input className="input-field py-2 text-sm w-full" placeholder="Leave blank to keep current" type="password"
                      value={notif.smtp_password} onChange={e => setNotif({ ...notif, smtp_password: e.target.value })} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>From Address</label>
                    <input className="input-field py-2 text-sm w-full" placeholder="noreply@yourorg.com"
                      value={notif.smtp_from} onChange={e => setNotif({ ...notif, smtp_from: e.target.value })} />
                  </div>
                  <div className="flex items-center gap-3 pt-5">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" checked={notif.smtp_tls}
                        onChange={e => setNotif({ ...notif, smtp_tls: e.target.checked })}
                        className="w-4 h-4 rounded accent-indigo-500" />
                      <span className="text-sm" style={{ color: "var(--text-secondary)" }}>Enable TLS</span>
                    </label>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Notification Emails</label>
                  <input className="input-field py-2 text-sm w-full" placeholder="admin@org.com, security@org.com"
                    value={notif.notification_emails} onChange={e => setNotif({ ...notif, notification_emails: e.target.value })} />
                  <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>Comma-separated email addresses for critical finding alerts</p>
                </div>
                <button onClick={async () => {
                  try {
                    await api.testSmtpNotification(selectedOrg || undefined);
                    toast.success("Test email sent");
                  } catch (e: any) { toast.error(e.message); }
                }} disabled={!notif.smtp_host || !notif.notification_emails}
                  className="btn-secondary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                  <Send className="w-3.5 h-3.5" /> Test Email
                </button>
              </div>
            </div>

            {/* Generic Webhook */}
            <div className="card p-5">
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-4" style={{ color: "var(--text-primary)" }}>
                <Webhook className="w-4 h-4 text-emerald-400" /> Generic Webhook
              </h2>
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Webhook URL</label>
                <input className="input-field py-2 text-sm w-full" placeholder="https://your-webhook-endpoint.com/events"
                  value={notif.webhook_url} onChange={e => setNotif({ ...notif, webhook_url: e.target.value })} />
                <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>Receives JSON POST events for critical findings and project updates</p>
              </div>
            </div>

            {/* Save All Notifications */}
            <button onClick={handleSaveNotifications} disabled={savingNotif}
              className="btn-primary flex items-center gap-2 text-sm py-2.5 px-5 disabled:opacity-50">
              <Save className="w-3.5 h-3.5" /> {savingNotif ? "Saving..." : "Save All Notification Settings"}
            </button>
          </motion.div>
        )}

        {/* Environment Info */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="card p-5 text-sm" style={{ color: "var(--text-secondary)" }}>
          <h3 className="font-semibold mb-2 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <Shield className="w-4 h-4" style={{ color: "var(--text-muted)" }} /> Environment Variable Fallbacks
          </h3>
          <p className="mb-3 text-xs">Settings configured above take priority. Environment variables serve as fallback.</p>
          <pre className="p-3 rounded-lg text-xs overflow-x-auto" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)", color: "var(--text-code)" }}>
{`# AI (optional fallback)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# JIRA (optional fallback)
JIRA_BASE_URL=https://yourorg.atlassian.net

# Notifications (optional fallback)
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
NOTIFICATION_EMAILS=admin@org.com`}
          </pre>
        </motion.div>
      </div>
    </div>
  );
}
