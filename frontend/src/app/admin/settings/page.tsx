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
  RefreshCw, ExternalLink, Shield, Bell, Mail, MessageSquare, Globe, Send, Webhook, Zap, Github
} from "lucide-react";

export default function AdminSettingsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingJira, setSavingJira] = useState(false);
  const [savingNotif, setSavingNotif] = useState(false);
  const [savingGithub, setSavingGithub] = useState(false);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [activeTab, setActiveTab] = useState<"ai" | "jira" | "github" | "notifications">("ai");

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

  // Test connection states
  const [testingLlm, setTestingLlm] = useState(false);
  const [llmTestResult, setLlmTestResult] = useState<any>(null);
  const [testingJira, setTestingJira] = useState(false);
  const [jiraTestResult, setJiraTestResult] = useState<any>(null);
  const [githubAppName, setGithubAppName] = useState("Navigator AppSec");
  const [githubAppSlug, setGithubAppSlug] = useState("");
  const [githubOauthClientId, setGithubOauthClientId] = useState("");
  const [githubOauthClientSecret, setGithubOauthClientSecret] = useState("");
  const [githubOauthRedirectUri, setGithubOauthRedirectUri] = useState("");
  const [selectedGithubProjectId, setSelectedGithubProjectId] = useState("");

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
        if (s?.github?.github_app_name) setGithubAppName(s.github.github_app_name);
        if (s?.github?.github_app_slug !== undefined) setGithubAppSlug(s.github.github_app_slug || "");
        if (s?.github?.github_oauth_client_id !== undefined) setGithubOauthClientId(s.github.github_oauth_client_id || "");
        if (s?.github?.github_oauth_redirect_uri !== undefined) setGithubOauthRedirectUri(s.github.github_oauth_redirect_uri || "");
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
      api.listProjects({ limit: 200, offset: 0 }).then((res: any) => {
        setProjects(res?.items || []);
      }).catch(() => {});
    }
  }, [user]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const tab = params.get("tab");
    if (tab === "github") setActiveTab("github");
    const urlOrgId = params.get("org_id");
    if (urlOrgId && urlOrgId !== selectedOrg) {
      setSelectedOrg(urlOrgId);
      refreshStatus(urlOrgId);
      loadNotificationSettings(urlOrgId);
    }
    const githubApp = params.get("github_app");
    const githubAppBootstrap = params.get("github_app_bootstrap");
    const githubOauth = params.get("github_oauth");
    const githubUsername = params.get("github_username");
    if (githubAppBootstrap === "success") {
      toast.success("Platform GitHub App created");
      refreshStatus(urlOrgId || selectedOrg || undefined);
      router.replace(`/admin/settings?tab=github${urlOrgId ? `&org_id=${urlOrgId}` : ""}`);
    }
    if (githubApp === "success") {
      toast.success("GitHub App connected");
      refreshStatus(urlOrgId || selectedOrg || undefined);
      router.replace(`/admin/settings?tab=github${urlOrgId ? `&org_id=${urlOrgId}` : ""}`);
    }
    if (githubOauth === "success") {
      toast.success(githubUsername ? `GitHub OAuth connected as ${githubUsername}` : "GitHub OAuth connected");
      refreshStatus(urlOrgId || selectedOrg || undefined);
      router.replace(`/admin/settings?tab=github${urlOrgId ? `&org_id=${urlOrgId}` : ""}`);
    }
  }, [router, selectedOrg]);

  const handleOrgChange = (orgId: string) => {
    setSelectedOrg(orgId);
    refreshStatus(orgId);
    loadNotificationSettings(orgId);
  };

  const visibleGithubProjects = projects.filter((project: any) => {
    if (!selectedOrg) return true;
    return project.organization_id === selectedOrg;
  });

  useEffect(() => {
    if (!visibleGithubProjects.length) {
      setSelectedGithubProjectId("");
      return;
    }
    if (!selectedGithubProjectId || !visibleGithubProjects.some((project: any) => project.id === selectedGithubProjectId)) {
      setSelectedGithubProjectId(visibleGithubProjects[0].id);
    }
  }, [selectedGithubProjectId, visibleGithubProjects]);

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

  const handleTestLlm = async () => {
    setTestingLlm(true);
    setLlmTestResult(null);
    try {
      const res = await api.testLlmConnection(selectedOrg || undefined);
      setLlmTestResult(res);
    } catch (e: any) {
      setLlmTestResult({ ok: false, error: e.message });
    } finally {
      setTestingLlm(false);
    }
  };

  const handleTestJira = async () => {
    setTestingJira(true);
    setJiraTestResult(null);
    try {
      const res = await api.testJiraConnection(selectedOrg || undefined);
      setJiraTestResult(res);
    } catch (e: any) {
      setJiraTestResult({ ok: false, error: e.message });
    } finally {
      setTestingJira(false);
    }
  };

  const selectedOrgId = selectedOrg || undefined;

  const handleGithubPopup = (url: string, successType: "github_app_success" | "github_oauth_success" | "github_app_bootstrap_success") => {
    const popup = window.open(url, successType, "width=760,height=820,scrollbars=yes");
    if (!popup) {
      toast.error("Popup blocked. Please allow popups and try again.");
      return;
    }
    const checkClosed = setInterval(() => {
      if (popup.closed) {
        clearInterval(checkClosed);
        window.removeEventListener("message", handler);
      }
    }, 500);
    const handler = async (e: MessageEvent) => {
      if (e.data?.type !== successType) return;
      clearInterval(checkClosed);
      window.removeEventListener("message", handler);
      if (successType === "github_app_bootstrap_success") {
        toast.success(`Platform GitHub App created${e.data?.app_slug ? `: ${e.data.app_slug}` : ""}`);
      } else if (successType === "github_app_success") {
        toast.success(`GitHub App connected${e.data?.account_login ? ` for ${e.data.account_login}` : ""}`);
      } else {
        toast.success(`GitHub OAuth connected${e.data?.github_username ? ` as ${e.data.github_username}` : ""}`);
      }
      refreshStatus(selectedOrgId);
      if ((successType === "github_app_success" || successType === "github_oauth_success") && selectedGithubProjectId) {
        const authMode = successType === "github_app_success" ? "github_app" : "oauth";
        router.push(`/projects/${selectedGithubProjectId}/sast?open_connect=1&github_auth_mode=${authMode}`);
      }
    };
    window.addEventListener("message", handler);
  };

  const startGithubAppConnect = async () => {
    try {
      const res = await api.adminGithubAppConnectStart(selectedOrgId, selectedGithubProjectId || undefined);
      if (res?.install_url) handleGithubPopup(res.install_url, "github_app_success");
    } catch (e: any) {
      toast.error(e.message || "Failed to start GitHub App connection");
    }
  };

  const startGithubAppBootstrap = async () => {
    try {
      const res = await api.adminGithubBootstrapAppStart(selectedOrgId, selectedGithubProjectId || undefined, false);
      if (res?.launch_url) handleGithubPopup(res.launch_url, "github_app_bootstrap_success");
    } catch (e: any) {
      toast.error(e.message || "Failed to start GitHub App bootstrap");
    }
  };

  const startGithubOAuthConnect = async () => {
    try {
      const res = await api.adminGithubOAuthConnectStart(selectedOrgId, selectedGithubProjectId || undefined);
      if (res?.authorize_url) handleGithubPopup(res.authorize_url, "github_oauth_success");
    } catch (e: any) {
      toast.error(e.message || "Failed to start GitHub OAuth connection");
    }
  };

  const saveGithubPlatformSettings = async () => {
    setSavingGithub(true);
    try {
      await api.updateGithubPlatformSettings({
        github_app_name: githubAppName,
        github_app_slug: githubAppSlug,
        github_oauth_client_id: githubOauthClientId,
        github_oauth_client_secret: githubOauthClientSecret || undefined,
        github_oauth_redirect_uri: githubOauthRedirectUri,
      });
      toast.success("GitHub platform settings saved");
      setGithubOauthClientSecret("");
      refreshStatus(selectedOrgId);
    } catch (e: any) {
      toast.error(e.message || "Failed to save GitHub platform settings");
    } finally {
      setSavingGithub(false);
    }
  };

  const disconnectGithubConnection = async (mode: "github_app" | "oauth" | "pat" | "all") => {
    try {
      await api.adminDisconnectGithubConnection(mode, selectedOrgId);
      toast.success("GitHub connection updated");
      refreshStatus(selectedOrgId);
    } catch (e: any) {
      toast.error(e.message || "Failed to update GitHub connection");
    }
  };

  const filteredModels = llmModels.filter((m: any) => m.provider === llmProvider);

  const settingsTabs = [
    { key: "ai" as const, label: "AI / LLM", icon: Cpu },
    { key: "jira" as const, label: "JIRA", icon: ExternalLink },
    { key: "github" as const, label: "GitHub", icon: Github },
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
        <div className="flex rounded-lg p-1 overflow-x-auto" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)" }}>
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
                <div className="flex gap-2 flex-wrap">
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
                <button onClick={handleTestLlm} disabled={testingLlm}
                  className="btn-secondary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                  <Zap className="w-3.5 h-3.5" /> {testingLlm ? "Testing..." : "Test Connection"}
                </button>
              </div>
              {llmTestResult && (
                <div className={`mt-3 p-3 rounded-lg text-xs border break-words ${llmTestResult.ok ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" : "bg-red-500/10 border-red-500/20 text-red-400"}`}>
                  {llmTestResult.ok ? (
                    <span className="flex items-start gap-1 min-w-0"><CheckCircle className="w-3 h-3 shrink-0 mt-0.5" /> <span className="break-words min-w-0">Connected — Model: {llmTestResult.model}, Response: {llmTestResult.response}</span></span>
                  ) : (
                    <span className="flex items-start gap-1 min-w-0"><XCircle className="w-3 h-3 shrink-0 mt-0.5" /> <span className="break-words min-w-0">{llmTestResult.error}</span></span>
                  )}
                </div>
              )}
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
              <div className="flex gap-2">
                <button onClick={handleSaveJira} disabled={savingJira}
                  className="btn-primary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                  <Save className="w-3.5 h-3.5" /> {savingJira ? "Saving..." : "Save JIRA Settings"}
                </button>
                <button onClick={handleTestJira} disabled={testingJira}
                  className="btn-secondary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                  <Zap className="w-3.5 h-3.5" /> {testingJira ? "Testing..." : "Test JIRA Connection"}
                </button>
              </div>
              {jiraTestResult && (
                <div className={`mt-3 p-3 rounded-lg text-xs border break-words ${jiraTestResult.ok ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" : "bg-red-500/10 border-red-500/20 text-red-400"}`}>
                  {jiraTestResult.ok ? (
                    <span className="flex items-start gap-1 min-w-0"><CheckCircle className="w-3 h-3 shrink-0 mt-0.5" /> <span className="break-words min-w-0">Connected — User: {jiraTestResult.user} ({jiraTestResult.email})</span></span>
                  ) : (
                    <span className="flex items-start gap-1 min-w-0"><XCircle className="w-3 h-3 shrink-0 mt-0.5" /> <span className="break-words min-w-0">{jiraTestResult.error}</span></span>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* GitHub Configuration */}
        {activeTab === "github" && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <Github className="w-4 h-4 text-slate-300" /> GitHub Repository Integration
              </h2>
            </div>
            <div className="space-y-4">
              <div className="rounded-lg border p-4" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-elevated)" }}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Platform GitHub setup</h3>
                  <span className="text-[11px] px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-300">
                    Enables org auth
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="md:col-span-2">
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Project to continue into after connect</label>
                    <select
                      className="input-field py-2 text-sm w-full"
                      value={selectedGithubProjectId}
                      onChange={e => setSelectedGithubProjectId(e.target.value)}
                    >
                      {visibleGithubProjects.length === 0 ? (
                        <option value="">No visible projects available</option>
                      ) : (
                        visibleGithubProjects.map((project: any) => (
                          <option key={project.id} value={project.id}>
                            {project.name}
                          </option>
                        ))
                      )}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>GitHub App Name</label>
                    <input className="input-field py-2 text-sm w-full" value={githubAppName} onChange={e => setGithubAppName(e.target.value)} placeholder="Navigator AppSec" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>GitHub App Slug</label>
                    <input className="input-field py-2 text-sm w-full" value={githubAppSlug} onChange={e => setGithubAppSlug(e.target.value)} placeholder="navigator-appsec" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>OAuth Client ID</label>
                    <input className="input-field py-2 text-sm w-full" value={githubOauthClientId} onChange={e => setGithubOauthClientId(e.target.value)} placeholder="Iv1..." />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>OAuth Client Secret</label>
                    <input className="input-field py-2 text-sm w-full" type="password" value={githubOauthClientSecret} onChange={e => setGithubOauthClientSecret(e.target.value)} placeholder="Leave blank to keep current" />
                  </div>
                  <div className="md:col-span-2">
                    <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>OAuth Redirect URI</label>
                    <input className="input-field py-2 text-sm w-full" value={githubOauthRedirectUri} onChange={e => setGithubOauthRedirectUri(e.target.value)} placeholder="https://your-domain/api/sast/github/oauth/callback" />
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 mt-4">
                  <button onClick={saveGithubPlatformSettings} disabled={savingGithub} className="btn-primary flex items-center gap-2 text-sm py-2 px-4 disabled:opacity-50">
                    <Save className="w-3.5 h-3.5" /> {savingGithub ? "Saving..." : "Save Platform GitHub Settings"}
                  </button>
                  <button onClick={startGithubAppBootstrap} className="btn-secondary flex items-center gap-2 text-sm py-2 px-4">
                    <Github className="w-3.5 h-3.5" /> Create GitHub App on GitHub
                  </button>
                </div>
                <p className="text-[11px] mt-3" style={{ color: "var(--text-muted)" }}>
                  Use the bootstrap button to create the platform GitHub App from a GitHub popup, or manually save an existing app slug / OAuth app configuration here.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="rounded-lg border p-4" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-elevated)" }}>
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>GitHub App</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      status?.github?.github_app_connected
                        ? "text-emerald-400 bg-emerald-500/10"
                        : status?.github?.github_app_configured
                          ? "text-amber-400 bg-amber-500/10"
                          : "text-red-400 bg-red-500/10"
                    }`}>
                      {status?.github?.github_app_connected ? "Connected" : status?.github?.github_app_configured ? "Configured" : "Not configured"}
                    </span>
                  </div>
                  <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
                    Recommended for enterprise SaaS. Repositories are listed from app installations and scoped to what the customer allows.
                  </p>
                  {status?.github?.github_app_name && (
                    <p className="text-xs mt-2" style={{ color: "var(--text-secondary)" }}>
                      App name: <span style={{ color: "var(--text-primary)" }}>{status.github.github_app_name}</span>
                    </p>
                  )}
                  {status?.github?.github_app_installation?.account_login && (
                    <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                      Connected account: <span style={{ color: "var(--text-primary)" }}>{status.github.github_app_installation.account_login}</span>
                    </p>
                  )}
                  <div className="flex flex-wrap gap-2 mt-3">
                    <button
                      onClick={startGithubAppConnect}
                      className="btn-primary text-xs py-2 px-3"
                    >
                      {status?.github?.github_app_connected
                        ? "Reconnect GitHub App"
                        : status?.github?.github_app_configured
                          ? "Connect GitHub App"
                          : "Create and Connect GitHub App"}
                    </button>
                    {status?.github?.github_app_connected && (
                      <button
                        onClick={() => disconnectGithubConnection("github_app")}
                        className="btn-secondary text-xs py-2 px-3"
                      >
                        Disconnect
                      </button>
                    )}
                  </div>
                  {!status?.github?.github_app_configured && (
                    <p className="text-[11px] mt-3" style={{ color: "var(--text-muted)" }}>
                      No platform app exists yet. Clicking the button above will create the GitHub App first, then open GitHub&apos;s repository authorization flow.
                    </p>
                  )}
                </div>
                <div className="rounded-lg border p-4" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-elevated)" }}>
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>GitHub OAuth</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      status?.github?.oauth_connected
                        ? "text-emerald-400 bg-emerald-500/10"
                        : status?.github?.oauth_configured
                          ? "text-amber-400 bg-amber-500/10"
                          : "text-red-400 bg-red-500/10"
                    }`}>
                      {status?.github?.oauth_connected ? "Connected" : status?.github?.oauth_configured ? "Configured" : "Not configured"}
                    </span>
                  </div>
                  <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
                    Good fallback for smaller teams. PAT remains available for edge cases and migration.
                  </p>
                  {status?.github?.oauth_account_login && (
                    <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                      Connected account: <span style={{ color: "var(--text-primary)" }}>{status.github.oauth_account_login}</span>
                    </p>
                  )}
                  {status?.github?.pat_connected && (
                    <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                      PAT connected for org: <span style={{ color: "var(--text-primary)" }}>{status?.github?.pat_account_login || "configured"}</span>
                    </p>
                  )}
                  <div className="flex flex-wrap gap-2 mt-3">
                    <button
                      onClick={startGithubOAuthConnect}
                      disabled={!status?.github?.oauth_configured}
                      className="btn-primary text-xs py-2 px-3 disabled:opacity-50"
                    >
                      {status?.github?.oauth_connected ? "Reconnect GitHub OAuth" : "Connect GitHub OAuth"}
                    </button>
                    {status?.github?.oauth_connected && (
                      <button
                        onClick={() => disconnectGithubConnection("oauth")}
                        className="btn-secondary text-xs py-2 px-3"
                      >
                        Disconnect OAuth
                      </button>
                    )}
                    {status?.github?.pat_connected && (
                      <button
                        onClick={() => disconnectGithubConnection("pat")}
                        className="btn-secondary text-xs py-2 px-3"
                      >
                        Disconnect PAT
                      </button>
                    )}
                  </div>
                  {!status?.github?.oauth_configured && (
                    <p className="text-[11px] mt-3" style={{ color: "var(--text-muted)" }}>
                      Missing platform setup: {(status?.github?.oauth_missing_env || []).join(", ") || "OAuth client ID and client secret"}
                    </p>
                  )}
                </div>
              </div>

              <div className="rounded-lg border p-4" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-elevated)" }}>
                <h3 className="text-sm font-medium mb-2" style={{ color: "var(--text-primary)" }}>How org GitHub auth works</h3>
                <div className="space-y-2 text-xs" style={{ color: "var(--text-secondary)" }}>
                  <p>1. A platform admin configures the one-time GitHub App or OAuth credentials on the backend server.</p>
                  <p>2. An organization admin clicks Connect here, signs in on GitHub, and approves all repositories or selected repositories.</p>
                  <p>3. Navigator stores that connection for the tenant, so other admins in the same organization can reuse it.</p>
                  <p>4. Only the repositories approved in GitHub are available for SAST scans and AI fix PR creation.</p>
                  <p>5. For enterprise rollout, prefer GitHub App. Use OAuth or PAT only as fallback and migration paths.</p>
                </div>
              </div>

              <div className="rounded-lg border p-4" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-elevated)" }}>
                <h3 className="text-sm font-medium mb-2" style={{ color: "var(--text-primary)" }}>Backend setup checklist</h3>
                <div className="space-y-2 text-xs" style={{ color: "var(--text-secondary)" }}>
                  <p>GitHub App requires `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, and `GITHUB_APP_PRIVATE_KEY` on the backend server.</p>
                  <p>GitHub OAuth requires `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` on the backend server.</p>
                  <p>The GitHub App install URL uses the app slug, not the display name. Configure the slug exactly as shown in GitHub.</p>
                  <p>After connection, go to a project&apos;s `SAST` tab to import the allowed repositories and start repo-wise or all-repo scans.</p>
                </div>
              </div>
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
