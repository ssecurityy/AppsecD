"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { Settings, Key, CheckCircle, XCircle, Info, Save, Shield } from "lucide-react";

const LLM_MODELS = [
  { value: "gpt-4o-mini", label: "gpt-4o-mini (fast, cheap)" },
  { value: "gpt-4o", label: "gpt-4o (better quality)" },
  { value: "gpt-4-turbo", label: "gpt-4-turbo" },
  { value: "gpt-4", label: "gpt-4" },
  { value: "gpt-3.5-turbo", label: "gpt-3.5-turbo" },
];

export default function AdminSettingsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [status, setStatus] = useState<{
    jira?: { configured: boolean; hint: string };
    ai?: { mode: string; model?: string; hint: string };
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [llmModel, setLlmModel] = useState("gpt-4o-mini");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [testingLlm, setTestingLlm] = useState(false);
  const [llmTestResult, setLlmTestResult] = useState<{ok: boolean; error?: string; response?: string; model?: string} | null>(null);
  const [testingJira, setTestingJira] = useState(false);
  const [jiraTestResult, setJiraTestResult] = useState<{ok: boolean; error?: string; user?: string} | null>(null);
  const [mfaStatus, setMfaStatus] = useState<{mfa_enabled: boolean} | null>(null);
  const [mfaSetupData, setMfaSetupData] = useState<{secret: string; qr_uri: string} | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);

  const refreshStatus = () => {
    api.getSettingsStatus()
      .then((s) => {
        setStatus(s);
        if (s?.ai?.model) setLlmModel(s.ai.model);
      })
      .catch(() => toast.error("Failed to load settings"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && user.role !== "admin") router.replace("/dashboard");
  }, [user, router]);

  useEffect(() => {
    if (user?.role === "admin") {
      refreshStatus();
      api.mfaStatus().then(setMfaStatus).catch(() => {});
    }
  }, [user]);

  const handleSaveLlm = async () => {
    setSaving(true);
    try {
      const payload: { model: string; api_key?: string } = { model: llmModel };
      if (llmApiKey !== "") payload.api_key = llmApiKey;
      await api.updateLlmSettings(payload);
      toast.success("LLM settings saved");
      setLlmApiKey("");
      refreshStatus();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  const handleTestLlm = async () => {
    setTestingLlm(true);
    setLlmTestResult(null);
    try {
      const result = await api.testLlmConnection();
      setLlmTestResult(result);
      if (result.ok) {
        toast.success("LLM connection successful!");
      } else {
        toast.error(result.error || "LLM test failed");
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Test failed";
      setLlmTestResult({ ok: false, error: msg });
      toast.error(msg);
    } finally {
      setTestingLlm(false);
    }
  };

  const handleTestJira = async () => {
    setTestingJira(true);
    setJiraTestResult(null);
    try {
      const result = await api.testJiraConnection();
      setJiraTestResult(result);
      if (result.ok) {
        toast.success(`JIRA connected as ${result.user}`);
      } else {
        toast.error(result.error || "JIRA test failed");
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Test failed";
      setJiraTestResult({ ok: false, error: msg });
      toast.error(msg);
    } finally {
      setTestingJira(false);
    }
  };

  const handleMfaSetup = async () => {
    setMfaLoading(true);
    try {
      const data = await api.mfaSetup();
      setMfaSetupData(data);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "MFA setup failed");
    } finally {
      setMfaLoading(false);
    }
  };

  const handleMfaVerify = async () => {
    setMfaLoading(true);
    try {
      await api.mfaVerify(mfaCode);
      toast.success("MFA enabled successfully!");
      setMfaSetupData(null);
      setMfaCode("");
      api.mfaStatus().then(setMfaStatus).catch(() => {});
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Verification failed");
    } finally {
      setMfaLoading(false);
    }
  };

  const handleMfaDisable = async () => {
    setMfaLoading(true);
    try {
      await api.mfaDisable(mfaCode);
      toast.success("MFA disabled");
      setMfaCode("");
      api.mfaStatus().then(setMfaStatus).catch(() => {});
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to disable MFA");
    } finally {
      setMfaLoading(false);
    }
  };

  if (!user || user.role !== "admin") return null;

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-2xl mx-auto p-4">
        <h1 className="text-xl font-bold text-white flex items-center gap-2 mb-6">
          <Settings className="w-5 h-5 text-blue-400" /> Admin Settings
        </h1>

        <div className="card p-4 mb-4">
          <h2 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Key className="w-4 h-4" /> AI Assist (LLM)
          </h2>
          {loading ? (
            <div className="text-[#9CA3AF] text-sm">Loading...</div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-white">Status</span>
                {status?.ai?.mode === "llm" ? (
                  <span className="flex items-center gap-1 text-xs text-green-400">
                    <CheckCircle className="w-3 h-3" /> LLM mode
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-xs text-amber-400">
                    <Info className="w-3 h-3" /> Rule-based
                  </span>
                )}
              </div>
              <p className="text-xs text-[#9CA3AF]">{(status?.ai as { hint?: string })?.hint}</p>

              <div>
                <label className="block text-xs font-medium text-[#9CA3AF] mb-1">Model</label>
                <select
                  value={llmModel}
                  onChange={(e) => setLlmModel(e.target.value)}
                  className="w-full bg-[#111827] border border-[#1F2937] rounded px-3 py-2 text-white text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  {LLM_MODELS.map((m) => (
                    <option key={m.value} value={m.value}>{m.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-[#9CA3AF] mb-1">API Key</label>
                <input
                  type="password"
                  value={llmApiKey}
                  onChange={(e) => setLlmApiKey(e.target.value)}
                  placeholder="Leave blank to keep current, or enter new key to replace"
                  className="w-full bg-[#111827] border border-[#1F2937] rounded px-3 py-2 text-white text-sm placeholder-[#6B7280] focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <p className="text-xs text-[#6B7280] mt-1">Leave blank to keep current. Use &quot;Clear key&quot; to remove stored key.</p>
              </div>
              <div className="flex gap-2">
              <button
                onClick={handleSaveLlm}
                disabled={saving}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded"
              >
                <Save className="w-4 h-4" /> {saving ? "Saving..." : "Save LLM Settings"}
              </button>
              <button
                onClick={async () => {
                  setSaving(true);
                  try {
                    await api.updateLlmSettings({ model: llmModel, api_key: "" });
                    toast.success("API key cleared");
                    refreshStatus();
                  } catch (e: unknown) {
                    toast.error(e instanceof Error ? e.message : "Failed to clear");
                  } finally {
                    setSaving(false);
                  }
                }}
                disabled={saving}
                className="px-4 py-2 bg-[#374151] hover:bg-[#4B5563] disabled:opacity-50 text-white text-sm font-medium rounded"
              >
                Clear key
              </button>
              <button
                onClick={handleTestLlm}
                disabled={testingLlm || saving}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm font-medium rounded"
              >
                {testingLlm ? "Testing..." : "Test Connection"}
              </button>
              </div>
              {llmTestResult && (
                <div className={`mt-3 p-3 rounded text-sm ${llmTestResult.ok ? 'bg-green-900/30 border border-green-700 text-green-300' : 'bg-red-900/30 border border-red-700 text-red-300'}`}>
                  {llmTestResult.ok ? (
                    <p>Connected to <strong>{llmTestResult.model}</strong>. Response: &quot;{llmTestResult.response}&quot;</p>
                  ) : (
                    <p>Failed: {llmTestResult.error}</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="card p-4 mb-4">
          <h2 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Key className="w-4 h-4" /> JIRA
          </h2>
          {!loading && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-white">Status</span>
                {status?.jira?.configured ? (
                  <span className="flex items-center gap-1 text-xs text-green-400">
                    <CheckCircle className="w-3 h-3" /> Configured
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-xs text-amber-400">
                    <XCircle className="w-3 h-3" /> Not configured
                  </span>
                )}
              </div>
              <p className="text-xs text-[#9CA3AF]">{(status?.jira as { hint?: string })?.hint}</p>
              <div className="text-xs text-[#6B7280]">
                <strong>Env:</strong> <code>JIRA_BASE_URL</code>, <code>JIRA_EMAIL</code>, <code>JIRA_API_TOKEN</code>, <code>JIRA_PROJECT_KEY</code>
              </div>
              <button
                onClick={handleTestJira}
                disabled={testingJira}
                className="mt-3 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm font-medium rounded"
              >
                {testingJira ? "Testing..." : "Test JIRA Connection"}
              </button>
              {jiraTestResult && (
                <div className={`mt-3 p-3 rounded text-sm ${jiraTestResult.ok ? 'bg-green-900/30 border border-green-700 text-green-300' : 'bg-red-900/30 border border-red-700 text-red-300'}`}>
                  {jiraTestResult.ok ? (
                    <p>Connected as <strong>{jiraTestResult.user}</strong></p>
                  ) : (
                    <p>Failed: {jiraTestResult.error}</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="card p-4 mb-4">
          <h2 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Shield className="w-4 h-4" /> Multi-Factor Authentication
          </h2>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-medium text-white">MFA Status</span>
              {mfaStatus?.mfa_enabled ? (
                <span className="flex items-center gap-1 text-xs text-green-400">
                  <CheckCircle className="w-3 h-3" /> Enabled
                </span>
              ) : (
                <span className="flex items-center gap-1 text-xs text-amber-400">
                  <XCircle className="w-3 h-3" /> Disabled
                </span>
              )}
            </div>

            {!mfaStatus?.mfa_enabled && !mfaSetupData && (
              <button onClick={handleMfaSetup} disabled={mfaLoading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded">
                {mfaLoading ? "Setting up..." : "Enable MFA"}
              </button>
            )}

            {mfaSetupData && (
              <div className="space-y-3">
                <p className="text-xs text-[#9CA3AF]">Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):</p>
                <div className="bg-white p-4 rounded inline-block">
                  <img src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(mfaSetupData.qr_uri)}`} alt="MFA QR Code" className="w-48 h-48" />
                </div>
                <p className="text-xs text-[#6B7280]">Manual key: <code className="bg-[#1F2937] px-1 rounded">{mfaSetupData.secret}</code></p>
                <div>
                  <label className="block text-xs font-medium text-[#9CA3AF] mb-1">Enter 6-digit code to verify</label>
                  <input type="text" maxLength={6} value={mfaCode} onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                    placeholder="000000" className="w-32 bg-[#111827] border border-[#1F2937] rounded px-3 py-2 text-white text-sm text-center tracking-widest" />
                </div>
                <button onClick={handleMfaVerify} disabled={mfaLoading || mfaCode.length !== 6}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm font-medium rounded">
                  {mfaLoading ? "Verifying..." : "Verify & Enable"}
                </button>
              </div>
            )}

            {mfaStatus?.mfa_enabled && (
              <div className="space-y-3">
                <p className="text-xs text-[#9CA3AF]">Enter your current TOTP code to disable MFA:</p>
                <div className="flex gap-2 items-end">
                  <input type="text" maxLength={6} value={mfaCode} onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                    placeholder="000000" className="w-32 bg-[#111827] border border-[#1F2937] rounded px-3 py-2 text-white text-sm text-center tracking-widest" />
                  <button onClick={handleMfaDisable} disabled={mfaLoading || mfaCode.length !== 6}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-sm font-medium rounded">
                    {mfaLoading ? "Disabling..." : "Disable MFA"}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="card p-4 text-sm text-[#9CA3AF]">
          <h3 className="font-semibold text-white mb-2">Fallback: Environment variables</h3>
          <p className="mb-2">You can also set <code className="bg-[#1F2937] px-1 rounded">OPENAI_API_KEY</code> in <code className="bg-[#1F2937] px-1 rounded">backend/.env</code> as fallback when no key is configured in Admin Settings.</p>
          <pre className="bg-[#0D1424] p-3 rounded text-xs overflow-x-auto">
{`# AI (optional — fallback if not set in Admin Settings)
OPENAI_API_KEY=sk-...

# JIRA (optional)
JIRA_BASE_URL=https://yourorg.atlassian.net
JIRA_EMAIL=your@email.com
JIRA_API_TOKEN=your_token
JIRA_PROJECT_KEY=PROJ`}
          </pre>
          <p className="mt-2 text-xs">Restart the backend after changing .env.</p>
        </div>
      </div>
    </div>
  );
}
