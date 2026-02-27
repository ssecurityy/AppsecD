"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { Settings, Key, CheckCircle, XCircle, Info, Save } from "lucide-react";

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
    if (user?.role === "admin") refreshStatus();
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
              </div>
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
            </div>
          )}
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
