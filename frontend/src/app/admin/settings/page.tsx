"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { Settings, Key, CheckCircle, XCircle, Info } from "lucide-react";

export default function AdminSettingsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [status, setStatus] = useState<{
    jira?: { configured: boolean; hint: string };
    ai?: { mode: string; hint: string };
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && user.role !== "admin") router.replace("/dashboard");
  }, [user, router]);

  useEffect(() => {
    if (user?.role === "admin") {
      api.getSettingsStatus()
        .then(setStatus)
        .catch(() => toast.error("Failed to load settings"))
        .finally(() => setLoading(false));
    }
  }, [user]);

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
            <Key className="w-4 h-4" /> API Keys & Integrations
          </h2>
          <p className="text-xs text-[#9CA3AF] mb-4">
            Add keys in <code className="bg-[#1F2937] px-1 rounded">backend/.env</code> and restart the backend.
          </p>

          {loading ? (
            <div className="text-[#9CA3AF] text-sm">Loading...</div>
          ) : (
            <div className="space-y-4">
              {/* AI Assist */}
              <div className="p-3 rounded bg-[#111827] border border-[#1F2937]">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-white">AI Assist</span>
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
                <p className="text-xs text-[#9CA3AF]">{(status?.ai as any)?.hint}</p>
                <div className="mt-2 text-xs text-[#6B7280]">
                  <strong>Env:</strong> <code>OPENAI_API_KEY=sk-...</code>
                </div>
              </div>

              {/* JIRA */}
              <div className="p-3 rounded bg-[#111827] border border-[#1F2937]">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-white">JIRA</span>
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
                <p className="text-xs text-[#9CA3AF]">{(status?.jira as any)?.hint}</p>
                <div className="mt-2 text-xs text-[#6B7280]">
                  <strong>Env:</strong> <code>JIRA_BASE_URL</code>, <code>JIRA_EMAIL</code>, <code>JIRA_API_TOKEN</code>, <code>JIRA_PROJECT_KEY</code>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="card p-4 text-sm text-[#9CA3AF]">
          <h3 className="font-semibold text-white mb-2">Where to add keys</h3>
          <p className="mb-2">Edit <code className="bg-[#1F2937] px-1 rounded">/opt/navigator/backend/.env</code> and add:</p>
          <pre className="bg-[#0D1424] p-3 rounded text-xs overflow-x-auto">
{`# AI (optional — enables LLM for AI Suggest)
OPENAI_API_KEY=sk-...

# JIRA (optional)
JIRA_BASE_URL=https://yourorg.atlassian.net
JIRA_EMAIL=your@email.com
JIRA_API_TOKEN=your_token
JIRA_PROJECT_KEY=PROJ`}
          </pre>
          <p className="mt-2 text-xs">Restart the backend after adding keys.</p>
        </div>
      </div>
    </div>
  );
}
