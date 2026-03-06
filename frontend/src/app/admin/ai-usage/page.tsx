"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore, isSuperAdmin } from "@/lib/store";
import toast from "react-hot-toast";
import {
  Cpu, DollarSign, Activity, Building2, Settings, Save,
  BarChart3, Zap, AlertTriangle, CheckCircle, XCircle
} from "lucide-react";

export default function AdminAIUsagePage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [usage, setUsage] = useState<any>(null);
  const [globalSettings, setGlobalSettings] = useState<any>(null);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);
  const [orgSettings, setOrgSettings] = useState<any>(null);
  const [savingOrg, setSavingOrg] = useState(false);
  const [activeTab, setActiveTab] = useState<"overview" | "organizations" | "settings">("overview");

  // Org settings form
  const [orgForm, setOrgForm] = useState({
    claude_enabled: true,
    claude_monthly_budget_usd: "",
    claude_per_scan_limit_usd: "20.00",
    claude_max_scans_per_day: "50",
    claude_deep_scan_approval_required: true,
    claude_allowed_models: ["claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-6"],
    claude_dast_api_key: "",
    claude_dast_api_key_set: false,
    claude_dast_api_key_preview: "",
  });

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  useEffect(() => {
    if (user && !isSuperAdmin(user.role)) {
      router.push("/dashboard");
      return;
    }
    if (user) {
      loadData();
    }
  }, [user]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [usageData, settingsData, orgsData] = await Promise.all([
        api.claudeDastAdminUsage().catch(() => null),
        api.claudeDastAdminSettings().catch(() => null),
        api.listOrganizations().catch(() => []),
      ]);
      setUsage(usageData);
      setGlobalSettings(settingsData);
      setOrgs(Array.isArray(orgsData) ? orgsData : orgsData?.organizations || []);
    } catch {
      toast.error("Failed to load AI usage data");
    }
    setLoading(false);
  };

  const loadOrgSettings = async (orgId: string) => {
    setSelectedOrg(orgId);
    try {
      const data = await api.claudeDastAdminSettingsOrg(orgId);
      setOrgSettings(data);
      setOrgForm({
        claude_enabled: data.claude_enabled ?? true,
        claude_monthly_budget_usd: data.claude_monthly_budget_usd?.toString() || "",
        claude_per_scan_limit_usd: data.claude_per_scan_limit_usd?.toString() || "20.00",
        claude_max_scans_per_day: data.claude_max_scans_per_day?.toString() || "50",
        claude_deep_scan_approval_required: data.claude_deep_scan_approval_required ?? true,
        claude_allowed_models: data.claude_allowed_models || ["claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-6"],
        claude_dast_api_key: "",
        claude_dast_api_key_set: data.claude_dast_api_key_set || false,
        claude_dast_api_key_preview: data.claude_dast_api_key_preview || "",
      });
    } catch {
      toast.error("Failed to load org settings");
    }
  };

  const saveOrgSettings = async () => {
    if (!selectedOrg) return;
    setSavingOrg(true);
    try {
      const payload: Record<string, unknown> = {
        claude_enabled: orgForm.claude_enabled,
        claude_monthly_budget_usd: orgForm.claude_monthly_budget_usd ? parseFloat(orgForm.claude_monthly_budget_usd) : null,
        claude_per_scan_limit_usd: orgForm.claude_per_scan_limit_usd ? parseFloat(orgForm.claude_per_scan_limit_usd) : null,
        claude_max_scans_per_day: orgForm.claude_max_scans_per_day ? parseInt(orgForm.claude_max_scans_per_day) : null,
        claude_deep_scan_approval_required: orgForm.claude_deep_scan_approval_required,
        claude_allowed_models: orgForm.claude_allowed_models,
      };
      // Only send API key if user entered a new one
      if (orgForm.claude_dast_api_key) {
        payload.claude_dast_api_key = orgForm.claude_dast_api_key;
      }
      await api.claudeDastAdminSettingsOrgUpdate(selectedOrg, payload);
      toast.success("Organization settings updated");
    } catch {
      toast.error("Failed to save settings");
    }
    setSavingOrg(false);
  };

  const totalCost = usage?.total_cost_usd || 0;
  const globalBudget = globalSettings?.claude_dast_max_cost_per_scan ? globalSettings.claude_dast_max_cost_per_scan * (globalSettings?.claude_dast_max_daily_scans || 50) * 30 : null;
  const budgetPct = globalBudget ? Math.min(100, (totalCost / globalBudget) * 100) : 0;

  const modelColors: Record<string, string> = {
    "claude-haiku-4-5": "#22c55e",
    "claude-sonnet-4-6": "#3b82f6",
    "claude-opus-4-6": "#a855f7",
  };

  if (loading) {
    return (
      <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
        <Navbar />
        <div className="flex items-center justify-center h-[60vh]">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2" style={{ borderColor: "#d97706" }} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "linear-gradient(135deg, #d97706, #ea580c)" }}>
              <Cpu className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold" style={{ color: "var(--text-primary)" }}>AI Usage Dashboard</h1>
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Claude DAST cost tracking & enterprise controls</p>
            </div>
          </div>
          <button onClick={loadData} className="px-3 py-1.5 rounded-lg text-xs font-medium" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>
            Refresh
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 p-1 rounded-xl w-fit" style={{ background: "var(--bg-elevated)" }}>
          {(["overview", "organizations", "settings"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="px-4 py-2 rounded-lg text-sm font-medium transition-all capitalize"
              style={{
                background: activeTab === tab ? "linear-gradient(135deg, #d97706, #ea580c)" : "transparent",
                color: activeTab === tab ? "white" : "var(--text-secondary)",
              }}
            >
              {tab === "overview" ? "Overview" : tab === "organizations" ? "Per-Organization" : "Global Settings"}
            </button>
          ))}
        </div>

        {/* Overview Tab */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {/* Top Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: "Total Cost (30d)", value: `$${totalCost.toFixed(2)}`, icon: DollarSign, color: "#d97706" },
                { label: "API Calls", value: usage?.by_organization?.reduce((s: number, o: any) => s + (o.total_calls || 0), 0) || 0, icon: Activity, color: "#3b82f6" },
                { label: "Organizations", value: usage?.by_organization?.length || 0, icon: Building2, color: "#22c55e" },
                { label: "Input Tokens", value: `${((usage?.by_organization?.reduce((s: number, o: any) => s + (o.total_input_tokens || 0), 0) || 0) / 1e6).toFixed(1)}M`, icon: Zap, color: "#a855f7" },
              ].map((stat) => (
                <div key={stat.label} className="rounded-xl p-5" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                  <div className="flex items-center justify-between mb-3">
                    <stat.icon className="w-5 h-5" style={{ color: stat.color }} />
                  </div>
                  <div className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{stat.value}</div>
                  <div className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>{stat.label}</div>
                </div>
              ))}
            </div>

            {/* Budget Bar */}
            {globalBudget && (
              <div className="rounded-xl p-5" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Monthly Budget Usage</span>
                  <span className="text-xs" style={{ color: "var(--text-secondary)" }}>${totalCost.toFixed(2)} / ${globalBudget.toFixed(0)}</span>
                </div>
                <div className="h-3 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${budgetPct}%`,
                      background: budgetPct > 80 ? "#ef4444" : budgetPct > 50 ? "#f59e0b" : "#22c55e",
                    }}
                  />
                </div>
                <div className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>{budgetPct.toFixed(1)}% used</div>
              </div>
            )}

            {/* By Model */}
            <div className="rounded-xl p-5" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              <h3 className="text-sm font-medium mb-4" style={{ color: "var(--text-primary)" }}>Cost by Model</h3>
              <div className="space-y-3">
                {Object.entries((usage?.by_model || {}) as Record<string, any>).map(([model, data]) => {
                  const pct = totalCost > 0 ? ((data.cost || 0) / totalCost) * 100 : 0;
                  return (
                    <div key={model} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium" style={{ color: modelColors[model] || "var(--text-primary)" }}>{model}</span>
                        <span className="text-xs" style={{ color: "var(--text-secondary)" }}>{data.calls} calls | ${(data.cost || 0).toFixed(2)} ({pct.toFixed(0)}%)</span>
                      </div>
                      <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: modelColors[model] || "#6b7280" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* By Organization Table */}
            <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              <div className="p-4 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                <h3 className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Usage by Organization</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ background: "var(--bg-elevated)" }}>
                      <th className="text-left px-4 py-2.5 font-medium" style={{ color: "var(--text-secondary)" }}>Organization</th>
                      <th className="text-right px-4 py-2.5 font-medium" style={{ color: "var(--text-secondary)" }}>API Calls</th>
                      <th className="text-right px-4 py-2.5 font-medium" style={{ color: "var(--text-secondary)" }}>Input Tokens</th>
                      <th className="text-right px-4 py-2.5 font-medium" style={{ color: "var(--text-secondary)" }}>Output Tokens</th>
                      <th className="text-right px-4 py-2.5 font-medium" style={{ color: "var(--text-secondary)" }}>Cost</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(usage?.by_organization || []).map((org: any, i: number) => (
                      <tr key={i} className="border-t" style={{ borderColor: "var(--border-subtle)" }}>
                        <td className="px-4 py-2.5 font-medium" style={{ color: "var(--text-primary)" }}>
                          {orgs.find((o: any) => String(o.id) === String(org.organization_id))?.name || org.organization_id?.slice(0, 8)}
                        </td>
                        <td className="px-4 py-2.5 text-right" style={{ color: "var(--text-secondary)" }}>{org.total_calls}</td>
                        <td className="px-4 py-2.5 text-right" style={{ color: "var(--text-secondary)" }}>{((org.total_input_tokens || 0) / 1000).toFixed(0)}k</td>
                        <td className="px-4 py-2.5 text-right" style={{ color: "var(--text-secondary)" }}>{((org.total_output_tokens || 0) / 1000).toFixed(0)}k</td>
                        <td className="px-4 py-2.5 text-right font-medium" style={{ color: "#d97706" }}>${(org.total_cost_usd || 0).toFixed(2)}</td>
                      </tr>
                    ))}
                    {(!usage?.by_organization || usage.by_organization.length === 0) && (
                      <tr>
                        <td colSpan={5} className="px-4 py-8 text-center" style={{ color: "var(--text-secondary)" }}>No usage data yet</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Per-Organization Tab */}
        {activeTab === "organizations" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Org List */}
              <div className="rounded-xl overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <div className="p-4 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                  <h3 className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Organizations</h3>
                </div>
                <div className="p-2 space-y-1 max-h-[60vh] overflow-y-auto">
                  {orgs.map((org: any) => (
                    <button
                      key={org.id}
                      onClick={() => loadOrgSettings(org.id)}
                      className="w-full text-left px-3 py-2.5 rounded-lg text-xs transition-all"
                      style={{
                        background: selectedOrg === org.id ? "rgba(217,119,6,0.15)" : "transparent",
                        color: selectedOrg === org.id ? "#f59e0b" : "var(--text-primary)",
                      }}
                    >
                      <div className="font-medium">{org.name}</div>
                      <div className="text-[10px] mt-0.5" style={{ color: "var(--text-secondary)" }}>{org.slug}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Org Settings Form */}
              <div className="lg:col-span-2 rounded-xl" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                {!selectedOrg ? (
                  <div className="flex items-center justify-center h-64">
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Select an organization to configure Claude DAST settings</p>
                  </div>
                ) : (
                  <div className="p-6 space-y-5">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                        {orgSettings?.name || "Organization"} - Claude Settings
                      </h3>
                      <button
                        onClick={saveOrgSettings}
                        disabled={savingOrg}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white"
                        style={{ background: "linear-gradient(135deg, #d97706, #ea580c)" }}
                      >
                        <Save className="w-3 h-3" />
                        {savingOrg ? "Saving..." : "Save"}
                      </button>
                    </div>

                    {/* Enable/Disable */}
                    <label className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={orgForm.claude_enabled}
                        onChange={(e) => setOrgForm({ ...orgForm, claude_enabled: e.target.checked })}
                      />
                      <div>
                        <div className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>Enable Claude DAST</div>
                        <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>Allow this organization to use Claude AI scanning</div>
                      </div>
                    </label>

                    {/* Budget */}
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-[10px] font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Monthly Budget (USD)</label>
                        <input
                          type="number"
                          step="0.01"
                          placeholder="Unlimited"
                          value={orgForm.claude_monthly_budget_usd}
                          onChange={(e) => setOrgForm({ ...orgForm, claude_monthly_budget_usd: e.target.value })}
                          className="w-full px-3 py-2 rounded-lg text-xs"
                          style={{ background: "var(--bg-elevated)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                        />
                      </div>
                      <div>
                        <label className="text-[10px] font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Per-Scan Limit (USD)</label>
                        <input
                          type="number"
                          step="0.01"
                          value={orgForm.claude_per_scan_limit_usd}
                          onChange={(e) => setOrgForm({ ...orgForm, claude_per_scan_limit_usd: e.target.value })}
                          className="w-full px-3 py-2 rounded-lg text-xs"
                          style={{ background: "var(--bg-elevated)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                        />
                      </div>
                    </div>

                    {/* Limits */}
                    <div>
                      <label className="text-[10px] font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>Max Scans Per Day</label>
                      <input
                        type="number"
                        value={orgForm.claude_max_scans_per_day}
                        onChange={(e) => setOrgForm({ ...orgForm, claude_max_scans_per_day: e.target.value })}
                        className="w-full px-3 py-2 rounded-lg text-xs"
                        style={{ background: "var(--bg-elevated)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                      />
                    </div>

                    {/* Deep scan approval */}
                    <label className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={orgForm.claude_deep_scan_approval_required}
                        onChange={(e) => setOrgForm({ ...orgForm, claude_deep_scan_approval_required: e.target.checked })}
                      />
                      <div>
                        <div className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>Require Approval for Deep Scans</div>
                        <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>Admin must approve deep scan mode before execution</div>
                      </div>
                    </label>

                    {/* DAST API Key */}
                    <div>
                      <label className="text-[10px] font-medium block mb-1" style={{ color: "var(--text-secondary)" }}>
                        Anthropic API Key (per-org override)
                      </label>
                      {orgForm.claude_dast_api_key_set && (
                        <div className="text-[10px] mb-1 flex items-center gap-1" style={{ color: "#22c55e" }}>
                          <CheckCircle className="w-3 h-3" /> Key configured: {orgForm.claude_dast_api_key_preview}
                        </div>
                      )}
                      <input
                        type="password"
                        placeholder={orgForm.claude_dast_api_key_set ? "Enter new key to replace existing" : "sk-ant-api03-... (leave blank to use global key)"}
                        value={orgForm.claude_dast_api_key}
                        onChange={(e) => setOrgForm({ ...orgForm, claude_dast_api_key: e.target.value })}
                        className="w-full px-3 py-2 rounded-lg text-xs"
                        style={{ background: "var(--bg-elevated)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
                      />
                      <div className="text-[10px] mt-1" style={{ color: "var(--text-secondary)" }}>
                        If set, this org uses its own Anthropic API key for Claude DAST scans instead of the global key.
                      </div>
                    </div>

                    {/* Allowed Models */}
                    <div>
                      <label className="text-[10px] font-medium block mb-2" style={{ color: "var(--text-secondary)" }}>Allowed Models</label>
                      <div className="space-y-2">
                        {[
                          { id: "claude-haiku-4-5", label: "Haiku 4.5", desc: "Fast, cheapest ($1/$5 per 1M tokens)" },
                          { id: "claude-sonnet-4-6", label: "Sonnet 4.6", desc: "Balanced ($3/$15 per 1M tokens)" },
                          { id: "claude-opus-4-6", label: "Opus 4.6", desc: "Most capable ($15/$75 per 1M tokens)" },
                        ].map((model) => (
                          <label key={model.id} className="flex items-center gap-3 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={orgForm.claude_allowed_models.includes(model.id)}
                              onChange={(e) => {
                                const models = e.target.checked
                                  ? [...orgForm.claude_allowed_models, model.id]
                                  : orgForm.claude_allowed_models.filter((m) => m !== model.id);
                                setOrgForm({ ...orgForm, claude_allowed_models: models });
                              }}
                            />
                            <div>
                              <div className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{model.label}</div>
                              <div className="text-[10px]" style={{ color: "var(--text-secondary)" }}>{model.desc}</div>
                            </div>
                          </label>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Global Settings Tab */}
        {activeTab === "settings" && globalSettings && (
          <div className="max-w-2xl space-y-4">
            <div className="rounded-xl p-5" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              <h3 className="text-sm font-medium mb-4" style={{ color: "var(--text-primary)" }}>Global Claude DAST Configuration</h3>
              <div className="space-y-3">
                {[
                  { label: "Claude DAST Enabled", value: globalSettings.claude_dast_enabled ? "Yes" : "No", icon: globalSettings.claude_dast_enabled ? CheckCircle : XCircle, color: globalSettings.claude_dast_enabled ? "#22c55e" : "#ef4444" },
                  { label: "Default Model", value: globalSettings.claude_dast_default_model, icon: Cpu, color: "#3b82f6" },
                  { label: "Max Cost Per Scan", value: `$${globalSettings.claude_dast_max_cost_per_scan}`, icon: DollarSign, color: "#d97706" },
                  { label: "Max API Calls", value: globalSettings.claude_dast_max_api_calls, icon: Activity, color: "#a855f7" },
                  { label: "Max Daily Scans", value: globalSettings.claude_dast_max_daily_scans, icon: BarChart3, color: "#22c55e" },
                  { label: "Session TTL", value: `${globalSettings.claude_dast_session_ttl_days} days`, icon: Zap, color: "#f59e0b" },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between p-3 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
                    <div className="flex items-center gap-2">
                      <item.icon className="w-4 h-4" style={{ color: item.color }} />
                      <span className="text-xs" style={{ color: "var(--text-secondary)" }}>{item.label}</span>
                    </div>
                    <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{item.value}</span>
                  </div>
                ))}
              </div>
              <p className="text-[10px] mt-4" style={{ color: "var(--text-secondary)" }}>
                Global settings are configured via environment variables. Per-organization overrides can be set in the Organizations tab.
              </p>
            </div>

            {/* Allowed Models */}
            <div className="rounded-xl p-5" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              <h3 className="text-sm font-medium mb-3" style={{ color: "var(--text-primary)" }}>Allowed Models (Global)</h3>
              <div className="flex flex-wrap gap-2">
                {(globalSettings.claude_dast_allowed_models || []).map((model: string) => (
                  <span key={model} className="text-xs px-2.5 py-1 rounded-full font-medium" style={{ background: `${modelColors[model] || "#6b7280"}20`, color: modelColors[model] || "#6b7280" }}>
                    {model}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
