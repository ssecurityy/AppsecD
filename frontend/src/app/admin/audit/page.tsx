"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { ChevronLeft, ChevronRight } from "lucide-react";

const PAGE_SIZE = 25;

const ACTION_TYPES = [
  "",
  "login",
  "logout",
  "create_user",
  "update_user",
  "create_project",
  "update_project",
  "create_finding",
  "update_finding",
  "update_settings",
  "export_report",
];

export default function AuditPage() {
  const { user, hydrate } = useAuthStore();
  const router = useRouter();
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [actionFilter, setActionFilter] = useState("");

  const loadLogs = useCallback(async (newOffset: number, action: string) => {
    setLoading(true);
    try {
      const params: Record<string, string> = { limit: String(PAGE_SIZE), offset: String(newOffset) };
      if (action) params.action = action;
      const result = await api.auditLogs(params as any);
      if (Array.isArray(result)) {
        setLogs(result);
        setTotal(result.length >= PAGE_SIZE ? newOffset + PAGE_SIZE + 1 : newOffset + result.length);
      } else if (result && typeof result === "object") {
        setLogs(result.items || result.logs || []);
        setTotal(result.total ?? (result.items || result.logs || []).length + newOffset);
      }
    } catch {
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user?.role !== "admin") {
      router.replace("/dashboard");
      return;
    }
    loadLogs(0, "");
  }, [user, router, loadLogs]);

  const handleFilterChange = (action: string) => {
    setActionFilter(action);
    setOffset(0);
    loadLogs(0, action);
  };

  const handlePrev = () => {
    const newOffset = Math.max(0, offset - PAGE_SIZE);
    setOffset(newOffset);
    loadLogs(newOffset, actionFilter);
  };

  const handleNext = () => {
    const newOffset = offset + PAGE_SIZE;
    setOffset(newOffset);
    loadLogs(newOffset, actionFilter);
  };

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-4xl mx-auto p-6">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-bold text-white">Audit Log</h1>
          <div className="flex items-center gap-3">
            <select
              value={actionFilter}
              onChange={(e) => handleFilterChange(e.target.value)}
              className="bg-[#111827] border border-[#1F2937] rounded px-3 py-1.5 text-white text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="">All Actions</option>
              {ACTION_TYPES.filter(Boolean).map((a) => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
            <span className="text-xs text-[#9CA3AF]">
              {total > 0 ? `${offset + 1}–${offset + logs.length} of ${total >= offset + PAGE_SIZE + 1 ? `${total}+` : total}` : "0 results"}
            </span>
          </div>
        </div>
        {loading ? (
          <div className="text-[#9CA3AF]">Loading...</div>
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1F2937]">
                  <th className="text-left p-3 text-[#9CA3AF]">Time</th>
                  <th className="text-left p-3 text-[#9CA3AF]">Action</th>
                  <th className="text-left p-3 text-[#9CA3AF]">Resource</th>
                  <th className="text-left p-3 text-[#9CA3AF]">Details</th>
                  <th className="text-left p-3 text-[#9CA3AF]">IP</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((l) => (
                  <tr key={l.id} className="border-b border-[#1F2937] hover:bg-[#0D1424]">
                    <td className="p-3 text-[#9CA3AF] text-xs">{new Date(l.created_at).toLocaleString()}</td>
                    <td className="p-3 text-blue-400">{l.action}</td>
                    <td className="p-3 text-white">{l.resource_type} {l.resource_id ? `#${l.resource_id.slice(0, 8)}` : ""}</td>
                    <td className="p-3 text-[#9CA3AF] text-xs">{JSON.stringify(l.details)}</td>
                    <td className="p-3 text-[#6B7280]">{l.ip_address || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {logs.length === 0 && <div className="p-8 text-center text-[#9CA3AF]">No audit logs yet</div>}
            {(offset > 0 || logs.length >= PAGE_SIZE) && (
              <div className="flex items-center justify-between p-3 border-t border-[#1F2937]">
                <button
                  onClick={handlePrev}
                  disabled={offset === 0}
                  className="flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-[#1F2937] hover:bg-[#374151] disabled:opacity-30 text-white"
                >
                  <ChevronLeft className="w-4 h-4" /> Previous
                </button>
                <span className="text-xs text-[#9CA3AF]">Page {Math.floor(offset / PAGE_SIZE) + 1}</span>
                <button
                  onClick={handleNext}
                  disabled={logs.length < PAGE_SIZE}
                  className="flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-[#1F2937] hover:bg-[#374151] disabled:opacity-30 text-white"
                >
                  Next <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
