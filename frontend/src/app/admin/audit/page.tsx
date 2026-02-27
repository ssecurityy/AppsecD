"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";

export default function AuditPage() {
  const { user, hydrate } = useAuthStore();
  const router = useRouter();
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user?.role !== "admin") {
      router.replace("/dashboard");
      return;
    }
    api.auditLogs().then(setLogs).catch(() => []).finally(() => setLoading(false));
  }, [user, router]);

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-4xl mx-auto p-6">
        <h1 className="text-xl font-bold text-white mb-4">Audit Log</h1>
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
          </div>
        )}
      </div>
    </div>
  );
}
