"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import {
  Search, Filter, Calendar, ChevronLeft, ChevronRight,
  Activity, Users, RefreshCw, BarChart3, Clock,
  Globe
} from "lucide-react";

const ACTION_COLORS: Record<string, string> = {
  login: "text-emerald-400 bg-emerald-500/10",
  logout: "text-slate-400 bg-slate-500/10",
  create_project: "text-blue-400 bg-blue-500/10",
  create_finding: "text-red-400 bg-red-500/10",
  user_update: "text-amber-400 bg-amber-500/10",
  user_password_change: "text-purple-400 bg-purple-500/10",
  update_project: "text-cyan-400 bg-cyan-500/10",
  delete_finding: "text-red-400 bg-red-500/10",
};

export default function AuditPage() {
  const { user, hydrate } = useAuthStore();
  const router = useRouter();
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [actions, setActions] = useState<string[]>([]);
  const [resourceTypes, setResourceTypes] = useState<string[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [orgs, setOrgs] = useState<any[]>([]);

  // Filters
  const [page, setPage] = useState(0);
  const [pageSize] = useState(25);
  const [filterAction, setFilterAction] = useState("");
  const [filterResourceType, setFilterResourceType] = useState("");
  const [filterSearch, setFilterSearch] = useState("");
  const [filterDateFrom, setFilterDateFrom] = useState("");
  const [filterDateTo, setFilterDateTo] = useState("");
  const [filterOrgId, setFilterOrgId] = useState("");
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && !isAdmin(user.role)) {
      router.replace("/dashboard");
    }
  }, [user, router]);

  const loadLogs = useCallback(async () => {
    if (!user || !isAdmin(user.role)) return;
    setLoading(true);
    try {
      const result = await api.auditLogs({
        limit: pageSize,
        offset: page * pageSize,
        action: filterAction || undefined,
        resource_type: filterResourceType || undefined,
        search: filterSearch || undefined,
        date_from: filterDateFrom || undefined,
        date_to: filterDateTo || undefined,
        org_id: filterOrgId || undefined,
      });
      setLogs(result.logs || []);
      setTotal(result.total || 0);
      setActions(result.actions || []);
      setResourceTypes(result.resource_types || []);
    } catch {
      toast.error("Failed to load audit logs");
    } finally {
      setLoading(false);
    }
  }, [user, page, pageSize, filterAction, filterResourceType, filterSearch, filterDateFrom, filterDateTo, filterOrgId]);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  useEffect(() => {
    if (user && isAdmin(user.role)) {
      api.auditStats(30).then(setStats).catch(() => {});
      if (isSuperAdmin(user.role)) {
        api.listOrganizations().then(setOrgs).catch(() => {});
      }
    }
  }, [user]);

  const totalPages = Math.ceil(total / pageSize);

  const clearFilters = () => {
    setFilterAction("");
    setFilterResourceType("");
    setFilterSearch("");
    setFilterDateFrom("");
    setFilterDateTo("");
    setFilterOrgId("");
    setPage(0);
  };

  const hasFilters = filterAction || filterResourceType || filterSearch || filterDateFrom || filterDateTo || filterOrgId;

  const formatTime = (iso: string) => {
    const d = new Date(iso);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: d.getFullYear() !== now.getFullYear() ? "numeric" : undefined });
  };

  if (!user || !isAdmin(user.role)) return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-2xl mx-auto p-6 mt-20">
        <div className="card p-8 text-center">
          <Activity className="w-12 h-12 mx-auto mb-4" style={{ color: "var(--text-muted)" }} />
          <h2 className="text-lg font-semibold mb-2" style={{ color: "var(--text-primary)" }}>Audit Trail — Restricted Access</h2>
          <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
            Audit trail access requires Admin or Super Admin privileges. This feature provides complete activity logging across your organization for compliance and security monitoring.
          </p>
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            Contact your organization administrator or email <strong>support@appsec.dev</strong> to request access.
          </p>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-7xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
              <Activity className="w-5 h-5 text-indigo-400" />
              Audit Trail
              {isSuperAdmin(user.role) && <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded-full ml-1">Platform-wide</span>}
              {!isSuperAdmin(user.role) && <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded-full ml-1">Organization</span>}
            </h1>
            <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
              {isSuperAdmin(user.role) ? "Complete platform activity log across all organizations" : "Organization activity log for your team"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={loadLogs}
              className="p-2 rounded-lg transition-all hover:opacity-80" style={{ color: "var(--text-muted)", background: "var(--bg-hover)" }}>
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            </button>
            <button onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                showFilters || hasFilters
                  ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                  : ""
              }`}
              style={!(showFilters || hasFilters) ? { color: "var(--text-muted)", background: "var(--bg-hover)" } : {}}>
              <Filter className="w-3.5 h-3.5" />
              Filters
              {hasFilters && <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />}
            </button>
          </div>
        </motion.div>

        {/* Stats Cards */}
        {stats && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
            className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="card p-4 border-blue-500/10 bg-gradient-to-br from-blue-500/5 to-cyan-500/5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium uppercase" style={{ color: "var(--text-muted)" }}>Total Events</p>
                  <p className="text-2xl font-bold mt-1 tabular-nums" style={{ color: "var(--text-primary)" }}>{stats.total_events}</p>
                </div>
                <div className="w-9 h-9 rounded-xl flex items-center justify-center text-blue-400" style={{ background: "var(--bg-card)" }}>
                  <BarChart3 className="w-4 h-4" />
                </div>
              </div>
            </div>
            <div className="card p-4 border-emerald-500/10 bg-gradient-to-br from-emerald-500/5 to-green-500/5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium uppercase" style={{ color: "var(--text-muted)" }}>Active Users</p>
                  <p className="text-2xl font-bold mt-1 tabular-nums" style={{ color: "var(--text-primary)" }}>{stats.unique_users}</p>
                </div>
                <div className="w-9 h-9 rounded-xl flex items-center justify-center text-emerald-400" style={{ background: "var(--bg-card)" }}>
                  <Users className="w-4 h-4" />
                </div>
              </div>
            </div>
            <div className="card p-4 border-indigo-500/10 bg-gradient-to-br from-indigo-500/5 to-purple-500/5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium uppercase" style={{ color: "var(--text-muted)" }}>Top Action</p>
                  <p className="text-lg font-bold mt-1 truncate" style={{ color: "var(--text-primary)" }}>
                    {stats.by_action?.[0]?.action || "-"}
                  </p>
                </div>
                <div className="w-9 h-9 rounded-xl flex items-center justify-center text-indigo-400" style={{ background: "var(--bg-card)" }}>
                  <Activity className="w-4 h-4" />
                </div>
              </div>
            </div>
            <div className="card p-4 border-amber-500/10 bg-gradient-to-br from-amber-500/5 to-orange-500/5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium uppercase" style={{ color: "var(--text-muted)" }}>Records Found</p>
                  <p className="text-2xl font-bold mt-1 tabular-nums" style={{ color: "var(--text-primary)" }}>{total}</p>
                </div>
                <div className="w-9 h-9 rounded-xl flex items-center justify-center text-amber-400" style={{ background: "var(--bg-card)" }}>
                  <Clock className="w-4 h-4" />
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Filters */}
        {showFilters && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}
            className="card p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Filter Logs</h3>
              {hasFilters && (
                <button onClick={clearFilters} className="text-xs text-indigo-400 hover:text-indigo-300">
                  Clear all
                </button>
              )}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                <input className="input-field pl-9 py-2 text-sm" placeholder="Search actions..."
                  value={filterSearch} onChange={e => { setFilterSearch(e.target.value); setPage(0); }} />
              </div>
              <select className="input-field py-2 text-sm" value={filterAction}
                onChange={e => { setFilterAction(e.target.value); setPage(0); }}>
                <option value="">All actions</option>
                {actions.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
              <select className="input-field py-2 text-sm" value={filterResourceType}
                onChange={e => { setFilterResourceType(e.target.value); setPage(0); }}>
                <option value="">All resources</option>
                {resourceTypes.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
              {isSuperAdmin(user.role) && orgs.length > 0 && (
                <select className="input-field py-2 text-sm" value={filterOrgId}
                  onChange={e => { setFilterOrgId(e.target.value); setPage(0); }}>
                  <option value="">All organizations</option>
                  {orgs.map((o: any) => <option key={o.id} value={o.id}>{o.name}</option>)}
                </select>
              )}
              <div className="relative">
                <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                <input type="date" className="input-field pl-9 py-2 text-sm"
                  value={filterDateFrom} onChange={e => { setFilterDateFrom(e.target.value); setPage(0); }} />
              </div>
              <div className="relative">
                <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                <input type="date" className="input-field pl-9 py-2 text-sm"
                  value={filterDateTo} onChange={e => { setFilterDateTo(e.target.value); setPage(0); }} />
              </div>
            </div>
          </motion.div>
        )}

        {/* Log entries */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
            <span className="text-sm" style={{ color: "var(--text-secondary)" }}>
              {total} event{total !== 1 ? "s" : ""}
              {hasFilters && " (filtered)"}
            </span>
            <div className="flex items-center gap-2 text-xs" style={{ color: "var(--text-muted)" }}>
              Page {page + 1} of {totalPages || 1}
            </div>
          </div>

          {loading ? (
            <div className="p-8 space-y-3">
              {[1, 2, 3, 4, 5].map(i => (
                <div key={i} className="h-14 rounded-lg animate-shimmer" style={{ background: "var(--bg-elevated)" }} />
              ))}
            </div>
          ) : logs.length === 0 ? (
            <div className="p-16 text-center">
              <Activity className="w-10 h-10 mx-auto mb-3" style={{ color: "var(--text-muted)" }} />
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>No audit events found</p>
              {hasFilters && <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>Try adjusting your filters</p>}
            </div>
          ) : (
            <div>
              {logs.map((l, i) => (
                <motion.div key={l.id}
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}
                  className="px-4 py-3 transition-colors group"
                  style={{ borderBottom: "1px solid var(--border-subtle)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--table-hover)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                  <div className="flex items-center gap-4">
                    <div className={`shrink-0 px-2.5 py-1 rounded-lg text-xs font-semibold ${ACTION_COLORS[l.action] || ""}`}
                      style={!ACTION_COLORS[l.action] ? { color: "var(--text-secondary)", background: "var(--bg-elevated)" } : {}}>
                      {l.action}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 text-sm">
                        <span className="font-medium truncate" style={{ color: "var(--text-primary)" }}>{l.user_name || "System"}</span>
                        {l.user_role && (
                          <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                            l.user_role === "super_admin" ? "text-amber-400 bg-amber-500/10" :
                            l.user_role === "admin" ? "text-emerald-400 bg-emerald-500/10" :
                            ""
                          }`}
                          style={!["super_admin", "admin"].includes(l.user_role) ? { color: "var(--text-muted)", background: "var(--bg-elevated)" } : {}}>
                            {l.user_role === "super_admin" ? "SA" : l.user_role}
                          </span>
                        )}
                        {l.resource_type && (
                          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                            on <span style={{ color: "var(--text-secondary)" }}>{l.resource_type}</span>
                            {l.resource_id && <span style={{ color: "var(--text-muted)" }}> #{l.resource_id.slice(0, 8)}</span>}
                          </span>
                        )}
                      </div>
                      {l.details && Object.keys(l.details).length > 0 && (
                        <div className="text-xs mt-0.5 truncate max-w-md" style={{ color: "var(--text-muted)" }}>
                          {Object.entries(l.details).map(([k, v]) =>
                            `${k}: ${typeof v === "string" ? v.slice(0, 40) : JSON.stringify(v).slice(0, 40)}`
                          ).join(" | ")}
                        </div>
                      )}
                    </div>
                    <div className="shrink-0 text-right hidden md:block">
                      <div className="text-xs flex items-center gap-1 justify-end" style={{ color: "var(--text-muted)" }}>
                        <Clock className="w-3 h-3" />
                        {formatTime(l.created_at)}
                      </div>
                      {l.ip_address && (
                        <div className="text-[10px] flex items-center gap-1 justify-end mt-0.5" style={{ color: "var(--text-muted)" }}>
                          <Globe className="w-2.5 h-2.5" />
                          {l.ip_address}
                        </div>
                      )}
                    </div>
                    <div className="shrink-0 text-[10px] hidden lg:block w-32 text-right tabular-nums" style={{ color: "var(--text-muted)" }}>
                      {new Date(l.created_at).toLocaleString()}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="px-4 py-3 flex items-center justify-between" style={{ borderTop: "1px solid var(--border-subtle)" }}>
              <button onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0}
                className="flex items-center gap-1 text-sm disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                style={{ color: "var(--text-secondary)" }}>
                <ChevronLeft className="w-4 h-4" /> Previous
              </button>
              <div className="flex items-center gap-1">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum: number;
                  if (totalPages <= 5) pageNum = i;
                  else if (page < 3) pageNum = i;
                  else if (page > totalPages - 4) pageNum = totalPages - 5 + i;
                  else pageNum = page - 2 + i;
                  return (
                    <button key={pageNum} onClick={() => setPage(pageNum)}
                      className={`w-8 h-8 rounded-lg text-xs font-medium transition-all ${
                        page === pageNum ? "bg-indigo-500 text-white" : ""
                      }`}
                      style={page !== pageNum ? { color: "var(--text-muted)", background: "var(--bg-hover)" } : {}}>
                      {pageNum + 1}
                    </button>
                  );
                })}
              </div>
              <button onClick={() => setPage(Math.min(totalPages - 1, page + 1))} disabled={page >= totalPages - 1}
                className="flex items-center gap-1 text-sm disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                style={{ color: "var(--text-secondary)" }}>
                Next <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
