"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
import toast from "react-hot-toast";
import { motion } from "framer-motion";
import {
  Building2, Plus, Users, FolderOpen, Search, Shield
} from "lucide-react";

export default function AdminOrganizationsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [orgs, setOrgs] = useState<any[]>([]);
  const [allUsers, setAllUsers] = useState<any[]>([]);
  const [allProjects, setAllProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [search, setSearch] = useState("");
  const [form, setForm] = useState({ name: "", slug: "" });

  // Assignment modals
  const [assignUserOrg, setAssignUserOrg] = useState<string | null>(null);
  const [assignProjectOrg, setAssignProjectOrg] = useState<string | null>(null);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [selectedProjectId, setSelectedProjectId] = useState("");

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && !isAdmin(user.role)) router.replace("/dashboard");
  }, [user, router]);

  const loadData = async () => {
    try {
      const [orgList, userList] = await Promise.all([
        api.listOrganizations(),
        api.users(),
      ]);
      setOrgs(orgList);
      setAllUsers(userList);
      try {
        const projList = await api.listProjects({ limit: 200 });
        setAllProjects(projList.items || projList);
      } catch {
        setAllProjects([]);
      }
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user && isAdmin(user.role)) loadData();
  }, [user]);

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createOrganization({ name: form.name, slug: form.slug || undefined });
      toast.success("Organization created");
      setForm({ name: "", slug: "" });
      setShowForm(false);
      loadData();
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleAssignUser = async () => {
    if (!assignUserOrg || !selectedUserId) return;
    try {
      await api.updateUser(selectedUserId, { organization_id: assignUserOrg });
      toast.success("User assigned to organization");
      setAssignUserOrg(null);
      setSelectedUserId("");
      loadData();
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleAssignProject = async () => {
    if (!assignProjectOrg || !selectedProjectId) return;
    try {
      await api.updateProject(selectedProjectId, { organization_id: assignProjectOrg });
      toast.success("Project assigned to organization");
      setAssignProjectOrg(null);
      setSelectedProjectId("");
      loadData();
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const filtered = orgs.filter((o) =>
    !search || o.name.toLowerCase().includes(search.toLowerCase()) || o.slug.toLowerCase().includes(search.toLowerCase())
  );

  if (!user || !isAdmin(user.role)) return null;

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
              <Building2 className="w-5 h-5 text-emerald-400" /> Organizations
              {isSuperAdmin(user.role) && <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded-full">Super Admin</span>}
            </h1>
            <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
              Manage organizations, assign users and projects
            </p>
          </div>
          {isSuperAdmin(user.role) && (
            <button onClick={() => setShowForm(!showForm)}
              className="btn-primary flex items-center gap-1.5 text-sm py-2 px-4">
              <Plus className="w-3.5 h-3.5" /> New Organization
            </button>
          )}
        </motion.div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-3">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-4 text-center">
            <p className="text-2xl font-bold tabular-nums" style={{ color: "var(--text-primary)" }}>{orgs.length}</p>
            <p className="text-xs font-medium mt-0.5 text-emerald-400">Organizations</p>
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-4 text-center">
            <p className="text-2xl font-bold tabular-nums" style={{ color: "var(--text-primary)" }}>{allUsers.length}</p>
            <p className="text-xs font-medium mt-0.5 text-indigo-400">Total Users</p>
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-4 text-center">
            <p className="text-2xl font-bold tabular-nums" style={{ color: "var(--text-primary)" }}>{allProjects.length}</p>
            <p className="text-xs font-medium mt-0.5 text-purple-400">Total Projects</p>
          </motion.div>
        </div>

        {/* Create Form */}
        {showForm && isSuperAdmin(user.role) && (
          <motion.form initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
            onSubmit={handleCreateOrg} className="card p-4 space-y-3">
            <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
              <Building2 className="w-4 h-4 text-emerald-400" /> New Organization
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input className="input-field py-2 text-sm" placeholder="Organization name" required
                value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              <input className="input-field py-2 text-sm" placeholder="Slug (auto if empty)"
                value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} />
              <div className="flex gap-2">
                <button type="submit" className="btn-primary text-sm flex-1">Create</button>
                <button type="button" onClick={() => setShowForm(false)} className="btn-secondary text-sm">Cancel</button>
              </div>
            </div>
          </motion.form>
        )}

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
          <input className="input-field pl-9 py-2 text-sm w-full" placeholder="Search organizations..."
            value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>

        {/* Org List */}
        <div className="space-y-4">
          {loading ? (
            <div className="card p-8 space-y-3">
              {[1, 2, 3].map((i) => <div key={i} className="h-14 rounded-lg animate-shimmer" style={{ background: "var(--bg-elevated)" }} />)}
            </div>
          ) : filtered.length === 0 ? (
            <div className="card p-12 text-center">
              <Building2 className="w-8 h-8 mx-auto mb-2" style={{ color: "var(--text-muted)" }} />
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>No organizations found</p>
            </div>
          ) : (
            filtered.map((org, i) => {
              const orgUsers = allUsers.filter((u) => u.organization_id === org.id);
              const orgProjects = allProjects.filter((p: any) => p.organization_id === org.id);
              return (
                <motion.div key={org.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }} className="card overflow-hidden">
                  <div className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 font-bold">
                          {org.name[0].toUpperCase()}
                        </div>
                        <div>
                          <h3 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{org.name}</h3>
                          <p className="text-xs" style={{ color: "var(--text-muted)" }}>/{org.slug}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-xs" style={{ color: "var(--text-secondary)" }}>
                        <span className="flex items-center gap-1"><Users className="w-3 h-3" /> {orgUsers.length} users</span>
                        <span className="flex items-center gap-1"><FolderOpen className="w-3 h-3" /> {orgProjects.length} projects</span>
                      </div>
                    </div>

                    {/* Users in this org */}
                    {orgUsers.length > 0 && (
                      <div className="mb-3">
                        <h4 className="text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Members</h4>
                        <div className="flex flex-wrap gap-1.5">
                          {orgUsers.slice(0, 10).map((u) => (
                            <span key={u.id} className="text-xs px-2 py-1 rounded" style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}>
                              {u.full_name} <span style={{ color: "var(--text-muted)" }}>({u.role})</span>
                            </span>
                          ))}
                          {orgUsers.length > 10 && (
                            <span className="text-xs px-2 py-1" style={{ color: "var(--text-muted)" }}>+{orgUsers.length - 10} more</span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Actions */}
                    {isSuperAdmin(user.role) && (
                      <div className="flex gap-2 mt-3">
                        <button onClick={() => { setAssignUserOrg(org.id); setSelectedUserId(""); }}
                          className="text-xs px-3 py-1.5 rounded border border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/10 transition-colors flex items-center gap-1">
                          <Users className="w-3 h-3" /> Assign User
                        </button>
                        <button onClick={() => { setAssignProjectOrg(org.id); setSelectedProjectId(""); }}
                          className="text-xs px-3 py-1.5 rounded border border-purple-500/30 text-purple-400 hover:bg-purple-500/10 transition-colors flex items-center gap-1">
                          <FolderOpen className="w-3 h-3" /> Assign Project
                        </button>
                      </div>
                    )}
                  </div>
                </motion.div>
              );
            })
          )}
        </div>

        {/* Assign User Modal */}
        {assignUserOrg && (
          <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setAssignUserOrg(null)}>
            <div className="rounded-lg max-w-md w-full p-5" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }} onClick={(e) => e.stopPropagation()}>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <Users className="w-4 h-4 text-indigo-400" /> Assign User to Organization
              </h3>
              <select className="input-field py-2 text-sm w-full mb-3" value={selectedUserId}
                onChange={(e) => setSelectedUserId(e.target.value)}>
                <option value="">Select a user...</option>
                {allUsers.filter((u) => u.organization_id !== assignUserOrg).map((u) => (
                  <option key={u.id} value={u.id}>{u.full_name} (@{u.username})</option>
                ))}
              </select>
              <div className="flex gap-2">
                <button onClick={handleAssignUser} disabled={!selectedUserId}
                  className="btn-primary text-sm flex-1 disabled:opacity-50">Assign</button>
                <button onClick={() => setAssignUserOrg(null)} className="btn-secondary text-sm">Cancel</button>
              </div>
            </div>
          </div>
        )}

        {/* Assign Project Modal */}
        {assignProjectOrg && (
          <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setAssignProjectOrg(null)}>
            <div className="rounded-lg max-w-md w-full p-5" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }} onClick={(e) => e.stopPropagation()}>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <FolderOpen className="w-4 h-4 text-purple-400" /> Assign Project to Organization
              </h3>
              <select className="input-field py-2 text-sm w-full mb-3" value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}>
                <option value="">Select a project...</option>
                {allProjects.map((p: any) => (
                  <option key={p.id} value={p.id}>{p.application_name || p.name}</option>
                ))}
              </select>
              <div className="flex gap-2">
                <button onClick={handleAssignProject} disabled={!selectedProjectId}
                  className="btn-primary text-sm flex-1 disabled:opacity-50">Assign</button>
                <button onClick={() => setAssignProjectOrg(null)} className="btn-secondary text-sm">Cancel</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
