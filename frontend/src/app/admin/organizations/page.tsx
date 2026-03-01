"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { Building2, Plus, UserPlus, FolderPlus, X } from "lucide-react";

export default function AdminOrganizationsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [orgs, setOrgs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", slug: "" });
  const [users, setUsers] = useState<any[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [assignOrgId, setAssignOrgId] = useState<string | null>(null);
  const [assignUserId, setAssignUserId] = useState("");
  const [assignProjectId, setAssignProjectId] = useState("");

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && user.role !== "admin") {
      router.replace("/dashboard");
      return;
    }
    if (!user && !loading) router.replace("/login");
  }, [user, router, loading]);

  const loadOrgs = async () => {
    try {
      const list = await api.listOrganizations();
      setOrgs(list);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load organizations");
    } finally {
      setLoading(false);
    }
  };

  const loadUsersAndProjects = async () => {
    try {
      const [u, p] = await Promise.all([api.users(), api.listProjects()]);
      setUsers(u);
      setProjects(p);
    } catch {}
  };

  useEffect(() => {
    if (user?.role === "admin") {
      loadOrgs();
      loadUsersAndProjects();
    }
  }, [user]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createOrganization({ name: form.name, slug: form.slug || form.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") });
      toast.success("Organization created");
      setForm({ name: "", slug: "" });
      setShowForm(false);
      loadOrgs();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to create organization");
    }
  };

  const handleAssignUser = async () => {
    if (!assignOrgId || !assignUserId) return;
    try {
      await api.assignUserToOrg(assignOrgId, assignUserId);
      toast.success("User assigned to organization");
      setAssignUserId("");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to assign user");
    }
  };

  const handleAssignProject = async () => {
    if (!assignOrgId || !assignProjectId) return;
    try {
      await api.assignProjectToOrg(assignOrgId, assignProjectId);
      toast.success("Project assigned to organization");
      setAssignProjectId("");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to assign project");
    }
  };

  if (!user) return null;
  if (user.role !== "admin") return null;

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-2xl mx-auto p-4">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Building2 className="w-5 h-5 text-blue-400" /> Organizations
          </h1>
          <button
            onClick={() => setShowForm(!showForm)}
            className="btn-primary flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Create Org
          </button>
        </div>

        {showForm && (
          <form onSubmit={handleCreate} className="card p-4 mb-6 space-y-3">
            <h3 className="text-sm font-semibold text-white">New Organization</h3>
            <input
              className="input-field"
              placeholder="Organization name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <input
              className="input-field"
              placeholder="Slug (auto-generated if empty)"
              value={form.slug}
              onChange={(e) => setForm({ ...form, slug: e.target.value })}
            />
            <div className="flex gap-2">
              <button type="submit" className="btn-primary">Create</button>
              <button type="button" onClick={() => setShowForm(false)} className="btn-secondary">Cancel</button>
            </div>
          </form>
        )}

        <div className="card overflow-hidden">
          {loading ? (
            <div className="p-8 text-center text-[#9CA3AF]">Loading...</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1F2937] text-left text-[#9CA3AF]">
                  <th className="p-3">Name</th>
                  <th className="p-3">Slug</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {orgs.map((o) => (
                  <tr key={o.id} className="border-b border-[#1F2937]/50 hover:bg-[#1F2937]/30">
                    <td className="p-3">
                      <div className="font-medium text-white">{o.name}</div>
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-xs bg-blue-900/40 text-blue-300 border border-blue-800">
                        {o.slug}
                      </span>
                    </td>
                    <td className="p-3">
                      <button
                        onClick={() => setAssignOrgId(assignOrgId === o.id ? null : o.id)}
                        className="text-blue-400 hover:text-blue-300 text-xs px-2 py-1 rounded border border-blue-800 hover:bg-blue-900/20"
                      >
                        {assignOrgId === o.id ? "Close" : "Assign"}
                      </button>
                    </td>
                  </tr>
                ))}
                {orgs.length === 0 && (
                  <tr>
                    <td colSpan={3} className="p-8 text-center text-[#9CA3AF]">No organizations yet</td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {assignOrgId && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="card p-6 w-full max-w-md space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">
                  Assign to: {orgs.find((o) => o.id === assignOrgId)?.name}
                </h3>
                <button onClick={() => setAssignOrgId(null)} className="text-[#6B7280] hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2">
                <label className="block text-xs font-medium text-[#9CA3AF]">
                  <UserPlus className="w-3 h-3 inline mr-1" /> Assign User
                </label>
                <div className="flex gap-2">
                  <select
                    className="input-field flex-1"
                    value={assignUserId}
                    onChange={(e) => setAssignUserId(e.target.value)}
                  >
                    <option value="">Select user</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>{u.full_name} (@{u.username})</option>
                    ))}
                  </select>
                  <button onClick={handleAssignUser} disabled={!assignUserId} className="btn-primary disabled:opacity-50">
                    Assign
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <label className="block text-xs font-medium text-[#9CA3AF]">
                  <FolderPlus className="w-3 h-3 inline mr-1" /> Assign Project
                </label>
                <div className="flex gap-2">
                  <select
                    className="input-field flex-1"
                    value={assignProjectId}
                    onChange={(e) => setAssignProjectId(e.target.value)}
                  >
                    <option value="">Select project</option>
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>{p.application_name}</option>
                    ))}
                  </select>
                  <button onClick={handleAssignProject} disabled={!assignProjectId} className="btn-primary disabled:opacity-50">
                    Assign
                  </button>
                </div>
              </div>

              <button onClick={() => setAssignOrgId(null)} className="btn-secondary w-full">
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
