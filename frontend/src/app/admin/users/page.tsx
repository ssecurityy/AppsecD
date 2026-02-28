"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
import toast from "react-hot-toast";
import { motion } from "framer-motion";
import {
  UserPlus, Shield, Crown, Building2, Search, Edit2, Check, X,
  Users, Eye, Key, ToggleLeft, ToggleRight, ChevronDown, Plus
} from "lucide-react";

const ROLE_COLORS: Record<string, string> = {
  super_admin: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  admin: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  lead: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  tester: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20",
  viewer: "text-[#94a3b8] bg-[#161922] border-[#1e2330]",
};

const ROLE_LABELS: Record<string, string> = {
  super_admin: "Super Admin",
  admin: "Org Admin",
  lead: "Lead",
  tester: "Tester",
  viewer: "Viewer",
};

export default function AdminUsersPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [users, setUsers] = useState<any[]>([]);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [showOrgForm, setShowOrgForm] = useState(false);
  const [search, setSearch] = useState("");
  const [filterRole, setFilterRole] = useState("");
  const [filterOrg, setFilterOrg] = useState("");
  const [editingUser, setEditingUser] = useState<string | null>(null);
  const [editRole, setEditRole] = useState("");
  const [editOrg, setEditOrg] = useState("");
  const [editActive, setEditActive] = useState(true);

  const [form, setForm] = useState({
    email: "", username: "", full_name: "", password: "", role: "tester", organization_id: "",
  });
  const [orgForm, setOrgForm] = useState({ name: "", slug: "" });

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && !isAdmin(user.role)) {
      router.replace("/dashboard");
    }
  }, [user, router]);

  const loadUsers = async () => {
    try {
      const list = await api.users();
      setUsers(list);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user && isAdmin(user.role)) {
      loadUsers();
      api.listOrganizations().then(setOrgs).catch(() => {});
    }
  }, [user]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const data: any = { ...form };
      if (!data.organization_id) delete data.organization_id;
      await api.createUser(data);
      toast.success("User created successfully");
      setForm({ email: "", username: "", full_name: "", password: "", role: "tester", organization_id: "" });
      setShowForm(false);
      loadUsers();
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createOrganization({ name: orgForm.name, slug: orgForm.slug || undefined });
      toast.success("Organization created");
      setOrgForm({ name: "", slug: "" });
      setShowOrgForm(false);
      api.listOrganizations().then(setOrgs).catch(() => {});
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleEditUser = async (userId: string) => {
    try {
      const data: any = { role: editRole, is_active: editActive };
      if (isSuperAdmin(user?.role) && editOrg) data.organization_id = editOrg;
      await api.updateUser(userId, data);
      toast.success("User updated");
      setEditingUser(null);
      loadUsers();
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleResetPassword = async (userId: string) => {
    const pwd = prompt("Enter new password for user:");
    if (!pwd || pwd.length < 6) {
      if (pwd) toast.error("Password must be at least 6 characters");
      return;
    }
    try {
      await api.updateUserPassword(userId, pwd);
      toast.success("Password reset successfully");
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const startEdit = (u: any) => {
    setEditingUser(u.id);
    setEditRole(u.role);
    setEditOrg(u.organization_id || "");
    setEditActive(u.is_active);
  };

  const filtered = users.filter(u => {
    if (search && !u.full_name.toLowerCase().includes(search.toLowerCase()) &&
        !u.username.toLowerCase().includes(search.toLowerCase()) &&
        !u.email.toLowerCase().includes(search.toLowerCase())) return false;
    if (filterRole && u.role !== filterRole) return false;
    if (filterOrg && u.organization_id !== filterOrg) return false;
    return true;
  });

  const availableRoles = isSuperAdmin(user?.role)
    ? ["viewer", "tester", "lead", "admin"]
    : ["viewer", "tester", "lead"];

  if (!user || !isAdmin(user.role)) return null;

  return (
    <div className="min-h-screen bg-[#09090b]">
      <Navbar />
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-indigo-400" /> User Management
              {isSuperAdmin(user.role) && <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded-full">All Orgs</span>}
            </h1>
            <p className="text-sm text-[#64748b] mt-1">
              {isSuperAdmin(user.role) ? "Manage users across all organizations" : "Manage users in your organization"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {isSuperAdmin(user.role) && (
              <button onClick={() => setShowOrgForm(!showOrgForm)}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-all">
                <Building2 className="w-3.5 h-3.5" /> New Org
              </button>
            )}
            <button onClick={() => setShowForm(!showForm)}
              className="btn-primary flex items-center gap-1.5 text-sm py-2 px-4">
              <UserPlus className="w-3.5 h-3.5" /> Create User
            </button>
          </div>
        </motion.div>

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          {["super_admin", "admin", "lead", "tester", "viewer"].map(role => {
            const count = users.filter(u => u.role === role).length;
            return (
              <motion.div key={role} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                className="card p-3 text-center cursor-pointer hover:border-indigo-500/20 transition-all"
                onClick={() => setFilterRole(filterRole === role ? "" : role)}>
                <p className="text-2xl font-bold text-white tabular-nums">{count}</p>
                <p className={`text-xs font-medium mt-0.5 ${ROLE_COLORS[role]?.split(" ")[0] || "text-[#64748b]"}`}>
                  {ROLE_LABELS[role]}
                </p>
              </motion.div>
            );
          })}
        </div>

        {/* Create Org Form */}
        {showOrgForm && isSuperAdmin(user.role) && (
          <motion.form initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
            onSubmit={handleCreateOrg} className="card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Building2 className="w-4 h-4 text-emerald-400" /> New Organization
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input className="input-field py-2 text-sm" placeholder="Organization name" required
                value={orgForm.name} onChange={e => setOrgForm({ ...orgForm, name: e.target.value })} />
              <input className="input-field py-2 text-sm" placeholder="Slug (auto-generated if empty)"
                value={orgForm.slug} onChange={e => setOrgForm({ ...orgForm, slug: e.target.value })} />
              <div className="flex gap-2">
                <button type="submit" className="btn-primary text-sm flex-1">Create</button>
                <button type="button" onClick={() => setShowOrgForm(false)} className="btn-secondary text-sm">Cancel</button>
              </div>
            </div>
          </motion.form>
        )}

        {/* Create User Form */}
        {showForm && (
          <motion.form initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
            onSubmit={handleCreate} className="card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <UserPlus className="w-4 h-4 text-indigo-400" /> New User
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input className="input-field py-2 text-sm" placeholder="Email" type="email" required
                value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
              <input className="input-field py-2 text-sm" placeholder="Username" required
                value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
              <input className="input-field py-2 text-sm" placeholder="Full name" required
                value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })} />
              <input className="input-field py-2 text-sm" placeholder="Password" type="password" required
                value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
              <select className="input-field py-2 text-sm" value={form.role}
                onChange={e => setForm({ ...form, role: e.target.value })}>
                {availableRoles.map(r => (
                  <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                ))}
              </select>
              {isSuperAdmin(user.role) && (
                <select className="input-field py-2 text-sm" value={form.organization_id}
                  onChange={e => setForm({ ...form, organization_id: e.target.value })}>
                  <option value="">No organization</option>
                  {orgs.map((o: any) => <option key={o.id} value={o.id}>{o.name}</option>)}
                </select>
              )}
            </div>
            <div className="flex gap-2 pt-1">
              <button type="submit" className="btn-primary text-sm">Create User</button>
              <button type="button" onClick={() => setShowForm(false)} className="btn-secondary text-sm">Cancel</button>
            </div>
          </motion.form>
        )}

        {/* Filters */}
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#64748b]" />
            <input className="input-field pl-9 py-2 text-sm" placeholder="Search users..."
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <select className="input-field py-2 text-sm w-36" value={filterRole}
            onChange={e => setFilterRole(e.target.value)}>
            <option value="">All roles</option>
            {Object.entries(ROLE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          {isSuperAdmin(user.role) && orgs.length > 0 && (
            <select className="input-field py-2 text-sm w-44" value={filterOrg}
              onChange={e => setFilterOrg(e.target.value)}>
              <option value="">All organizations</option>
              {orgs.map((o: any) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          )}
        </div>

        {/* Users Table */}
        <div className="card overflow-hidden">
          {loading ? (
            <div className="p-8 space-y-3">
              {[1, 2, 3].map(i => <div key={i} className="h-14 rounded-lg animate-shimmer bg-[#161922]" />)}
            </div>
          ) : (
            <div className="divide-y divide-[#1e2330]/50">
              {filtered.map((u, i) => (
                <motion.div key={u.id}
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}
                  className="px-4 py-3 hover:bg-[#0D1424] transition-colors">
                  <div className="flex items-center gap-4">
                    {/* Avatar */}
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 ${
                      u.role === "super_admin"
                        ? "bg-gradient-to-br from-amber-500/20 to-orange-500/20 border border-amber-500/30 text-amber-400"
                        : u.role === "admin"
                          ? "bg-gradient-to-br from-emerald-500/20 to-teal-500/20 border border-emerald-500/20 text-emerald-400"
                          : "bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border border-indigo-500/10 text-indigo-400"
                    }`}>
                      {u.role === "super_admin" ? <Crown className="w-4 h-4" /> : (u.full_name || "U")[0].toUpperCase()}
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-white truncate">{u.full_name}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${ROLE_COLORS[u.role] || ROLE_COLORS.viewer}`}>
                          {ROLE_LABELS[u.role] || u.role}
                        </span>
                        {!u.is_active && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full text-red-400 bg-red-500/10 border border-red-500/20">
                            Inactive
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-[#64748b] mt-0.5 flex items-center gap-2">
                        <span>{u.username}</span>
                        <span className="text-[#334155]">&middot;</span>
                        <span>{u.email}</span>
                        {u.organization_name && (
                          <>
                            <span className="text-[#334155]">&middot;</span>
                            <span className="text-emerald-500 flex items-center gap-0.5">
                              <Building2 className="w-3 h-3" /> {u.organization_name}
                            </span>
                          </>
                        )}
                      </div>
                    </div>

                    {/* XP/Level */}
                    <div className="hidden md:block text-right shrink-0">
                      <div className="text-xs font-semibold text-indigo-400 tabular-nums">{u.xp_points} XP</div>
                      <div className="text-[10px] text-[#64748b]">Lv.{u.level} | {u.streak_days}d streak</div>
                    </div>

                    {/* Edit mode */}
                    {editingUser === u.id ? (
                      <div className="flex items-center gap-2 shrink-0">
                        <select className="input-field py-1 px-2 text-xs w-24" value={editRole}
                          onChange={e => setEditRole(e.target.value)}>
                          {availableRoles.map(r => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
                        </select>
                        {isSuperAdmin(user.role) && (
                          <select className="input-field py-1 px-2 text-xs w-28" value={editOrg}
                            onChange={e => setEditOrg(e.target.value)}>
                            <option value="">No org</option>
                            {orgs.map((o: any) => <option key={o.id} value={o.id}>{o.name}</option>)}
                          </select>
                        )}
                        <button onClick={() => setEditActive(!editActive)}
                          className={`p-1 rounded ${editActive ? "text-emerald-400" : "text-red-400"}`}
                          title={editActive ? "Active" : "Inactive"}>
                          {editActive ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
                        </button>
                        <button onClick={() => handleEditUser(u.id)}
                          className="p-1 rounded text-emerald-400 hover:bg-emerald-500/10">
                          <Check className="w-4 h-4" />
                        </button>
                        <button onClick={() => setEditingUser(null)}
                          className="p-1 rounded text-red-400 hover:bg-red-500/10">
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 shrink-0">
                        <button onClick={() => startEdit(u)}
                          className="p-1.5 rounded text-[#64748b] hover:text-white hover:bg-white/5" title="Edit user">
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => handleResetPassword(u.id)}
                          className="p-1.5 rounded text-[#64748b] hover:text-amber-400 hover:bg-amber-500/5" title="Reset password">
                          <Key className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </div>
                </motion.div>
              ))}
              {filtered.length === 0 && (
                <div className="p-12 text-center">
                  <Users className="w-8 h-8 text-[#334155] mx-auto mb-2" />
                  <p className="text-[#64748b] text-sm">No users found</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Organizations List (super_admin) */}
        {isSuperAdmin(user.role) && orgs.length > 0 && (
          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-[#1e2330]">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Building2 className="w-4 h-4 text-emerald-400" /> Organizations ({orgs.length})
              </h3>
            </div>
            <div className="divide-y divide-[#1e2330]/50">
              {orgs.map((o: any) => {
                const orgUsers = users.filter(u => u.organization_id === o.id);
                return (
                  <div key={o.id} className="px-4 py-3 flex items-center justify-between hover:bg-[#0D1424] transition-colors">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 text-xs font-bold">
                        {o.name[0].toUpperCase()}
                      </div>
                      <div>
                        <div className="text-sm font-medium text-white">{o.name}</div>
                        <div className="text-xs text-[#64748b]">/{o.slug}</div>
                      </div>
                    </div>
                    <div className="text-xs text-[#64748b]">{orgUsers.length} user{orgUsers.length !== 1 ? "s" : ""}</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
