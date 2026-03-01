"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { UserPlus, Shield, Pencil, X } from "lucide-react";

export default function AdminUsersPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    email: "",
    username: "",
    full_name: "",
    password: "",
    role: "tester",
  });
  const [editUser, setEditUser] = useState<any | null>(null);
  const [editForm, setEditForm] = useState({ email: "", username: "", full_name: "", role: "", is_active: true });
  const [editPassword, setEditPassword] = useState("");
  const [editSaving, setEditSaving] = useState(false);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (user && user.role !== "admin") {
      router.replace("/dashboard");
      return;
    }
    if (!user && !loading) router.replace("/login");
  }, [user, router, loading]);

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
    if (user?.role === "admin") loadUsers();
  }, [user]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createUser(form);
      toast.success("User created. They can now log in.");
      setForm({ email: "", username: "", full_name: "", password: "", role: "tester" });
      setShowForm(false);
      loadUsers();
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const openEdit = (u: any) => {
    setEditUser(u);
    setEditForm({ email: u.email, username: u.username, full_name: u.full_name, role: u.role, is_active: u.is_active !== false });
    setEditPassword("");
  };

  const handleEditSave = async () => {
    if (!editUser) return;
    setEditSaving(true);
    try {
      await api.updateUser(editUser.id, editForm);
      if (editPassword) {
        await api.updateUserPassword(editUser.id, editPassword);
      }
      toast.success("User updated");
      setEditUser(null);
      loadUsers();
    } catch (e: any) {
      toast.error(e.message || "Update failed");
    } finally {
      setEditSaving(false);
    }
  };

  const handleToggleActive = async (u: any) => {
    try {
      await api.updateUser(u.id, { is_active: !u.is_active });
      toast.success(`User ${u.is_active ? "deactivated" : "activated"}`);
      loadUsers();
    } catch (e: any) {
      toast.error(e.message || "Failed to toggle status");
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
            <Shield className="w-5 h-5 text-blue-400" /> User Management
          </h1>
          <button
            onClick={() => setShowForm(!showForm)}
            className="btn-primary flex items-center gap-2"
          >
            <UserPlus className="w-4 h-4" /> Create User
          </button>
        </div>

        {showForm && (
          <form onSubmit={handleCreate} className="card p-4 mb-6 space-y-3">
            <h3 className="text-sm font-semibold text-white">New User</h3>
            <input
              className="input-field"
              placeholder="Email"
              type="email"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              required
            />
            <input
              className="input-field"
              placeholder="Username"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              required
            />
            <input
              className="input-field"
              placeholder="Full name"
              value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              required
            />
            <input
              className="input-field"
              placeholder="Password"
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              required
            />
            <select
              className="input-field"
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
            >
              <option value="viewer">Viewer</option>
              <option value="tester">Tester</option>
              <option value="lead">Lead</option>
              <option value="admin">Admin</option>
            </select>
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
                  <th className="p-3">User</th>
                  <th className="p-3">Role</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-[#1F2937]/50 hover:bg-[#1F2937]/30">
                    <td className="p-3">
                      <div className="font-medium text-white">{u.full_name}</div>
                      <div className="text-xs text-[#9CA3AF]">{u.username} · {u.email}</div>
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-xs bg-blue-900/40 text-blue-300 border border-blue-800">
                        {u.role}
                      </span>
                    </td>
                    <td className="p-3">
                      <button
                        onClick={() => handleToggleActive(u)}
                        className={`px-2 py-0.5 rounded text-xs ${u.is_active !== false ? 'bg-green-900/40 text-green-300 border border-green-800' : 'bg-red-900/40 text-red-300 border border-red-800'}`}
                      >
                        {u.is_active !== false ? "Active" : "Inactive"}
                      </button>
                    </td>
                    <td className="p-3">
                      <button onClick={() => openEdit(u)} className="text-blue-400 hover:text-blue-300">
                        <Pencil className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {editUser && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="card p-6 w-full max-w-md space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">Edit User: {editUser.username}</h3>
                <button onClick={() => setEditUser(null)} className="text-[#6B7280] hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <input
                className="input-field"
                placeholder="Full name"
                value={editForm.full_name}
                onChange={(e) => setEditForm({ ...editForm, full_name: e.target.value })}
              />
              <input
                className="input-field"
                placeholder="Email"
                type="email"
                value={editForm.email}
                onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
              />
              <input
                className="input-field"
                placeholder="Username"
                value={editForm.username}
                onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
              />
              <div>
                <label className="block text-xs font-medium text-[#9CA3AF] mb-1">Role</label>
                <select
                  className="input-field"
                  value={editForm.role}
                  onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                >
                  <option value="viewer">Viewer</option>
                  <option value="tester">Tester</option>
                  <option value="lead">Lead</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-xs font-medium text-[#9CA3AF]">Active</label>
                <button
                  type="button"
                  onClick={() => setEditForm({ ...editForm, is_active: !editForm.is_active })}
                  className={`relative w-10 h-5 rounded-full transition-colors ${editForm.is_active ? 'bg-green-600' : 'bg-[#374151]'}`}
                >
                  <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${editForm.is_active ? 'translate-x-5' : ''}`} />
                </button>
              </div>
              <div>
                <label className="block text-xs font-medium text-[#9CA3AF] mb-1">New Password (leave blank to keep)</label>
                <input
                  className="input-field"
                  placeholder="New password"
                  type="password"
                  value={editPassword}
                  onChange={(e) => setEditPassword(e.target.value)}
                />
              </div>
              <div className="flex gap-2">
                <button onClick={handleEditSave} disabled={editSaving} className="btn-primary disabled:opacity-50">
                  {editSaving ? "Saving..." : "Save Changes"}
                </button>
                <button onClick={() => setEditUser(null)} className="btn-secondary">Cancel</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
