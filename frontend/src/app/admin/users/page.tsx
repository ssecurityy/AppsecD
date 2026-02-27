"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { UserPlus, Shield } from "lucide-react";

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
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
