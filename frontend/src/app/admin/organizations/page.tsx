"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import { api, getApiBase } from "@/lib/api";
import { useAuthStore, isAdmin, isSuperAdmin } from "@/lib/store";
import toast from "react-hot-toast";
import { motion } from "framer-motion";
import {
  Building2, Plus, Users, FolderOpen, Search, Shield, Palette, Upload, X, Cpu, ToggleLeft, ToggleRight
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

  // Branding modal
  const [brandingOrg, setBrandingOrg] = useState<any>(null);
  const [brandingForm, setBrandingForm] = useState({ description: "", brand_color: "#6366f1" });
  const [brandingUploading, setBrandingUploading] = useState(false);
  const [brandingSaving, setBrandingSaving] = useState(false);

  // Feature flags modal
  const [featureFlagsOrg, setFeatureFlagsOrg] = useState<any>(null);
  const [featureFlags, setFeatureFlags] = useState<Record<string, { label: string; enabled: boolean }>>({});
  const [featureFlagsLoading, setFeatureFlagsLoading] = useState(false);
  const [featureFlagsSaving, setFeatureFlagsSaving] = useState(false);
  // Cache of feature flag counts per org: { orgId: { enabled: number, total: number } }
  const [orgFeatureCounts, setOrgFeatureCounts] = useState<Record<string, { enabled: number; total: number }>>({});

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
      // Load feature flag counts in background
      loadFeatureCounts(orgList);
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

  // Load feature flag counts for all orgs
  const loadFeatureCounts = async (orgList: any[]) => {
    const counts: Record<string, { enabled: number; total: number }> = {};
    await Promise.all(
      orgList.map(async (org) => {
        try {
          const res = await api.getFeatureFlags(org.id);
          const flags = res.flags || {};
          const total = Object.keys(flags).length;
          const enabled = Object.values(flags).filter((f: any) => f.enabled).length;
          counts[org.id] = { enabled, total };
        } catch {
          counts[org.id] = { enabled: 0, total: 0 };
        }
      })
    );
    setOrgFeatureCounts(counts);
  };

  // Open feature flags modal for an org
  const openFeatureFlags = async (org: any) => {
    setFeatureFlagsOrg(org);
    setFeatureFlagsLoading(true);
    try {
      const res = await api.getFeatureFlags(org.id);
      setFeatureFlags(res.flags || {});
    } catch (e: any) {
      toast.error(e.message || "Failed to load feature flags");
      setFeatureFlags({});
    } finally {
      setFeatureFlagsLoading(false);
    }
  };

  // Save feature flags
  const handleSaveFeatureFlags = async () => {
    if (!featureFlagsOrg) return;
    setFeatureFlagsSaving(true);
    try {
      const flagsPayload: Record<string, boolean> = {};
      Object.entries(featureFlags).forEach(([key, val]) => {
        flagsPayload[key] = val.enabled;
      });
      await api.updateFeatureFlags({ org_id: featureFlagsOrg.id, flags: flagsPayload });
      toast.success("Feature flags updated");
      // Update cached counts
      const total = Object.keys(featureFlags).length;
      const enabled = Object.values(featureFlags).filter((f) => f.enabled).length;
      setOrgFeatureCounts((prev) => ({ ...prev, [featureFlagsOrg.id]: { enabled, total } }));
      setFeatureFlagsOrg(null);
    } catch (e: any) {
      toast.error(e.message || "Failed to update feature flags");
    } finally {
      setFeatureFlagsSaving(false);
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
                        {org.logo_url ? (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img
                            src={org.logo_url.startsWith("http") ? org.logo_url : `${getApiBase()}${org.logo_url}`}
                            alt={org.name}
                            className="w-10 h-10 rounded-lg object-cover border"
                            style={{ borderColor: org.brand_color ? `${org.brand_color}40` : "var(--border-subtle)" }}
                          />
                        ) : (
                          <div
                            className="w-10 h-10 rounded-lg flex items-center justify-center font-bold"
                            style={{
                              background: org.brand_color ? `${org.brand_color}15` : "rgba(16,185,129,0.1)",
                              border: `1px solid ${org.brand_color ? `${org.brand_color}30` : "rgba(16,185,129,0.2)"}`,
                              color: org.brand_color || "#34d399",
                            }}
                          >
                            {org.name[0].toUpperCase()}
                          </div>
                        )}
                        <div>
                          <h3 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{org.name}</h3>
                          <p className="text-xs" style={{ color: "var(--text-muted)" }}>/{org.slug}</p>
                          {org.description && (
                            <p className="text-xs mt-0.5 max-w-[300px] truncate" style={{ color: "var(--text-secondary)" }}>{org.description}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-xs" style={{ color: "var(--text-secondary)" }}>
                        <span className="flex items-center gap-1"><Users className="w-3 h-3" /> {orgUsers.length} users</span>
                        <span className="flex items-center gap-1"><FolderOpen className="w-3 h-3" /> {orgProjects.length} projects</span>
                        {orgFeatureCounts[org.id] && (
                          <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium"
                            style={{
                              background: orgFeatureCounts[org.id].enabled > 0 ? "rgba(16,185,129,0.1)" : "rgba(239,68,68,0.1)",
                              color: orgFeatureCounts[org.id].enabled > 0 ? "#34d399" : "#f87171",
                              border: `1px solid ${orgFeatureCounts[org.id].enabled > 0 ? "rgba(16,185,129,0.2)" : "rgba(239,68,68,0.2)"}`,
                            }}>
                            <Cpu className="w-2.5 h-2.5" /> AI {orgFeatureCounts[org.id].enabled}/{orgFeatureCounts[org.id].total}
                          </span>
                        )}
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
                        <button
                          onClick={() => {
                            setBrandingOrg(org);
                            setBrandingForm({
                              description: org.description || "",
                              brand_color: org.brand_color || "#6366f1",
                            });
                          }}
                          className="text-xs px-3 py-1.5 rounded border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 transition-colors flex items-center gap-1"
                        >
                          <Palette className="w-3 h-3" /> Edit Branding
                        </button>
                        <button
                          onClick={() => openFeatureFlags(org)}
                          className="text-xs px-3 py-1.5 rounded border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 transition-colors flex items-center gap-1"
                        >
                          <Cpu className="w-3 h-3" /> Feature Controls
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

        {/* Edit Branding Modal */}
        {brandingOrg && (
          <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setBrandingOrg(null)}>
            <div className="rounded-lg max-w-md w-full p-5 space-y-4" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }} onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                  <Palette className="w-4 h-4 text-emerald-400" /> Edit Branding: {brandingOrg.name}
                </h3>
                <button onClick={() => setBrandingOrg(null)} className="text-[var(--text-muted)] hover:text-[var(--text-primary)]">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Logo Upload */}
              <div>
                <label className="text-xs font-medium block mb-1.5" style={{ color: "var(--text-secondary)" }}>Organization Logo</label>
                <div className="flex items-center gap-3">
                  {brandingOrg.logo_url ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={brandingOrg.logo_url.startsWith("http") ? brandingOrg.logo_url : `${getApiBase()}${brandingOrg.logo_url}`}
                      alt="Logo"
                      className="w-14 h-14 rounded-lg object-cover border"
                      style={{ borderColor: "var(--border-subtle)" }}
                    />
                  ) : (
                    <div className="w-14 h-14 rounded-lg flex items-center justify-center text-lg font-bold"
                      style={{ background: "var(--bg-elevated)", color: "var(--text-muted)", border: "1px solid var(--border-subtle)" }}>
                      {brandingOrg.name[0].toUpperCase()}
                    </div>
                  )}
                  <label className="cursor-pointer">
                    <input
                      type="file"
                      className="hidden"
                      accept=".png,.jpg,.jpeg,.svg,.webp"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        setBrandingUploading(true);
                        try {
                          const res = await api.uploadOrgLogo(brandingOrg.id, file);
                          toast.success("Logo uploaded");
                          setBrandingOrg({ ...brandingOrg, logo_url: res.logo_url || res.url });
                          loadData();
                        } catch (err: any) {
                          toast.error(err.message || "Upload failed");
                        } finally {
                          setBrandingUploading(false);
                          e.target.value = "";
                        }
                      }}
                      disabled={brandingUploading}
                    />
                    <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs transition-colors ${brandingUploading ? "opacity-50 cursor-not-allowed" : "border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/10"}`}>
                      <Upload className="w-3 h-3" /> {brandingUploading ? "Uploading..." : "Upload Logo"}
                    </span>
                  </label>
                </div>
              </div>

              {/* Brand Color */}
              <div>
                <label className="text-xs font-medium block mb-1.5" style={{ color: "var(--text-secondary)" }}>Brand Color</label>
                <div className="flex items-center gap-3">
                  <input
                    type="color"
                    value={brandingForm.brand_color}
                    onChange={(e) => setBrandingForm({ ...brandingForm, brand_color: e.target.value })}
                    className="w-10 h-10 rounded-lg cursor-pointer border-0 p-0"
                    style={{ background: "transparent" }}
                  />
                  <input
                    className="input-field py-2 text-sm flex-1"
                    value={brandingForm.brand_color}
                    onChange={(e) => setBrandingForm({ ...brandingForm, brand_color: e.target.value })}
                    placeholder="#6366f1"
                  />
                  <div className="w-10 h-10 rounded-lg" style={{ background: brandingForm.brand_color }} />
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="text-xs font-medium block mb-1.5" style={{ color: "var(--text-secondary)" }}>Description</label>
                <textarea
                  className="input-field text-sm h-20 resize-none w-full"
                  placeholder="Organization description..."
                  value={brandingForm.description}
                  onChange={(e) => setBrandingForm({ ...brandingForm, description: e.target.value })}
                />
              </div>

              {/* Save */}
              <div className="flex gap-2">
                <button
                  onClick={async () => {
                    setBrandingSaving(true);
                    try {
                      await api.updateOrganization(brandingOrg.id, {
                        description: brandingForm.description,
                        brand_color: brandingForm.brand_color,
                      });
                      toast.success("Branding updated");
                      setBrandingOrg(null);
                      loadData();
                    } catch (err: any) {
                      toast.error(err.message || "Update failed");
                    } finally {
                      setBrandingSaving(false);
                    }
                  }}
                  disabled={brandingSaving}
                  className="btn-primary text-sm flex-1 disabled:opacity-50"
                >
                  {brandingSaving ? "Saving..." : "Save Branding"}
                </button>
                <button onClick={() => setBrandingOrg(null)} className="btn-secondary text-sm">Cancel</button>
              </div>
            </div>
          </div>
        )}

        {/* Feature Controls Modal */}
        {featureFlagsOrg && (
          <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setFeatureFlagsOrg(null)}>
            <div className="rounded-lg max-w-lg w-full p-5 space-y-4" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }} onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                  <Cpu className="w-4 h-4 text-cyan-400" /> AI Feature Controls: {featureFlagsOrg.name}
                </h3>
                <button onClick={() => setFeatureFlagsOrg(null)} className="text-[var(--text-muted)] hover:text-[var(--text-primary)]">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                Toggle AI features for this organization. Disabled features will show &quot;Contact admin to enable&quot; for org users.
              </p>

              {featureFlagsLoading ? (
                <div className="space-y-3 py-2">
                  {[1, 2, 3, 4, 5, 6].map((i) => (
                    <div key={i} className="h-10 rounded-lg animate-shimmer" style={{ background: "var(--bg-elevated)" }} />
                  ))}
                </div>
              ) : Object.keys(featureFlags).length === 0 ? (
                <div className="py-6 text-center">
                  <Cpu className="w-6 h-6 mx-auto mb-2" style={{ color: "var(--text-muted)" }} />
                  <p className="text-xs" style={{ color: "var(--text-muted)" }}>No feature flags configured for this organization.</p>
                </div>
              ) : (
                <div className="space-y-1">
                  {Object.entries(featureFlags).map(([key, flag]) => (
                    <div
                      key={key}
                      className="flex items-center justify-between p-3 rounded-lg transition-colors"
                      style={{
                        background: flag.enabled ? "rgba(16,185,129,0.05)" : "var(--bg-elevated)",
                        border: `1px solid ${flag.enabled ? "rgba(16,185,129,0.15)" : "var(--border-subtle)"}`,
                      }}
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{flag.label}</p>
                        <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>{key}</p>
                      </div>
                      <button
                        onClick={() => {
                          setFeatureFlags((prev) => ({
                            ...prev,
                            [key]: { ...prev[key], enabled: !prev[key].enabled },
                          }));
                        }}
                        className="flex-shrink-0 ml-3 transition-colors"
                        title={flag.enabled ? "Disable feature" : "Enable feature"}
                      >
                        {flag.enabled ? (
                          <ToggleRight className="w-8 h-8 text-emerald-400" />
                        ) : (
                          <ToggleLeft className="w-8 h-8" style={{ color: "var(--text-muted)" }} />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Summary */}
              {Object.keys(featureFlags).length > 0 && !featureFlagsLoading && (
                <div className="flex items-center justify-between pt-1">
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                    {Object.values(featureFlags).filter((f) => f.enabled).length} of {Object.keys(featureFlags).length} features enabled
                  </span>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => {
                        setFeatureFlags((prev) => {
                          const updated = { ...prev };
                          Object.keys(updated).forEach((k) => { updated[k] = { ...updated[k], enabled: true }; });
                          return updated;
                        });
                      }}
                      className="text-[10px] px-2 py-1 rounded border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 transition-colors"
                    >
                      Enable All
                    </button>
                    <button
                      onClick={() => {
                        setFeatureFlags((prev) => {
                          const updated = { ...prev };
                          Object.keys(updated).forEach((k) => { updated[k] = { ...updated[k], enabled: false }; });
                          return updated;
                        });
                      }}
                      className="text-[10px] px-2 py-1 rounded border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors"
                    >
                      Disable All
                    </button>
                  </div>
                </div>
              )}

              {/* Save / Cancel */}
              <div className="flex gap-2 pt-1">
                <button
                  onClick={handleSaveFeatureFlags}
                  disabled={featureFlagsSaving || featureFlagsLoading}
                  className="btn-primary text-sm flex-1 disabled:opacity-50"
                >
                  {featureFlagsSaving ? "Saving..." : "Save Feature Flags"}
                </button>
                <button onClick={() => setFeatureFlagsOrg(null)} className="btn-secondary text-sm">Cancel</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
