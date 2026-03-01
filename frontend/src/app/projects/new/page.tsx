"use client";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import toast from "react-hot-toast";
import { ChevronRight, ChevronLeft, Shield, Code, Database, Globe, Lock, Zap, Scan } from "lucide-react";

const STEPS = [
  { id: 1, title: "Project Info", icon: Shield, desc: "Application details & team" },
  { id: 2, title: "Frontend Stack", icon: Code, desc: "Frontend technologies" },
  { id: 3, title: "Backend Stack", icon: Globe, desc: "Backend & server" },
  { id: 4, title: "Database & API", icon: Database, desc: "Data layer & API type" },
  { id: 5, title: "Auth & Features", icon: Lock, desc: "Authentication & features" },
  { id: 6, title: "Review & Launch", icon: Zap, desc: "Review and start testing" },
];

const Toggle = ({ label, value, onChange }: { label: string; value: boolean; onChange: (v: boolean) => void }) => (
  <label className="flex items-center gap-3 cursor-pointer group">
    <div onClick={() => onChange(!value)}
      className={`relative w-10 h-5 rounded-full transition-colors ${value ? "bg-indigo-500" : ""}`}
      style={!value ? { background: "var(--bg-tertiary)" } : {}}>
      <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${value ? "translate-x-5" : "translate-x-0.5"}`} />
    </div>
    <span className="text-sm transition-colors" style={{ color: "var(--text-secondary)" }}>{label}</span>
  </label>
);

const MultiSelect = ({ options, value, onChange }: { options: string[]; value: string[]; onChange: (v: string[]) => void }) => (
  <div className="flex flex-wrap gap-2">
    {options.map(opt => (
      <button key={opt} type="button"
        onClick={() => onChange(value.includes(opt) ? value.filter(v => v !== opt) : [...value, opt])}
        className={`px-3 py-1.5 rounded-full text-xs border transition-all ${
          value.includes(opt)
            ? "bg-indigo-500 border-indigo-500 text-white"
            : ""
        }`}
        style={!value.includes(opt) ? { background: "var(--bg-elevated)", borderColor: "var(--border-subtle)", color: "var(--text-secondary)" } : {}}>
        {opt}
      </button>
    ))}
  </div>
);

export default function NewProject() {
  const router = useRouter();
  const { hydrate, user } = useAuthStore();
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);

  const [info, setInfo] = useState({
    name: "", application_name: "", application_version: "",
    application_url: "", app_owner_name: "", app_spoc_name: "",
    app_spoc_email: "", testing_type: "grey_box", environment: "staging",
    testing_scope: "", target_completion_date: "", classification: "internal",
    lead_id: "" as string, assigned_tester_ids: [] as string[],
  });
  const [assignableUsers, setAssignableUsers] = useState<{ id: string; full_name: string; role: string }[]>([]);
  const [detectingTech, setDetectingTech] = useState(false);

  const [stack, setStack] = useState({
    frontend: [] as string[],
    backend: [] as string[],
    database: [] as string[],
    api_type: [] as string[],
    api_format: [] as string[],
    auth_type: [] as string[],
    cms: "none",
    features: {
      file_upload: false, payment: false, shopping_cart: false,
      admin_panel: false, graphql: false, websocket: false,
      otp: false, captcha: false, user_roles: false, email_notifications: false,
      rich_text_editor: false, export_functionality: false, two_factor: false,
    },
  });

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (!user) router.replace("/login"); }, [user, router]);
  useEffect(() => {
    api.assignableUsers().then(setAssignableUsers).catch(() => []);
  }, []);

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      const stackProfile = {
        frontend: stack.frontend,
        backend: stack.backend,
        database: stack.database,
        api_type: stack.api_type.join(","),
        api_format: stack.api_format.join(","),
        auth_type: stack.auth_type.join(","),
        ...Object.entries(stack.features).reduce((acc, [k, v]) => ({ ...acc, [`features:${k}`]: v ? "yes" : "no" }), {}),
      };
      const payload: Record<string, unknown> = {
        name: info.name,
        application_name: info.application_name,
        application_version: info.application_version || null,
        application_url: info.application_url,
        app_owner_name: info.app_owner_name || null,
        app_spoc_name: info.app_spoc_name || null,
        app_spoc_email: info.app_spoc_email || null,
        testing_type: info.testing_type,
        environment: info.environment,
        stack_profile: stackProfile,
        lead_id: info.lead_id || null,
        assigned_tester_ids: info.assigned_tester_ids.length ? info.assigned_tester_ids : null,
        target_completion_date: info.target_completion_date || null,
        classification: info.classification || null,
        testing_scope: info.testing_scope || null,
      };
      const project = await api.createProject(payload);
      toast.success(`Project created! ${project.total_test_cases} test cases loaded!`);
      router.push(`/projects/${project.id}`);
    } catch (err: any) {
      toast.error(err.message || "Failed to create project");
    } finally {
      setSubmitting(false);
    }
  };

  const canProceed = () => {
    if (step === 1) return info.application_name && info.application_url && info.name;
    return true;
  };

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-3xl mx-auto p-6">
        {/* Step indicators */}
        <div className="flex items-center justify-between mb-8 overflow-x-auto pb-2">
          {STEPS.map((s, i) => (
            <div key={s.id} className="flex items-center">
              <div onClick={() => s.id < step && setStep(s.id)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-all ${
                  step === s.id ? "bg-indigo-500 text-white" :
                  step > s.id ? "bg-green-900/30 text-green-400 cursor-pointer hover:bg-green-900/50" :
                  ""
                }`}
                style={step !== s.id && step <= s.id ? { background: "var(--bg-elevated)", color: "var(--text-muted)" } : {}}>
                <s.icon className="w-4 h-4 shrink-0" />
                <span className="text-xs font-medium whitespace-nowrap hidden sm:block">{s.title}</span>
              </div>
              {i < STEPS.length - 1 && <ChevronRight className="w-4 h-4 mx-1 shrink-0" style={{ color: "var(--border-subtle)" }} />}
            </div>
          ))}
        </div>

        <AnimatePresence mode="wait">
          <motion.div key={step} initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.3 }}
            className="card p-6">

            {step === 1 && (
              <div className="space-y-4">
                <h2 className="text-xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>Project & Application Details</h2>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Project Name *</label>
                    <input className="input-field" placeholder="e.g., ACME Corp VAPT Q1 2026"
                      value={info.name} onChange={e => setInfo({ ...info, name: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Application Name *</label>
                    <input className="input-field" placeholder="e.g., ACME eCommerce Portal"
                      value={info.application_name} onChange={e => setInfo({ ...info, application_name: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Application URL *</label>
                    <div className="flex gap-2">
                      <input className="input-field flex-1" type="url" placeholder="https://app.example.com"
                        value={info.application_url} onChange={e => setInfo({ ...info, application_url: e.target.value })} />
                      <button
                        type="button"
                        disabled={!info.application_url || detectingTech}
                        onClick={async () => {
                          if (!info.application_url) return;
                          setDetectingTech(true);
                          try {
                            const res = await api.detectTech(info.application_url);
                            if (res.stack_profile && res._detected) {
                              const sp = res.stack_profile;
                              const all = [...(sp.frontend || []), ...(sp.backend || []), ...(sp.cms || []), ...(sp.api || []), ...(sp.waf || [])].slice(0, 8);
                              setStack(prev => ({
                                ...prev,
                                frontend: Array.from(new Set([...prev.frontend, ...(sp.frontend || [])])),
                                backend: Array.from(new Set([...prev.backend, ...(sp.backend || [])])),
                                cms: sp.cms?.length ? (sp.cms[0] || "none") : prev.cms,
                                api_type: Array.from(new Set([...prev.api_type, ...(sp.api || []).map((a: string) => a.toLowerCase())])),
                              }));
                              toast.success(`Detected: ${all.join(", ") || "tech stack"}`);
                            } else {
                              toast.error(res._error || "Could not detect technology");
                            }
                          } catch {
                            toast.error("Detection failed");
                          } finally {
                            setDetectingTech(false);
                          }
                        }}
                        className="btn-secondary flex items-center gap-1.5 shrink-0 disabled:opacity-50"
                        title="Auto-detect technology from URL"
                      >
                        <Scan className="w-4 h-4" /> {detectingTech ? "Detecting..." : "Detect"}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Version</label>
                    <input className="input-field" placeholder="e.g., 2.3.1"
                      value={info.application_version} onChange={e => setInfo({ ...info, application_version: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>App Owner</label>
                    <input className="input-field" placeholder="Application owner name"
                      value={info.app_owner_name} onChange={e => setInfo({ ...info, app_owner_name: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>SPOC Name</label>
                    <input className="input-field" placeholder="Technical SPOC"
                      value={info.app_spoc_name} onChange={e => setInfo({ ...info, app_spoc_name: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>SPOC Email</label>
                    <input className="input-field" type="email" placeholder="spoc@example.com"
                      value={info.app_spoc_email} onChange={e => setInfo({ ...info, app_spoc_email: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Testing Type</label>
                    <select className="input-field" value={info.testing_type}
                      onChange={e => setInfo({ ...info, testing_type: e.target.value })}>
                      <option value="black_box">Black Box</option>
                      <option value="grey_box">Grey Box</option>
                      <option value="white_box">White Box</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Environment</label>
                    <select className="input-field" value={info.environment}
                      onChange={e => setInfo({ ...info, environment: e.target.value })}>
                      <option value="production">Production</option>
                      <option value="staging">Staging</option>
                      <option value="uat">UAT</option>
                      <option value="development">Development</option>
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Testing Scope</label>
                    <textarea className="input-field h-20 resize-none" placeholder="URLs in scope, exclusions, special notes..."
                      value={info.testing_scope} onChange={e => setInfo({ ...info, testing_scope: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Target Completion Date</label>
                    <input className="input-field" type="date"
                      value={info.target_completion_date} onChange={e => setInfo({ ...info, target_completion_date: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Classification</label>
                    <select className="input-field" value={info.classification}
                      onChange={e => setInfo({ ...info, classification: e.target.value })}>
                      <option value="internal">Internal</option>
                      <option value="confidential">Confidential</option>
                      <option value="public">Public</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Lead Tester</label>
                    <select className="input-field" value={info.lead_id}
                      onChange={e => setInfo({ ...info, lead_id: e.target.value })}>
                      <option value="">— Select lead (optional)</option>
                      {assignableUsers.filter(u => ["admin", "lead"].includes(u.role)).map(u => (
                        <option key={u.id} value={u.id}>{u.full_name} ({u.role})</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-sm mb-1 block" style={{ color: "var(--text-secondary)" }}>Assigned Testers</label>
                    <div className="flex flex-wrap gap-2">
                      {assignableUsers.map(u => (
                        <button key={u.id} type="button"
                          onClick={() => setInfo({
                            ...info,
                            assigned_tester_ids: info.assigned_tester_ids.includes(u.id)
                              ? info.assigned_tester_ids.filter(id => id !== u.id)
                              : [...info.assigned_tester_ids, u.id],
                          })}
                          className={`px-3 py-1.5 rounded-full text-xs border transition-all ${
                            info.assigned_tester_ids.includes(u.id)
                              ? "bg-blue-600 border-blue-500 text-white"
                              : ""
                          }`}
                          style={!info.assigned_tester_ids.includes(u.id) ? { background: "var(--bg-elevated)", borderColor: "var(--border-subtle)", color: "var(--text-secondary)" } : {}}>
                          {u.full_name}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {step === 2 && (
              <div className="space-y-5">
                <h2 className="text-xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>Frontend Stack</h2>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>Frontend Framework</label>
                  <MultiSelect
                    options={["React", "Angular", "Vue", "Next.js", "Nuxt", "Svelte", "jQuery", "Vanilla JS", "Unknown"]}
                    value={stack.frontend}
                    onChange={v => setStack({ ...stack, frontend: v })}
                  />
                </div>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>Application Type</label>
                  <MultiSelect
                    options={["SPA (Single Page App)", "Traditional Multi-Page", "Hybrid", "Unknown"]}
                    value={stack.frontend}
                    onChange={v => setStack({ ...stack, frontend: [...stack.frontend.filter(f => !["SPA (Single Page App)", "Traditional Multi-Page", "Hybrid", "Unknown"].includes(f)), ...v] })}
                  />
                </div>
              </div>
            )}

            {step === 3 && (
              <div className="space-y-5">
                <h2 className="text-xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>Backend Stack</h2>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>Backend Language / Framework</label>
                  <MultiSelect
                    options={["Python/Django", "Python/Flask", "Python/FastAPI", "Node.js/Express", "Java/Spring Boot", "PHP/Laravel", "Ruby/Rails", ".NET/ASP.NET", "Go", "Unknown"]}
                    value={stack.backend}
                    onChange={v => setStack({ ...stack, backend: v })}
                  />
                </div>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>Template Engine</label>
                  <MultiSelect
                    options={["Jinja2", "Thymeleaf", "EJS", "Blade (PHP)", "ERB", "Twig", "Handlebars", "None"]}
                    value={stack.backend}
                    onChange={v => setStack({ ...stack, backend: [...stack.backend.filter(b => !["Jinja2","Thymeleaf","EJS","Blade (PHP)","ERB","Twig","Handlebars","None"].includes(b)), ...v] })}
                  />
                </div>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>CMS</label>
                  <select className="input-field" value={stack.cms}
                    onChange={e => setStack({ ...stack, cms: e.target.value })}>
                    <option value="none">None / Custom</option>
                    <option value="wordpress">WordPress</option>
                    <option value="drupal">Drupal</option>
                    <option value="joomla">Joomla</option>
                  </select>
                </div>
              </div>
            )}

            {step === 4 && (
              <div className="space-y-5">
                <h2 className="text-xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>Database & API</h2>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>Primary Database</label>
                  <MultiSelect
                    options={["PostgreSQL", "MySQL", "MSSQL", "Oracle", "MongoDB", "DynamoDB", "SQLite", "Unknown"]}
                    value={stack.database}
                    onChange={v => setStack({ ...stack, database: v })}
                  />
                </div>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>API Type</label>
                  <MultiSelect
                    options={["REST", "GraphQL", "SOAP", "gRPC", "WebSocket", "XML-RPC", "Not Sure"]}
                    value={stack.api_type}
                    onChange={v => setStack({ ...stack, api_type: v })}
                  />
                </div>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>API Format</label>
                  <MultiSelect
                    options={["JSON", "XML", "Form Data", "Multipart", "Plain Text", "Mixed"]}
                    value={stack.api_format}
                    onChange={v => setStack({ ...stack, api_format: v })}
                  />
                </div>
              </div>
            )}

            {step === 5 && (
              <div className="space-y-5">
                <h2 className="text-xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>Authentication & Application Features</h2>
                <div>
                  <label className="text-sm mb-2 block" style={{ color: "var(--text-secondary)" }}>Authentication Mechanism</label>
                  <MultiSelect
                    options={["Username+Password", "SSO", "OAuth2", "SAML", "JWT", "Session Cookie", "API Key", "MFA/OTP", "Unknown"]}
                    value={stack.auth_type}
                    onChange={v => setStack({ ...stack, auth_type: v })}
                  />
                </div>
                <div>
                  <label className="text-sm mb-3 block" style={{ color: "var(--text-secondary)" }}>Application Features (affects test case applicability)</label>
                  <div className="grid grid-cols-2 gap-3">
                    {Object.entries(stack.features).map(([key, val]) => (
                      <Toggle key={key}
                        label={key.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}
                        value={val}
                        onChange={v => setStack({ ...stack, features: { ...stack.features, [key]: v } })}
                      />
                    ))}
                  </div>
                </div>
              </div>
            )}

            {step === 6 && (
              <div className="space-y-4">
                <h2 className="text-xl font-bold mb-2" style={{ color: "var(--text-primary)" }}>Review & Launch</h2>
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>Review your configuration. The system will auto-filter applicable test cases based on your stack.</p>
                <div className="grid md:grid-cols-2 gap-4 mt-4">
                  <div className="rounded-lg p-4 border" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                    <h3 className="text-indigo-400 font-semibold mb-2 text-sm">Project Info</h3>
                    <p style={{ color: "var(--text-primary)" }}>{info.application_name}</p>
                    <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>{info.application_url}</p>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>{info.testing_type} | {info.environment}</p>
                  </div>
                  <div className="rounded-lg p-4 border" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                    <h3 className="text-green-400 font-semibold mb-2 text-sm">Stack Profile</h3>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Frontend: {stack.frontend.join(", ") || "Unknown"}</p>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Backend: {stack.backend.join(", ") || "Unknown"}</p>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>API: {stack.api_type.join(", ") || "Unknown"}</p>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Auth: {stack.auth_type.join(", ") || "Unknown"}</p>
                  </div>
                  <div className="rounded-lg p-4 border" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                    <h3 className="text-purple-400 font-semibold mb-2 text-sm">Enabled Features</h3>
                    {Object.entries(stack.features).filter(([, v]) => v).map(([k]) => (
                      <span key={k} className="inline-block text-xs bg-purple-900/30 text-purple-300 border border-purple-800 rounded px-2 py-0.5 mr-1 mb-1">
                        {k.replace(/_/g, " ")}
                      </span>
                    ))}
                    {!Object.values(stack.features).some(Boolean) && (
                      <p className="text-xs" style={{ color: "var(--text-muted)" }}>No special features selected</p>
                    )}
                  </div>
                  <div className="rounded-lg p-4 border" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
                    <h3 className="text-yellow-400 font-semibold mb-2 text-sm">What Happens Next</h3>
                    <ul className="text-xs space-y-1" style={{ color: "var(--text-secondary)" }}>
                      <li>Test cases auto-filtered for your stack</li>
                      <li>Payloads from PayloadsAllTheThings</li>
                      <li>Tool commands pre-filled with target URL</li>
                      <li>Progress tracked per phase</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>

        {/* Navigation */}
        <div className="flex items-center justify-between mt-6">
          <button onClick={() => setStep(s => s - 1)} disabled={step === 1}
            className="btn-secondary flex items-center gap-2 disabled:opacity-30">
            <ChevronLeft className="w-4 h-4" /> Back
          </button>
          {step < STEPS.length ? (
            <button onClick={() => setStep(s => s + 1)} disabled={!canProceed()}
              className="btn-primary flex items-center gap-2 disabled:opacity-50">
              Next <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            <motion.button onClick={handleSubmit} disabled={submitting}
              whileTap={{ scale: 0.96 }}
              className="btn-primary flex items-center gap-2 disabled:opacity-50 glow-indigo">
              <Zap className="w-4 h-4" />
              {submitting ? "Creating..." : "Launch Testing Mission"}
            </motion.button>
          )}
        </div>
      </div>
    </div>
  );
}
