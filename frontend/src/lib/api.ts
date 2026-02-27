// Use same host as page when in browser — fixes remote access (31.97.239.245:3000 → API at :5001)
// and avoids ERR_BLOCKED_BY_CLIENT when extensions block cross-origin requests to localhost
export function getApiBase(): string {
  if (typeof window !== "undefined") {
    const env = process.env.NEXT_PUBLIC_API_URL;
    // If env points to localhost but we're on a remote host, override to avoid blocked requests
    const isRemote = !["localhost", "127.0.0.1", ""].includes(window.location.hostname);
    if (isRemote && (!env || env.includes("127.0.0.1") || env.includes("localhost"))) {
      return `${window.location.protocol}//${window.location.hostname}:5001`;
    }
    return env || `${window.location.protocol}//${window.location.hostname}:5001`;
  }
  return process.env.NEXT_PUBLIC_API_URL || "http://localhost:5001";
}
const API = getApiBase();

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("vapt_token");
}

async function request(path: string, opts: RequestInit = {}): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, { ...opts, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const msg = Array.isArray(err.detail)
      ? err.detail.map((e: { msg?: string }) => e.msg).filter(Boolean).join("; ") || "Validation failed"
      : err.detail || "Request failed";
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  // Auth
  login: (username: string, password: string) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  register: (data: object) =>
    request("/auth/register", { method: "POST", body: JSON.stringify(data) }),
  me: () => request("/auth/me"),
  users: () => request("/auth/users"),
  assignableUsers: () => request("/auth/users/assignable"),
  createUser: (data: { email: string; username: string; full_name: string; password: string; role?: string }) =>
    request("/auth/users", { method: "POST", body: JSON.stringify(data) }),

  // Projects
  createProject: (data: object) =>
    request("/projects", { method: "POST", body: JSON.stringify(data) }),
  listProjects: () => request("/projects"),
  getProject: (id: string) => request(`/projects/${id}`),
  updateProject: (id: string, data: object) =>
    request(`/projects/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  getProjectProgress: (id: string) => request(`/projects/${id}/progress`),
  listProjectMembers: (projectId: string) => request(`/projects/${projectId}/members`),
  getAvailableUsersForProject: (projectId: string) => request(`/projects/${projectId}/members/available-users`),
  addProjectMember: (projectId: string, data: { user_id: string; role: string; can_read?: boolean; can_write?: boolean; can_download_report?: boolean; can_manage_members?: boolean }) =>
    request(`/projects/${projectId}/members`, { method: "POST", body: JSON.stringify(data) }),
  updateProjectMember: (projectId: string, memberId: string, data: { role?: string; can_read?: boolean; can_write?: boolean; can_download_report?: boolean; can_manage_members?: boolean }) =>
    request(`/projects/${projectId}/members/${memberId}`, { method: "PATCH", body: JSON.stringify(data) }),
  removeProjectMember: (projectId: string, memberId: string) =>
    request(`/projects/${projectId}/members/${memberId}`, { method: "DELETE" }),
  getReportUrl: (projectId: string, format: "html" | "docx" | "pdf" | "json" | "csv") =>
    `${API}/projects/${projectId}/report?format=${format}`,
  getReportData: (projectId: string) => request(`/projects/${projectId}/report/data`),
  uploadEvidence: async (projectId: string, file: File) => {
    const MAX_SIZE = 10 * 1024 * 1024; // 10MB
    const ALLOWED = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".txt", ".json", ".xml", ".har"];
    const ext = "." + (file.name.split(".").pop() || "").toLowerCase();
    if (!ALLOWED.includes(ext)) {
      throw new Error(`File type not allowed. Allowed: ${ALLOWED.join(", ")}`);
    }
    if (file.size > MAX_SIZE) {
      throw new Error(`File too large. Max 10MB.`);
    }
    if (file.size === 0) {
      throw new Error("Empty file not allowed.");
    }
    const token = getToken();
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${API}/projects/${projectId}/evidence`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: form,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Upload failed");
    }
    return res.json();
  },
  /** Fetch evidence as blob URL for preview/download (auth required) */
  getEvidenceBlobUrl: async (url: string): Promise<string> => {
    const token = getToken();
    const fullUrl = url.startsWith("http") ? url : `${getApiBase()}${url}`;
    const res = await fetch(fullUrl, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    if (!res.ok) throw new Error("Failed to load evidence");
    const blob = await res.blob();
    return URL.createObjectURL(blob);
  },
  downloadReport: async (projectId: string, format: "html" | "docx" | "pdf" | "json" | "csv", filename?: string) => {
    const token = getToken();
    const res = await fetch(`${API}/projects/${projectId}/report?format=${format}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || `VAPT_Report.${format === "html" ? "html" : format}`;
    a.click();
    URL.revokeObjectURL(url);
  },

  // Test Cases
  getProjectTestCases: (projectId: string, phase?: string) =>
    request(`/testcases/project/${projectId}${phase ? `?phase=${phase}` : ""}`),
  updateResult: (resultId: string, data: object) =>
    request(`/testcases/results/${resultId}`, { method: "PATCH", body: JSON.stringify(data) }),
  getPhases: () => request("/testcases/phases"),
  getLibrary: (phase?: string) =>
    request(`/testcases/library${phase ? `?phase=${phase}` : ""}`),

  // Findings
  createFinding: (data: object) =>
    request("/findings", { method: "POST", body: JSON.stringify(data) }),
  getFindings: (projectId: string) => request(`/findings/project/${projectId}`),
  updateFinding: (id: string, data: object) =>
    request(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  createJiraIssue: (findingId: string, projectKey?: string) =>
    request(`/findings/${findingId}/jira${projectKey ? `?project_key=${projectKey}` : ""}`, { method: "POST" }),

  // Badges
  badges: () => request("/badges"),

  // AI Assist
  suggestFinding: (data: { title: string; description?: string; severity?: string }) =>
    request("/ai-assist/suggest", { method: "POST", body: JSON.stringify(data) }),

  // Admin settings (integration status)
  getSettingsStatus: () => request("/admin/settings"),

  // Audit (admin)
  auditLogs: (params?: { limit?: number; offset?: number; action?: string }) => {
    const q = new URLSearchParams(params as Record<string, string>).toString();
    return request(`/audit${q ? `?${q}` : ""}`);
  },

  // Payloads
  payloadCategories: () => request("/payloads/categories"),
  payloadContent: (cat: string) => {
    const decoded = decodeURIComponent(cat);
    return request(`/payloads/categories/${encodeURIComponent(decoded)}/content`);
  },
  seclistsCategories: () => request("/payloads/seclists/categories"),
  seclistsFiles: (category: string) => {
    const decoded = decodeURIComponent(category);
    return request(`/payloads/seclists/categories/${encodeURIComponent(decoded)}/files`);
  },
  seclistsPreview: (path: string, lines?: number) =>
    request(`/payloads/seclists/preview?path=${encodeURIComponent(path)}&lines=${lines ?? 50}`),
};
