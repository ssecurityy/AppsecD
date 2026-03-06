// API base: /api when behind Nginx (appsecd.com), else host:5001 or env
export function getApiBase(): string {
  if (typeof window !== "undefined") {
    const env = process.env.NEXT_PUBLIC_API_URL;
    const host = window.location.hostname;
    // Same-origin /api when on appsecd.com (Nginx proxies /api to backend, no path conflict)
    if (host === "appsecd.com" || host === "www.appsecd.com") {
      return "/api";
    }
    // Explicit env overrides (e.g. https://appsecd.com/api)
    if (env && !env.includes("localhost") && !env.includes("127.0.0.1")) {
      return env;
    }
    // Remote host (e.g. IP): use host + port 5001
    const isRemote = !["localhost", "127.0.0.1"].includes(host);
    if (isRemote) {
      return `${window.location.protocol}//${host}:5001`;
    }
    return env || `${window.location.protocol}//${host}:5001`;
  }
  return process.env.NEXT_PUBLIC_API_URL || "http://localhost:5001";
}
const API = getApiBase();

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("appsecdtoken");
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
  mfaCompleteLogin: (mfaToken: string, code: string) =>
    request("/mfa/complete-login", { method: "POST", body: JSON.stringify({ mfa_token: mfaToken, code }) }),
  register: (data: object) =>
    request("/auth/register", { method: "POST", body: JSON.stringify(data) }),
  me: () => request("/auth/me"),
  users: (orgId?: string) => request(`/auth/users${orgId ? `?org_id=${orgId}` : ""}`),
  assignableUsers: () => request("/auth/users/assignable"),
  createUser: (data: { email: string; username: string; full_name: string; password: string; role?: string; organization_id?: string }) =>
    request("/auth/users", { method: "POST", body: JSON.stringify(data) }),
  updateUser: (userId: string, data: { email?: string; username?: string; full_name?: string; role?: string; organization_id?: string; is_active?: boolean; xp_points?: number; level?: number }) =>
    request(`/auth/users/${userId}`, { method: "PATCH", body: JSON.stringify(data) }),
  updateUserPassword: (userId: string, password: string) =>
    request(`/auth/users/${userId}/password`, { method: "PUT", body: JSON.stringify({ password }) }),

  // Projects
  detectTech: (url: string) =>
    request("/projects/detect-tech", { method: "POST", body: JSON.stringify({ url }) }),
  createProject: (data: object) =>
    request("/projects", { method: "POST", body: JSON.stringify(data) }),
  listProjects: (params?: { limit?: number; offset?: number }) => {
    const q = params ? `?limit=${params.limit ?? 50}&offset=${params.offset ?? 0}` : "";
    return request(`/projects${q}`);
  },
  getProject: (id: string) => request(`/projects/${id}`),
  updateProject: (id: string, data: object) =>
    request(`/projects/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  getProjectProgress: (id: string) => request(`/projects/${id}/progress`),
  getProjectFindingsTrend: (projectId: string) => request(`/projects/${projectId}/findings/trend`),
  getDashboardFindingsTrend: () => request("/projects/trend/findings"),
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
    a.download = filename || `AppSecD_Report.${format === "html" ? "html" : format}`;
    a.click();
    URL.revokeObjectURL(url);
  },

  // Test Cases (paginated for 1000+ tests)
  getProjectTestCases: (projectId: string, phase?: string, limit?: number, offset?: number) => {
    const params = new URLSearchParams();
    if (phase) params.set("phase", phase);
    if (limit != null) params.set("limit", String(limit));
    if (offset != null) params.set("offset", String(offset));
    return request(`/testcases/project/${projectId}${params.toString() ? `?${params}` : ""}`);
  },
  updateResult: (resultId: string, data: object) =>
    request(`/testcases/results/${resultId}`, { method: "PATCH", body: JSON.stringify(data) }),
  getPhases: () => request("/testcases/phases"),
  getLibrary: (phase?: string) =>
    request(`/testcases/library${phase ? `?phase=${phase}` : ""}`),

  // Findings
  createFinding: (data: object) =>
    request("/findings", { method: "POST", body: JSON.stringify(data) }),
  getFindings: (projectId: string, params?: { limit?: number; offset?: number; severity?: string; recheck_status?: string }) => {
    const q = new URLSearchParams();
    if (params?.limit != null) q.set("limit", String(params.limit));
    if (params?.offset != null) q.set("offset", String(params.offset));
    if (params?.severity) q.set("severity", params.severity);
    if (params?.recheck_status) q.set("recheck_status", params.recheck_status);
    return request(`/findings/project/${projectId}${q.toString() ? `?${q}` : ""}`);
  },
  updateFinding: (id: string, data: object) =>
    request(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  createJiraIssue: (findingId: string, projectKey?: string) =>
    request(`/findings/${findingId}/jira${projectKey ? `?project_key=${projectKey}` : ""}`, { method: "POST" }),
  getVulnSummary: (projectId: string) => request(`/findings/project/${projectId}/summary`),
  updateRecheckStatus: (findingId: string, data: object) =>
    request(`/findings/${findingId}/recheck`, { method: "PATCH", body: JSON.stringify(data) }),
  addFindingComment: (findingId: string, comment: string) =>
    request(`/findings/${findingId}/comment`, { method: "POST", body: JSON.stringify({ comment }) }),
  getSlaPolicyForOrg: (orgId: string) => request(`/organizations/${orgId}/sla-policy`),
  updateSlaPolicyForOrg: (orgId: string, slaPolicy: Record<string, number>) =>
    request(`/organizations/${orgId}/sla-policy`, { method: "PUT", body: JSON.stringify({ sla_policy: slaPolicy }) }),

  // Badges
  badges: () => request("/badges"),

  // AI Assist
  suggestFinding: (data: { title: string; description?: string; severity?: string }) =>
    request("/ai-assist/suggest", { method: "POST", body: JSON.stringify(data) }),

  // Admin settings (integration status, LLM config)
  getSettingsStatus: (orgId?: string) => request(`/admin/settings${orgId ? `?org_id=${orgId}` : ""}`),
  updateLlmSettings: (data: { provider?: string; model: string; api_key?: string }, orgId?: string) =>
    request(`/admin/settings/llm${orgId ? `?org_id=${orgId}` : ""}`, { method: "PUT", body: JSON.stringify(data) }),
  updateJiraSettings: (data: { base_url: string; email: string; api_token: string; project_key: string }, orgId?: string) =>
    request(`/admin/settings/jira${orgId ? `?org_id=${orgId}` : ""}`, { method: "PUT", body: JSON.stringify(data) }),

  // Organizations
  listOrganizations: () => request("/organizations"),
  createOrganization: (data: { name: string; slug?: string }) =>
    request("/organizations", { method: "POST", body: JSON.stringify(data) }),

  // Audit (admin+ access)
  auditLogs: (params?: Record<string, string | number | undefined>) => {
    const clean: Record<string, string> = {};
    if (params) {
      Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== "") clean[k] = String(v); });
    }
    const q = new URLSearchParams(clean).toString();
    return request(`/audit${q ? `?${q}` : ""}`);
  },
  auditStats: (days?: number) =>
    request(`/audit/stats${days ? `?days=${days}` : ""}`),

  // User management
  deleteUser: (userId: string) =>
    request(`/auth/users/${userId}`, { method: "DELETE" }),

  // MFA
  mfaSetup: () => request("/mfa/setup"),
  mfaSetupWithToken: (mfaToken: string) =>
    request("/mfa/setup-with-token", { method: "POST", body: JSON.stringify({ mfa_token: mfaToken }) }),
  mfaCompleteSetup: (mfaToken: string, code: string) =>
    request("/mfa/complete-setup", { method: "POST", body: JSON.stringify({ mfa_token: mfaToken, code }) }),
  mfaVerify: (code: string) =>
    request("/mfa/verify", { method: "POST", body: JSON.stringify({ code }) }),
  mfaDisable: (code: string) =>
    request("/mfa/disable", { method: "POST", body: JSON.stringify({ code }) }),
  mfaStatus: () => request("/mfa/status"),
  mfaAdminEnableForUser: (userId: string, enable: boolean) =>
    request("/mfa/admin/enable-for-user", { method: "POST", body: JSON.stringify({ user_id: userId, enable }) }),
  mfaAdminResetForUser: (userId: string) =>
    request("/mfa/admin/reset-mfa", { method: "POST", body: JSON.stringify({ user_id: userId }) }),

  // Notification settings
  getNotificationSettings: (orgId?: string) =>
    request(`/admin/settings/notifications${orgId ? `?org_id=${orgId}` : ""}`),
  updateNotificationSettings: (data: object, orgId?: string) =>
    request(`/admin/settings/notifications${orgId ? `?org_id=${orgId}` : ""}`, { method: "PUT", body: JSON.stringify(data) }),
  testSlackNotification: (orgId?: string) =>
    request(`/admin/settings/notifications/test-slack${orgId ? `?org_id=${orgId}` : ""}`, { method: "POST" }),
  testSmtpNotification: (orgId?: string) =>
    request(`/admin/settings/notifications/test-smtp${orgId ? `?org_id=${orgId}` : ""}`, { method: "POST" }),

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
  seclistsDownload: (fileId: string) =>
    `${getApiBase()}/payloads/seclists/download/${fileId}`,
  seclistsContent: (fileId: string) =>
    request(`/payloads/seclists/content/${fileId}`),
  payloadSources: () => request("/payloads/sources"),
  sourceFiles: (sourceSlug: string) =>
    request(`/payloads/sources/${encodeURIComponent(sourceSlug)}/files`),

  // LLM & JIRA test connections (org-scoped)
  testLlmConnection: (orgId?: string) => request(`/admin/settings/llm/test${orgId ? `?org_id=${orgId}` : ""}`, { method: "POST" }),
  testJiraConnection: (orgId?: string) => request(`/admin/settings/jira/test${orgId ? `?org_id=${orgId}` : ""}`, { method: "POST" }),

  // Auto-suggest finding
  autoSuggestFinding: (data: { test_title: string; test_description?: string; notes?: string }) =>
    request("/findings/auto-suggest", { method: "POST", body: JSON.stringify(data) }),

  // Report summarize
  summarizeReport: (projectId: string) =>
    request(`/projects/${projectId}/report/summarize`, { method: "POST" }),

  // Burp XML import
  importBurpXml: async (projectId: string, file: File) => {
    const token = getToken();
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${API}/findings/import/burp?project_id=${projectId}`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: form,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Import failed");
    }
    return res.json();
  },

  // Async report
  startAsyncReport: (projectId: string, format: string) =>
    request(`/projects/${projectId}/report/async?format=${format}`, { method: "POST" }),
  getAsyncReportStatus: async (projectId: string, taskId: string) => {
    const token = getToken();
    const res = await fetch(`${API}/projects/${projectId}/report/async/${taskId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (res.status === 202) return { status: "pending" };
    if (res.ok) {
      const blob = await res.blob();
      return { status: "ready", blob };
    }
    throw new Error("Failed to get report status");
  },

  // LLM Payload Crafting
  craftPayload: (data: { test_title: string; test_description?: string; existing_payloads: string[]; target_url?: string; context?: string }) =>
    request("/ai-assist/craft-payload", { method: "POST", body: JSON.stringify(data) }),

  // Organization branding
  getMyBranding: () => request("/organizations/my-branding"),
  updateOrganization: (orgId: string, data: { name?: string; description?: string; brand_color?: string }) =>
    request(`/organizations/${orgId}`, { method: "PATCH", body: JSON.stringify(data) }),
  uploadOrgLogo: async (orgId: string, file: File) => {
    const token = getToken();
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${API}/organizations/${orgId}/logo`, {
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

  // Bulk JIRA
  bulkCreateJira: (data: { finding_ids: string[]; project_key?: string }) =>
    request("/findings/bulk-jira", { method: "POST", body: JSON.stringify(data) }),

  // Security Intelligence
  securityDashboard: () => request("/security-intel/dashboard"),
  cveFeed: (params?: { page?: number; page_size?: number; keyword?: string; severity?: string; cwe?: string; date_from?: string; date_to?: string }) => {
    const q = new URLSearchParams();
    if (params?.page) q.set("page", String(params.page));
    if (params?.page_size) q.set("page_size", String(params.page_size));
    if (params?.keyword) q.set("keyword", params.keyword);
    if (params?.severity) q.set("severity", params.severity);
    if (params?.cwe) q.set("cwe", params.cwe);
    if (params?.date_from) q.set("date_from", params.date_from);
    if (params?.date_to) q.set("date_to", params.date_to);
    return request(`/security-intel/cve-feed${q.toString() ? `?${q}` : ""}`);
  },
  cveSync: (params?: { keyword?: string; days?: number; source?: string }) => {
    const q = new URLSearchParams();
    if (params?.keyword) q.set("keyword", params.keyword);
    if (params?.days) q.set("days", String(params.days));
    if (params?.source) q.set("source", params.source);
    return request(`/security-intel/cve-sync${q.toString() ? `?${q}` : ""}`, { method: "POST" });
  },
  generateTestCases: (data: { context: string; tech_stack?: string; app_type?: string; focus_areas?: string[]; project_id?: string }) =>
    request("/security-intel/generate-test-cases", { method: "POST", body: JSON.stringify(data) }),
  saveTestCases: (data: { project_id: string; test_cases: any[] }) =>
    request("/security-intel/save-test-cases", { method: "POST", body: JSON.stringify(data) }),
  securityAssistant: (data: { question: string; project_id?: string; context?: string; chat_history?: { role: string; content: string }[]; add_test_cases?: boolean }) =>
    request("/security-intel/assistant", { method: "POST", body: JSON.stringify(data) }),
  cveDetail: (cveId: string) => request(`/security-intel/cve/${cveId}`),
  cveSearch: (cveId: string) => request(`/security-intel/cve-search/${cveId}`),
  assistantAddTestCases: (data: { project_id: string; test_cases: any[] }) =>
    request("/security-intel/assistant/add-test-cases", { method: "POST", body: JSON.stringify(data) }),
  getFeatureFlags: (orgId?: string) =>
    request(`/security-intel/feature-flags${orgId ? `?org_id=${orgId}` : ""}`),
  updateFeatureFlags: (data: { org_id: string; flags: Record<string, boolean> }) =>
    request("/security-intel/feature-flags", { method: "PUT", body: JSON.stringify(data) }),

  // AI Enhanced Features
  analyzeEndpoint: (data: { endpoint: string; method?: string; parameters?: string; request_sample?: string; response_sample?: string; framework?: string; project_id?: string }) =>
    request("/ai-assist/analyze-endpoint", { method: "POST", body: JSON.stringify(data) }),
  generateSimilarTests: (data: { existing_test: object; target_context: string; project_id?: string }) =>
    request("/ai-assist/generate-similar-tests", { method: "POST", body: JSON.stringify(data) }),
  missingTests: (data: { project_id: string }) =>
    request("/ai-assist/missing-tests", { method: "POST", body: JSON.stringify(data) }),
  frameworkTests: (data: { framework: string; version?: string; features?: string[]; project_id?: string }) =>
    request("/ai-assist/framework-tests", { method: "POST", body: JSON.stringify(data) }),
  enrichRemediation: (data: { finding_title: string; finding_description?: string; current_remediation?: string; app_framework?: string; app_language?: string; project_id?: string }) =>
    request("/ai-assist/enrich-remediation", { method: "POST", body: JSON.stringify(data) }),
  deduplicateFindings: (data: { project_id: string }) =>
    request("/ai-assist/deduplicate-findings", { method: "POST", body: JSON.stringify(data) }),
  queryFindings: (data: { query: string; project_id?: string }) =>
    request("/ai-assist/query-findings", { method: "POST", body: JSON.stringify(data) }),
  vulnerabilityTrends: (data: { project_ids?: string[] }) =>
    request("/ai-assist/vulnerability-trends", { method: "POST", body: JSON.stringify(data) }),
  cvePayloads: (data: { cve_id: string; cve_description?: string; affected_product?: string; project_id?: string }) =>
    request("/ai-assist/cve-payloads", { method: "POST", body: JSON.stringify(data) }),
  generateCommands: (data: { test_title: string; test_description?: string; target_url?: string; parameters?: string; vuln_type?: string; project_id?: string }) =>
    request("/ai-assist/generate-commands", { method: "POST", body: JSON.stringify(data) }),
  interpretResults: (data: { tool_name: string; raw_output: string; test_context?: string; project_id?: string }) =>
    request("/ai-assist/interpret-results", { method: "POST", body: JSON.stringify(data) }),
  fullReportSummary: (data: { project_id: string }) =>
    request("/ai-assist/full-report-summary", { method: "POST", body: JSON.stringify(data) }),

  // DAST
  dastScan: (data: { project_id: string; target_url?: string; checks?: string[] }) =>
    request("/dast/scan", { method: "POST", body: JSON.stringify(data) }),
  dastScanProgress: (scanId: string) =>
    request(`/dast/scan/${scanId}`, { method: "GET" }),
  dastProjectLatest: (projectId: string) =>
    request(`/dast/project/${projectId}/latest`, { method: "GET" }),
  dastProjectScan: (projectId: string, scanId: string) =>
    request(`/dast/project/${projectId}/scan/${scanId}`, { method: "GET" }),
  dastProjectHistory: (projectId: string, limit = 20) =>
    request(`/dast/project/${projectId}/history?limit=${limit}`, { method: "GET" }),
  dastScans: () => request("/dast/scans", { method: "GET" }),
  dastCheck: (data: { target_url: string; check: string }) =>
    request("/dast/check", { method: "POST", body: JSON.stringify(data) }),
  dastChecks: () => request("/dast/checks"),
  dastFfufScan: (data: { target_url: string; base_path?: string; wordlist?: string }) =>
    request("/dast/ffuf-scan", { method: "POST", body: JSON.stringify(data) }),
  dastFfufExhaustive: (data: { project_id: string; target_url: string; base_path?: string }) =>
    request("/dast/ffuf-exhaustive", { method: "POST", body: JSON.stringify(data) }),
  dastFfufExhaustiveProgress: (jobId: string) =>
    request(`/dast/ffuf-exhaustive/${jobId}`, { method: "GET" }),
  dastLastDiscoveredPaths: (projectId: string) =>
    request(`/dast/project/${projectId}/last-discovered-paths`, { method: "GET" }),
  dastLastDirScan: (projectId: string) =>
    request(`/dast/project/${projectId}/last-dir-scan`, { method: "GET" }),

  // Crawler / Spider
  dastCrawl: (data: { project_id: string; target_url?: string; auth_config?: any; max_depth?: number; crawl_scope?: string; run_param_discovery?: boolean; use_playwright?: boolean }) =>
    request("/dast/crawl", { method: "POST", body: JSON.stringify(data) }),
  dastCrawlProgress: (crawlId: string) =>
    request(`/dast/crawl/${crawlId}`, { method: "GET" }),
  dastCrawlHistory: (projectId: string, limit = 20) =>
    request(`/dast/crawl/project/${projectId}/history?limit=${limit}`, { method: "GET" }),
  dastCrawlLatest: (projectId: string) =>
    request(`/dast/crawl/project/${projectId}/latest`, { method: "GET" }),
  dastCrawlSession: (projectId: string, crawlId: string) =>
    request(`/dast/crawl/project/${projectId}/session/${crawlId}`, { method: "GET" }),

  // Recursive Directory Scan
  dastDirScan: (data: { project_id: string; target_url: string; base_path?: string; max_depth?: number; wordlist?: string; auth_config?: any }) =>
    request("/dast/dir-scan", { method: "POST", body: JSON.stringify(data) }),
  dastDirScanProgress: (jobId: string) =>
    request(`/dast/dir-scan/${jobId}`, { method: "GET" }),

  // Fetch URL content
  dastFetchUrl: (data: { url: string; auth_config?: any }) =>
    request("/dast/fetch-url", { method: "POST", body: JSON.stringify(data) }),

  // DAST AI Analysis
  dastAiSummarizeScan: (data: { project_id: string; scan_id?: string }) =>
    request("/dast/ai/summarize-scan", { method: "POST", body: JSON.stringify(data) }),
  dastAiAnalyzeCrawl: (data: { project_id: string; crawl_id?: string }) =>
    request("/dast/ai/analyze-crawl", { method: "POST", body: JSON.stringify(data) }),
  dastAiSuggestChecks: (data: { project_id: string; target_url?: string }) =>
    request("/dast/ai/suggest-checks", { method: "POST", body: JSON.stringify(data) }),
  dastAiCategorizePaths: (data: { project_id: string; paths: any[]; target_url: string }) =>
    request("/dast/ai/categorize-paths", { method: "POST", body: JSON.stringify(data) }),
  dastAiInterpretResult: (data: { check_result: any; target_url: string }) =>
    request("/dast/ai/interpret-result", { method: "POST", body: JSON.stringify(data) }),
  dastAiCoverageGaps: (data: { project_id: string; target_url?: string }) =>
    request("/dast/ai/coverage-gaps", { method: "POST", body: JSON.stringify(data) }),

  // Claude AI DAST
  claudeDastScan: (data: { project_id: string; target_url?: string; scan_mode?: string; include_subdomains?: boolean; max_cost_usd?: number }) =>
    request("/dast/claude/scan", { method: "POST", body: JSON.stringify(data) }),
  claudeDastScanProgress: (scanId: string) =>
    request(`/dast/claude/scan/${scanId}`, { method: "GET" }),
  claudeDastScanStop: (scanId: string) =>
    request(`/dast/claude/scan/${scanId}/stop`, { method: "POST" }),
  claudeDastPentestOption: (scanId: string, data: { option_id: string; selected_action: string }) =>
    request(`/dast/claude/scan/${scanId}/pentest-option`, { method: "POST", body: JSON.stringify(data) }),
  claudeDastRetest: (data: { project_id: string; finding_ids: string[]; target_url?: string }) =>
    request("/dast/claude/retest", { method: "POST", body: JSON.stringify(data) }),
  claudeDastCrawl: (data: { project_id: string; target_url?: string; include_subdomains?: boolean }) =>
    request("/dast/claude/crawl", { method: "POST", body: JSON.stringify(data) }),
  claudeDastCrawlResults: (projectId: string) =>
    request(`/dast/claude/crawl/${projectId}/results`, { method: "GET" }),
  claudeDastGenerateChecks: (data: { project_id: string; target_url?: string }) =>
    request("/dast/claude/generate-checks", { method: "POST", body: JSON.stringify(data) }),
  claudeDastSession: (projectId: string) =>
    request(`/dast/claude/session/${projectId}`, { method: "GET" }),
  claudeDastSessionClear: (projectId: string) =>
    request(`/dast/claude/session/${projectId}`, { method: "DELETE" }),
  claudeDastCostEstimate: (data: { scan_mode?: string; target_url?: string; include_subdomains?: boolean }) =>
    request("/dast/claude/cost-estimate", { method: "POST", body: JSON.stringify(data) }),
  claudeDastHistory: (projectId: string) =>
    request(`/dast/claude/history/${projectId}`, { method: "GET" }),
  claudeDastAdminUsage: () =>
    request("/dast/claude/admin/usage", { method: "GET" }),
  claudeDastAdminSettings: () =>
    request("/dast/claude/admin/settings", { method: "GET" }),
  claudeDastAdminSettingsOrg: (orgId: string) =>
    request(`/dast/claude/admin/settings/${orgId}`, { method: "GET" }),
  claudeDastAdminSettingsOrgUpdate: (orgId: string, data: Record<string, unknown>) =>
    request(`/dast/claude/admin/settings/${orgId}`, { method: "PATCH", body: JSON.stringify(data) }),

  // Project Admin (delete, transfer)
  deleteProject: (projectId: string) =>
    request(`/projects/${projectId}`, { method: "DELETE" }),
  transferProject: (projectId: string, targetOrgId: string) =>
    request(`/projects/${projectId}/transfer`, { method: "POST", body: JSON.stringify({ target_organization_id: targetOrgId }) }),

  // DAST Export
  dastExportBurpXml: async (projectId: string) => {
    const token = getToken();
    const res = await fetch(`${API}/dast/export/${projectId}/burp-xml`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error("Export failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `dast-findings-${projectId.slice(0, 8)}.xml`; a.click();
    URL.revokeObjectURL(url);
  },
  dastExportJson: async (projectId: string) => {
    const token = getToken();
    const res = await fetch(`${API}/dast/export/${projectId}/json`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error("Export failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `dast-findings-${projectId.slice(0, 8)}.json`; a.click();
    URL.revokeObjectURL(url);
  },
  dastExportCsv: async (projectId: string) => {
    const token = getToken();
    const res = await fetch(`${API}/dast/export/${projectId}/csv`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error("Export failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `dast-findings-${projectId.slice(0, 8)}.csv`; a.click();
    URL.revokeObjectURL(url);
  },
  dastExportHar: async (projectId: string) => {
    const token = getToken();
    const res = await fetch(`${API}/dast/export/${projectId}/har`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error("Export failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `dast-crawl-${projectId.slice(0, 8)}.har`; a.click();
    URL.revokeObjectURL(url);
  },

  // DAST Learnings
  dastLearnings: (projectId: string) =>
    request(`/dast/learnings/${projectId}`, { method: "GET" }),
  dastDeleteLearnings: (projectId: string) =>
    request(`/dast/learnings/${projectId}`, { method: "DELETE" }),

  // Claude DAST with auth config
  claudeDastScanWithAuth: (data: { project_id: string; target_url?: string; scan_mode?: string; include_subdomains?: boolean; max_cost_usd?: number; auth_config?: any; proxy_url?: string }) =>
    request("/dast/claude/scan", { method: "POST", body: JSON.stringify(data) }),
};
