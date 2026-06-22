const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type ApiUser = {
  id: string;
  clerk_id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
};

export type ProjectStatus = "pending" | "processing" | "ready" | "failed";
export type SourceType = "github" | "zip" | "folder" | "local" | "website" | "api";

export type AuthType = "none" | "bearer" | "basic" | "cookie" | "header";

export type AuthConfig = {
  type: AuthType;
  token?: string | null;
  username?: string | null;
  password?: string | null;
  cookies?: string | null;
  header_name?: string | null;
  header_value?: string | null;
};

export type ApiProject = {
  id: string;
  name: string;
  description: string | null;
  source_type: SourceType;
  repo_url: string | null;
  repo_branch: string | null;
  status: ProjectStatus;
  status_message: string | null;
  file_count: number;
  domain_verified?: boolean;
  domain_verification_token?: string | null;
  pr_checks_enabled?: boolean;
  active_dast_enabled?: boolean;
  api_spec_url?: string | null;
  has_auth_configured?: boolean;
  created_at: string;
  updated_at: string;
};

export type ProjectListResponse = {
  projects: ApiProject[];
  total: number;
};

export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type IssueSeverity = "critical" | "high" | "medium" | "low";

export type ApiScan = {
  id: string;
  project_id: string;
  status: ScanStatus;
  scanners_used: string[];
  total_issues: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  health_score: number | null;
  security_score: number | null;
  architecture_score: number | null;
  performance_score: number | null;
  quality_score: number | null;
  devops_score: number | null;
  grade: string | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
};

export type ApiIssue = {
  id: string;
  scan_id: string;
  category: string;
  severity: IssueSeverity;
  title: string;
  description: string;
  impact: string;
  fix_recommendation: string;
  business_risk: string | null;
  file_path: string | null;
  line_start: number;
  line_end: number;
  rule_id: string;
  scanner: string;
  confidence: string;
  priority: number | null;
  report_category: string | null;
  dismissed: boolean;
  dismissed_reason: string | null;
  cwe_id: string | null;
  owasp_category: string | null;
  ai_triage_verdict: string | null;
  ai_triage_reason: string | null;
  ai_fix_suggestion: string | null;
  created_at: string;
};

export type AuditChatMessage = {
  role: "user" | "assistant";
  content: string;
};

export type AuditChatResponse = {
  reply: string;
  provider: string;
};

export type CategoryScore = {
  category: string;
  score: number;
  issue_count: number;
};

export type AuditReport = {
  scan_id: string;
  project_id: string;
  status: ScanStatus;
  overall_score: number;
  grade: string;
  categories: CategoryScore[];
  severity_breakdown: Record<string, number>;
  executive_summary: string;
  fix_plan: string[];
  top_priority_issues: ApiIssue[];
  production_ready: boolean;
  estimated_score_if_top_fixed: number | null;
  ai_summary: string | null;
  ai_business_risk: string | null;
  ai_recommendations: string[];
  ai_provider: string | null;
  compliance: ComplianceControl[];
};

export type ComplianceControl = {
  framework: string;
  control_id: string;
  title: string;
  issue_count: number;
  max_severity: string;
  status: string;
};

export type ScanListResponse = { scans: ApiScan[]; total: number };
export type IssueListResponse = { issues: ApiIssue[]; total: number };

export type DashboardStats = {
  total_projects: number;
  ready_projects: number;
  total_scans: number;
  completed_scans: number;
  average_health_score: number | null;
  best_health_score: number | null;
  score_change: number | null;
};

export type RecentScanItem = {
  scan_id: string;
  project_id: string;
  project_name: string;
  status: ScanStatus;
  health_score: number | null;
  grade: string | null;
  total_issues: number;
  critical_count: number;
  created_at: string;
  completed_at: string | null;
};

export type TrendPoint = {
  scan_id: string;
  project_id: string;
  project_name: string;
  health_score: number;
  grade: string | null;
  completed_at: string;
};

export type CategoryAverage = {
  category: string;
  score: number;
  project_count: number;
};

export type ActiveScanItem = {
  scan_id: string;
  project_id: string;
  project_name: string;
  status: ScanStatus;
  created_at: string;
};

export type DashboardData = {
  stats: DashboardStats;
  recent_scans: RecentScanItem[];
  score_trend: TrendPoint[];
  category_averages: CategoryAverage[];
  active_scans: ActiveScanItem[];
};

export type ScanCompareResult = {
  project_id: string;
  base_scan: ApiScan;
  target_scan: ApiScan;
  score_delta: number | null;
  issues_delta: number;
  critical_delta: number;
  high_delta: number;
  medium_delta: number;
  low_delta: number;
  category_deltas: Record<string, number | null>;
  improved: boolean;
  fixed_count: number;
  new_count: number;
  recurring_count: number;
  fixed_issues: RemediationItem[];
  new_issues: RemediationItem[];
};

export type RemediationItem = {
  title: string;
  severity: IssueSeverity;
  rule_id: string;
  file_path: string | null;
};

export type PlanFeatures = {
  pdf_export: boolean;
  sbom_export: boolean;
  deep_audit: boolean;
  private_repos: boolean;
  unlimited_scans: boolean;
};

export type SubscriptionInfo = {
  plan: string;
  plan_label: string;
  price_display: string;
  scans_used: number;
  scan_limit: number | null;
  scans_remaining: number | null;
  features: PlanFeatures;
  billing_period_start: string | null;
  has_active_subscription: boolean;
  stripe_enabled: boolean;
};

export type PricingPlan = {
  id: string;
  label: string;
  price_display: string;
  scan_limit: number | null;
  features: string[];
};

export type PricingData = {
  plans: PricingPlan[];
  stripe_enabled: boolean;
};

export async function apiFetch<T>(
  path: string,
  token: string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    ...(options.headers as Record<string, string>),
  };

  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers,
    });
  } catch {
    throw new Error(
      `Cannot reach the API at ${API_URL}. Start the backend with: npm run dev:backend`,
    );
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Request failed" }));
    const detail = error.detail;
    const message = typeof detail === "string" ? detail : "Request failed";
    throw new Error(message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

export async function getCurrentUser(token: string): Promise<ApiUser> {
  return apiFetch<ApiUser>("/api/users/me", token);
}

export async function updateCurrentUser(
  token: string,
  data: { first_name?: string; last_name?: string },
): Promise<ApiUser> {
  return apiFetch<ApiUser>("/api/users/me", token, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function listProjects(token: string): Promise<ProjectListResponse> {
  return apiFetch<ProjectListResponse>("/api/projects", token);
}

export async function getProject(token: string, projectId: string): Promise<ApiProject> {
  return apiFetch<ApiProject>(`/api/projects/${projectId}`, token);
}

export async function createGithubProject(
  token: string,
  data: { name: string; repo_url: string; branch?: string; description?: string },
): Promise<ApiProject> {
  return apiFetch<ApiProject>("/api/projects/github", token, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function uploadZipProject(
  token: string,
  data: { name: string; file: File; description?: string },
): Promise<ApiProject> {
  const formData = new FormData();
  formData.append("name", data.name);
  formData.append("file", data.file);
  if (data.description) {
    formData.append("description", data.description);
  }

  return apiFetch<ApiProject>("/api/projects/upload", token, {
    method: "POST",
    body: formData,
  });
}

export async function uploadFolderProject(
  token: string,
  data: { name: string; files: File[]; description?: string },
): Promise<ApiProject> {
  const formData = new FormData();
  formData.append("name", data.name);
  if (data.description) {
    formData.append("description", data.description);
  }
  for (const file of data.files) {
    const relativePath = file.webkitRelativePath || file.name;
    formData.append("files", file, relativePath);
  }

  const response = await fetch(`${API_URL}/api/projects/folder`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Folder upload failed" }));
    const detail = error.detail;
    throw new Error(typeof detail === "string" ? detail : "Folder upload failed");
  }
  return response.json();
}

export async function createLocalProject(
  token: string,
  data: { name: string; local_path: string; description?: string },
): Promise<ApiProject> {
  return apiFetch<ApiProject>("/api/projects/local", token, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function getApiFeatures(): Promise<{ local_project_paths: boolean }> {
  const response = await fetch(`${API_URL}/api/health`);
  if (!response.ok) {
    return { local_project_paths: false };
  }
  const data = await response.json();
  return data.features ?? { local_project_paths: false };
}

export async function createWebsiteProject(
  token: string,
  data: {
    name: string;
    website_url: string;
    description?: string;
    ownership_confirmed: boolean;
    active_dast_enabled?: boolean;
    auth?: AuthConfig | null;
  },
): Promise<ApiProject> {
  return apiFetch<ApiProject>("/api/projects/website", token, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function createApiProject(
  token: string,
  data: {
    name: string;
    api_spec_url: string;
    description?: string;
    ownership_confirmed: boolean;
    auth?: AuthConfig | null;
  },
): Promise<ApiProject> {
  return apiFetch<ApiProject>("/api/projects/api", token, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateProjectAuth(
  token: string,
  projectId: string,
  data: { auth: AuthConfig; active_dast_enabled?: boolean | null },
): Promise<ApiProject> {
  return apiFetch<ApiProject>(`/api/projects/${projectId}/auth`, token, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function updateProject(
  token: string,
  projectId: string,
  data: { name?: string; description?: string },
): Promise<ApiProject> {
  return apiFetch<ApiProject>(`/api/projects/${projectId}`, token, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteProject(token: string, projectId: string): Promise<void> {
  await apiFetch<void>(`/api/projects/${projectId}`, token, { method: "DELETE" });
}

export type DomainVerificationInfo = {
  domain: string;
  token: string;
  dns_record_name: string;
  dns_record_value: string;
  meta_tag: string;
  verified: boolean;
};

export async function getDomainVerification(
  token: string,
  projectId: string,
): Promise<DomainVerificationInfo> {
  return apiFetch<DomainVerificationInfo>(`/api/projects/${projectId}/domain-verification`, token);
}

export async function verifyDomain(
  token: string,
  projectId: string,
): Promise<DomainVerificationInfo> {
  return apiFetch<DomainVerificationInfo>(`/api/projects/${projectId}/verify-domain`, token, {
    method: "POST",
  });
}

export async function updateProjectPrChecks(
  token: string,
  projectId: string,
  enabled: boolean,
): Promise<ApiProject> {
  return apiFetch<ApiProject>(`/api/projects/${projectId}/pr-checks`, token, {
    method: "PATCH",
    body: JSON.stringify({ enabled }),
  });
}

export async function updateGithubPat(
  token: string,
  github_pat: string | null,
): Promise<{ github_pat_configured: boolean }> {
  const user = await apiFetch<ApiUser & { github_pat_configured: boolean }>(
    "/api/users/me/github-pat",
    token,
    { method: "PATCH", body: JSON.stringify({ github_pat }) },
  );
  return { github_pat_configured: user.github_pat_configured };
}

export async function startScan(token: string, projectId: string): Promise<ApiScan> {
  return apiFetch<ApiScan>(`/api/projects/${projectId}/scans`, token, { method: "POST" });
}

export async function listScans(token: string, projectId: string): Promise<ScanListResponse> {
  return apiFetch<ScanListResponse>(`/api/projects/${projectId}/scans`, token);
}

export async function getScan(token: string, scanId: string): Promise<ApiScan> {
  return apiFetch<ApiScan>(`/api/scans/${scanId}`, token);
}

export async function listScanIssues(
  token: string,
  scanId: string,
  filters?: { severity?: string; category?: string },
): Promise<IssueListResponse> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.category) params.set("category", filters.category);
  const qs = params.toString();
  return apiFetch<IssueListResponse>(`/api/scans/${scanId}/issues${qs ? `?${qs}` : ""}`, token);
}

export async function getAuditReport(token: string, scanId: string): Promise<AuditReport> {
  return apiFetch<AuditReport>(`/api/scans/${scanId}/report`, token);
}

export async function chatWithAudit(
  token: string,
  scanId: string,
  data: { message: string; history?: AuditChatMessage[] },
): Promise<AuditChatResponse> {
  return apiFetch<AuditChatResponse>(`/api/scans/${scanId}/chat`, token, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function getDashboard(token: string): Promise<DashboardData> {
  return apiFetch<DashboardData>("/api/dashboard", token);
}

export async function compareScans(
  token: string,
  projectId: string,
  baseScanId: string,
  targetScanId: string,
): Promise<ScanCompareResult> {
  const params = new URLSearchParams({ base: baseScanId, target: targetScanId });
  return apiFetch<ScanCompareResult>(
    `/api/dashboard/projects/${projectId}/scans/compare?${params}`,
    token,
  );
}

export async function getPricing(): Promise<PricingData> {
  const response = await fetch(`${API_URL}/api/billing/pricing`);
  if (!response.ok) throw new Error("Failed to load pricing");
  return response.json();
}

export async function getSubscription(token: string): Promise<SubscriptionInfo> {
  return apiFetch<SubscriptionInfo>("/api/billing/subscription", token);
}

export async function createCheckout(token: string, plan: "pro" | "team"): Promise<string> {
  const data = await apiFetch<{ checkout_url: string }>("/api/billing/checkout", token, {
    method: "POST",
    body: JSON.stringify({ plan }),
  });
  return data.checkout_url;
}

export async function createBillingPortal(token: string): Promise<string> {
  const data = await apiFetch<{ portal_url: string }>("/api/billing/portal", token, {
    method: "POST",
  });
  return data.portal_url;
}

export async function downloadAuditPdf(token: string, scanId: string): Promise<Blob> {
  const response = await fetch(`${API_URL}/api/scans/${scanId}/report/pdf`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "PDF download failed" }));
    const detail = error.detail;
    throw new Error(typeof detail === "string" ? detail : "PDF download failed");
  }
  return response.blob();
}

export async function downloadSbom(token: string, scanId: string): Promise<Blob> {
  const response = await fetch(`${API_URL}/api/scans/${scanId}/sbom`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "SBOM download failed" }));
    const detail = error.detail;
    throw new Error(typeof detail === "string" ? detail : "SBOM download failed");
  }
  return response.blob();
}

export type ApiKeyInfo = {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  created_at: string;
};

export type ApiKeyCreated = ApiKeyInfo & { api_key: string };

export type ScheduleInfo = {
  id: string;
  project_id: string;
  frequency: string;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  created_at: string;
};

export type CustomRuleInfo = {
  id: string;
  name: string;
  pattern: string;
  category: string;
  severity: string;
  enabled: boolean;
  created_at: string;
};

export async function dismissIssue(
  token: string,
  issueId: string,
  reason?: string,
): Promise<void> {
  await apiFetch(`/api/enterprise/issues/${issueId}/dismiss`, token, {
    method: "PATCH",
    body: JSON.stringify({ reason }),
  });
}

export async function listApiKeys(token: string): Promise<ApiKeyInfo[]> {
  return apiFetch<ApiKeyInfo[]>("/api/enterprise/api-keys", token);
}

export async function createApiKey(token: string, name: string): Promise<ApiKeyCreated> {
  return apiFetch<ApiKeyCreated>("/api/enterprise/api-keys", token, {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

export async function deleteApiKey(token: string, keyId: string): Promise<void> {
  await apiFetch(`/api/enterprise/api-keys/${keyId}`, token, { method: "DELETE" });
}

export async function listSchedules(token: string): Promise<ScheduleInfo[]> {
  return apiFetch<ScheduleInfo[]>("/api/enterprise/schedules", token);
}

export async function createSchedule(
  token: string,
  data: { project_id: string; frequency: "weekly" | "monthly" },
): Promise<ScheduleInfo> {
  return apiFetch<ScheduleInfo>("/api/enterprise/schedules", token, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function listCustomRules(token: string): Promise<CustomRuleInfo[]> {
  return apiFetch<CustomRuleInfo[]>("/api/enterprise/custom-rules", token);
}

export async function createCustomRule(
  token: string,
  data: { name: string; pattern: string; category?: string; severity?: string },
): Promise<CustomRuleInfo> {
  return apiFetch<CustomRuleInfo>("/api/enterprise/custom-rules", token, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateProjectWebhook(
  token: string,
  projectId: string,
  data: { webhook_url?: string; webhook_secret?: string },
): Promise<{ webhook_url: string | null; configured: boolean }> {
  return apiFetch(`/api/enterprise/projects/${projectId}/webhook`, token, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function updateNotificationSettings(
  token: string,
  email_alerts_enabled: boolean,
): Promise<void> {
  await apiFetch("/api/enterprise/notifications", token, {
    method: "PATCH",
    body: JSON.stringify({ email_alerts_enabled }),
  });
}
