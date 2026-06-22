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
export type SourceType = "github" | "zip";

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
  created_at: string;
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
};

export type ScanListResponse = { scans: ApiScan[]; total: number };
export type IssueListResponse = { issues: ApiIssue[]; total: number };

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

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

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
