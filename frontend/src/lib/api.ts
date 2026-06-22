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
