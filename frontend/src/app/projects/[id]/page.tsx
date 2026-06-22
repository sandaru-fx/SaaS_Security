"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { ApiProject, deleteProject, getProject } from "@/lib/api";

const statusColors: Record<ApiProject["status"], string> = {
  pending: "text-zinc-400",
  processing: "text-amber-400",
  ready: "text-emerald-400",
  failed: "text-red-400",
};

export default function ProjectDetailPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const params = useParams();
  const projectId = params.id as string;

  const [project, setProject] = useState<ApiProject | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const token = await getToken();
        if (!token) return;
        const data = await getProject(token, projectId);
        setProject(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load project");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [getToken, projectId]);

  async function handleDelete() {
    if (!confirm("Delete this project and all uploaded files?")) return;
    setDeleting(true);
    try {
      const token = await getToken();
      if (!token) return;
      await deleteProject(token, projectId);
      router.push("/projects");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete project");
      setDeleting(false);
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Project Detail" />

      <main className="mx-auto max-w-3xl px-6 py-12">
        <Link href="/projects" className="text-sm text-zinc-500 hover:text-zinc-300">
          ← Back to Projects
        </Link>

        {loading && <p className="mt-8 text-zinc-400">Loading project...</p>}
        {error && (
          <p className="mt-8 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {project && (
          <div className="mt-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold tracking-tight">{project.name}</h1>
                {project.description && (
                  <p className="mt-2 text-zinc-400">{project.description}</p>
                )}
              </div>
              <span
                className={`rounded-full border border-zinc-700 px-3 py-1 text-sm capitalize ${statusColors[project.status]}`}
              >
                {project.status}
              </span>
            </div>

            <div className="mt-8 space-y-4 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
              <DetailRow label="Source" value={project.source_type === "github" ? "GitHub" : "ZIP Upload"} />
              {project.repo_url && (
                <DetailRow label="Repository" value={project.repo_url} mono />
              )}
              {project.repo_branch && (
                <DetailRow label="Branch" value={project.repo_branch} />
              )}
              <DetailRow label="Files" value={String(project.file_count)} />
              <DetailRow
                label="Created"
                value={new Date(project.created_at).toLocaleString()}
              />
              {project.status_message && (
                <DetailRow label="Status Message" value={project.status_message} />
              )}
            </div>

            <div className="mt-8 flex flex-wrap gap-3">
              <button
                type="button"
                disabled={project.status !== "ready"}
                className="cursor-not-allowed rounded-lg bg-emerald-500/40 px-6 py-2.5 text-sm font-semibold text-zinc-950"
                title="Available in Phase 4"
              >
                Start Audit — Phase 4
              </button>
              <button
                type="button"
                onClick={handleDelete}
                disabled={deleting}
                className="rounded-lg border border-red-900 px-6 py-2.5 text-sm text-red-400 transition hover:bg-red-950/30 disabled:opacity-50"
              >
                {deleting ? "Deleting..." : "Delete Project"}
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-4 border-b border-zinc-800 pb-3 last:border-0 last:pb-0">
      <span className="text-sm text-zinc-500">{label}</span>
      <span className={`text-right text-sm text-zinc-200 ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </span>
    </div>
  );
}
