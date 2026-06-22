"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { ProjectCard } from "@/components/ProjectCard";
import { ApiProject, listProjects } from "@/lib/api";

export default function ProjectsPage() {
  const { getToken } = useAuth();
  const [projects, setProjects] = useState<ApiProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const token = await getToken();
        if (!token) return;
        const data = await listProjects(token);
        setProjects(data.projects);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load projects");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [getToken]);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Projects" />

      <main className="mx-auto max-w-6xl px-6 py-12">
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Projects</h1>
            <p className="mt-2 text-zinc-400">
              Connect GitHub repos or upload ZIP files to audit.
            </p>
          </div>
          <Link
            href="/projects/new"
            className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400"
          >
            + New Project
          </Link>
        </div>

        {loading && <p className="text-zinc-400">Loading projects...</p>}
        {error && (
          <p className="rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {!loading && !error && projects.length === 0 && (
          <div className="rounded-xl border border-dashed border-zinc-700 bg-zinc-900/30 p-12 text-center">
            <p className="text-lg font-medium text-zinc-300">No projects yet</p>
            <p className="mt-2 text-sm text-zinc-500">
              Create your first project by connecting a GitHub repo or uploading a ZIP.
            </p>
            <Link
              href="/projects/new"
              className="mt-6 inline-block rounded-lg bg-emerald-500 px-6 py-2.5 text-sm font-semibold text-zinc-950"
            >
              Create Project
            </Link>
          </div>
        )}

        {projects.length > 0 && (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {projects.map((project) => (
              <ProjectCard key={project.id} project={project} />
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
