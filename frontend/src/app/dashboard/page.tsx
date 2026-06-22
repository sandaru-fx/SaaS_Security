"use client";

import { useAuth, useUser } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { ProjectCard } from "@/components/ProjectCard";
import { ApiProject, ApiUser, getCurrentUser, listProjects } from "@/lib/api";

export default function DashboardPage() {
  const { getToken } = useAuth();
  const { user } = useUser();
  const [apiUser, setApiUser] = useState<ApiUser | null>(null);
  const [projects, setProjects] = useState<ApiProject[]>([]);
  const [projectTotal, setProjectTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const token = await getToken();
        if (!token) {
          setError("No auth token available");
          return;
        }
        const [userData, projectData] = await Promise.all([
          getCurrentUser(token),
          listProjects(token),
        ]);
        setApiUser(userData);
        setProjects(projectData.projects.slice(0, 3));
        setProjectTotal(projectData.total);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load dashboard");
      } finally {
        setLoading(false);
      }
    }

    load();
  }, [getToken]);

  const displayName =
    apiUser?.first_name ||
    user?.firstName ||
    user?.emailAddresses[0]?.emailAddress ||
    "User";

  const readyProjects = projects.filter((p) => p.status === "ready").length;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Phase 3 — Projects" />

      <main className="mx-auto max-w-6xl px-6 py-12">
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              Welcome, {displayName}
            </h1>
            <p className="mt-2 text-zinc-400">
              Manage your projects and prepare them for security audits.
            </p>
          </div>
          <Link
            href="/projects/new"
            className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400"
          >
            + New Project
          </Link>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <StatCard label="Projects" value={String(projectTotal)} hint="Total projects" />
          <StatCard label="Ready" value={String(readyProjects)} hint="Ready to audit" />
          <StatCard label="Health Score" value="—" hint="Phase 5" />
        </div>

        {loading && <p className="mt-8 text-zinc-400">Loading dashboard...</p>}
        {error && (
          <p className="mt-8 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {!loading && !error && (
          <section className="mt-8">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
                Recent Projects
              </h2>
              <Link href="/projects" className="text-sm text-emerald-400 hover:text-emerald-300">
                View all →
              </Link>
            </div>

            {projects.length === 0 ? (
              <div className="rounded-xl border border-dashed border-zinc-700 bg-zinc-900/30 p-10 text-center">
                <p className="text-zinc-300">No projects yet</p>
                <p className="mt-2 text-sm text-zinc-500">
                  Connect a GitHub repo or upload a ZIP to get started.
                </p>
                <Link
                  href="/projects/new"
                  className="mt-4 inline-block rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950"
                >
                  Create First Project
                </Link>
              </div>
            ) : (
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {projects.map((project) => (
                  <ProjectCard key={project.id} project={project} />
                ))}
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
      <p className="text-sm text-zinc-500">{label}</p>
      <p className="mt-2 text-4xl font-bold">{value}</p>
      <p className="mt-1 text-xs text-zinc-600">{hint}</p>
    </div>
  );
}
