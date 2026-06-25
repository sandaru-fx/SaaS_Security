"use client";

import { useAuth, useUser } from "@clerk/nextjs";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { ActiveScanBanner } from "@/components/ActiveScanBanner";
import { AppHeader } from "@/components/AppHeader";
import { CategoryBreakdown } from "@/components/CategoryBreakdown";
import { OnboardingWizard } from "@/components/OnboardingWizard";
import { ProjectCard } from "@/components/ProjectCard";
import { RecentScansList } from "@/components/RecentScansList";
import { ScoreTrendChart } from "@/components/ScoreTrendChart";
import {
  ApiProject,
  ApiUser,
  DashboardData,
  getCurrentUser,
  getDashboard,
  listProjects,
} from "@/lib/api";

export default function DashboardPage() {
  const { getToken } = useAuth();
  const { user } = useUser();
  const [apiUser, setApiUser] = useState<ApiUser | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [projects, setProjects] = useState<ApiProject[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState<string | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [showOnboarding, setShowOnboarding] = useState(false);

  const loadDashboard = useCallback(async () => {
    const token = await getToken();
    if (!token) {
      setError("No auth token available");
      return null;
    }

    const [userData, projectData, dashboardData] = await Promise.all([
      getCurrentUser(token),
      listProjects(token),
      getDashboard(token),
    ]);

    setApiUser(userData);
    setProjects(projectData.projects.slice(0, 3));
    setDashboard(dashboardData);
    setAuthToken(token);
    setShowOnboarding(!userData.onboarding_completed && projectData.total === 0);
    setError(null);
    return dashboardData;
  }, [getToken]);

  useEffect(() => {
    let active = true;
    let interval: ReturnType<typeof setInterval> | null = null;
    let previousActiveCount = 0;

    async function init() {
      try {
        const data = await loadDashboard();
        if (!active || !data) return;
        previousActiveCount = data.active_scans.length;

        if (data.active_scans.length > 0) {
          interval = setInterval(async () => {
            try {
              const updated = await loadDashboard();
              if (!active || !updated) return;

              if (previousActiveCount > 0 && updated.active_scans.length === 0) {
                const latest = updated.recent_scans[0];
                if (latest?.status === "completed" && latest.health_score != null) {
                  setNotification(
                    `Audit complete for ${latest.project_name} — score ${latest.health_score}/100`,
                  );
                }
              }
              previousActiveCount = updated.active_scans.length;
            } catch {
              // keep polling quietly
            }
          }, 5000);
        }
      } catch (err) {
        if (active) {
          setError(err instanceof Error ? err.message : "Failed to load dashboard");
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    init();

    return () => {
      active = false;
      if (interval) clearInterval(interval);
    };
  }, [loadDashboard]);

  const displayName =
    apiUser?.first_name ||
    user?.firstName ||
    user?.emailAddresses[0]?.emailAddress ||
    "User";

  const stats = dashboard?.stats;
  const scoreChange = stats?.score_change;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Dashboard" />

      <main className="mx-auto max-w-6xl px-6 py-12">
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Welcome, {displayName}</h1>
            <p className="mt-2 text-zinc-400">
              Your audit health overview, trends, and recent activity.
            </p>
          </div>
          <Link
            href="/projects/new"
            className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400"
          >
            + New Project
          </Link>
        </div>

        {showOnboarding && authToken && (
          <OnboardingWizard
            token={authToken}
            onComplete={() => setShowOnboarding(false)}
          />
        )}

        {notification && (
          <div className="mb-6 flex items-center justify-between gap-4 rounded-xl border border-emerald-500/30 bg-emerald-950/30 px-4 py-3">
            <p className="text-sm text-emerald-200">{notification}</p>
            <button
              type="button"
              onClick={() => setNotification(null)}
              className="text-sm text-emerald-400 hover:text-emerald-300"
            >
              Dismiss
            </button>
          </div>
        )}

        {dashboard && <ActiveScanBanner scans={dashboard.active_scans} />}

        {loading && <p className="text-zinc-400">Loading dashboard...</p>}
        {error && (
          <p className="rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {dashboard && !loading && !error && (
          <>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <StatCard label="Projects" value={String(stats?.total_projects ?? 0)} />
              <StatCard label="Ready to Audit" value={String(stats?.ready_projects ?? 0)} />
              <StatCard
                label="Average Score"
                value={stats?.average_health_score != null ? String(stats.average_health_score) : "—"}
              />
              <StatCard
                label="Best Score"
                value={stats?.best_health_score != null ? String(stats.best_health_score) : "—"}
                delta={scoreChange}
              />
            </div>

            <div className="mt-8 grid gap-6 lg:grid-cols-5">
              <section className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-6 lg:col-span-3">
                <ScoreTrendChart points={dashboard.score_trend} />
              </section>
              <section className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-6 lg:col-span-2">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-widest text-zinc-500">
                  Category Overview
                </h2>
                <CategoryBreakdown
                  categories={dashboard.category_averages.map((c) => ({
                    category: c.category,
                    score: c.score,
                    issue_count: c.project_count,
                  }))}
                  countLabel="projects"
                />
              </section>
            </div>

            <section className="mt-8">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
                  Recent Audits
                </h2>
                <span className="text-xs text-zinc-600">
                  {stats?.completed_scans ?? 0} completed · {stats?.total_scans ?? 0} total
                </span>
              </div>
              <RecentScansList scans={dashboard.recent_scans} />
            </section>

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
          </>
        )}
      </main>
    </div>
  );
}

function StatCard({
  label,
  value,
  delta,
}: {
  label: string;
  value: string;
  delta?: number | null;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
      <p className="text-sm text-zinc-500">{label}</p>
      <p className="mt-2 text-3xl font-bold">{value}</p>
      {delta != null && (
        <p
          className={`mt-1 text-xs font-medium ${
            delta >= 0 ? "text-emerald-400" : "text-red-400"
          }`}
        >
          {delta >= 0 ? "+" : ""}
          {delta} since last audit
        </p>
      )}
    </div>
  );
}
