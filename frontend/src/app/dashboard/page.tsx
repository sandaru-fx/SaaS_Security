"use client";

import { useAuth, useUser } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { ApiUser, getCurrentUser } from "@/lib/api";

export default function DashboardPage() {
  const { getToken } = useAuth();
  const { user } = useUser();
  const [apiUser, setApiUser] = useState<ApiUser | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function syncUser() {
      try {
        const token = await getToken();
        if (!token) {
          setError("No auth token available");
          return;
        }
        const data = await getCurrentUser(token);
        setApiUser(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to sync user");
      } finally {
        setLoading(false);
      }
    }

    syncUser();
  }, [getToken]);

  const displayName =
    apiUser?.first_name ||
    user?.firstName ||
    user?.emailAddresses[0]?.emailAddress ||
    "User";

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Phase 2 — Auth" />

      <main className="mx-auto max-w-6xl px-6 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold tracking-tight">
            Welcome, {displayName}
          </h1>
          <p className="mt-2 text-zinc-400">
            Your auditor dashboard. Projects and scans coming in Phase 3.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <StatCard label="Projects" value="0" hint="Phase 3" />
          <StatCard label="Scans" value="0" hint="Phase 4" />
          <StatCard label="Health Score" value="—" hint="Phase 5" />
        </div>

        <div className="mt-8 grid gap-6 lg:grid-cols-2">
          <section className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
            <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
              Account Status
            </h2>
            {loading && <p className="mt-4 text-zinc-400">Syncing with API...</p>}
            {error && (
              <p className="mt-4 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
                {error}
              </p>
            )}
            {apiUser && (
              <dl className="mt-4 space-y-3 text-sm">
                <Row label="Email" value={apiUser.email} />
                <Row label="Clerk ID" value={apiUser.clerk_id} mono />
                <Row label="DB User ID" value={apiUser.id} mono />
                <Row
                  label="Synced"
                  value={new Date(apiUser.created_at).toLocaleString()}
                />
              </dl>
            )}
          </section>

          <section className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
            <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
              Quick Actions
            </h2>
            <div className="mt-4 flex flex-col gap-3">
              <Link
                href="/profile"
                className="rounded-lg border border-zinc-700 px-4 py-3 text-sm text-zinc-300 transition hover:border-emerald-500 hover:text-white"
              >
                Edit Profile →
              </Link>
              <button
                type="button"
                disabled
                className="cursor-not-allowed rounded-lg border border-zinc-800 px-4 py-3 text-left text-sm text-zinc-600"
              >
                Create Project — Phase 3
              </button>
              <button
                type="button"
                disabled
                className="cursor-not-allowed rounded-lg border border-zinc-800 px-4 py-3 text-left text-sm text-zinc-600"
              >
                Start Audit — Phase 4
              </button>
            </div>
          </section>
        </div>
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

function Row({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-4 border-b border-zinc-800 pb-3">
      <dt className="text-zinc-500">{label}</dt>
      <dd className={`text-right text-zinc-200 ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </dd>
    </div>
  );
}
