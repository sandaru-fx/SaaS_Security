"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { IssueCard } from "@/components/IssueCard";
import { ApiIssue, ApiScan, getScan, listScanIssues } from "@/lib/api";

const severityFilters = ["all", "critical", "high", "medium", "low"] as const;

export default function ScanResultsPage() {
  const { getToken } = useAuth();
  const params = useParams();
  const projectId = params.id as string;
  const scanId = params.scanId as string;

  const [scan, setScan] = useState<ApiScan | null>(null);
  const [issues, setIssues] = useState<ApiIssue[]>([]);
  const [filter, setFilter] = useState<(typeof severityFilters)[number]>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const token = await getToken();
      if (!token) return;

      const [scanData, issueData] = await Promise.all([
        getScan(token, scanId),
        listScanIssues(token, scanId, filter === "all" ? undefined : { severity: filter }),
      ]);

      setScan(scanData);
      setIssues(issueData.issues);
      setError(null);

      if (scanData.status === "queued" || scanData.status === "running") {
        return false;
      }
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
      return true;
    } finally {
      setLoading(false);
    }
  }, [getToken, scanId, filter]);

  useEffect(() => {
    let active = true;
    let interval: ReturnType<typeof setInterval> | null = null;

    async function poll() {
      const done = await loadData();
      if (!active) return;
      if (!done && !interval) {
        interval = setInterval(async () => {
          const finished = await loadData();
          if (finished && interval) {
            clearInterval(interval);
            interval = null;
          }
        }, 3000);
      }
    }

    poll();

    return () => {
      active = false;
      if (interval) clearInterval(interval);
    };
  }, [loadData]);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Scan Results" />

      <main className="mx-auto max-w-4xl px-6 py-12">
        <Link
          href={`/projects/${projectId}`}
          className="text-sm text-zinc-500 hover:text-zinc-300"
        >
          ← Back to Project
        </Link>

        {loading && !scan && <p className="mt-8 text-zinc-400">Loading scan...</p>}
        {error && (
          <p className="mt-8 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {scan && (
          <>
            <div className="mt-6 flex flex-wrap items-start justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold tracking-tight">Audit Results</h1>
                <p className="mt-2 capitalize text-zinc-400">Status: {scan.status}</p>
              </div>
              {(scan.status === "queued" || scan.status === "running") && (
                <div className="flex items-center gap-2 text-amber-400">
                  <span className="h-2 w-2 animate-pulse rounded-full bg-amber-400" />
                  <span className="text-sm">Scanning in progress...</span>
                </div>
              )}
            </div>

            {scan.error_message && (
              <p className="mt-4 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
                {scan.error_message}
              </p>
            )}

            <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-5">
              <CountCard label="Total" value={scan.total_issues} />
              <CountCard label="Critical" value={scan.critical_count} color="text-red-400" />
              <CountCard label="High" value={scan.high_count} color="text-orange-400" />
              <CountCard label="Medium" value={scan.medium_count} color="text-amber-400" />
              <CountCard label="Low" value={scan.low_count} color="text-zinc-400" />
            </div>

            {scan.scanners_used.length > 0 && (
              <p className="mt-4 text-xs text-zinc-500">
                Scanners: {scan.scanners_used.join(", ")}
              </p>
            )}

            <div className="mt-8 flex flex-wrap gap-2">
              {severityFilters.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setFilter(s)}
                  className={`rounded-lg px-3 py-1.5 text-sm capitalize transition ${
                    filter === s
                      ? "bg-emerald-500 text-zinc-950"
                      : "border border-zinc-700 text-zinc-400 hover:text-white"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>

            <div className="mt-6 space-y-4">
              {issues.length === 0 && scan.status === "completed" && (
                <p className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-8 text-center text-zinc-400">
                  No issues found — great job!
                </p>
              )}
              {issues.map((issue) => (
                <IssueCard key={issue.id} issue={issue} />
              ))}
            </div>
          </>
        )}
      </main>
    </div>
  );
}

function CountCard({
  label,
  value,
  color = "text-zinc-50",
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 text-center">
      <p className="text-xs text-zinc-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}
