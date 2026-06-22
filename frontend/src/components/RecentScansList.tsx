import Link from "next/link";

import { RecentScanItem } from "@/lib/api";

const statusColors: Record<string, string> = {
  queued: "text-zinc-400",
  running: "text-amber-400",
  completed: "text-emerald-400",
  failed: "text-red-400",
};

export function RecentScansList({ scans }: { scans: RecentScanItem[] }) {
  if (scans.length === 0) {
    return (
      <p className="rounded-xl border border-dashed border-zinc-700 p-8 text-center text-sm text-zinc-500">
        No audits yet. Start one from a project page.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {scans.map((scan) => (
        <Link
          key={scan.scan_id}
          href={`/projects/${scan.project_id}/scans/${scan.scan_id}`}
          className="flex items-center justify-between gap-4 rounded-xl border border-zinc-800 bg-zinc-900/40 px-4 py-3 transition hover:border-emerald-500/40"
        >
          <div className="min-w-0">
            <p className="truncate font-medium text-zinc-100">{scan.project_name}</p>
            <p className="text-xs text-zinc-500">
              {new Date(scan.created_at).toLocaleString()} · {scan.total_issues} issues
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            {scan.health_score != null && (
              <div className="text-right">
                <p className="text-lg font-bold text-zinc-50">{scan.health_score}</p>
                {scan.grade && <p className="text-xs text-zinc-500">Grade {scan.grade}</p>}
              </div>
            )}
            <span className={`text-sm capitalize ${statusColors[scan.status] ?? "text-zinc-400"}`}>
              {scan.status}
            </span>
          </div>
        </Link>
      ))}
    </div>
  );
}
