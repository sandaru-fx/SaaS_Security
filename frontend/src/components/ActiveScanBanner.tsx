import Link from "next/link";

import { ActiveScanItem } from "@/lib/api";

export function ActiveScanBanner({ scans }: { scans: ActiveScanItem[] }) {
  if (scans.length === 0) return null;

  return (
    <div className="mb-6 space-y-2">
      {scans.map((scan) => (
        <div
          key={scan.scan_id}
          className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/30 bg-amber-950/30 px-4 py-3"
        >
          <div className="flex items-center gap-3">
            <span className="h-2 w-2 animate-pulse rounded-full bg-amber-400" />
            <div>
              <p className="text-sm font-medium text-amber-100">
                Audit {scan.status === "running" ? "running" : "queued"} — {scan.project_name}
              </p>
              <p className="text-xs text-amber-200/70">
                Started {new Date(scan.created_at).toLocaleString()}
              </p>
            </div>
          </div>
          <Link
            href={`/projects/${scan.project_id}/scans/${scan.scan_id}`}
            className="text-sm font-medium text-amber-300 hover:text-amber-200"
          >
            View progress →
          </Link>
        </div>
      ))}
    </div>
  );
}
