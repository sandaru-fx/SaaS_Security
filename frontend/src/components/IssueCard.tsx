import { ApiIssue } from "@/lib/api";

const severityStyles: Record<ApiIssue["severity"], string> = {
  critical: "border-red-500/50 bg-red-950/30 text-red-300",
  high: "border-orange-500/50 bg-orange-950/30 text-orange-300",
  medium: "border-amber-500/50 bg-amber-950/30 text-amber-300",
  low: "border-zinc-600 bg-zinc-900/50 text-zinc-400",
};

type IssueCardProps = {
  issue: ApiIssue;
  onSelect?: (issue: ApiIssue) => void;
};

export function IssueCard({ issue, onSelect }: IssueCardProps) {
  return (
    <button
      type="button"
      onClick={() => onSelect?.(issue)}
      className="w-full rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 text-left transition hover:border-emerald-500/40"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium text-zinc-100">{issue.title}</p>
          <p className="mt-1 text-sm text-zinc-400">{issue.description}</p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <span
            className={`rounded-full border px-2.5 py-1 text-xs font-medium capitalize ${severityStyles[issue.severity]}`}
          >
            {issue.severity}
          </span>
          {issue.priority != null && (
            <span className="text-xs text-zinc-500">Priority {issue.priority}</span>
          )}
        </div>
      </div>

      {issue.file_path && (
        <p className="mt-3 font-mono text-xs text-zinc-500">
          {issue.file_path}
          {issue.line_start > 0 && `:${issue.line_start}`}
        </p>
      )}

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <InfoBlock label="Business Impact" value={issue.impact} />
        <InfoBlock label="Recommended Fix" value={issue.fix_recommendation} />
      </div>

      <div className="mt-3 flex flex-wrap gap-2 text-xs text-zinc-500">
        <span className="rounded border border-zinc-800 px-2 py-0.5">{issue.category}</span>
        {issue.report_category && (
          <span className="rounded border border-zinc-800 px-2 py-0.5">
            {issue.report_category}
          </span>
        )}
        <span className="rounded border border-zinc-800 px-2 py-0.5">{issue.scanner}</span>
      </div>
    </button>
  );
}

function InfoBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
      <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">{label}</p>
      <p className="mt-1 text-sm text-zinc-300">{value}</p>
    </div>
  );
}
