import { ApiIssue } from "@/lib/api";

type IssueDetailModalProps = {
  issue: ApiIssue | null;
  onClose: () => void;
};

export function IssueDetailModal({ issue, onClose }: IssueDetailModalProps) {
  if (!issue) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-widest text-emerald-400">
              Audit Finding
            </p>
            <h2 className="mt-2 text-xl font-bold text-zinc-50">{issue.title}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-zinc-700 px-3 py-1 text-sm text-zinc-400 hover:text-white"
          >
            Close
          </button>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <Badge label={issue.severity} />
          {issue.priority != null && <Badge label={`Priority ${issue.priority}`} />}
          {issue.report_category && <Badge label={issue.report_category} />}
          <Badge label={issue.scanner} />
        </div>

        <Section title="Problem" content={issue.description} />
        <Section title="Business Impact" content={issue.impact} />
        <Section title="Technical Risk" content={`Severity: ${issue.severity.toUpperCase()} · Confidence: ${issue.confidence}`} />
        <Section title="How To Fix" content={issue.fix_recommendation} highlight />

        {(issue.file_path || issue.rule_id) && (
          <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 font-mono text-xs text-zinc-400">
            {issue.file_path && (
              <p>
                File: {issue.file_path}
                {issue.line_start > 0 && `:${issue.line_start}`}
              </p>
            )}
            <p className="mt-1">Rule: {issue.rule_id}</p>
          </div>
        )}
      </div>
    </div>
  );
}

function Section({
  title,
  content,
  highlight = false,
}: {
  title: string;
  content: string;
  highlight?: boolean;
}) {
  return (
    <div className="mt-4">
      <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">{title}</p>
      <p className={`mt-2 text-sm leading-relaxed ${highlight ? "text-emerald-300" : "text-zinc-300"}`}>
        {content}
      </p>
    </div>
  );
}

function Badge({ label }: { label: string }) {
  return (
    <span className="rounded-full border border-zinc-700 px-2.5 py-1 text-xs capitalize text-zinc-300">
      {label}
    </span>
  );
}
