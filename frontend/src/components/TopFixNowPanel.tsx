import { ApiIssue } from "@/lib/api";

type TopFixNowPanelProps = {
  issues: ApiIssue[];
  fixNowCount: number;
  maxRiskScore: number | null;
  onSelect: (issue: ApiIssue) => void;
};

export function TopFixNowPanel({
  issues,
  fixNowCount,
  maxRiskScore,
  onSelect,
}: TopFixNowPanelProps) {
  if (issues.length === 0) return null;

  return (
    <section className="mt-8 rounded-2xl border border-rose-500/30 bg-rose-950/15 p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs font-medium uppercase tracking-widest text-rose-300">
            Risk Scoring v2 — Fix Now Queue
          </p>
          <h2 className="mt-2 text-xl font-semibold text-zinc-50">
            Top {issues.length} highest-risk findings
          </h2>
          <p className="mt-2 text-sm text-zinc-400">
            Weighted by EPSS exploit probability, CISA KEV (exploited in the wild),
            reachability, live-validated secrets, and internet exposure — not just
            raw severity.
          </p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-bold text-rose-300">{fixNowCount}</p>
          <p className="text-xs text-zinc-500">fix-now items</p>
          {maxRiskScore != null && (
            <p className="mt-2 text-xs text-zinc-400">
              Peak risk score: <span className="font-semibold text-rose-200">{maxRiskScore}</span>/100
            </p>
          )}
        </div>
      </div>

      <ol className="mt-6 space-y-3">
        {issues.map((issue, index) => (
          <li key={issue.id}>
            <button
              type="button"
              onClick={() => onSelect(issue)}
              className="w-full rounded-xl border border-zinc-800 bg-zinc-950/60 p-4 text-left transition hover:border-rose-500/40"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex gap-3">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-rose-500/20 text-sm font-bold text-rose-300">
                    {index + 1}
                  </span>
                  <div>
                    <p className="font-medium text-zinc-100">{issue.title}</p>
                    <p className="mt-1 line-clamp-2 text-sm text-zinc-400">{issue.description}</p>
                  </div>
                </div>
                <RiskBadge score={issue.risk_score} severity={issue.severity} />
              </div>
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                {issue.kev_listed && (
                  <span className="rounded border border-red-500/50 bg-red-500/10 px-2 py-0.5 font-semibold text-red-300">
                    CISA KEV
                  </span>
                )}
                {issue.epss_score != null && issue.epss_score >= 0.1 && (
                  <span className="rounded border border-orange-500/40 bg-orange-500/10 px-2 py-0.5 text-orange-300">
                    EPSS {(issue.epss_score * 100).toFixed(1)}%
                  </span>
                )}
                {issue.validated === "active" && (
                  <span className="rounded border border-red-500/50 bg-red-500/10 px-2 py-0.5 font-semibold text-red-300">
                    VALIDATED ACTIVE
                  </span>
                )}
                {issue.reachable === "yes" && (
                  <span className="rounded border border-violet-500/40 bg-violet-500/10 px-2 py-0.5 text-violet-300">
                    Reachable
                  </span>
                )}
                {issue.taint_verified && (
                  <span className="rounded border border-violet-500/40 bg-violet-500/10 px-2 py-0.5 text-violet-300">
                    Taint verified
                  </span>
                )}
              </div>
            </button>
          </li>
        ))}
      </ol>
    </section>
  );
}

function RiskBadge({ score, severity }: { score: number | null; severity: string }) {
  const value = score ?? 0;
  const tone =
    value >= 75
      ? "border-red-500/50 bg-red-500/15 text-red-200"
      : value >= 50
        ? "border-orange-500/40 bg-orange-500/10 text-orange-200"
        : "border-amber-500/30 bg-amber-500/10 text-amber-200";

  return (
    <div className="text-right">
      <span className={`rounded-lg border px-3 py-1.5 text-sm font-bold ${tone}`}>
        Risk {value}
      </span>
      <p className="mt-1 text-xs capitalize text-zinc-500">{severity}</p>
    </div>
  );
}
