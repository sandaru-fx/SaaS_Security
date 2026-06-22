import { ScanCompareResult } from "@/lib/api";

type ScanComparePanelProps = {
  comparison: ScanCompareResult | null;
  loading: boolean;
};

function Delta({ value, invert = false }: { value: number; invert?: boolean }) {
  const good = invert ? value < 0 : value > 0;
  const bad = invert ? value > 0 : value < 0;
  const color = good ? "text-emerald-400" : bad ? "text-red-400" : "text-zinc-400";
  const prefix = value > 0 ? "+" : "";
  return <span className={color}>{prefix}{value}</span>;
}

export function ScanComparePanel({ comparison, loading }: ScanComparePanelProps) {
  if (loading) {
    return <p className="text-sm text-zinc-400">Comparing scans...</p>;
  }
  if (!comparison) {
    return (
      <p className="rounded-lg border border-dashed border-zinc-700 p-6 text-center text-sm text-zinc-500">
        Select two completed scans to compare before vs after fixes.
      </p>
    );
  }

  const { base_scan: base, target_scan: target } = comparison;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
          Scan Comparison
        </h3>
        <span
          className={`rounded-full px-3 py-1 text-xs font-medium ${
            comparison.improved
              ? "bg-emerald-500/20 text-emerald-300"
              : "bg-amber-500/20 text-amber-300"
          }`}
        >
          {comparison.improved ? "Improved" : "No improvement"}
        </span>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2">
        <ScanSummary label="Before" scan={base} />
        <ScanSummary label="After" scan={target} />
      </div>

      <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric label="Score" value={comparison.score_delta} />
        <Metric label="Issues" value={comparison.issues_delta} invert />
        <Metric label="Critical" value={comparison.critical_delta} invert />
        <Metric label="High" value={comparison.high_delta} invert />
      </div>

      <div className="mt-6">
        <p className="mb-3 text-xs uppercase tracking-widest text-zinc-500">Category Changes</p>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          {Object.entries(comparison.category_deltas).map(([category, delta]) => (
            <div
              key={category}
              className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2 text-sm capitalize"
            >
              <span className="text-zinc-500">{category}</span>
              <p className="mt-1 font-semibold">
                {delta == null ? "—" : <Delta value={delta} />}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ScanSummary({
  label,
  scan,
}: {
  label: string;
  scan: ScanCompareResult["base_scan"];
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-4">
      <p className="text-xs uppercase tracking-widest text-zinc-500">{label}</p>
      <p className="mt-2 text-xs text-zinc-500">{new Date(scan.created_at).toLocaleString()}</p>
      <p className="mt-3 text-3xl font-bold text-zinc-50">
        {scan.health_score ?? "—"}
        {scan.grade && <span className="ml-2 text-sm font-normal text-zinc-400">({scan.grade})</span>}
      </p>
      <p className="mt-2 text-sm text-zinc-400">{scan.total_issues} issues</p>
    </div>
  );
}

function Metric({
  label,
  value,
  invert = false,
}: {
  label: string;
  value: number | null;
  invert?: boolean;
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 text-center">
      <p className="text-xs text-zinc-500">{label}</p>
      <p className="mt-1 text-xl font-bold">
        {value == null ? "—" : <Delta value={value} invert={invert} />}
      </p>
    </div>
  );
}
