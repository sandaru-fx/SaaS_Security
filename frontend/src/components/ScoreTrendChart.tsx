import { TrendPoint } from "@/lib/api";

type ScoreTrendChartProps = {
  points: TrendPoint[];
};

export function ScoreTrendChart({ points }: ScoreTrendChartProps) {
  if (points.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center rounded-xl border border-dashed border-zinc-700 text-sm text-zinc-500">
        Complete audits to see your score trend
      </div>
    );
  }

  const width = 640;
  const height = 200;
  const padding = { top: 20, right: 16, bottom: 36, left: 36 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const scores = points.map((p) => p.health_score);
  const minScore = Math.max(0, Math.min(...scores) - 10);
  const maxScore = Math.min(100, Math.max(...scores) + 10);
  const range = maxScore - minScore || 1;

  const coords = points.map((point, index) => {
    const x =
      padding.left +
      (points.length === 1 ? chartW / 2 : (index / (points.length - 1)) * chartW);
    const y = padding.top + chartH - ((point.health_score - minScore) / range) * chartH;
    return { x, y, point };
  });

  const linePath = coords.map((c, i) => `${i === 0 ? "M" : "L"} ${c.x} ${c.y}`).join(" ");
  const areaPath = `${linePath} L ${coords[coords.length - 1].x} ${padding.top + chartH} L ${coords[0].x} ${padding.top + chartH} Z`;

  const latest = points[points.length - 1];
  const previous = points.length > 1 ? points[points.length - 2] : null;
  const delta = previous ? latest.health_score - previous.health_score : null;

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-widest text-zinc-500">Score Trend</p>
          <p className="mt-1 text-2xl font-bold text-zinc-50">
            {latest.health_score}
            <span className="ml-2 text-sm font-normal text-zinc-400">latest</span>
          </p>
        </div>
        {delta != null && (
          <span
            className={`rounded-full px-3 py-1 text-xs font-medium ${
              delta >= 0 ? "bg-emerald-500/20 text-emerald-300" : "bg-red-500/20 text-red-300"
            }`}
          >
            {delta >= 0 ? "+" : ""}
            {delta} vs previous scan
          </span>
        )}
      </div>

      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" role="img" aria-label="Health score trend chart">
        {[0, 25, 50, 75, 100].map((tick) => {
          if (tick < minScore || tick > maxScore) return null;
          const y = padding.top + chartH - ((tick - minScore) / range) * chartH;
          return (
            <g key={tick}>
              <line
                x1={padding.left}
                x2={width - padding.right}
                y1={y}
                y2={y}
                stroke="#3f3f46"
                strokeDasharray="4 4"
              />
              <text x={8} y={y + 4} fill="#71717a" fontSize="10">
                {tick}
              </text>
            </g>
          );
        })}

        <path d={areaPath} fill="url(#trendGradient)" opacity={0.35} />
        <defs>
          <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={linePath} fill="none" stroke="#10b981" strokeWidth="2.5" />

        {coords.map(({ x, y, point }) => (
          <g key={point.scan_id}>
            <circle cx={x} cy={y} r="4" fill="#10b981" />
            <title>
              {point.project_name}: {point.health_score} on{" "}
              {new Date(point.completed_at).toLocaleDateString()}
            </title>
          </g>
        ))}
      </svg>

      <p className="mt-2 text-xs text-zinc-600">
        {points.length} completed audit{points.length === 1 ? "" : "s"} over time
      </p>
    </div>
  );
}
