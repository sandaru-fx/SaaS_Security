type CategoryScore = {
  category: string;
  score: number;
  issue_count: number;
};

const labels: Record<string, string> = {
  security: "Security",
  architecture: "Architecture",
  performance: "Performance",
  quality: "Code Quality",
  devops: "DevOps",
};

export function CategoryBreakdown({
  categories,
  countLabel = "issues",
}: {
  categories: CategoryScore[];
  countLabel?: string;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      {categories.map((cat) => (
        <div
          key={cat.category}
          className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4"
        >
          <p className="text-xs text-zinc-500">{labels[cat.category] ?? cat.category}</p>
          <p className="mt-2 text-2xl font-bold text-zinc-50">{cat.score}</p>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-zinc-800">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all"
              style={{ width: `${cat.score}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-zinc-600">
            {cat.issue_count} {countLabel}
          </p>
        </div>
      ))}
    </div>
  );
}
