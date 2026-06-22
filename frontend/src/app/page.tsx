async function getHealthStatus() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

  try {
    const res = await fetch(`${apiUrl}/api/health`, {
      next: { revalidate: 10 },
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function Home() {
  const health = await getHealthStatus();

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <header className="border-b border-zinc-800">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500 text-sm font-bold text-zinc-950">
              A
            </div>
            <span className="font-semibold tracking-tight">AI Software Auditor</span>
          </div>
          <span className="rounded-full border border-zinc-700 px-3 py-1 text-xs text-zinc-400">
            Phase 1 — Foundation
          </span>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-20">
        <div className="max-w-3xl">
          <p className="mb-4 text-sm font-medium uppercase tracking-widest text-emerald-400">
            Plan 0
          </p>
          <h1 className="text-4xl font-bold leading-tight tracking-tight sm:text-5xl">
            Is your system production-ready?
          </h1>
          <p className="mt-6 text-lg leading-relaxed text-zinc-400">
            Upload your project or connect GitHub. Get a professional audit report
            covering security, architecture, performance, and code quality — with
            business impact and fix recommendations.
          </p>
        </div>

        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: "Security", score: "—" },
            { label: "Architecture", score: "—" },
            { label: "Performance", score: "—" },
            { label: "Code Quality", score: "—" },
          ].map((item) => (
            <div
              key={item.label}
              className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5"
            >
              <p className="text-sm text-zinc-500">{item.label}</p>
              <p className="mt-2 text-3xl font-bold text-zinc-300">{item.score}</p>
            </div>
          ))}
        </div>

        <div className="mt-8 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
          <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
            System Status
          </h2>
          <div className="mt-4 flex flex-wrap items-center gap-4">
            <StatusBadge
              label="Frontend"
              status="healthy"
              detail="Next.js running"
            />
            <StatusBadge
              label="API"
              status={health ? "healthy" : "offline"}
              detail={
                health
                  ? `${health.service} v${health.version}`
                  : "Start backend on :8000"
              }
            />
            <StatusBadge
              label="Database"
              status="pending"
              detail="Phase 1 — Docker required"
            />
            <StatusBadge
              label="Worker"
              status="pending"
              detail="Phase 4 — Scan engine"
            />
          </div>
        </div>

        <div className="mt-12 flex flex-wrap gap-4">
          <button
            type="button"
            disabled
            className="cursor-not-allowed rounded-lg bg-emerald-500/50 px-6 py-3 text-sm font-semibold text-zinc-950"
          >
            Start Audit — Phase 3
          </button>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg border border-zinc-700 px-6 py-3 text-sm font-medium text-zinc-300 transition hover:border-zinc-500 hover:text-white"
          >
            API Docs →
          </a>
        </div>
      </main>
    </div>
  );
}

function StatusBadge({
  label,
  status,
  detail,
}: {
  label: string;
  status: "healthy" | "offline" | "pending";
  detail: string;
}) {
  const colors = {
    healthy: "bg-emerald-500",
    offline: "bg-red-500",
    pending: "bg-amber-500",
  };

  return (
    <div className="flex items-center gap-3 rounded-lg border border-zinc-800 px-4 py-3">
      <div className={`h-2.5 w-2.5 rounded-full ${colors[status]}`} />
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-zinc-500">{detail}</p>
      </div>
    </div>
  );
}
