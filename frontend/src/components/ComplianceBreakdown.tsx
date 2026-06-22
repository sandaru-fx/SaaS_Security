import { ComplianceControl } from "@/lib/api";

const statusStyles: Record<string, string> = {
  fail: "border-red-500/40 bg-red-950/30 text-red-300",
  review: "border-amber-500/40 bg-amber-950/30 text-amber-300",
  pass: "border-emerald-500/40 bg-emerald-950/30 text-emerald-300",
};

const FRAMEWORK_ORDER = ["PCI-DSS", "GDPR", "SOC2", "HIPAA"] as const;

export function ComplianceBreakdown({ controls }: { controls: ComplianceControl[] }) {
  if (controls.length === 0) return null;

  const grouped = FRAMEWORK_ORDER.map((framework) => ({
    framework,
    items: controls.filter((c) => c.framework === framework),
  })).filter((g) => g.items.length > 0);

  return (
    <section className="mt-8 rounded-2xl border border-zinc-800 bg-zinc-900/50 p-6">
      <h3 className="text-lg font-semibold text-zinc-50">Compliance Mapping</h3>
      <p className="mt-1 text-sm text-zinc-400">
        Findings mapped to PCI-DSS, GDPR, SOC2, and HIPAA controls based on CWE and category tags.
      </p>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {grouped.map(({ framework, items }) => (
          <ComplianceGroup key={framework} title={framework} items={items} />
        ))}
      </div>
    </section>
  );
}

function ComplianceGroup({ title, items }: { title: string; items: ComplianceControl[] }) {
  if (items.length === 0) {
    return (
      <div>
        <h4 className="text-sm font-medium uppercase tracking-wider text-zinc-500">{title}</h4>
        <p className="mt-2 text-sm text-zinc-500">No mapped findings.</p>
      </div>
    );
  }

  return (
    <div>
      <h4 className="text-sm font-medium uppercase tracking-wider text-zinc-500">{title}</h4>
      <ul className="mt-3 space-y-2">
        {items.map((item) => (
          <li
            key={`${item.framework}-${item.control_id}`}
            className={`rounded-lg border px-4 py-3 ${statusStyles[item.status] ?? statusStyles.review}`}
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="font-medium">{item.control_id}</p>
                <p className="mt-1 text-sm opacity-90">{item.title}</p>
              </div>
              <span className="shrink-0 text-xs uppercase">{item.status}</span>
            </div>
            {item.issue_count > 0 && (
              <p className="mt-2 text-xs opacity-75">
                {item.issue_count} finding(s) · max severity {item.max_severity}
              </p>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
